#!/bin/bash
# Section 15 "Machine" checklist, run as root inside the guest. Read-only: reports, never fixes.
# The host-side items (FileVault, snapshot) are checked by `make checklist` on the Mac.
set -uo pipefail

FAILED=0
check() {
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS  $label"
    else
        echo "FAIL  $label"
        FAILED=1
    fi
}

is_vm() { [ "$(systemd-detect-virt)" != none ]; }

crawler_has_no_sudo() {
    ! id -nG crawler | tr ' ' '\n' | grep -qxE 'sudo|adm|wheel' &&
        sudo -l -U crawler | grep -q "not allowed"
}

data_dir_locked() { [ "$(stat -c '%U %a' /home/analyst/data)" = "analyst 700" ]; }

tor_instances_hardened() {
    for n in 1 2 3 4 5 6; do
        local torrc=/etc/tor/instances/crawl$n/torrc
        systemctl is-active --quiet "tor@crawl$n" || return 1
        grep -qx "ClientOnly 1" "$torrc" || return 1
        grep -qx "SafeLogging 1" "$torrc" || return 1
        grep -qx "SocksPort 127.0.0.1:1005$n IsolateSOCKSAuth" "$torrc" || return 1
        ss -ltnH "sport = :1005$n" | grep -q "127.0.0.1:1005$n" || return 1
        [ ! -e "/run/tor-instances/crawl$n/socks" ] || return 1
    done
}

password_file_locked() {
    local file=/home/crawler/control-password
    [ "$(stat -c '%U %a' "$file")" = "crawler 600" ] && [ -s "$file" ] &&
        ! git -C "$(dirname "$file")" rev-parse 2>/dev/null
}

expected_output_chain() {
    echo "-P OUTPUT ACCEPT"
    echo "-A OUTPUT -o lo -j ACCEPT"
    echo "-A OUTPUT -p tcp -m tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
    for n in 1 2 3 4 5 6; do
        echo "-A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -m owner --uid-owner $(id -u "_tor-crawl$n") -j CONNMARK --set-xmark 0x746f72/0xffffffff"
    done
    for n in 1 2 3 4 5 6; do
        echo "-A OUTPUT -m owner --uid-owner $(id -u "_tor-crawl$n") -j ACCEPT"
    done
    device=$(ip -4 route show default | awk '{print $5; exit}')
    subnet=$(ip -4 route show dev "$device" proto kernel scope link | awk '{print $1; exit}')
    echo "-A OUTPUT -d $subnet -o $device -p udp -m udp --sport 68 --dport 67 -m owner --uid-owner $(id -u systemd-network) -j ACCEPT"
    echo "-A OUTPUT -p tcp -m connmark --mark 0x746f72 -j ACCEPT"
    echo "-A OUTPUT -j DROP"
}

kill_switch_live() {
    diff <(expected_output_chain) <(iptables -S OUTPUT) &&
        [ "$(ip6tables -S OUTPUT)" = "-P OUTPUT DROP" ]
}

saved_output_rules() {
    grep '^-A OUTPUT' /etc/iptables/rules.v4 | while read -r rule; do
        for n in 1 2 3 4 5 6; do
            rule=${rule//--uid-owner _tor-crawl$n /--uid-owner $(id -u "_tor-crawl$n") }
        done
        rule=${rule//--uid-owner systemd-network /--uid-owner $(id -u systemd-network) }
        # iptables -S prints a rule's destination before its interface.
        echo "$rule" | sed -E 's/^-A OUTPUT (-o [^ ]+) (-d [^ ]+) /-A OUTPUT \2 \1 /'
    done
}

kill_switch_persisted() {
    systemctl is-enabled --quiet netfilter-persistent &&
        diff <(saved_output_rules) <(iptables -S OUTPUT | grep '^-A') &&
        grep -qx ":OUTPUT DROP \[0:0\]" /etc/iptables/rules.v6
}

no_proxy_env() {
    ! grep -qiE '^[^#]*(http|https|all|no)_proxy' /etc/environment /etc/profile /etc/profile.d/* /home/crawler/.profile /home/crawler/.bashrc 2>/dev/null &&
        ! sudo -u crawler -i env | grep -qi '_proxy='
}

no_ntp() {
    [ "$(systemctl is-enabled systemd-timesyncd 2>/dev/null)" = masked ] &&
        ! dpkg-query -W -f='${Status}' chrony ntp ntpsec 2>/dev/null | grep -q "install ok installed" &&
        [ "$(timedatectl show -p NTP --value)" = no ]
}

no_unattended_updates() {
    ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed" &&
        [ "$(systemctl is-enabled apt-daily.timer)" = masked ] &&
        [ "$(systemctl is-enabled apt-daily-upgrade.timer)" = masked ]
}

only_tor_leaves_the_box() { ! ss -tnpH state established | grep -v '127.0.0.1' | grep -v '"tor"' | grep -q .; }

check "dedicated VM" is_vm
check "crawler has no sudo" crawler_has_no_sudo
check "analyst owns data/ with mode 700" data_dir_locked
check "six tor@crawlN running: ClientOnly, SafeLogging, IsolateSOCKSAuth, SOCKS on loopback only" tor_instances_hardened
check "control password file mode 600, owned by crawler, outside any repo" password_file_locked
check "iptables OUTPUT: lo, SSH replies, six Tor SYN marks, six Tor UIDs, DHCP renewal, marked TCP, DROP; ip6tables OUTPUT policy DROP" kill_switch_live
check "kill switch persisted and loaded at boot" kill_switch_persisted
check "no proxy variables in the environment" no_proxy_env
check "no NTP client (hypervisor sets the clock)" no_ntp
check "unattended updates off" no_unattended_updates
check "every established non-loopback TCP socket belongs to tor" only_tor_leaves_the_box
exit $FAILED
