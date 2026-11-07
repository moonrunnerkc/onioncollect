#!/bin/bash
# Converges the guest to section 3 of docs/build-guide.md. Runs as root on every boot and from
# `make provision`. Each step checks state before changing it, so a rerun changes nothing.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1

STAGE=/etc/onioncrawl
INSTANCES="1 2 3 4 5 6"
CRAWLER_HOME=/home/crawler
PASSWORD_FILE=$CRAWLER_HOME/control-password
HASH_FILE=/etc/tor/onioncrawl-control.hash
VENV=$CRAWLER_HOME/venv
TOR_KEY_FPR=A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
TOR_KEYRING=/usr/share/keyrings/deb.torproject.org-keyring.gpg
PACKAGES="tor deb.torproject.org-keyring python3-venv iptables iptables-persistent tcpdump bind9-dnsutils curl sqlite3"

log() { echo "provision: $*"; }

# With the kill switch already loaded, root, apt, pip and the resolver cannot reach the network.
# Section 3.4's update procedure: punch a temporary hole, do the work, restore the saved rules.
open_egress() {
    iptables -C OUTPUT -j DROP 2>/dev/null || return 0
    for user in root _apt crawler systemd-resolve; do
        id -u "$user" >/dev/null 2>&1 || continue
        iptables -C OUTPUT -m owner --uid-owner "$user" -j ACCEPT 2>/dev/null && continue
        iptables -I OUTPUT 1 -m owner --uid-owner "$user" -j ACCEPT
        log "temporary egress opened for $user"
    done
}
restore_firewall() {
    if [ -f /etc/iptables/rules.v4 ]; then
        iptables-restore < /etc/iptables/rules.v4
        ip6tables-restore < /etc/iptables/rules.v6
    fi
}
trap restore_firewall EXIT

missing_packages() {
    for pkg in $PACKAGES; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || echo "$pkg"
    done
}

install_tor_repo() {
    [ -f /etc/apt/sources.list.d/tor.sources ] && return
    open_egress
    apt-get update -q
    apt-get install -y -q curl gpg ca-certificates
    local key
    key=$(mktemp)
    curl -fsSL "https://deb.torproject.org/torproject.org/$TOR_KEY_FPR.asc" | gpg --dearmor > "$key"
    local fpr
    fpr=$(gpg --show-keys --with-colons "$key" | awk -F: '/^fpr/ {print $10; exit}')
    if [ "$fpr" != "$TOR_KEY_FPR" ]; then
        echo "provision: Tor Project key fingerprint mismatch: $fpr" >&2
        exit 1
    fi
    install -m 644 "$key" "$TOR_KEYRING"
    rm -f "$key"
    . /etc/os-release
    cat > /etc/apt/sources.list.d/tor.sources <<EOF
Types: deb
URIs: https://deb.torproject.org/torproject.org
Suites: $VERSION_CODENAME
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: $TOR_KEYRING
EOF
    cat > /etc/apt/preferences.d/tor <<EOF
Package: tor tor-geoipdb
Pin: origin deb.torproject.org
Pin-Priority: 900
EOF
    log "Tor Project apt repository added"
}

install_packages() {
    local missing
    missing=$(missing_packages)
    [ -z "$missing" ] && return
    open_egress
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections
    apt-get update -q
    # shellcheck disable=SC2086
    apt-get install -y -q $missing
    log "installed: $(echo $missing)"
}

quiet_the_box() {
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
        apt-get purge -y -q unattended-upgrades
    fi
    # NTP is a clearnet packet from root. The hypervisor sets the clock instead.
    for unit in systemd-timesyncd.service chrony.service apt-daily.timer apt-daily-upgrade.timer tor@default.service; do
        if systemctl cat "$unit" >/dev/null 2>&1 && [ "$(systemctl is-enabled "$unit" 2>/dev/null)" != masked ]; then
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            systemctl mask "$unit" >/dev/null 2>&1
        fi
    done
    local resolved=/etc/systemd/resolved.conf.d/onioncrawl.conf
    if [ ! -f "$resolved" ]; then
        install -d -m 755 /etc/systemd/resolved.conf.d
        printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' > "$resolved"
        systemctl restart systemd-resolved
        log "LLMNR and mDNS listeners off"
    fi
}

create_crawler() {
    if ! id crawler >/dev/null 2>&1; then
        useradd --create-home --user-group --shell /bin/bash crawler
        log "crawler user created"
    fi
    chmod 700 "$CRAWLER_HOME"
    for group in sudo adm; do
        id -nG crawler | tr ' ' '\n' | grep -qx "$group" && gpasswd -d crawler "$group"
    done
    install -d -m 700 -o crawler -g crawler "$CRAWLER_HOME/data"
}

create_control_password() {
    if [ ! -s "$PASSWORD_FILE" ]; then
        (umask 077; head -c 48 /dev/urandom | base64 | tr -d '/+=\n' > "$PASSWORD_FILE")
        log "control password generated at $PASSWORD_FILE"
    fi
    chown crawler:crawler "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
    if [ ! -s "$HASH_FILE" ] || [ "$PASSWORD_FILE" -nt "$HASH_FILE" ]; then
        # Tor's HashedControlPassword is OpenPGP iterated+salted S2K over SHA-1, count byte 0x60.
        # Computed here so the plaintext never appears in argv, which `tor --hash-password` would need.
        (umask 077; python3 - "$PASSWORD_FILE" > "$HASH_FILE" <<'EOF'
import hashlib, os, sys
secret = open(sys.argv[1], "rb").read().strip()
salt, indicator = os.urandom(8), 0x60
count = (16 + (indicator & 15)) << ((indicator >> 4) + 6)
data = salt + secret
stream = (data * (count // len(data) + 1))[:count]
print("16:" + (salt + bytes([indicator]) + hashlib.sha1(stream).digest()).hex().upper())
EOF
        )
        log "control password hash refreshed"
    fi
}

configure_tor() {
    local hash
    hash=$(cat "$HASH_FILE")
    for n in $INSTANCES; do
        local name=crawl$n
        local torrc=/etc/tor/instances/$name/torrc
        [ -d "/etc/tor/instances/$name" ] || tor-instance-create "$name"
        local rendered
        rendered=$(mktemp)
        sed -e "s/@N@/$n/g" -e "s/@HASH@/$hash/" "$STAGE/torrc.template" > "$rendered"
        if ! cmp -s "$rendered" "$torrc"; then
            install -m 640 -o root -g "_tor-$name" "$rendered" "$torrc"
            systemctl enable "tor@$name" >/dev/null 2>&1
            systemctl restart "tor@$name"
            log "tor@$name configured"
        else
            systemctl enable --now "tor@$name" >/dev/null 2>&1
        fi
        rm -f "$rendered"
    done
}

install_venv() {
    [ -x "$VENV/bin/python" ] || sudo -u crawler -H python3 -m venv "$VENV"
    local want have
    want=$(sha256sum "$STAGE/requirements.txt" | cut -d' ' -f1)
    have=$(cat "$VENV/.requirements.sha256" 2>/dev/null || true)
    [ "$want" = "$have" ] && return
    open_egress
    sudo -u crawler -H "$VENV/bin/pip" install -q --require-hashes -r "$STAGE/requirements.txt"
    echo "$want" | sudo -u crawler tee "$VENV/.requirements.sha256" >/dev/null
    log "venv installed with --require-hashes"
}

write_settings() {
    local settings=$CRAWLER_HOME/settings.toml
    local rendered
    rendered=$(mktemp)
    cat > "$rendered" <<EOF
control_password_file = "$PASSWORD_FILE"
data_dir = "$CRAWLER_HOME/data"
exclusions_file = "$CRAWLER_HOME/exclusions.txt"
safety_patterns_file = "$CRAWLER_HOME/safety-patterns.txt"
EOF
    if ! cmp -s "$rendered" "$settings"; then
        install -m 600 -o crawler -g crawler "$rendered" "$settings"
        log "settings.toml written"
    fi
    rm -f "$rendered"
    if [ ! -e "$CRAWLER_HOME/exclusions.txt" ]; then
        echo "# One v3 onion host per line. Content fetched from these hosts is never saved." |
            install -m 600 -o crawler -g crawler /dev/stdin "$CRAWLER_HOME/exclusions.txt"
        log "exclusions.txt created"
    fi
}

install_kill_switch() {
    install -d -m 755 /etc/iptables
    local before
    before=$(cat /etc/iptables/rules.v4 /etc/iptables/rules.v6 2>/dev/null | sha256sum)
    {
        echo "*filter"
        echo ":INPUT ACCEPT [0:0]"
        echo ":FORWARD ACCEPT [0:0]"
        echo ":OUTPUT ACCEPT [0:0]"
        echo "-A OUTPUT -o lo -j ACCEPT"
        echo "-A OUTPUT -p tcp -m tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
        for n in $INSTANCES; do
            echo "-A OUTPUT -m owner --uid-owner _tor-crawl$n -j ACCEPT"
        done
        echo "-A OUTPUT -j DROP"
        echo "COMMIT"
    } > /etc/iptables/rules.v4
    printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n' > /etc/iptables/rules.v6
    chmod 600 /etc/iptables/rules.v4 /etc/iptables/rules.v6
    systemctl enable netfilter-persistent >/dev/null 2>&1
    restore_firewall
    if [ "$before" != "$(cat /etc/iptables/rules.v4 /etc/iptables/rules.v6 | sha256sum)" ]; then
        log "kill switch rules written and persisted"
    fi
}

install_tor_repo
install_packages
quiet_the_box
create_crawler
create_control_password
configure_tor
install_venv
write_settings
install_kill_switch
log "converged"
