#!/bin/bash
# Converges the guest to section 3 of docs/build-guide.md. Runs as root on every boot and from
# `make provision`. Each step checks state before changing it, so a rerun changes nothing.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1

STAGE=/etc/onioncrawl
INSTANCES="1 2 3 4 5 6"
# The layout's paths, users and groups. tests/test_provision.py overrides them to run migrate_layout on a fake tree.
CRAWLER=${CRAWLER:-crawler}
ANALYST=${ANALYST:-analyst}
CRAWLER_GROUP=${CRAWLER_GROUP:-crawler}
ANALYST_GROUP=${ANALYST_GROUP:-analyst}
IPC_GROUP=${IPC_GROUP:-onioncollect-ipc}
CRAWLER_HOME=${CRAWLER_HOME:-/home/crawler}
ANALYST_HOME=${ANALYST_HOME:-/home/analyst}
SHARED=${SHARED:-/var/lib/onioncollect}
LOG_DIR=${LOG_DIR:-/var/log/onioncollect}
DATA_DIR=$ANALYST_HOME/data
CONFIGS_DIR=$SHARED/configs
STATE_DIR=$CRAWLER_HOME/state
PASSWORD_FILE=$CRAWLER_HOME/control-password
SALT_FILE=$CRAWLER_HOME/redaction-salt
HASH_FILE=/etc/tor/onioncrawl-control.hash
VENV=$CRAWLER_HOME/venv
OPT=/opt/onioncollect
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
    for group in sudo adm; do
        id -nG crawler | tr ' ' '\n' | grep -qx "$group" && gpasswd -d crawler "$group"
    done
}

# The analyst owns the stores (mode 700) and runs the writer, which the crawler reaches over a unix socket whose
# group, onioncollect-ipc, holds the crawler alone. The analyst gets no firewall rule of its own, so the kill switch
# leaves it loopback only, like every user but Tor's.
create_analyst() {
    if ! id analyst >/dev/null 2>&1; then
        useradd --create-home --user-group --shell /bin/bash analyst
        log "analyst user created"
    fi
    chmod 700 "$ANALYST_HOME"
    for group in sudo adm; do
        id -nG analyst | tr ' ' '\n' | grep -qx "$group" && gpasswd -d analyst "$group"
    done
    if ! getent group "$IPC_GROUP" >/dev/null; then
        groupadd --system "$IPC_GROUP"
        log "$IPC_GROUP group created"
    fi
    id -nG crawler | tr ' ' '\n' | grep -qx "$IPC_GROUP" || usermod -aG "$IPC_GROUP" crawler
    id -nG analyst | tr ' ' '\n' | grep -qx "$IPC_GROUP" && gpasswd -d analyst "$IPC_GROUP"
    migrate_layout
    # Triage refuses an excluded host, so the analyst keeps its own copy of the crawler's list.
    if ! cmp -s "$CRAWLER_HOME/exclusions.txt" "$ANALYST_HOME/exclusions.txt"; then
        install -m 600 -o analyst -g analyst "$CRAWLER_HOME/exclusions.txt" "$ANALYST_HOME/exclusions.txt"
        log "analyst exclusions.txt copied from the crawler's"
    fi
    local settings=$ANALYST_HOME/settings.toml rendered
    rendered=$(mktemp)
    printf 'data_dir = "%s"\nconfigs_dir = "%s"\nlog_dir = "%s"\nexclusions_file = "%s"\n' \
        "$DATA_DIR" "$CONFIGS_DIR" "$LOG_DIR" "$ANALYST_HOME/exclusions.txt" > "$rendered"
    if ! cmp -s "$rendered" "$settings"; then
        install -m 600 -o analyst -g analyst "$rendered" "$settings"
        log "analyst settings.toml written"
    fi
    rm -f "$rendered"
}

# The layout the writer needs, from whatever an earlier one left. Stores to the analyst's data dir, the frontier
# and run lock to the crawler's state dir, the crawl log to the log dir the analyst audits, configs to the shared
# dir the crawler reads. Moves happen once; ownership and modes converge on every run.
migrate_layout() {
    local old=$CRAWLER_HOME/data name file
    install -d -m 700 -o "$ANALYST" -g "$ANALYST_GROUP" "$DATA_DIR"
    install -d -m 700 -o "$CRAWLER" -g "$CRAWLER_GROUP" "$STATE_DIR"
    install -d -m 755 "$SHARED"
    install -d -m 2750 -o "$ANALYST" -g "$IPC_GROUP" "$CONFIGS_DIR"
    install -d -m 2750 -o "$CRAWLER" -g "$ANALYST_GROUP" "$LOG_DIR"
    if [ -d "$old" ]; then
        for name in collect.db collect.db-wal collect.db-shm records.db records.db-wal records.db-shm snapshots; do
            if [ -e "$old/$name" ] && [ ! -e "$DATA_DIR/$name" ]; then
                mv "$old/$name" "$DATA_DIR/"
                log "$name moved to the analyst's data dir"
            fi
        done
        for name in frontier.db frontier.db-wal frontier.db-shm; do
            if [ -e "$old/$name" ] && [ ! -e "$STATE_DIR/$name" ]; then
                mv "$old/$name" "$STATE_DIR/"
                log "$name moved to the crawler's state dir"
            fi
        done
        for file in "$old"/crawl.log*; do
            if [ -e "$file" ] && [ ! -e "$LOG_DIR/$(basename "$file")" ]; then
                mv "$file" "$LOG_DIR/"
                log "$(basename "$file") moved to $LOG_DIR"
            fi
        done
        rm -f "$old/run.lock"
        if rmdir "$old" 2>/dev/null; then log "$old removed"; else log "$old kept: it holds files no store uses"; fi
    fi
    if [ -d "$CRAWLER_HOME/configs" ]; then
        for file in "$CRAWLER_HOME"/configs/*.toml; do
            if [ -e "$file" ] && [ ! -e "$CONFIGS_DIR/$(basename "$file")" ]; then
                mv "$file" "$CONFIGS_DIR/"
                log "config $(basename "$file") moved to $CONFIGS_DIR"
            fi
        done
        if rmdir "$CRAWLER_HOME/configs" 2>/dev/null; then log "$CRAWLER_HOME/configs removed"; fi
    fi
    chown -R "$ANALYST:$ANALYST_GROUP" "$DATA_DIR"
    chmod -R go-rwx "$DATA_DIR"
    find "$DATA_DIR" -type d -perm -2000 -exec chmod g-s {} +
    chown -R "$CRAWLER:$CRAWLER_GROUP" "$STATE_DIR"
    chmod -R go-rwx "$STATE_DIR"
    chown -R "$ANALYST:$IPC_GROUP" "$CONFIGS_DIR"
    find "$CONFIGS_DIR" -type f -exec chmod 640 {} +
    chown -R "$CRAWLER:$ANALYST_GROUP" "$LOG_DIR"
    find "$LOG_DIR" -type f -exec chmod 640 {} +
    # An earlier layout let the analyst's group into the crawler's home.
    chown "$CRAWLER:$CRAWLER_GROUP" "$CRAWLER_HOME"
    chmod 700 "$CRAWLER_HOME"
}

create_redaction_salt() {
    # Keyed hashes in the records are only as private as this. It is never regenerated: a new salt
    # would orphan every hash already stored.
    if [ ! -s "$SALT_FILE" ]; then
        (umask 077; head -c 48 /dev/urandom | base64 | tr -d '\n' > "$SALT_FILE")
        log "redaction salt generated at $SALT_FILE"
    fi
    chown crawler:crawler "$SALT_FILE"
    chmod 600 "$SALT_FILE"
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

# The systemd units run from a root-owned copy of the code and this root-owned venv, so the user a unit runs as
# cannot change what it runs. Same hashes as the crawler's venv.
install_runtime() {
    install -d -m 755 -o root -g root "$OPT"
    [ -x "$OPT/venv/bin/python" ] || python3 -m venv "$OPT/venv"
    local want have
    want=$(sha256sum "$STAGE/requirements.txt" | cut -d' ' -f1)
    have=$(cat "$OPT/venv/.requirements.sha256" 2>/dev/null || true)
    [ "$want" = "$have" ] && return
    open_egress
    "$OPT/venv/bin/pip" install -q --require-hashes -r "$STAGE/requirements.txt"
    echo "$want" > "$OPT/venv/.requirements.sha256"
    log "root-owned venv installed at $OPT/venv with --require-hashes"
}

write_settings() {
    local settings=$CRAWLER_HOME/settings.toml
    local rendered
    rendered=$(mktemp)
    cat > "$rendered" <<EOF
control_password_file = "$PASSWORD_FILE"
redaction_salt_file = "$SALT_FILE"
data_dir = "$DATA_DIR"
configs_dir = "$CONFIGS_DIR"
state_dir = "$STATE_DIR"
log_dir = "$LOG_DIR"
exclusions_file = "$CRAWLER_HOME/exclusions.txt"
safety_patterns_file = "$CRAWLER_HOME/safety-patterns.txt"
EOF
    if ! cmp -s "$rendered" "$settings"; then
        install -m 600 -o crawler -g crawler "$rendered" "$settings"
        log "settings.toml written"
    fi
    rm -f "$rendered"
    if [ ! -e "$CRAWLER_HOME/exclusions.txt" ]; then
        printf '%s\n' "# One v3 onion host per line. These hosts are never fetched." \
            "# The crawler will not start until at least one host is listed." |
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

# Sourced by tests/test_provision.py for migrate_layout alone.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0

install_tor_repo
install_packages
quiet_the_box
create_crawler
create_control_password
create_redaction_salt
configure_tor
install_venv
install_runtime
write_settings
create_analyst
install_kill_switch
log "converged"
