#!/bin/bash
# Section 15's self-hosted onion, on testonion-vm. `make testonion` stages this directory and runs this as root:
#   sudo bash setup.sh STAGE_DIR
# Each step checks state first, so a rerun changes nothing but the installed app and torrc. Never run it on the
# crawler VM: it refuses a box with a crawler user.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

STAGE=${1:?usage: setup.sh STAGE_DIR}
APP_DIR=/opt/testonion
CREDENTIALS=/etc/testonion/credentials
HOSTNAME_FILE=/var/lib/tor/testonion/hostname
PACKAGES="tor python3"

log() { echo "testonion: $*"; }

if id crawler >/dev/null 2>&1; then
    echo "testonion: this box has a crawler user; the self-hosted onion never runs on the crawler VM" >&2
    exit 1
fi

missing=""
for pkg in $PACKAGES; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing="$missing $pkg"
done
if [ -n "$missing" ]; then
    apt-get update -q
    apt-get install -y -q $missing
    log "installed$missing"
fi

id testonion >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin testonion

install -d -m 755 "$APP_DIR"
install -m 644 "$STAGE/app.py" "$APP_DIR/app.py"

# Made once, here, and never shown. `make testonion-credentials` pipes it to the crawler guest through the host,
# so it never lands on the host's disk or a terminal. The password always mixes cases and digits over 32
# characters, the token shape onioncollect's redaction gate catches on any page, should the app ever show it.
install -d -m 750 -o root -g testonion /etc/testonion
if [ ! -s "$CREDENTIALS" ]; then
    (umask 077 && python3 -I -c 'import secrets
password = ""
while not (any(c.isupper() for c in password) and any(c.islower() for c in password)
           and any(c.isdigit() for c in password)):
    password = secrets.token_urlsafe(24)
print(f"username=operator-{secrets.token_hex(4)}")
print(f"password={password}")' > "$CREDENTIALS")
    log "credentials generated in $CREDENTIALS"
fi
chown testonion:testonion "$CREDENTIALS"
chmod 600 "$CREDENTIALS"

install -m 644 "$STAGE/testonion.service" /etc/systemd/system/testonion.service
install -m 644 "$STAGE/torrc" /etc/tor/torrc
systemctl daemon-reload
systemctl enable --quiet testonion.service tor
systemctl restart testonion.service tor

for _ in $(seq 90); do
    [ -s "$HOSTNAME_FILE" ] && break
    sleep 1
done
[ -s "$HOSTNAME_FILE" ] || { echo "testonion: tor wrote no hostname to $HOSTNAME_FILE" >&2; exit 1; }
python3 -I -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/", timeout=5)' \
    || { echo "testonion: the app does not answer on 127.0.0.1:8080" >&2; exit 1; }
log "app answering on 127.0.0.1:8080"
log "onion address: $(cat "$HOSTNAME_FILE")"
