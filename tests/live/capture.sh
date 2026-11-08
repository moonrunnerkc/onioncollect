# Sourced by leak_test.sh and crawl_capture.sh, as root in the guest. Opens and closes the section 15
# test 3 capture window and judges it with leak_analyze.py. Crawler code always runs as crawler.
APP=/home/crawler/app
PY=/home/crawler/venv/bin/python
WORK=$(mktemp -d)
FAILED=0
# Non-terminating rule, present only for the capture window: the kernel logs the owning UID of every
# new outbound flow, so attribution never depends on catching a short-lived socket with ss.
LOG_RULE=(OUTPUT ! -o lo -m conntrack --ctstate NEW -j LOG --log-prefix "onioncrawl-lt3: " --log-uid)
capture_cleanup() {
    iptables -D "${LOG_RULE[@]}" 2>/dev/null
    rm -rf "$WORK"
}
trap capture_cleanup EXIT

report() {
    if [ "$2" = pass ]; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi
}
# runuser, not sudo: root drops to the crawler with no setuid binary, so the daily timer's NoNewPrivileges holds.
as_crawler() { runuser -u crawler -- env HOME=/home/crawler "$@"; }
drop_count() { iptables -L OUTPUT -v -n -x | awk '$3 == "DROP" {print $1}'; }
# Counts packets in the finished capture that match a tcpdump filter.
captured() { tcpdump -r "$WORK/cap.pcap" -nn "$1" 2>/dev/null | wc -l; }

capture_start() {
    DEV=$(ip route show default | awk '{print $5; exit}')
    LOCAL_IP=$(ip -4 -o addr show dev "$DEV" | awk '{split($4, a, "/"); print a[1]; exit}')
    echo "capture: tcpdump -i $DEV 'not port 22' for $1, guest address $LOCAL_IP"
    tcpdump -i "$DEV" -nn -Z root -w "$WORK/cap.pcap" 'not port 22' 2>"$WORK/tcpdump.err" &
    TCPDUMP=$!
    ( while :; do echo "sample $(date +%s)"; ss -tnpH state established; sleep 1; done ) > "$WORK/ss.txt" &
    SAMPLER=$!
    iptables -I "${LOG_RULE[@]:0:1}" 1 "${LOG_RULE[@]:1}"
    sleep 2
    STARTED=$(date +%s)
    DROPS_BEFORE=$(drop_count)
}

capture_stop() {
    DROPS_AFTER=$(drop_count)
    iptables -D "${LOG_RULE[@]}"
    journalctl -k --since "@$((STARTED - 2))" -o cat --no-pager | grep "onioncrawl-lt3: " > "$WORK/flows.txt"
    kill "$SAMPLER" 2>/dev/null
    kill -INT "$TCPDUMP" && wait "$TCPDUMP" 2>/dev/null
    tcpdump -r "$WORK/cap.pcap" -nn -q -tt 2>/dev/null > "$WORK/cap.txt"
    chmod 755 "$WORK" && chmod 644 "$WORK/cap.txt" "$WORK/ss.txt" "$WORK/flows.txt"
    echo "      capture closed after $(( $(date +%s) - STARTED ))s"
    echo "      kill switch DROP counter: $DROPS_BEFORE -> $DROPS_AFTER (blocked attempts never reach the wire)"
    echo "      ss -tnp | grep -v 127.0.0.1, at the end of the window:"
    ss -tnpH | grep -v 127.0.0.1 | awk '{print "        " $1, $4, $5, $6}' | head -12
}

# The crawler's own end of each SOCKS connection, counted per Tor port in every one-second sample. Each
# connection is one Tor stream, so the peak per port is the most streams that instance carried for us.
socks_peaks() {
    awk '/^sample / { for (port in now) { if (now[port] > peak[port]) peak[port] = now[port] }; delete now; next }
         $4 ~ /^127\.0\.0\.1:100[0-9][0-9]$/ && $5 ~ /python/ { split($4, a, ":"); now[a[2]]++ }
         END { for (port in now) { if (now[port] > peak[port]) peak[port] = now[port] }
               for (port in peak) print port, peak[port] }' "$WORK/ss.txt" | sort
}

capture_judge() {
    if as_crawler "$PY" "$APP/tests/live/leak_analyze.py" "$WORK/cap.txt" "$WORK/ss.txt" "$WORK/flows.txt" \
            "$LOCAL_IP" /home/crawler/control-password | sed 's/^/      /'; then
        report "$1" pass
    else
        report "$1" fail
    fi
}
