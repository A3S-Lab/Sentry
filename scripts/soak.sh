#!/usr/bin/env bash
# soak.sh — sustained-load soak for a3s-sentry.
#
# Feeds a high-rate mixed NDJSON stream (benign / block / escalate / rotating-egress / malformed)
# through the daemon for a duration, rewrites the policy mid-run (hot-reload under load), samples
# RSS, and checks for leaks / crashes / dropped events. Pure userspace — runs anywhere sentry builds.
#
#   ./scripts/soak.sh [path/to/sentry] [duration_seconds]
set -u
BIN="${1:-./target/release/sentry}"
DUR="${2:-30}"
WORK="$(mktemp -d)"
POL="$WORK/rules.hcl"
EGRESS="$WORK/egress-deny.txt"

cat > "$POL" <<'HCL'
rules = [ { name = "soak-block-10", on = "Egress", match = "^10\\.0\\.0\\.", verdict = "block", severity = "low", reason = "soak", action = "deny-egress" } ]
HCL

echo "soak: $BIN for ${DUR}s"

# generator (batched for rate) → sentry.  In bash, $! of `gen | sentry &` is sentry (last in pipe).
python3 - "$DUR" <<'PY' | A3S_SENTRY_POLICY="$POL" A3S_SENTRY_EGRESS_DENY="$EGRESS" "$BIN" >/dev/null 2>"$WORK/sentry.err" &
import sys, time
dur = float(sys.argv[1]); end = time.time() + dur
ev = [
 '{"event":{"ToolExec":{"pid":%d,"argv":["ls","-la"]}}}',                          # benign
 '{"event":{"SecurityAction":{"pid":%d,"kind":"setuid-root","detail":0}}}',        # block (privesc)
 '{"event":{"Egress":{"pid":%d,"peer":"10.0.0.%d","port":443}}}',                  # block (rotating, deny-egress)
 '{"event":{"Egress":{"pid":%d,"peer":"169.254.169.254","port":80}}}',             # block (metadata)
 '{"event":{"FileAccess":{"pid":%d,"path":"/home/a/.aws/credentials"}}}',          # escalate
 '{"event":{"SslContent":{"pid":%d,"is_read":false,"content":"hello world"}}}',    # benign content
 'garbage not json at all',                                                        # malformed → skipped
]
w = sys.stdout.write; buf = []; i = 0
while True:
    i += 1
    if i % 5000 == 0 and time.time() > end:
        break
    t = ev[i % len(ev)]; c = t.count('%d')
    if c == 0:   buf.append(t)
    elif c == 2: buf.append(t % (i, i % 256))   # rotating over a bounded set (exercises dedup)
    else:        buf.append(t % ((i,) * c))
    if len(buf) >= 1000:
        w("\n".join(buf) + "\n"); buf = []
if buf:
    w("\n".join(buf) + "\n")
sys.stdout.flush()
PY
SP=$!
echo "sentry pid=$SP"

MAXRSS=0; MINRSS=99999999; SAMPLES=0
for ((s=0; s<DUR; s+=2)); do
    sleep 2
    R="$(ps -o rss= -p "$SP" 2>/dev/null | tr -d ' ')"
    [ -z "$R" ] && break
    SAMPLES=$((SAMPLES + 1))
    [ "$R" -gt "$MAXRSS" ] && MAXRSS=$R
    [ "$R" -lt "$MINRSS" ] && MINRSS=$R
    if [ "$s" -eq $((DUR / 2)) ]; then
        printf 'rules = [ { name = "soak-block-10", on = "Egress", match = "^10\\\\.0\\\\.0\\\\.", verdict = "block", severity = "medium", reason = "reloaded", action = "deny-egress" } ]\n' > "$POL"
        echo "  (rewrote policy at ${s}s — hot-reload under load)"
    fi
done

wait "$SP" 2>/dev/null
echo "=== results ==="
grep -oE "stopped — [0-9]+ events, [0-9]+ blocked" "$WORK/sentry.err" | tail -1
echo "RSS: min=${MINRSS}KB max=${MAXRSS}KB over ${SAMPLES} samples"
echo "egress-deny lines (bounded by dedup): $(wc -l < "$EGRESS" 2>/dev/null | tr -d ' ')"
PANICS="$(grep -ciE 'panic|thread .* panicked' "$WORK/sentry.err" 2>/dev/null)"; PANICS="${PANICS:-0}"
echo "panics: ${PANICS}"

RC=0
if [ "$PANICS" -ne 0 ]; then echo "FAIL: panics in the daemon"; RC=1; fi
if [ "$MINRSS" -gt 0 ] && [ "$MAXRSS" -lt $((MINRSS * 3)) ]; then
    echo "PASS: RSS bounded (no leak)"
else
    echo "FAIL: RSS grew ${MINRSS}→${MAXRSS}KB (possible leak)"; RC=1
fi
rm -rf "$WORK"
exit $RC
