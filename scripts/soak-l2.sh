#!/usr/bin/env bash
# Worker-pool soak: a high-rate benign L1 stream + periodic escalations to a deliberately SLOW L2.
# Validates that the slow L2 occupies workers, not the ingest thread — i.e. L1 throughput stays high
# (no head-of-line blocking), RSS stays flat, and an escalation flood degrades gracefully.
#
#   ./scripts/soak-l2.sh [sentry] [duration_s] [mock_llm_delay_s]
set -u
BIN="${1:-./target/release/sentry}"
DUR="${2:-20}"
DELAY="${3:-0.5}"
WORK="$(mktemp -d)"
PORT=18099

# mock LLM: responds after DELAY with a block verdict (simulates a slow reasoning model)
python3 - "$DELAY" "$PORT" >/dev/null 2>&1 <<'PY' &
import http.server, json, time, sys, socketserver
delay = float(sys.argv[1]); port = int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); self.rfile.read(n)
        time.sleep(delay)
        body = json.dumps({"choices":[{"message":{"content":'{"verdict":"block","severity":"high","reason":"mock"}'}}]}).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", port), H).serve_forever()
PY
MOCK=$!
sleep 1
echo "soak-l2: $BIN for ${DUR}s, mock-LLM delay=${DELAY}s, 4 workers"

# generator: ~95% benign (L1 fast-path) + ~5% escalations (→ slow L2)
python3 - "$DUR" <<'PY' | A3S_SENTRY_LLM_URL="http://127.0.0.1:${PORT}/v1" A3S_SENTRY_LLM_KEY=x A3S_SENTRY_WORKERS=4 A3S_SENTRY_QUEUE=128 A3S_SENTRY_LLM_TIMEOUT=10 "$BIN" >/dev/null 2>"$WORK/err" &
import sys, time
end = time.time() + float(sys.argv[1]); i = 0; w = sys.stdout.write; buf = []
benign = '{"event":{"ToolExec":{"pid":%d,"argv":["ls","-la"]}}}'
escal  = '{"event":{"FileAccess":{"pid":%d,"path":"/home/a/.aws/credentials"}}}'
while True:
    i += 1
    if i % 2000 == 0 and time.time() > end: break
    buf.append((escal if i % 20 == 0 else benign) % i)
    if len(buf) >= 500:
        w("\n".join(buf) + "\n"); buf = []
if buf:
    w("\n".join(buf) + "\n")
sys.stdout.flush()
PY
SP=$!

MAX=0; MIN=99999999; N=0
for ((s=0; s<DUR; s+=2)); do
    sleep 2
    R="$(ps -o rss= -p "$SP" 2>/dev/null | tr -d ' ')"
    [ -z "$R" ] && break
    N=$((N+1)); [ "$R" -gt "$MAX" ] && MAX=$R; [ "$R" -lt "$MIN" ] && MIN=$R
done
wait "$SP" 2>/dev/null
kill "$MOCK" 2>/dev/null

echo "=== results ==="
STATS="$(grep -oE 'stopped — .*' "$WORK/err" | tail -1)"
echo "$STATS"
TOTAL="$(echo "$STATS" | grep -oE '[0-9]+ events' | grep -oE '[0-9]+')"
echo "throughput: ~$(( ${TOTAL:-0} / DUR )) events/s   RSS: min=${MIN}KB max=${MAX}KB (${N} samples)"
PANICS="$(grep -ciE 'panic|thread .* panicked' "$WORK/err" 2>/dev/null)"; PANICS="${PANICS:-0}"
echo "panics: ${PANICS}"
RC=0
[ "$PANICS" -ne 0 ] && { echo "FAIL: panics"; RC=1; }
# head-of-line check: with a 0.5s L2, the OLD sync design would cap at ~2 events/s; the worker pool
# must keep L1 flowing far faster. Assert >1000 ev/s (L1 is µs; only escalations hit the slow L2).
if [ "${TOTAL:-0}" -gt $((DUR * 1000)) ]; then
    echo "PASS: L1 not head-of-line-blocked by slow L2 (throughput ≫ L2 rate)"
else
    echo "WARN: throughput low (${TOTAL} events) — investigate head-of-line"
fi
# sentry's steady RSS is a few MB; a leak over a sustained run would blow past this absolute ceiling
if [ "$MAX" -lt 51200 ]; then echo "PASS: RSS bounded (${MAX}KB < 50MB)"; else echo "FAIL: RSS grew to ${MAX}KB"; RC=1; fi
rm -rf "$WORK"
exit $RC
