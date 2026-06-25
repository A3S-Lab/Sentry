// Soak the napi binding's HOT PATH: hammer evaluate() and assert RSS stays flat — an FFI boundary is
// where per-call leaks hide. Run: node --expose-gc soak.mjs [evals]  (default 2,000,000).
//
// We soak evaluate() (called millions of times), not create() (called once, at startup). A loop of
// Sentry.create() does grow RSS transiently, but it's napi/V8 *lazy finalization* of the #[napi]
// object, not a leak — it plateaus and reclaims under pressure (verified: 5k→+1.1GB, 10k→+1.2GB). The
// pattern is create-once: build one Sentry, then evaluate() forever.
import { Sentry, egress, toolExec, dns } from "./index.js";

const CFG = `
deny { egress = "" }
rules = [
  { name = "evil-dns", on = "Dns", match = "evil", verdict = "block", severity = "high", reason = "x" },
]
`;

const EVENTS = [
  egress(1, "169.254.169.254", 80), // block (built-in)
  toolExec(1, ["ls", "-la"]), // allow
  dns(1, "evil.test"), // block (custom)
  egress(1, "8.8.8.8", 443), // allow
];

const MB = (b) => (b / 1e6).toFixed(1);
const gc = () => global.gc && global.gc();
const N = Number(process.argv[2] || 2_000_000);

const s = Sentry.create(CFG);
for (let i = 0; i < 100_000; i++) s.evaluate(EVENTS[i % EVENTS.length]); // warm up
gc();
const base = process.memoryUsage().rss;
for (let i = 0; i < N; i++) s.evaluate(EVENTS[i % EVENTS.length]);
gc();
const end = process.memoryUsage().rss;
console.log(`evaluate x${N}: base=${MB(base)}MB end=${MB(end)}MB delta=${MB(end - base)}MB`);
if (end - base > 30e6) {
  console.error("RSS grew — possible napi leak on the evaluate hot path");
  process.exit(1);
}
console.log("SOAK OK — evaluate() RSS flat across the FFI boundary");
