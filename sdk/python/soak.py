#!/usr/bin/env python3
"""Soak the PyO3 binding: hammer evaluate() (and create()) and assert RSS stays flat — an FFI
boundary is where per-call leaks hide. Run: python soak.py [evals]  (default 2,000,000)."""

import os
import subprocess
import sys

from a3s_sentry import Sentry, dns, egress, tool_exec

CFG = """
deny { egress = "" }
rules = [
  { name = "evil-dns", on = "Dns", match = "evil", verdict = "block", severity = "high", reason = "x" },
]
"""

EVENTS = [
    egress(1, "169.254.169.254", 80),   # block (built-in)
    tool_exec(1, ["ls", "-la"]),        # allow
    dns(1, "evil.test"),                # block (custom)
    egress(1, "8.8.8.8", 443),          # allow
]


def rss_kb() -> int:
    out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())])
    return int(out.strip())


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000
    s = Sentry.create(CFG)

    # Phase 1: steady-state evaluate() — the hot path.
    for i in range(100_000):
        s.evaluate(EVENTS[i % len(EVENTS)])  # warm up allocators
    base = rss_kb()
    peak = base
    for i in range(n):
        s.evaluate(EVENTS[i % len(EVENTS)])
        if i % 250_000 == 0:
            peak = max(peak, rss_kb())
    end = rss_kb()
    print(f"evaluate x{n}: base={base}KB end={end}KB peak={peak}KB delta={end - base}KB")
    assert end - base < 20_000, f"RSS grew {end - base}KB — leak across the pyo3 boundary"

    # Phase 2: build + drop the whole pipeline repeatedly (RuleEngine compiles ~14 regexes each time).
    base2 = rss_kb()
    for _ in range(5_000):
        Sentry.create(CFG)  # built and dropped each iteration
    end2 = rss_kb()
    print(f"create x5000: base={base2}KB end={end2}KB delta={end2 - base2}KB")
    assert end2 - base2 < 30_000, f"create/drop leaked {end2 - base2}KB"

    print("SOAK OK — RSS flat across the FFI boundary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
