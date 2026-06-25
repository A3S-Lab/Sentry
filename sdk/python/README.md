# a3s-sentry (Python SDK)

Native (PyO3) Python bindings for [a3s-sentry](https://github.com/A3S-Lab/Sentry) — the tiered
(L1 rules / L2 LLM / L3 a3s-code agent) runtime security judge for AI agents.

This is an **in-process** binding: the Rust `Sentry` judge runs inside your Python process. There is
**no daemon and no subprocess** to manage (beyond what an L3 agent tier itself spawns). You build the
judge from one ACL config and call `evaluate` on observer events — judging happens locally, in-process.

## Install

abi3 wheels (py3.9+) are published to GitHub Releases (not PyPI yet, matching a3s-code). Grab the
wheel for your platform from the [`python-v0.1.0` release](https://github.com/A3S-Lab/Sentry/releases/tag/python-v0.1.0):

```bash
pip install a3s_sentry-0.1.0-cp39-abi3-manylinux_2_39_x86_64.whl   # or the macOS / Windows wheel
```

Or from a checkout (builds the native extension into the current environment):

```bash
cd sdk/python
maturin develop          # or: maturin build --release
```

## Quick start

Author a unified ACL config (`sentry.acl`) — L1 rules, optional L2/L3 backends, deny-file sinks:

```hcl
fail_closed = false

deny  { egress = "egress.txt" file = "file.txt" exec = "exec.txt" }

rules = [
  { name = "block-evil-dns", on = "Dns", match = "evil\\.test",
    verdict = "block", severity = "high", reason = "known-bad domain" },
]
```

Build the judge and evaluate observer events:

```python
from a3s_sentry import Sentry, egress, dns, tool_exec

# `create` takes a config PATH (if it's a readable file) or inline ACL content.
sentry = Sentry.create("sentry.acl")

# Built-in default rules always apply — e.g. cloud-metadata SSRF.
d = sentry.evaluate(egress(1234, "169.254.169.254", 80))
print(d.verdict)          # "block"
print(d.tier)             # "Rules"
print(d.severity)         # "high"
print(d.action.kind)      # "DenyEgress"
print(d.action.target)    # "169.254.169.254"

# A benign event is allowed.
print(sentry.evaluate(tool_exec(1234, ["ls", "-la"])).verdict)   # "allow"

# An unparseable line returns None.
assert sentry.evaluate("not json") is None
```

A `Decision` exposes `verdict` (`"allow"`/`"block"`/`"escalate"`), `tier` (`"Rules"`/`"Llm"`/`"Agent"`),
`severity` (`"info"`..`"critical"`), `reason`, and `action` (an `EnforceAction` with `kind` +
`target`, or `None`).

## Enforcing (writing the deny-file)

`evaluate_and_enforce` judges the event and, on a `block` carrying a target, writes the deny to the
configured deny-file sink (which a3s-observer's kernel guards read). It returns `(decision, path)`,
where `path` is the deny-file the block landed in (or `None`):

```python
from a3s_sentry import Sentry, tool_exec

sentry = Sentry.create("""
deny  { exec = "exec.txt" }
rules = [
  { name = "no-netcat", on = "ToolExec", match = "nc",
    verdict = "block", severity = "high", reason = "netcat",
    action = "deny-exec" },
]
""")

decision, enforced = sentry.evaluate_and_enforce(tool_exec(1, ["/usr/bin/nc", "x", "4444"]))
print(decision.verdict)   # "block"
print(enforced)           # "exec.txt"  (now contains /usr/bin/nc)
```

## Event builders

These return the observer event JSON string that `evaluate` / `evaluate_and_enforce` take. Each
also accepts optional `agent=` and `provider=` keywords (added to the event's identity/provider):

| Builder | Signature |
|---------|-----------|
| `tool_exec` | `tool_exec(pid, argv)` |
| `egress` | `egress(pid, peer, port=0)` |
| `file_access` | `file_access(pid, path, write=False)` |
| `dns` | `dns(pid, query)` |
| `ssl_content` | `ssl_content(pid, content, is_read=False)` |
| `security_action` | `security_action(pid, kind, detail=0)` |

## Develop & test

```bash
cd sdk/python
python3 -m venv .venv && . .venv/bin/activate
maturin develop
python -m unittest discover -s tests -t .
```
