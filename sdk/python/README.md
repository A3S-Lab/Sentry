# a3s-sentry — Python SDK

Author [a3s-sentry](../../) policy in code, run the judge, stream typed decisions, and read its
metrics. Pure standard library — no dependencies. Async (`asyncio`).

```bash
pip install a3s-sentry        # or: pip install -e sdk/python
```

## Author policy (ACL, hot-reloaded)

Rules are an ordered list (first match wins). `Policy.write` writes the ACL file atomically, so
sentry's ~2s hot-reload never sees a half-written policy — rewrite it any time to update rules live.

```python
from a3s_sentry import Policy, Rule, Verdict, Severity, Action

Policy([
    Rule("no-netcat", on="ToolExec", match=r"(?i)\b(ncat|netcat)\b",
         verdict=Verdict.BLOCK, severity=Severity.MEDIUM, reason="netcat", action=Action.DENY_EXEC),
    Rule("admin-egress", on="Egress", match=r"^10\.0\.99\.",
         verdict=Verdict.ESCALATE, severity=Severity.MEDIUM, reason="admin subnet"),
]).write("rules.acl")
```

## Run sentry, submit events, stream decisions

Sentry emits an audit line only for blocks / escalations / flagged events — plain benign allows are
counted, not printed — so `decisions()` yields exactly the noteworthy ones.

```python
import asyncio
from a3s_sentry import Sentry, SentryConfig, Event, Verdict

async def main():
    cfg = SentryConfig(policy="rules.acl", egress_deny="egress-deny.txt",
                       llm_url="http://llm:18051/v1")  # L2 optional
    async with Sentry(cfg) as s:
        await s.submit(Event.egress(pid=1, peer="169.254.169.254", port=80))  # cloud-metadata SSRF
        async for audit in s.decisions():
            d = audit.decision
            print(d.verdict, audit.subject, "->", d.action and (d.action.kind, d.action.target))
            if d.verdict is Verdict.BLOCK:
                break

asyncio.run(main())
```

Event builders: `tool_exec`, `egress`, `file_access`, `dns`, `ssl_content`, `security_action`.

## Read metrics

```python
from a3s_sentry import MetricsClient

m = MetricsClient("127.0.0.1:9100")        # SentryConfig(metrics_addr="127.0.0.1:9100")
assert m.health()
snap = m.metrics()
# alarm on these two — both mean a block did not take effect:
print(snap.overload_degraded, snap.enforce_failed)
```

## Test

```bash
cd sdk/python
cargo build --manifest-path ../../Cargo.toml      # build the sentry binary for the integration tests
python -m unittest discover -s tests -t .
```

The integration tests run the real `sentry` binary (from `target/debug`, or `A3S_SENTRY_BIN`) and are
skipped if it isn't present.
