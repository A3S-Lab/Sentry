"""In-process tests for the native a3s-sentry Python SDK.

These are real judgments by the embedded Rust judge — no daemon, no external LLM/agent binary.
"""

import os
import tempfile
import unittest

import a3s_sentry
from a3s_sentry import Sentry, dns, egress, tool_exec


# A custom Dns rule on top of the built-in defaults (cloud-metadata SSRF, etc.).
CFG = r"""
fail_closed = false
rules = [
  { name = "block-evil-dns", on = "Dns", match = "evil\\.test",
    verdict = "block", severity = "high", reason = "custom dns rule" },
]
"""


class TestSentry(unittest.TestCase):
    def setUp(self):
        self.sentry = Sentry.create(CFG)

    def test_cloud_metadata_ssrf_blocks_with_deny_egress(self):
        # Built-in rule: egress to the cloud-metadata IP is an SSRF block.
        d = self.sentry.evaluate(egress(1, "169.254.169.254", 80))
        self.assertIsNotNone(d)
        self.assertEqual(d.verdict, "block")
        self.assertIsNotNone(d.action)
        self.assertEqual(d.action.kind, "DenyEgress")
        self.assertEqual(d.action.target, "169.254.169.254")

    def test_custom_dns_rule_fires_at_rules_tier(self):
        d = self.sentry.evaluate(dns(1, "evil.test"))
        self.assertIsNotNone(d)
        self.assertEqual(d.verdict, "block")
        self.assertEqual(d.tier, "Rules")
        self.assertEqual(d.severity, "high")
        self.assertIn("custom dns rule", d.reason)

    def test_benign_tool_exec_allows(self):
        d = self.sentry.evaluate(tool_exec(1, ["ls", "-la"]))
        self.assertIsNotNone(d)
        self.assertEqual(d.verdict, "allow")

    def test_unparseable_event_returns_none(self):
        self.assertIsNone(self.sentry.evaluate("not json"))

    def test_evaluate_and_enforce_writes_deny_exec_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            exec_sink = os.path.join(tmp, "exec.txt")
            cfg = (
                'deny { exec = "%s" }\n'
                'rules = [\n'
                '  { name = "no-netcat", on = "ToolExec", match = "nc",\n'
                '    verdict = "block", severity = "high", reason = "netcat",\n'
                '    action = "deny-exec" },\n'
                "]\n" % exec_sink
            )
            sentry = Sentry.create(cfg)
            result = sentry.evaluate_and_enforce(tool_exec(1, ["/usr/bin/nc", "x", "4444"]))
            self.assertIsNotNone(result)
            decision, enforced = result
            self.assertEqual(decision.verdict, "block")
            self.assertEqual(decision.action.kind, "DenyExec")
            self.assertEqual(enforced, exec_sink)
            with open(exec_sink) as f:
                contents = f.read()
            self.assertIn("/usr/bin/nc", contents)

    def test_repr_is_readable(self):
        d = self.sentry.evaluate(dns(1, "evil.test"))
        text = repr(d)
        self.assertIn("Decision(", text)
        self.assertIn('verdict="block"', text)

    def test_bad_config_raises_value_error(self):
        with self.assertRaises(ValueError):
            Sentry.create('rules = [ { this is not valid hcl ')

    def test_module_exposes_builders(self):
        for name in ("tool_exec", "egress", "file_access", "dns", "ssl_content", "security_action"):
            self.assertTrue(hasattr(a3s_sentry, name), name)


if __name__ == "__main__":
    unittest.main()
