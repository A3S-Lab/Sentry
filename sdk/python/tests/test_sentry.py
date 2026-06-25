"""In-process tests for the native a3s-sentry Python SDK.

These are real judgments by the embedded Rust judge — no daemon, no external LLM/agent binary.
Mirrors ``sdk/typescript/test/sdk.test.mjs`` so both bindings exercise the same paths.
"""

import os
import stat
import tempfile
import unittest

import a3s_sentry
from a3s_sentry import (
    Sentry,
    dns,
    egress,
    file_access,
    security_action,
    ssl_content,
    tool_exec,
)


# Custom rules covering every severity, on top of the built-in defaults. (Inline-object fields
# are comma-separated; the regex backslash is doubled for the ACL and a raw string keeps it.)
CFG = r"""
fail_closed = false
rules = [
  { name = "high-dns", on = "Dns", match = "high\\.test", verdict = "block", severity = "high",     reason = "high rule" },
  { name = "low-dns",  on = "Dns", match = "low\\.test",  verdict = "block", severity = "low",      reason = "low rule" },
  { name = "med-dns",  on = "Dns", match = "med\\.test",  verdict = "block", severity = "medium",   reason = "med rule" },
  { name = "crit-dns", on = "Dns", match = "crit\\.test", verdict = "block", severity = "critical", reason = "crit rule" },
]
"""


class TestSentry(unittest.TestCase):
    def setUp(self):
        self.sentry = Sentry.create(CFG)

    # --- create + built-in rules ---

    def test_cloud_metadata_ssrf_blocks_with_deny_egress(self):
        # Built-in rule: egress to the cloud-metadata IP is an SSRF block.
        d = self.sentry.evaluate(egress(1, "169.254.169.254", 80))
        self.assertIsNotNone(d)
        self.assertEqual(d.verdict, "block")
        self.assertIsNotNone(d.action)
        self.assertEqual(d.action.kind, "DenyEgress")
        self.assertEqual(d.action.target, "169.254.169.254")

    def test_sdk_authored_rule_fires_at_rules_tier(self):
        d = self.sentry.evaluate(dns(1, "high.test"))
        self.assertIsNotNone(d)
        self.assertEqual(d.verdict, "block")
        self.assertEqual(d.tier, "Rules")
        self.assertIn("high rule", d.reason)

    # --- all severity arms: info / low / medium / high / critical ---

    def test_severity_arms(self):
        # benign allow → info
        self.assertEqual(self.sentry.evaluate(tool_exec(1, ["ls", "-la"])).severity, "info")
        self.assertEqual(self.sentry.evaluate(dns(1, "low.test")).severity, "low")
        self.assertEqual(self.sentry.evaluate(dns(1, "med.test")).severity, "medium")
        self.assertEqual(self.sentry.evaluate(dns(1, "high.test")).severity, "high")
        self.assertEqual(self.sentry.evaluate(dns(1, "crit.test")).severity, "critical")

    # --- benign allow + unparseable handling ---

    def test_benign_tool_exec_allows(self):
        d = self.sentry.evaluate(tool_exec(1, ["ls", "-la"]))
        self.assertIsNotNone(d)
        self.assertEqual(d.verdict, "allow")

    def test_unparseable_event_returns_none(self):
        self.assertIsNone(self.sentry.evaluate("not json"))
        self.assertIsNone(self.sentry.evaluate_and_enforce("still not json"))

    # --- all six event builders, with and without identity/provider ---

    def test_all_six_builders_produce_judgeable_events(self):
        for ev in (
            tool_exec(1, ["echo", "hi"]),
            egress(1, "8.8.8.8", 443),
            file_access(1, "/tmp/x", False),
            dns(1, "example.com"),
            ssl_content(1, "hello", True),
            security_action(1, "setuid-root", 0),
        ):
            self.assertIsNotNone(self.sentry.evaluate(ev), "unparseable event: %s" % ev)

    def test_builders_with_identity_and_provider(self):
        # Exercises the optional `agent`/`provider` envelope branches in `wrap`.
        for ev in (
            tool_exec(1, ["echo", "hi"], "agent-x", "openai"),
            egress(1, "8.8.8.8", 443, "agent-x", "openai"),
            file_access(1, "/tmp/x", False, "agent-x", "openai"),
            dns(1, "example.com", "agent-x", "openai"),
            ssl_content(1, "hello", True, "agent-x", "openai"),
            security_action(1, "setuid-root", 0, "agent-x", "openai"),
        ):
            self.assertIn('"agent":"agent-x"', ev)
            self.assertIn('"provider":"openai"', ev)
            self.assertIsNotNone(self.sentry.evaluate(ev), "unparseable event: %s" % ev)

    # --- all action arms via evaluate_and_enforce: DenyExec / DenyFile / DenyEgress / non-block ---

    def test_evaluate_and_enforce_all_action_arms(self):
        with tempfile.TemporaryDirectory() as tmp:
            exec_sink = os.path.join(tmp, "exec.txt")
            file_sink = os.path.join(tmp, "file.txt")
            egress_sink = os.path.join(tmp, "egress.txt")
            cfg = (
                "deny {\n"
                '  exec = "%s"\n'
                '  file = "%s"\n'
                '  egress = "%s"\n'
                "}\n"
                "rules = [\n"
                '  { name = "x-exec", on = "ToolExec",   match = "danger",      verdict = "block", severity = "high", reason = "x", action = "deny-exec" },\n'
                '  { name = "x-file", on = "FileAccess", match = "/etc/shadow",  verdict = "block", severity = "high", reason = "x", action = "deny-file" },\n'
                "]\n"
            ) % (exec_sink, file_sink, egress_sink)
            sentry = Sentry.create(cfg)

            # DenyExec — custom rule, writes the exec deny-file.
            ex = sentry.evaluate_and_enforce(tool_exec(1, ["/usr/bin/danger", "x"]))
            self.assertIsNotNone(ex)
            ex_decision, ex_enforced = ex
            self.assertEqual(ex_decision.verdict, "block")
            self.assertEqual(ex_decision.action.kind, "DenyExec")
            self.assertEqual(ex_enforced, exec_sink)
            with open(exec_sink) as f:
                self.assertIn("danger", f.read())

            # DenyFile — custom rule, writes the file deny-file.
            fa = sentry.evaluate_and_enforce(file_access(1, "/etc/shadow", True))
            self.assertIsNotNone(fa)
            fa_decision, fa_enforced = fa
            self.assertEqual(fa_decision.verdict, "block")
            self.assertEqual(fa_decision.action.kind, "DenyFile")
            self.assertEqual(fa_enforced, file_sink)

            # DenyEgress — built-in cloud-metadata SSRF block, writes the egress deny-file.
            eg = sentry.evaluate_and_enforce(egress(1, "169.254.169.254", 80))
            self.assertIsNotNone(eg)
            eg_decision, eg_enforced = eg
            self.assertEqual(eg_decision.verdict, "block")
            self.assertEqual(eg_decision.action.kind, "DenyEgress")
            self.assertEqual(eg_enforced, egress_sink)

            # non-block — benign event → no deny-file written.
            ok = sentry.evaluate_and_enforce(tool_exec(1, ["echo", "ok"]))
            self.assertIsNotNone(ok)
            ok_decision, ok_enforced = ok
            self.assertEqual(ok_decision.verdict, "allow")
            self.assertIsNone(ok_enforced)

    # --- tier=Llm: escalating event with an unreachable LLM keeps tier=Llm / verdict=escalate ---

    def test_llm_tier_escalation(self):
        # No mock server (an in-process HTTP server would deadlock the blocking FFI call). A closed
        # port refuses fast → L2 errors → escalate; with no L3 the unresolved escalation is resolved
        # per fail_closed (fail-open default → allow) but the tier is still recorded as Llm.
        # Exercises the Llm arm of `tier_str`.
        s = Sentry.create('llm { url = "http://127.0.0.1:1/v1" }')
        d = s.evaluate(file_access(1, "/home/u/.aws/credentials", False))  # built-in: escalate
        self.assertIsNotNone(d)
        self.assertEqual(d.tier, "Llm")

    # --- tier=Agent: escalating event → mock L3 agent binary → tier=Agent ---

    def test_agent_tier_via_mock_l3_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "mock-agent.sh")
            with open(bin_path, "w") as f:
                f.write('#!/bin/sh\necho \'{"verdict":"block","severity":"critical","reason":"mock L3"}\'\n')
            os.chmod(bin_path, 0o755)
            self.assertTrue(os.stat(bin_path).st_mode & stat.S_IXUSR)
            # agent{} but no llm{} → an L1 escalate goes straight to L3 (the mock).
            s = Sentry.create('agent { bin = "%s" }' % bin_path)
            d = s.evaluate(file_access(1, "/home/u/.aws/credentials", False))  # built-in: escalate
            self.assertIsNotNone(d)
            self.assertEqual(d.tier, "Agent")
            self.assertEqual(d.verdict, "block")
            self.assertIn("mock L3", d.reason)

    # --- repr coverage: Decision repr with an action, and EnforceAction repr ---

    def test_repr_includes_action(self):
        d = self.sentry.evaluate(egress(1, "169.254.169.254", 80))
        text = repr(d)
        self.assertIn("Decision(", text)
        self.assertIn('verdict="block"', text)
        # Decision repr embeds the EnforceAction repr (covers both __repr__ paths).
        self.assertIn("EnforceAction(", text)
        self.assertIn('kind="DenyEgress"', text)

    def test_repr_without_action_is_none(self):
        d = self.sentry.evaluate(tool_exec(1, ["ls"]))
        text = repr(d)
        self.assertIn("Decision(", text)
        self.assertIn("action=None", text)

    def test_enforce_action_repr_directly(self):
        d = self.sentry.evaluate(egress(1, "169.254.169.254", 80))
        action_text = repr(d.action)
        self.assertIn("EnforceAction(", action_text)
        self.assertIn('kind="DenyEgress"', action_text)
        self.assertIn('target="169.254.169.254"', action_text)

    # --- create() error mapping ---

    def test_bad_config_raises_value_error(self):
        with self.assertRaises(ValueError):
            Sentry.create("not valid acl {{{")

    # --- module surface ---

    def test_module_exposes_builders(self):
        for name in ("tool_exec", "egress", "file_access", "dns", "ssl_content", "security_action"):
            self.assertTrue(hasattr(a3s_sentry, name), name)
        for name in ("Sentry", "Decision", "EnforceAction"):
            self.assertTrue(hasattr(a3s_sentry, name), name)


if __name__ == "__main__":
    unittest.main()
