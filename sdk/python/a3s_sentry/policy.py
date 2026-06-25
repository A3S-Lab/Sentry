"""Author L1 rules in code and serialize them to the ACL policy sentry hot-reloads.

ACL is the a3s config language; sentry parses it with an HCL-grammar parser, so a policy is an
ordered ``rules = [ ... ]`` list (the order is the first-match-wins evaluation order). Write it with
:meth:`Policy.write` — atomically, so the daemon's ~2s hot-reload never reads a half-written file.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from .types import Action, Severity, Verdict


def _acl_str(s: str) -> str:
    """Quote + escape a string for an ACL value (regexes carry backslashes, so this matters)."""
    out = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{out}"'


@dataclass
class Rule:
    name: str
    on: str  # event kind ("ToolExec", "Egress", ...) or "*"
    match: str  # regex tested against the event subject
    verdict: Verdict
    severity: Severity
    reason: str
    action: Optional[Action] = None

    def to_acl(self) -> str:
        fields = [
            ("name", self.name),
            ("on", self.on),
            ("match", self.match),
            ("verdict", Verdict(self.verdict).value),
            ("severity", Severity(self.severity).value),
            ("reason", self.reason),
        ]
        if self.action is not None:
            fields.append(("action", Action(self.action).value))
        body = "\n".join(f"    {k} = {_acl_str(v)}" for k, v in fields)
        return "  {\n" + body + "\n  }"


class Policy:
    """An ordered set of L1 rules, serializable to sentry's ACL policy."""

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self.rules: List[Rule] = list(rules or [])

    def add(self, rule: Rule) -> "Policy":
        self.rules.append(rule)
        return self

    def to_acl(self) -> str:
        if not self.rules:
            return "rules = []\n"
        return "rules = [\n" + ",\n".join(r.to_acl() for r in self.rules) + "\n]\n"

    def write(self, path: str) -> None:
        """Atomically write the policy (default extension ``.acl``).

        Writes a temp file in the target's directory then ``os.replace`` over it, so sentry's
        hot-reload only ever sees a complete, parseable file.
        """
        directory = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".acl")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(self.to_acl())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
