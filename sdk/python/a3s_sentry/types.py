"""Typed model of sentry's decision wire format (the audit NDJSON it writes on stdout)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """A rule's enforcement action (the ``action`` field in an ACL rule)."""

    DENY_EGRESS = "deny-egress"
    DENY_FILE = "deny-file"
    DENY_EXEC = "deny-exec"


@dataclass(frozen=True)
class EnforceAction:
    """A concrete deny carried by a block decision.

    ``kind`` is ``DenyEgress`` / ``DenyFile`` / ``DenyExec``; ``target`` is the IP/host, path, or
    binary the kernel guard will deny.
    """

    kind: str
    target: str

    @classmethod
    def from_json(cls, obj: Optional[dict]) -> Optional["EnforceAction"]:
        # externally tagged: {"DenyExec": "curl"}
        if not obj:
            return None
        (kind, target), = obj.items()
        return cls(kind, target)


@dataclass
class Decision:
    verdict: Verdict
    tier: str  # "Rules" | "Llm" | "Agent"
    severity: Severity
    reason: str
    action: Optional[EnforceAction] = None

    @classmethod
    def from_json(cls, d: dict) -> "Decision":
        return cls(
            verdict=Verdict(d["verdict"]),
            tier=d["tier"],
            severity=Severity(d["severity"]),
            reason=d.get("reason", ""),
            action=EnforceAction.from_json(d.get("action")),
        )


@dataclass
class Audit:
    """One decision-audit line from sentry's stdout.

    Note: sentry emits a line only for blocks / escalations / flagged-but-allowed events — plain
    benign allows are counted, not printed. :meth:`Sentry.decisions` yields exactly the audited ones.
    """

    event: str
    subject: str
    decision: Decision
    agent: Optional[str] = None
    enforced: Optional[str] = None

    @classmethod
    def from_json(cls, d: dict) -> "Audit":
        return cls(
            event=d["event"],
            subject=d.get("subject", ""),
            decision=Decision.from_json(d["decision"]),
            agent=d.get("agent"),
            enforced=d.get("enforced"),
        )
