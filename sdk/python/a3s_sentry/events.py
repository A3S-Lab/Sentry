"""Build the observer-shaped events you submit to sentry for judging.

Normally a3s-observer produces these from kernel signals; the builders here let any program feed
sentry its own events (a custom pipeline, a test, a different telemetry source).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Identity:
    agent: Optional[str] = None
    task: Optional[str] = None
    session: Optional[str] = None

    def to_json(self) -> dict:
        return {
            k: v
            for k, v in (("agent", self.agent), ("task", self.task), ("session", self.session))
            if v is not None
        }


@dataclass
class Event:
    """An event envelope. Use the builders (:meth:`tool_exec`, …), not the constructor directly."""

    kind: str
    fields: dict
    identity: Optional[Identity] = None
    provider: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict = {"event": {self.kind: self.fields}}
        if self.identity is not None:
            ident = self.identity.to_json()
            if ident:
                out["identity"] = ident
        if self.provider is not None:
            out["provider"] = self.provider
        return out

    def to_line(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @staticmethod
    def tool_exec(
        pid: int, argv: List[str], *, identity: Optional[Identity] = None, provider: Optional[str] = None
    ) -> "Event":
        return Event("ToolExec", {"pid": pid, "argv": list(argv)}, identity, provider)

    @staticmethod
    def egress(
        pid: int, peer: str, port: int = 0, *, identity: Optional[Identity] = None, provider: Optional[str] = None
    ) -> "Event":
        return Event("Egress", {"pid": pid, "peer": peer, "port": port}, identity, provider)

    @staticmethod
    def file_access(
        pid: int, path: str, write: bool = False, *, identity: Optional[Identity] = None, provider: Optional[str] = None
    ) -> "Event":
        return Event("FileAccess", {"pid": pid, "path": path, "write": write}, identity, provider)

    @staticmethod
    def dns(
        pid: int, query: str, *, identity: Optional[Identity] = None, provider: Optional[str] = None
    ) -> "Event":
        return Event("Dns", {"pid": pid, "query": query}, identity, provider)

    @staticmethod
    def ssl_content(
        pid: int, content: str, is_read: bool = False, *, identity: Optional[Identity] = None, provider: Optional[str] = None
    ) -> "Event":
        return Event("SslContent", {"pid": pid, "is_read": is_read, "content": content}, identity, provider)

    @staticmethod
    def security_action(
        pid: int, kind: str, detail: int = 0, *, identity: Optional[Identity] = None, provider: Optional[str] = None
    ) -> "Event":
        return Event("SecurityAction", {"pid": pid, "kind": kind, "detail": detail}, identity, provider)
