"""Supervise a sentry process: feed it events, stream typed decisions back."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import AsyncIterator, Dict, Optional

from .events import Event
from .types import Audit


@dataclass
class SentryConfig:
    """Typed configuration → sentry's ``A3S_SENTRY_*`` environment. Unset fields are omitted."""

    bin: str = "sentry"  # the sentry binary (name on PATH or a path)
    policy: Optional[str] = None  # ACL policy file (hot-reloaded)
    egress_deny: Optional[str] = None
    file_deny: Optional[str] = None
    exec_deny: Optional[str] = None
    llm_url: Optional[str] = None
    llm_model: Optional[str] = None
    llm_key: Optional[str] = None
    agent_bin: Optional[str] = None
    skills: Optional[str] = None
    fail_closed: bool = False
    speculate: Optional[str] = None  # severity threshold, e.g. "high"
    llm_timeout: Optional[int] = None
    agent_timeout: Optional[int] = None
    workers: Optional[int] = None
    queue: Optional[int] = None
    dry_run: bool = False
    metrics_addr: Optional[str] = None  # e.g. "127.0.0.1:9100"

    def env(self) -> Dict[str, str]:
        e: Dict[str, str] = {}

        def put(key: str, value: object) -> None:
            if value is not None:
                e[key] = str(value)

        put("A3S_SENTRY_POLICY", self.policy)
        put("A3S_SENTRY_EGRESS_DENY", self.egress_deny)
        put("A3S_SENTRY_FILE_DENY", self.file_deny)
        put("A3S_SENTRY_EXEC_DENY", self.exec_deny)
        put("A3S_SENTRY_LLM_URL", self.llm_url)
        put("A3S_SENTRY_LLM_MODEL", self.llm_model)
        put("A3S_SENTRY_LLM_KEY", self.llm_key)
        put("A3S_SENTRY_AGENT_BIN", self.agent_bin)
        put("A3S_SENTRY_SKILLS", self.skills)
        if self.fail_closed:
            e["A3S_SENTRY_FAIL_CLOSED"] = "1"
        put("A3S_SENTRY_SPECULATE", self.speculate)
        put("A3S_SENTRY_LLM_TIMEOUT", self.llm_timeout)
        put("A3S_SENTRY_AGENT_TIMEOUT", self.agent_timeout)
        put("A3S_SENTRY_WORKERS", self.workers)
        put("A3S_SENTRY_QUEUE", self.queue)
        if self.dry_run:
            e["A3S_SENTRY_DRY_RUN"] = "1"
        put("A3S_SENTRY_METRICS_ADDR", self.metrics_addr)
        return e


class Sentry:
    """A running sentry process. Use it as an async context manager::

        async with Sentry(SentryConfig(egress_deny="egress.txt")) as s:
            await s.submit(Event.egress(1, "169.254.169.254", 80))
            async for audit in s.decisions():
                print(audit.decision.verdict, audit.subject)

    Sentry emits an audit line only for blocks / escalations / flagged events — plain benign allows
    are counted, not printed — so :meth:`decisions` yields exactly the noteworthy ones.
    """

    def __init__(self, config: Optional[SentryConfig] = None) -> None:
        self.config = config or SentryConfig()
        self._proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> "Sentry":
        env = dict(os.environ)
        env.update(self.config.env())
        self._proc = await asyncio.create_subprocess_exec(
            self.config.bin,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        return self

    async def submit(self, event: Event) -> None:
        proc = self._require()
        assert proc.stdin is not None
        proc.stdin.write((event.to_line() + "\n").encode())
        await proc.stdin.drain()

    async def decisions(self) -> AsyncIterator[Audit]:
        proc = self._require()
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield Audit.from_json(obj)

    async def stop(self, timeout: float = 10.0) -> None:
        """Graceful stop: close stdin (EOF → sentry drains the queue and exits), then wait."""
        proc = self._proc
        if proc is None:
            return
        if proc.stdin is not None and not proc.stdin.is_closing():
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.terminate()
            await proc.wait()
        finally:
            self._proc = None

    def _require(self) -> asyncio.subprocess.Process:
        if self._proc is None:
            raise RuntimeError("sentry is not running; call start() (or use 'async with')")
        return self._proc

    async def __aenter__(self) -> "Sentry":
        return await self.start()

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()
