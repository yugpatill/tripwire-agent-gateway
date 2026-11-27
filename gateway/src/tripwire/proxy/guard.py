"""Manifest guard: decides which upstream tools the agent may see and call.

Every tools/list from an upstream goes through `ManifestGuard.process`:

- a tool seen for the first time is scanned (poisoning + shadowing). Clean tools
  are pinned; flagged ones are quarantined and an operator review
  (`tool_quarantine` approval) is opened;
- a pinned tool whose manifest hash changed is a rug pull: it is blocked and a
  `tool_change` approval with a before/after diff is opened;
- only tools with status `pinned` are returned to the agent, and only those can
  be called.

First seen wins for shadowing: an already pinned tool is not re-scanned when a
look-alike appears later; the newcomer is quarantined.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal, Protocol

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.approvals.service import ApprovalRecord, ApprovalService
from tripwire.db import models as db
from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.manifest import (
    Manifest,
    ScanResult,
    find_shadowing,
    manifest_diff,
    scan_poisoning,
)

log = structlog.get_logger(__name__)

PinStatus = Literal["pinned", "quarantined", "changed"]


@dataclass(slots=True)
class PinRecord:
    name: str
    server: str
    hash: str
    manifest: dict[str, Any]
    status: PinStatus
    risk_score: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    pending_manifest: dict[str, Any] | None = None  # {"hash", "manifest", "scan"} after a change


class PinStore(Protocol):
    async def get(self, name: str) -> PinRecord | None: ...
    async def put(self, pin: PinRecord) -> None: ...
    async def all(self) -> list[PinRecord]: ...


@dataclass
class MemoryPinStore:
    pins: dict[str, PinRecord] = field(default_factory=dict)

    async def get(self, name: str) -> PinRecord | None:
        p = self.pins.get(name)
        return replace(p) if p is not None else None

    async def put(self, pin: PinRecord) -> None:
        self.pins[pin.name] = replace(pin)

    async def all(self) -> list[PinRecord]:
        return [replace(p) for p in self.pins.values()]


def _status(value: str) -> PinStatus:
    if value in ("pinned", "quarantined", "changed"):
        return value  # type: ignore[return-value]
    return "quarantined"  # unknown states never expose a tool


class SqlPinStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory

    @staticmethod
    def _rec(r: db.ToolPin) -> PinRecord:
        return PinRecord(
            name=r.name,
            server=r.server,
            hash=r.description_hash,
            manifest=r.manifest,
            status=_status(r.status),
            risk_score=r.risk_score,
            findings=list(r.flagged_spans or []),
            pending_manifest=r.pending_manifest,
        )

    async def get(self, name: str) -> PinRecord | None:
        async with self._factory() as s:
            r = await s.scalar(select(db.ToolPin).where(db.ToolPin.name == name))
            return self._rec(r) if r is not None else None

    async def put(self, pin: PinRecord) -> None:
        async with self._factory() as s, s.begin():
            r = await s.scalar(
                select(db.ToolPin).where(db.ToolPin.name == pin.name).with_for_update()
            )
            if r is None:
                r = db.ToolPin(name=pin.name)
                s.add(r)
            r.server = pin.server
            r.description_hash = pin.hash
            r.manifest = pin.manifest
            r.pending_manifest = pin.pending_manifest
            r.status = pin.status
            r.risk_score = pin.risk_score
            r.flagged_spans = pin.findings

    async def all(self) -> list[PinRecord]:
        async with self._factory() as s:
            rows = (await s.scalars(select(db.ToolPin).order_by(db.ToolPin.name))).all()
            return [self._rec(r) for r in rows]


def _manifest_json(m: Manifest) -> dict[str, Any]:
    return {**m.canonical(), "server": m.server, "tool": m.tool}


class ManifestGuard:
    def __init__(
        self,
        store: PinStore,
        approvals: ApprovalService | None,
        detection: DetectionPipeline | None,
    ) -> None:
        self.store = store
        self.approvals = approvals
        self.detection = detection
        if approvals is not None:
            approvals.on_tool_decision(self._on_decision)

    async def _scan(self, m: Manifest, listed: list[Manifest]) -> ScanResult:
        scan = await scan_poisoning(m, self.detection)
        shadow = find_shadowing(m, listed)
        if shadow:
            scan.findings.extend(shadow)
            scan.score = max(scan.score, max(f.weight for f in shadow))
        return scan

    async def process(self, listed: list[Manifest]) -> list[Manifest]:
        """Pin, scan and filter one full listing (all upstreams). Returns visible tools."""
        visible: list[Manifest] = []
        for m in listed:
            pin = await self.store.get(m.name)
            if pin is None:
                pin = await self._first_seen(m, listed)
            elif pin.hash != m.hash:
                pin = await self._changed(pin, m, listed)
            if pin.status == "pinned" and pin.hash == m.hash:
                visible.append(m)
        return visible

    async def _first_seen(self, m: Manifest, listed: list[Manifest]) -> PinRecord:
        scan = await self._scan(m, listed)
        pin = PinRecord(
            name=m.name,
            server=m.server,
            hash=m.hash,
            manifest=_manifest_json(m),
            status="quarantined" if scan.flagged else "pinned",
            risk_score=round(scan.score, 4),
            findings=scan.as_json()["findings"],
        )
        await self.store.put(pin)
        if scan.flagged:
            log.warning(
                "tool.quarantined",
                tool=m.name,
                score=round(scan.score, 3),
                rules=sorted({f.rule for f in scan.findings}),
            )
            if self.approvals is not None:
                await self.approvals.request_tool(
                    "tool_quarantine",
                    m.name,
                    {"hash": m.hash, "manifest": pin.manifest, **scan.as_json()},
                )
        else:
            log.info("tool.pinned", tool=m.name, hash=m.hash[:12])
        return pin

    async def _changed(self, pin: PinRecord, m: Manifest, listed: list[Manifest]) -> PinRecord:
        if pin.pending_manifest and pin.pending_manifest.get("hash") == m.hash:
            return pin  # this change is already blocked and under review
        scan = await self._scan(m, listed)
        after = _manifest_json(m)
        diff = manifest_diff(pin.manifest, after)
        pin.status = "changed"
        pin.pending_manifest = {"hash": m.hash, "manifest": after, "scan": scan.as_json()}
        await self.store.put(pin)
        log.warning("tool.rug_pull", tool=m.name, pinned=pin.hash[:12], current=m.hash[:12])
        if self.approvals is not None:
            await self.approvals.request_tool(
                "tool_change",
                m.name,
                {
                    "hash": m.hash,
                    "previous_hash": pin.hash,
                    "diff": diff,
                    "before": pin.manifest,
                    "after": after,
                    **scan.as_json(),
                },
            )
        return pin

    async def callable_status(self, name: str) -> tuple[bool, str]:
        """(may the agent call this tool, reason if not)."""
        pin = await self.store.get(name)
        if pin is None:
            return False, f"Tool {name} has not been listed through Tripwire."
        if pin.status == "pinned":
            return True, ""
        if pin.status == "changed":
            return False, (
                f"Tool {name} changed its description or schema since it was approved "
                "(possible rug pull). It is blocked until an operator reviews the change."
            )
        rules = sorted({str(f.get("rule")) for f in pin.findings})
        return False, (
            f"Tool {name} is quarantined by Tripwire ({', '.join(rules) or 'flagged'}). "
            "An operator must review it before it can be used."
        )

    async def approve(self, name: str) -> PinRecord | None:
        """Operator re-pin: trust the latest known manifest of a tool."""
        pin = await self.store.get(name)
        if pin is None:
            return None
        if pin.pending_manifest:
            pin.hash = str(pin.pending_manifest["hash"])
            pin.manifest = dict(pin.pending_manifest["manifest"])
            scan = pin.pending_manifest.get("scan") or {}
            pin.risk_score = float(scan.get("score", 0.0))
            pin.findings = list(scan.get("findings", []))
            pin.pending_manifest = None
        pin.status = "pinned"
        await self.store.put(pin)
        log.info("tool.approved", tool=name, hash=pin.hash[:12])
        return pin

    async def _on_decision(self, rec: ApprovalRecord) -> None:
        if rec.status != "approved":
            return
        pin = await self.store.get(rec.tool)
        if pin is None:
            return
        target = rec.detail.get("hash")
        current = pin.pending_manifest.get("hash") if pin.pending_manifest else pin.hash
        if target != current:
            log.warning("tool.approval_stale", tool=rec.tool, approved=target, current=current)
            return
        await self.approve(rec.tool)
