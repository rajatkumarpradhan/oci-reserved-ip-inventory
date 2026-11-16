"""Data model + snapshot loading for the reserved-IP inventory audit."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date, datetime


class SnapshotError(ValueError):
    """Raised when a snapshot file is malformed."""


IDLE_DAYS = 30


def parse_date(value: str, what: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError) as exc:
        raise SnapshotError(f"invalid date for {what}: {value!r} (expected YYYY-MM-DD)") from exc


@dataclass(frozen=True)
class ReservedIp:
    ocid: str
    ip_address: str
    name: str
    created_at: date
    assigned_entity_id: str | None
    tags: dict = field(default_factory=dict)

    def is_attached(self) -> bool:
        return self.assigned_entity_id is not None

    def idle_days(self, as_of: date) -> int:
        return (as_of - self.created_at).days


@dataclass(frozen=True)
class Snapshot:
    known_entities: frozenset
    reserved_ips: tuple


def load_snapshot(path: str) -> Snapshot:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("reserved_ips"), list):
        raise SnapshotError(f"{path}: top level must be an object with a 'reserved_ips' list")
    known = raw.get("known_entities", [])
    if not isinstance(known, list):
        raise SnapshotError(f"{path}: 'known_entities' must be a list")
    ips = []
    for i, r in enumerate(raw["reserved_ips"]):
        where = f"reserved_ips[{i}]"
        for req in ("ocid", "ip_address", "created_at"):
            if req not in r:
                raise SnapshotError(f"{where}: missing required field {req!r}")
        try:
            ipaddress.ip_address(r["ip_address"])
        except ValueError as exc:
            raise SnapshotError(f"{where}: invalid ip_address {r['ip_address']!r}") from exc
        ips.append(
            ReservedIp(
                ocid=r["ocid"],
                ip_address=r["ip_address"],
                name=r.get("name", "") or "",
                created_at=parse_date(r["created_at"], f"{where}.created_at"),
                assigned_entity_id=r.get("assigned_entity_id"),
                tags=r.get("tags", {}) or {},
            )
        )
    return Snapshot(known_entities=frozenset(known), reserved_ips=tuple(ips))
