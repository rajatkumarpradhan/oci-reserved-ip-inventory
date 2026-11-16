"""IP001-IP004 rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .model import IDLE_DAYS, Snapshot


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # HIGH | MEDIUM | LOW
    ip: str
    detail: str


def rule_dangling_assignment(snapshot: Snapshot, as_of: date) -> list:
    """IP001 HIGH: assigned entity absent from the export's known entities (suspect, not proven)."""
    del as_of
    out = []
    for ip in snapshot.reserved_ips:
        if ip.assigned_entity_id is not None and ip.assigned_entity_id not in snapshot.known_entities:
            out.append(
                Finding(
                    rule="IP001",
                    severity="HIGH",
                    ip=ip.ip_address,
                    detail=(
                        f"assigned to {ip.assigned_entity_id}, which is absent from this export's "
                        f"known-entities list; SUSPECT dangling assignment - absence from an export is "
                        f"not proof the target is gone; confirm the export is complete for this entity "
                        f"type before acting"
                    ),
                )
            )
    return out


def rule_idle_unattached(snapshot: Snapshot, as_of: date) -> list:
    """IP002 MEDIUM: unattached for more than IDLE_DAYS."""
    out = []
    for ip in snapshot.reserved_ips:
        if not ip.is_attached() and ip.idle_days(as_of) > IDLE_DAYS:
            out.append(
                Finding(
                    rule="IP002",
                    severity="MEDIUM",
                    ip=ip.ip_address,
                    detail=f"unattached for {ip.idle_days(as_of)} days (> {IDLE_DAYS}); idle reserved inventory",
                )
            )
    return out


def rule_unowned(snapshot: Snapshot, as_of: date) -> list:
    """IP003 MEDIUM: no owner tag."""
    del as_of
    out = []
    for ip in snapshot.reserved_ips:
        if not str(ip.tags.get("owner", "")).strip():
            out.append(
                Finding(
                    rule="IP003",
                    severity="MEDIUM",
                    ip=ip.ip_address,
                    detail="no 'owner' tag; nobody is accountable for keeping or releasing it",
                )
            )
    return out


def rule_unnamed(snapshot: Snapshot, as_of: date) -> list:
    """IP004 LOW: no name metadata."""
    del as_of
    out = []
    for ip in snapshot.reserved_ips:
        if not ip.name.strip():
            out.append(
                Finding(
                    rule="IP004",
                    severity="LOW",
                    ip=ip.ip_address,
                    detail="no name recorded; its purpose exists only in someone's memory",
                )
            )
    return out


ALL_RULES = (
    rule_dangling_assignment,
    rule_idle_unattached,
    rule_unowned,
    rule_unnamed,
)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all(snapshot: Snapshot, as_of: date) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(snapshot, as_of))
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.rule, f.ip))
    return findings


def exit_code(findings: list) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    if findings:
        return 1
    return 0
