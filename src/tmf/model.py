"""Threat-model schema.

Plain dataclasses + a from_dict loader. Light validation; we don't pull in
pydantic for a tool this small.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VALID_STRIDE = {
    "spoofing", "tampering", "repudiation",
    "information_disclosure", "denial_of_service", "elevation_of_privilege",
}
VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
VALID_STATUS = {"proposed", "in_progress", "implemented", "wontfix", "deferred"}


@dataclass
class TrustBoundary:
    id: str
    crosses: str
    trust: str = ""


@dataclass
class Threat:
    id: str
    stride: str
    title: str
    description: str = ""
    severity: str = "medium"
    mitre: list[str] = field(default_factory=list)
    mitigation: str = ""
    status: str = "proposed"

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.stride not in VALID_STRIDE:
            errs.append(f"{self.id}: invalid stride '{self.stride}' (expected one of {sorted(VALID_STRIDE)})")
        if self.severity not in VALID_SEVERITY:
            errs.append(f"{self.id}: invalid severity '{self.severity}'")
        if self.status not in VALID_STATUS:
            errs.append(f"{self.id}: invalid status '{self.status}'")
        if not self.title:
            errs.append(f"{self.id}: title is required")
        if self.status != "wontfix" and not self.mitigation:
            errs.append(f"{self.id}: mitigation is required (unless status=wontfix)")
        return errs


@dataclass
class ThreatModel:
    title: str
    scope: str = ""
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThreatModel":
        return cls(
            title=data.get("title", "Untitled"),
            scope=(data.get("scope") or "").strip(),
            trust_boundaries=[TrustBoundary(**tb) for tb in data.get("trust_boundaries", [])],
            threats=[Threat(**t) for t in data.get("threats", [])],
        )

    def validate(self) -> list[str]:
        errs: list[str] = []
        if not self.title:
            errs.append("title is required")
        for t in self.threats:
            errs.extend(t.validate())
        ids = [t.id for t in self.threats]
        if len(ids) != len(set(ids)):
            errs.append("duplicate threat IDs detected")
        return errs
