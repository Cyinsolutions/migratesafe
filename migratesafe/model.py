from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
INFO = "INFO"
MANUAL = "MANUAL"
SKIP = "SKIP"
ERROR = "ERROR"

# Worst-first ordering, used to pick an overall status for a check.
SEVERITY = {FAIL: 6, ERROR: 5, WARN: 4, MANUAL: 3, INFO: 2, PASS: 1, SKIP: 0}

PHASES = ("P0", "P1", "P2", "P3", "P4")


def worst(statuses: List[str]) -> str:
    return max(statuses, key=lambda s: SEVERITY[s]) if statuses else SKIP


@dataclass
class Finding:
    status: str
    target: str
    message: str


@dataclass
class Result:
    check_id: str
    title: str
    threats: str
    findings: List[Finding] = field(default_factory=list)
    fix: str = ""

    @property
    def status(self) -> str:
        return worst([f.status for f in self.findings])

    def add(self, status: str, target: str, message: str) -> None:
        self.findings.append(Finding(status, target, message))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.check_id,
            "title": self.title,
            "threats": self.threats,
            "status": self.status,
            "fix": self.fix if self.status in (FAIL, WARN, ERROR) else "",
            "findings": [f.__dict__ for f in self.findings],
        }


@dataclass
class Config:
    """Optional operator knowledge that the audit cannot discover remotely."""

    inventory: Dict[str, str] = field(default_factory=dict)  # hostname -> fate
    allowed_issuers: List[str] = field(default_factory=list)  # substrings of CA org names
    dkim_selectors: List[str] = field(default_factory=list)
    old_host_ip: Optional[str] = None
    dnssec_exception: bool = False
    old_domain_mail: str = "retired"  # "retired" or "active"
    session_paths: List[str] = field(default_factory=lambda: ["/"])
    config_ignore: List[str] = field(default_factory=list)  # path substrings to skip in C12

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class Context:
    new: str
    old: Optional[str]
    phase: str = "P3"
    project: Optional[str] = None
    since_days: int = 30
    timeout: float = 10.0
    config: Config = field(default_factory=Config)
    cache: Dict[str, Any] = field(default_factory=dict)

    @property
    def domains(self) -> List[str]:
        return [d for d in (self.new, self.old) if d]

    def phase_at_least(self, phase: str) -> bool:
        return PHASES.index(self.phase) >= PHASES.index(phase)
