"""
Base class for all SecAudit scanner modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .target import Target


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "green",
        }[self.value]


@dataclass
class Finding:
    """Represents a single security finding."""

    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references,
        }


@dataclass
class ModuleResult:
    """Container for all findings from a module."""

    module_name: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def has_error(self) -> bool:
        return bool(self.error)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module_name,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "error": self.error,
        }


class BaseModule(ABC):
    """Abstract base class for all scanner modules."""

    name: str = "base"
    description: str = ""

    def __init__(self, timeout: int = 10, verbose: bool = False) -> None:
        self.timeout = timeout
        self.verbose = verbose

    @abstractmethod
    def run(self, target: Target) -> ModuleResult:
        """Execute the module against the target and return findings."""
        ...

    def _result(self, target: Target) -> ModuleResult:
        return ModuleResult(module_name=self.name, target=str(target))
