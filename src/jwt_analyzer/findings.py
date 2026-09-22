"""Structured security findings produced by analyzers.

Field names follow the finding model: id, title, severity, confidence,
description, evidence, impact, remediation, and references.

Severity uses the documented scale CRITICAL, HIGH, MEDIUM, LOW, and INFO.
Header warnings such as a suspicious ``kid`` or an external ``jku`` are
reported as MEDIUM. Confidence records how sure the static check is.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Impact of a finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """How certain the analyzer is that the condition is present."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Finding:
    """One security finding emitted by an analyzer."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    impact: str
    remediation: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of this finding."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": list(self.references),
        }
