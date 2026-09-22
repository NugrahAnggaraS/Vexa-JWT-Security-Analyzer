"""Pipeline stage shared by every security analyzer."""

from __future__ import annotations

from abc import ABC, abstractmethod

from jwt_analyzer.findings import Finding
from jwt_analyzer.parser import ParsedJWT


class BaseAnalyzer(ABC):
    """One stage in the analysis chain of responsibility.

    The engine runs stages in order. A stage reports findings and does not
    raise for policy violations. Malformed tokens are rejected earlier by
    the parser, so analyzers can assume a decoded compact JWS.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short stage name used by the engine and reports."""

    @abstractmethod
    def analyze(self, token: ParsedJWT) -> list[Finding]:
        """Inspect a parsed token and return zero or more findings."""
