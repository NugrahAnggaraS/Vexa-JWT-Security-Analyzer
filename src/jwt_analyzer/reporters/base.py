"""Reporter strategy used by the analysis engine."""

from __future__ import annotations

from abc import ABC, abstractmethod

from jwt_analyzer.engine import AnalysisResult


class BaseReporter(ABC):
    """Render one analysis result as a document."""

    format_name: str

    @abstractmethod
    def render(self, result: AnalysisResult) -> str:
        """Return the full report. Do not write a file."""
