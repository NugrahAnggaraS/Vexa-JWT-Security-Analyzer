"""Machine-readable JSON report."""

from __future__ import annotations

import json

from jwt_analyzer.engine import AnalysisResult
from jwt_analyzer.reporters.base import BaseReporter


class JsonReporter(BaseReporter):
    """Stable JSON document for other tools."""

    format_name = "json"

    def render(self, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"
