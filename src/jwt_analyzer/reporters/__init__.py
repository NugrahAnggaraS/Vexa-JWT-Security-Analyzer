"""Report factory.

``get_reporter`` returns the strategy for ``--format``.
"""

from __future__ import annotations

from jwt_analyzer.exceptions import ReporterError
from jwt_analyzer.reporters.base import BaseReporter
from jwt_analyzer.reporters.csv_reporter import CsvReporter
from jwt_analyzer.reporters.html_reporter import HtmlReporter
from jwt_analyzer.reporters.json_reporter import JsonReporter
from jwt_analyzer.reporters.markdown_reporter import MarkdownReporter
from jwt_analyzer.reporters.text_reporter import TextReporter

_FORMATS = {
    "text": TextReporter,
    "terminal": TextReporter,
    "cli": TextReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "csv": CsvReporter,
}


def get_reporter(fmt: str, *, color: bool = False) -> BaseReporter:
    """Return the reporter for ``fmt``.

    ``color`` applies only to the terminal reporter.
    """
    if not isinstance(fmt, str) or not fmt.strip():
        raise ReporterError("Report format is required", code="INVALID_FORMAT")
    key = fmt.strip().lower()
    factory = _FORMATS.get(key)
    if factory is None:
        known = ", ".join(sorted({"text", "json", "html", "markdown", "csv"}))
        raise ReporterError(f"Unknown report format: {fmt}. Expected one of: {known}", code="INVALID_FORMAT")
    if factory is TextReporter:
        return TextReporter(color=color)
    return factory()


__all__ = [
    "BaseReporter",
    "CsvReporter",
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "TextReporter",
    "get_reporter",
]
