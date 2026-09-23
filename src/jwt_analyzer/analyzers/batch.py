"""Analyze many tokens and aggregate their findings.

Pipeline for each token:

    Input -> Parser -> HeaderAnalyzer -> PayloadAnalyzer

A token that fails parsing stops that chain and is reported as invalid.
The other tokens continue. Parsing and analysis run concurrently. The
result order matches the input order.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.header import HeaderAnalyzer
from jwt_analyzer.analyzers.payload import PayloadAnalyzer
from jwt_analyzer.exceptions import BatchError, JWTParseError
from jwt_analyzer.findings import Finding, Severity
from jwt_analyzer.parser import parse_jwt

ProgressCallback = Callable[[int, int], None]

_SEVERITY_RANK = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


@dataclass(frozen=True)
class TokenSource:
    """One compact JWT and the label shown in the report."""

    label: str
    text: str


@dataclass(frozen=True)
class BatchItem:
    """The analysis row for one input token."""

    label: str
    algorithm: str
    status: str
    glyph: str
    summary: str
    findings: tuple[Finding, ...]
    error: Optional[str] = None


@dataclass(frozen=True)
class BatchReport:
    """Ordered rows plus every finding from tokens that parsed."""

    items: tuple[BatchItem, ...]

    @property
    def findings(self) -> tuple[Finding, ...]:
        collected: list[Finding] = []
        for item in self.items:
            collected.extend(item.findings)
        return tuple(collected)


class BatchAnalyzer:
    """Facade that runs the analyzer chain over a collection of tokens."""

    def __init__(
        self,
        analyzers: Optional[Sequence[BaseAnalyzer]] = None,
        max_workers: int = 4,
    ) -> None:
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
            raise BatchError("workers must be a positive integer", code="INVALID_WORKERS")
        self.analyzers: tuple[BaseAnalyzer, ...] = (
            tuple(analyzers) if analyzers is not None else default_batch_analyzers()
        )
        self.max_workers = max_workers

    def analyze(
        self,
        sources: Sequence[TokenSource],
        on_progress: Optional[ProgressCallback] = None,
    ) -> BatchReport:
        """Analyze every source. ``on_progress(done, total)`` runs on the caller thread."""
        items = tuple(sources)
        total = len(items)
        if total == 0:
            return BatchReport(items=())
        results: list[Optional[BatchItem]] = [None] * total
        workers = min(self.max_workers, total)
        done = 0
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="jwt-batch") as executor:
            futures = [
                executor.submit(_analyze_source, index, source, self.analyzers)
                for index, source in enumerate(items)
            ]
            for future in as_completed(futures):
                index, item = future.result()
                results[index] = item
                done += 1
                if on_progress is not None:
                    on_progress(done, total)
        finished = tuple(item for item in results if item is not None)
        if len(finished) != total:
            raise BatchError("Batch analysis did not finish", code="INCOMPLETE")
        return BatchReport(items=finished)


def default_batch_analyzers() -> tuple[BaseAnalyzer, ...]:
    """Return the header and payload stages used for a batch."""
    return (HeaderAnalyzer(), PayloadAnalyzer())


def analyze_batch(
    sources: Sequence[TokenSource],
    *,
    analyzers: Optional[Sequence[BaseAnalyzer]] = None,
    max_workers: int = 4,
    on_progress: Optional[ProgressCallback] = None,
) -> BatchReport:
    """Analyze ``sources`` with the default or supplied analyzer chain."""
    return BatchAnalyzer(analyzers, max_workers).analyze(sources, on_progress)


def load_token_source(path: str) -> tuple[TokenSource, ...]:
    """Load tokens from a directory or from a file with one JWT per line."""
    location = Path(path)
    if not location.exists():
        raise BatchError(f"Token source not found: {path}", code="NOT_FOUND")
    if location.is_dir():
        sources = _from_directory(location)
    elif location.is_file():
        sources = _from_file(location)
    else:
        raise BatchError(f"Token source is not a file or directory: {path}", code="INVALID_SOURCE")
    if not sources:
        raise BatchError(f"No tokens found in {path}", code="EMPTY_BATCH")
    return tuple(sources)


def format_progress(done: int, total: int, width: int = 20) -> str:
    """Return a one-line text progress bar."""
    if total < 1:
        return f"[{'-' * width}] 0/0"
    bounded = min(max(done, 0), total)
    filled = int(width * bounded / total)
    return f"[{'#' * filled}{'-' * (width - filled)}] {bounded}/{total}"


def format_batch_report(report: BatchReport) -> str:
    """Render the per-token rows and the aggregate summary."""
    lines = ["TOKEN ANALYSIS", "────────────────────────────", ""]
    if not report.items:
        lines.append("(no tokens)")
    else:
        width = min(32, max(len(item.label) for item in report.items))
        for item in report.items:
            label = item.label if len(item.label) <= width else item.label[: width - 3] + "..."
            summary = item.summary if len(item.summary) <= 72 else item.summary[:69] + "..."
            lines.append(f"{label:<{width}}  {item.algorithm:<6}  {item.glyph} {summary}")
    lines.append("")
    lines.append("Summary")
    lines.append("────────────────────────────")
    counts = _counts(report)
    lines.append(f"Tokens     : {counts['tokens']}")
    lines.append(f"Parsed     : {counts['parsed']}")
    lines.append(f"Invalid    : {counts['invalid']}")
    lines.append(f"Secure     : {counts['secure']}")
    lines.append(f"Warning    : {counts['warning']}")
    lines.append(f"Critical   : {counts['critical']}")
    lines.append(f"Findings   : {len(report.findings)}")
    for severity in Severity:
        lines.append(f"{severity.value:<10} : {counts[severity.value]}")
    if counts["algorithms"]:
        rendered = ", ".join(f"{name}={amount}" for name, amount in counts["algorithms"])
        lines.append(f"Algorithms : {rendered}")
    return "\n".join(lines)


def _analyze_source(
    index: int,
    source: TokenSource,
    analyzers: Sequence[BaseAnalyzer],
) -> tuple[int, BatchItem]:
    try:
        parsed = parse_jwt(source.text)
    except JWTParseError as exc:
        return index, BatchItem(
            label=source.label,
            algorithm="-",
            status="invalid",
            glyph="!",
            summary="Invalid token",
            findings=(),
            error=exc.message,
        )
    findings: list[Finding] = []
    for analyzer in analyzers:
        findings.extend(analyzer.analyze(parsed))
    alg = parsed.header.get("alg")
    algorithm = alg if isinstance(alg, str) and alg.strip() else "-"
    status, glyph, summary = _status(findings)
    return index, BatchItem(
        label=source.label,
        algorithm=algorithm,
        status=status,
        glyph=glyph,
        summary=summary,
        findings=tuple(findings),
    )


def _status(findings: Sequence[Finding]) -> tuple[str, str, str]:
    primary = _primary(findings)
    if primary is None or primary.severity is Severity.INFO:
        return "secure", "✓", "Secure"
    extra = max(0, len(findings) - 1)
    summary = primary.title if extra == 0 else f"{primary.title} +{extra}"
    if primary.id == "JWT-ALG-001" or primary.severity is Severity.CRITICAL:
        return "critical", "✗", summary
    return "warning", "⚠", summary


def _primary(findings: Sequence[Finding]) -> Optional[Finding]:
    for item in findings:
        if item.id == "JWT-ALG-001":
            return item
    chosen: Optional[Finding] = None
    for item in findings:
        if item.severity is Severity.INFO:
            continue
        if chosen is None or _SEVERITY_RANK[item.severity] > _SEVERITY_RANK[chosen.severity]:
            chosen = item
    return chosen


def _counts(report: BatchReport) -> dict[str, Any]:
    counts: dict[str, Any] = {
        "tokens": len(report.items),
        "parsed": sum(1 for item in report.items if item.status != "invalid"),
        "invalid": sum(1 for item in report.items if item.status == "invalid"),
        "secure": sum(1 for item in report.items if item.status == "secure"),
        "warning": sum(1 for item in report.items if item.status == "warning"),
        "critical": sum(1 for item in report.items if item.status == "critical"),
        "algorithms": [],
    }
    for severity in Severity:
        counts[severity.value] = sum(1 for item in report.findings if item.severity is severity)
    totals: dict[str, int] = {}
    for item in report.items:
        if item.status == "invalid":
            continue
        totals[item.algorithm] = totals.get(item.algorithm, 0) + 1
    counts["algorithms"] = sorted(totals.items())
    return counts


def _from_directory(path: Path) -> list[TokenSource]:
    sources: list[TokenSource] = []
    for child in sorted(path.iterdir()):
        if not child.is_file() or child.name.startswith("."):
            continue
        sources.extend(_from_file(child))
    return sources


def _from_file(path: Path) -> list[TokenSource]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [TokenSource(path.name, "")]
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.count(".") < 2:
            continue
        found.append((number, stripped))
    if not found and text.strip().count(".") >= 2:
        return [TokenSource(path.name, text.strip())]
    if len(found) == 1:
        return [TokenSource(path.name, found[0][1])]
    return [TokenSource(f"{path.name}:{number}", token) for number, token in found]
