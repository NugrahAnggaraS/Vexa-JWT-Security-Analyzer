"""Configuration file loading and the shared settings object.

The module keeps one ``Settings`` instance. ``configure`` replaces it, and
``get_settings`` returns that same object. CLI flags replace values loaded
from ``--config`` or from ``~/.vexa.yaml``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, TextIO

from jwt_analyzer.exceptions import ConfigError
from jwt_analyzer.findings import Severity

TRACE = 5
logging.addLevelName(TRACE, "TRACE")

_LEVELS = {
    "TRACE": TRACE,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}
_MODES = {"fast": "fast", "passive": "fast", "assessment": "assessment"}
_FORMATS = {
    "terminal": "text",
    "text": "text",
    "cli": "text",
    "json": "json",
    "html": "html",
    "markdown": "markdown",
    "md": "markdown",
    "csv": "csv",
}
_TOP_LEVEL = {"analysis", "security", "report", "ignore", "mode", "issuer", "log_level"}
_ANALYSIS_KEYS = {"max_token_lifetime", "check_sensitive_claims", "check_duplicate_claims"}
_SECURITY_KEYS = {"severity_threshold"}
_REPORT_KEYS = {"format", "color"}
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_HOME_NAMES = (
    ".vexa.yaml",
    ".vexa.yml",
    ".vexa.json",
    ".jwt-analyzer.yaml",
    ".jwt-analyzer.yml",
    ".jwt-analyzer.json",
)
_NUMBER_RE = re.compile(r"-?\d+")
_FLOAT_RE = re.compile(r"-?\d+\.\d+")


@dataclass(frozen=True)
class Settings:
    """Resolved defaults for one CLI invocation."""

    mode: str = "fast"
    max_token_lifetime: float = 3600
    check_sensitive_claims: bool = True
    check_duplicate_claims: bool = True
    severity_threshold: Severity = Severity.HIGH
    report_format: str = "text"
    color: Optional[bool] = None
    ignore: tuple[str, ...] = ()
    issuer: Optional[str] = None
    log_level: str = "WARNING"
    source: Optional[str] = None


_current = Settings()


def configure(settings: Settings) -> Settings:
    """Replace the shared settings and return them."""
    global _current
    _current = settings
    return _current


def get_settings() -> Settings:
    """Return the shared settings object."""
    return _current


def default_config_path(home: Optional[Path] = None) -> Optional[Path]:
    """Return ``~/.vexa.yaml`` when it exists, otherwise an older home config."""
    root = home if home is not None else Path.home()
    for name in _HOME_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def load_settings(path: str | Path) -> Settings:
    """Read a YAML or JSON configuration file."""
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"Configuration file not found: {file}")
    try:
        text = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Configuration file cannot be read: {file}") from exc
    suffix = file.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Configuration JSON is invalid: {exc.msg}") from exc
    elif suffix in {".yaml", ".yml"}:
        data = parse_yaml(text)
    else:
        raise ConfigError("Configuration file must end in .json, .yaml, or .yml")
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a mapping")
    return settings_from_document(data, source=str(file))


def settings_from_document(data: Mapping[str, Any], *, source: Optional[str] = None) -> Settings:
    """Validate the documented configuration mapping."""
    unknown = sorted(set(data) - _TOP_LEVEL)
    if unknown:
        raise ConfigError("Unknown configuration keys: " + ", ".join(unknown))
    analysis = _section(data.get("analysis"), "analysis", _ANALYSIS_KEYS)
    security = _section(data.get("security"), "security", _SECURITY_KEYS)
    report = _section(data.get("report"), "report", _REPORT_KEYS)
    lifetime = analysis.get("max_token_lifetime", 3600)
    if isinstance(lifetime, bool) or not isinstance(lifetime, (int, float)) or lifetime < 0:
        raise ConfigError("analysis.max_token_lifetime must be a non-negative number")
    ignore = _ignore_list(data.get("ignore", ()))
    mode = _mode(data.get("mode", "fast"))
    issuer = data.get("issuer")
    if issuer is not None and (not isinstance(issuer, str) or not issuer.strip()):
        raise ConfigError("issuer must be a non-empty string")
    level = _log_level(data.get("log_level", "WARNING"))
    report_format = normalize_format(report.get("format", "text"))
    color = report.get("color")
    if color is not None and not isinstance(color, bool):
        raise ConfigError("report.color must be true or false")
    return Settings(
        mode=mode,
        max_token_lifetime=float(lifetime),
        check_sensitive_claims=_bool_option(analysis, "check_sensitive_claims", True),
        check_duplicate_claims=_bool_option(analysis, "check_duplicate_claims", True),
        severity_threshold=parse_severity(security.get("severity_threshold", "HIGH")),
        report_format=report_format,
        color=color,
        ignore=ignore,
        issuer=issuer.strip() if isinstance(issuer, str) else None,
        log_level=level,
        source=source,
    )


def apply_cli(settings: Settings, args: Any) -> Settings:
    """Return settings with explicit CLI flags taking precedence."""
    mode = settings.mode
    if getattr(args, "mode", None):
        mode = _mode(args.mode)
    if getattr(args, "command", None) == "assess":
        mode = "assessment"
    threshold = settings.severity_threshold
    if getattr(args, "severity_threshold", None):
        threshold = parse_severity(args.severity_threshold)
    report_format = settings.report_format
    if getattr(args, "format", None):
        report_format = normalize_format(args.format)
    color = settings.color
    if getattr(args, "no_color", False):
        color = False
    elif getattr(args, "color", False):
        color = True
    issuer = settings.issuer
    if getattr(args, "issuer", None):
        issuer = str(args.issuer).strip()
    level = settings.log_level
    if getattr(args, "log_level", None):
        level = _log_level(args.log_level)
    elif getattr(args, "debug", False):
        level = "DEBUG"
    elif getattr(args, "verbose", False):
        level = "INFO"
    ignore = _merge_ignore(settings.ignore, getattr(args, "ignore", None), getattr(args, "ignore_rule", None))
    return replace(
        settings,
        mode=mode,
        severity_threshold=threshold,
        report_format=report_format,
        color=color,
        issuer=issuer,
        log_level=level,
        ignore=ignore,
    )


def normalize_format(value: object) -> str:
    """Map a report format name, including ``terminal``, to a reporter key."""
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("report.format must be a format name")
    key = _FORMATS.get(value.strip().lower())
    if key is None:
        known = ", ".join(("text", "json", "html", "markdown", "csv"))
        raise ConfigError(f"Unknown report format: {value}. Expected one of: {known}")
    return key


def parse_severity(value: object) -> Severity:
    """Return a severity threshold from a configuration or flag value."""
    if isinstance(value, Severity):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("security.severity_threshold must name a severity")
    try:
        return Severity(value.strip().upper())
    except ValueError as exc:
        raise ConfigError("security.severity_threshold must be CRITICAL, HIGH, MEDIUM, LOW, or INFO") from exc


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    """Return whether ``severity`` meets or exceeds ``threshold``."""
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[threshold]


def setup_logging(level: str, stream: TextIO) -> logging.Logger:
    """Attach one stderr handler to the package logger."""
    logger = logging.getLogger("jwt_analyzer")
    logger.handlers.clear()
    logger.setLevel(_LEVELS[_log_level(level)])
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def parse_yaml(text: str) -> Any:
    """Parse the indented YAML subset used by configuration files."""
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        indent_text = raw[: len(raw) - len(raw.lstrip(" \t"))]
        if "\t" in indent_text:
            raise ConfigError("Configuration YAML cannot use tabs for indentation")
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    if not lines:
        return {}
    if lines[0][1].startswith("-"):
        raise ConfigError("Configuration root must be a mapping")
    value, index = _parse_map(lines, 0, 0)
    if index != len(lines):
        raise ConfigError("Configuration YAML has trailing content that could not be read")
    return value


def _section(value: object, name: str, allowed: set[str]) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{name} must be a mapping")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"Unknown {name} keys: " + ", ".join(unknown))
    return value


def _bool_option(section: Mapping[str, Any], key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"analysis.{key} must be true or false")
    return value


def _ignore_list(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ConfigError("ignore must be a list of finding ids")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError("ignore entries must be non-empty finding ids")
        items.append(item.strip())
    return tuple(items)


def _merge_ignore(current: Sequence[str], *groups: object) -> tuple[str, ...]:
    merged = list(current)
    seen = {item.upper() for item in merged}
    for group in groups:
        if not group:
            continue
        if isinstance(group, str):
            values = [group]
        else:
            values = list(group)
        for value in values:
            for part in str(value).split(","):
                text = part.strip()
                if text and text.upper() not in seen:
                    merged.append(text)
                    seen.add(text.upper())
    return tuple(merged)


def _mode(value: object) -> str:
    if not isinstance(value, str) or value.strip().lower() not in _MODES:
        raise ConfigError("mode must be fast, passive, or assessment")
    return _MODES[value.strip().lower()]


def _log_level(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigError("log_level must be ERROR, WARN, INFO, DEBUG, or TRACE")
    key = value.strip().upper()
    if key not in _LEVELS:
        raise ConfigError("log_level must be ERROR, WARN, INFO, DEBUG, or TRACE")
    return "WARNING" if key == "WARN" else key


def _parse_map(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        current, content = lines[index]
        if current < indent:
            break
        if current != indent or content.startswith("-"):
            raise ConfigError("Configuration YAML indentation is inconsistent")
        key, separator, rest = content.partition(":")
        if not separator or not key.strip():
            raise ConfigError("Configuration YAML mapping entry must contain a key")
        key = key.strip()
        if key in mapping:
            raise ConfigError(f"Configuration YAML repeats {key}")
        rest = rest.strip()
        index += 1
        if rest == "":
            if index < len(lines) and lines[index][0] > indent:
                child_indent = lines[index][0]
                if lines[index][1].startswith("-"):
                    child, index = _parse_list(lines, index, child_indent)
                else:
                    child, index = _parse_map(lines, index, child_indent)
            else:
                child = None
        else:
            child = _scalar(rest)
        mapping[key] = child
    return mapping, index


def _parse_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        current, content = lines[index]
        if current < indent:
            break
        if current != indent or not content.startswith("-"):
            break
        rest = content[1:].strip()
        index += 1
        if rest == "":
            if index < len(lines) and lines[index][0] > indent:
                child_indent = lines[index][0]
                if lines[index][1].startswith("-"):
                    child, index = _parse_list(lines, index, child_indent)
                else:
                    child, index = _parse_map(lines, index, child_indent)
            else:
                child = None
        else:
            child = _scalar(rest)
        items.append(child)
    return items, index


def _scalar(value: str) -> Any:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "~"}:
        return None
    if _NUMBER_RE.fullmatch(value):
        return int(value)
    if _FLOAT_RE.fullmatch(value):
        return float(value)
    return value


def _strip_comment(line: str) -> str:
    quote: Optional[str] = None
    for index, char in enumerate(line):
        if char in {'"', "'"}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        elif char == "#" and quote is None:
            return line[:index]
    return line
