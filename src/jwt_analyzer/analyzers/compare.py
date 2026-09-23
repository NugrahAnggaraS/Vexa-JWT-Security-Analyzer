"""Diff two or more JWTs and flag privilege or algorithm changes.

Each comparison aspect is a strategy. The default chain is:

    HeaderDiff -> ClaimDiff -> LifetimeDiff -> PrivilegeDiff -> AlgorithmDiff -> IdentityDiff

A changed claim is always shown in the diff. A finding is emitted only when
the change is security-relevant: a higher role, a weaker algorithm, a
different issuer, a wider audience, or a longer lifetime.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from jwt_analyzer.exceptions import CompareError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import ParsedJWT

RFC_7519 = "https://www.rfc-editor.org/rfc/rfc7519"
RFC_8725 = "https://www.rfc-editor.org/rfc/rfc8725"

_SYMMETRIC = frozenset({"HS256", "HS384", "HS512", "HS1"})
_SHA1 = frozenset({"HS1", "RS1", "ES1", "PS1"})
_ROLE_KEYS = frozenset(
    {
        "role",
        "roles",
        "rolename",
        "permission",
        "permissions",
        "scope",
        "scp",
        "groups",
        "group",
        "authorities",
        "isadmin",
        "admin",
    }
)
_PRIVILEGE = {
    "anonymous": 0,
    "guest": 0,
    "viewer": 1,
    "read": 1,
    "member": 1,
    "user": 1,
    "editor": 2,
    "operator": 2,
    "write": 2,
    "admin": 3,
    "administrator": 3,
    "superadmin": 4,
    "superuser": 4,
    "root": 4,
    "owner": 4,
}
_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class DiffEntry:
    """One side of a changed field."""

    label: str
    value: str


@dataclass(frozen=True)
class DiffLine:
    """A header or payload field whose values are not all the same."""

    section: str
    field: str
    values: tuple[DiffEntry, ...]


@dataclass(frozen=True)
class ComparisonReport:
    """Visual diff plus the security findings that came from it."""

    labels: tuple[str, ...]
    diffs: tuple[DiffLine, ...]
    findings: tuple[Finding, ...]


class ComparisonCheck(ABC):
    """Strategy that compares one aspect of several parsed tokens."""

    @abstractmethod
    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        """Return diff lines and findings. Do not raise for a weak change."""


class HeaderDiffCheck(ComparisonCheck):
    """Show JOSE header parameters that differ, including alg and kid."""

    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        return _diff_maps("Header", [token.header for token in tokens], labels), []


class ClaimDiffCheck(ComparisonCheck):
    """Show payload claims that differ. Lifetime owns the exp line."""

    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        maps = []
        for token in tokens:
            flat = _flatten(token.payload)
            flat.pop("exp", None)
            maps.append(flat)
        return _diff_maps("Payload", maps, labels), []


class LifetimeDiffCheck(ComparisonCheck):
    """Compare exp - iat and surface a longer-lived token."""

    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        lifetimes = [_lifetime(token) for token in tokens]
        if all(item is not None for item in lifetimes):
            rendered = [(_seconds(item)) for item in lifetimes]
            diffs = []
            if len(set(rendered)) > 1:
                diffs.append(_line("Payload", "exp", labels, rendered))
            findings = []
            baseline = lifetimes[0]
            assert baseline is not None
            for label, lifetime in zip(labels[1:], lifetimes[1:]):
                assert lifetime is not None
                if lifetime > baseline:
                    findings.append(
                        _finding(
                            "JWT-CMP-005",
                            "Token lifetime increased",
                            Severity.LOW,
                            "A later token stays valid for longer than the baseline token.",
                            f"baseline={labels[0]}; token={label}; baseline_seconds={_num(baseline)}; token_seconds={_num(lifetime)}",
                            "A longer lifetime gives an attacker more time to reuse a stolen token.",
                            "Keep the same lifetime policy for tokens that share an issuer and audience.",
                        )
                    )
            return diffs, findings
        raw = [_render(token.payload.get("exp")) if "exp" in token.payload else "-" for token in tokens]
        if len(set(raw)) <= 1:
            return [], []
        return [_line("Payload", "exp", labels, raw)], []


class PrivilegeDiffCheck(ComparisonCheck):
    """Flag a role, scope, or admin flag that is higher than the baseline."""

    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        baseline = _privileges(tokens[0].payload)
        findings: list[Finding] = []
        for label, token in zip(labels[1:], tokens[1:]):
            current = _privileges(token.payload)
            for path in sorted(set(baseline) | set(current)):
                old = baseline.get(path)
                new = current.get(path)
                old_rank = 0 if old is None else old[0]
                new_rank = 0 if new is None else new[0]
                if new_rank <= old_rank:
                    continue
                old_text = "-" if old is None else old[1]
                new_text = "-" if new is None else new[1]
                severity = Severity.HIGH if new_rank >= 3 else Severity.MEDIUM
                findings.append(
                    _finding(
                        "JWT-CMP-001",
                        "Privilege escalation",
                        severity,
                        "A role or permission claim is more privileged than the same claim on the baseline token.",
                        f"field={path}; baseline={labels[0]}; {labels[0]}={_clip(old_text)}; {label}={_clip(new_text)}",
                        "The later token may authorize actions the baseline token cannot perform.",
                        "Confirm the subject was meant to receive the higher role before trusting this token.",
                    )
                )
        return [], findings


class AlgorithmDiffCheck(ComparisonCheck):
    """Flag a move to none, HMAC, or SHA-1 from a stronger algorithm."""

    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        baseline = _algorithm(tokens[0])
        findings: list[Finding] = []
        for label, token in zip(labels[1:], tokens[1:]):
            current = _algorithm(token)
            if current is None or current == baseline:
                continue
            if not _algorithm_weakened(baseline, current):
                continue
            findings.append(
                _finding(
                    "JWT-CMP-002",
                    "Algorithm weakened",
                    Severity.HIGH,
                    "The later token uses a weaker signature algorithm than the baseline.",
                    f"baseline={labels[0]}; {labels[0]}={baseline or '-'}; {label}={current}",
                    "A weaker algorithm can make the token easier to forge or confuse a verifier.",
                    "Reject algorithm changes that drop to none, HMAC, or SHA-1.",
                    references=(RFC_8725,),
                )
            )
        return [], findings


class IdentityDiffCheck(ComparisonCheck):
    """Flag an issuer change and an audience that grows or moves."""

    def check(
        self,
        tokens: Sequence[ParsedJWT],
        labels: Sequence[str],
    ) -> tuple[list[DiffLine], list[Finding]]:
        findings: list[Finding] = []
        base_iss = _text(tokens[0].payload.get("iss"))
        base_aud = _audiences(tokens[0])
        for label, token in zip(labels[1:], tokens[1:]):
            iss = _text(token.payload.get("iss"))
            if base_iss is not None and iss is not None and iss != base_iss:
                findings.append(
                    _finding(
                        "JWT-CMP-003",
                        "Issuer changed",
                        Severity.MEDIUM,
                        "The iss claim is not the same as the baseline token.",
                        f"baseline={labels[0]}; {labels[0]}={_clip(base_iss)}; {label}={_clip(iss)}",
                        "The token may have been issued by a different party.",
                        "Compare tokens from the same issuer when judging a privilege change.",
                    )
                )
            audiences = _audiences(token)
            if base_aud is None or audiences is None or audiences == base_aud:
                continue
            widened = base_aud < audiences
            findings.append(
                _finding(
                    "JWT-CMP-004",
                    "Audience widened" if widened else "Audience changed",
                    Severity.MEDIUM,
                    "The aud claim does not match the baseline token.",
                    f"baseline={labels[0]}; token={label}; widened={str(widened).lower()}",
                    "A wider audience makes the token acceptable to more resources.",
                    "Keep aud limited to the resource that should accept the token.",
                )
            )
        return [], findings


def get_comparison_checks() -> tuple[ComparisonCheck, ...]:
    """Return the default comparison chain."""
    return (
        HeaderDiffCheck(),
        ClaimDiffCheck(),
        LifetimeDiffCheck(),
        PrivilegeDiffCheck(),
        AlgorithmDiffCheck(),
        IdentityDiffCheck(),
    )


def compare_tokens(
    tokens: Sequence[ParsedJWT],
    labels: Optional[Sequence[str]] = None,
    checks: Optional[Sequence[ComparisonCheck]] = None,
) -> ComparisonReport:
    """Diff ``tokens`` and collect security-relevant changes.

    The first token is the baseline. Later tokens are compared with it.
    """
    if len(tokens) < 2:
        raise CompareError("At least two tokens are required", code="TOO_FEW_TOKENS")
    names = tuple(labels) if labels is not None else tuple(f"token{index + 1}" for index in range(len(tokens)))
    if len(names) != len(tokens):
        raise CompareError("Each token needs one label", code="INVALID_LABELS")
    if any(not isinstance(label, str) or not label.strip() for label in names):
        raise CompareError("Labels must be non-empty strings", code="INVALID_LABELS")
    chain = tuple(checks) if checks is not None else get_comparison_checks()
    diffs: list[DiffLine] = []
    findings: list[Finding] = []
    for check in chain:
        extra_diffs, extra_findings = check.check(tokens, names)
        diffs.extend(extra_diffs)
        findings.extend(extra_findings)
    return ComparisonReport(labels=names, diffs=tuple(diffs), findings=tuple(findings))


def format_comparison(report: ComparisonReport, *, color: bool = False) -> str:
    """Render the diff. Changed baseline values are red and later values are green."""
    lines = ["JWT COMPARISON", "──────────────────────", ""]
    if not report.diffs and not report.findings:
        lines.append("No differences")
        return "\n".join(lines)
    current = ""
    for diff in report.diffs:
        if diff.section != current:
            if current:
                lines.append("")
            lines.append(diff.section)
            current = diff.section
        lines.append(f"{diff.field}:")
        for index, entry in enumerate(diff.values):
            paint = 31 if index == 0 else 32
            value = _paint(entry.value, paint, color)
            lines.append(f"    {entry.label} = {value}")
    if report.findings:
        lines.append("")
        lines.append("Findings")
        lines.append("──────────────────────")
        for item in report.findings:
            lines.append(f"[{item.severity.value}] {item.id} {item.title}")
            lines.append(item.evidence)
    return "\n".join(lines)


def _diff_maps(section: str, maps: Sequence[dict[str, Any]], labels: Sequence[str]) -> list[DiffLine]:
    prepared = [_flatten(item) for item in maps]
    fields = sorted({key for item in prepared for key in item})
    diffs: list[DiffLine] = []
    for field in fields:
        values = [item.get(field, "-") for item in prepared]
        if len(set(values)) <= 1:
            continue
        diffs.append(_line(section, field, labels, values))
    return diffs


def _line(section: str, field: str, labels: Sequence[str], values: Sequence[str]) -> DiffLine:
    return DiffLine(
        section=section,
        field=field,
        values=tuple(DiffEntry(label, value) for label, value in zip(labels, values)),
    )


def _flatten(node: Any, prefix: str = "") -> dict[str, str]:
    if isinstance(node, dict):
        flat: dict[str, str] = {}
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                flat.update(_flatten(value, path))
            else:
                flat[path] = _render(value)
        return flat
    if prefix:
        return {prefix: _render(node)}
    return {}


def _render(value: Any) -> str:
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            return ", ".join(_render(item) for item in value) if value else "[]"
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def _lifetime(token: ParsedJWT) -> Optional[float]:
    exp = _numeric(token.payload.get("exp"))
    iat = _numeric(token.payload.get("iat"))
    if exp is None or iat is None:
        return None
    return exp - iat


def _privileges(payload: Any) -> dict[str, tuple[int, str]]:
    found: dict[str, tuple[int, str]] = {}
    _walk_privileges(payload, "", found)
    return found


def _walk_privileges(node: Any, path: str, found: dict[str, tuple[int, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            name = str(key)
            child = f"{path}.{name}" if path else name
            if _is_role_key(name) and not isinstance(value, dict):
                found[child] = (_privilege_rank(value), _render(value))
            else:
                _walk_privileges(value, child, found)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                _walk_privileges(item, path, found)


def _is_role_key(key: str) -> bool:
    return re.sub(r"[^a-z0-9]", "", key.lower()) in _ROLE_KEYS


def _privilege_rank(value: Any) -> int:
    if isinstance(value, bool):
        return 3 if value else 0
    if isinstance(value, str):
        return _rank_text(value)
    if isinstance(value, list):
        ranks = [_privilege_rank(item) for item in value]
        return max(ranks) if ranks else 0
    if isinstance(value, dict):
        ranks = [_privilege_rank(item) for item in value.values()]
        return max(ranks) if ranks else 0
    return 0


def _rank_text(text: str) -> int:
    parts = [part for part in _SPLIT.split(text.lower()) if part]
    ranks = [_PRIVILEGE.get(part, 0) for part in parts]
    return max(ranks) if ranks else 0


def _algorithm(token: ParsedJWT) -> Optional[str]:
    alg = token.header.get("alg")
    if isinstance(alg, str) and alg.strip():
        return alg.strip()
    return None


def _algorithm_weakened(baseline: Optional[str], current: str) -> bool:
    if baseline is None:
        return False
    if current.lower() == "none" and baseline.lower() != "none":
        return True
    if current in _SYMMETRIC and baseline not in _SYMMETRIC and baseline.lower() != "none":
        return True
    if current in _SHA1 and baseline not in _SHA1:
        return True
    return False


def _audiences(token: ParsedJWT) -> Optional[set[str]]:
    aud = token.payload.get("aud")
    if isinstance(aud, str):
        return {aud}
    if isinstance(aud, list) and all(isinstance(item, str) for item in aud):
        return set(aud)
    return None


def _text(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _seconds(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{_num(value)}s"


def _num(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return str(value)


def _clip(value: str, limit: int = 80) -> str:
    collapsed = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "...(truncated)"


def _paint(value: str, code: int, enabled: bool) -> str:
    if not enabled:
        return value
    return f"\033[{code}m{value}\033[0m"


def _finding(
    finding_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: tuple[str, ...] = (RFC_7519,),
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=Confidence.HIGH,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        references=references,
    )
