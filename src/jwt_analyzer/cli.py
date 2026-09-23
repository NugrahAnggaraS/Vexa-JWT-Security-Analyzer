"""Command-line facade for analysis, JWKS, OIDC, comparison, and batch.

``jwt-analyzer jwks`` prints key metadata and suspicious-key findings.
``jwt-analyzer oidc`` prints OpenID Provider metadata and advertised
signing algorithms. ``jwt-analyzer verify --jwks-url`` selects the key
by ``kid``. ``jwt-analyzer compare`` diffs tokens. ``jwt-analyzer batch``
analyzes a file or directory and prints an aggregate report.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from jwt_analyzer.analyzers.batch import analyze_batch, format_batch_report, format_progress, load_token_source
from jwt_analyzer.engine import AnalyzerEngine
from jwt_analyzer.analyzers.compare import compare_tokens, format_comparison
from jwt_analyzer.analyzers.jwks import format_jwks_analysis, load_jwks, match_token
from jwt_analyzer.analyzers.oidc import (
    OidcAnalysisConfig,
    OidcTokenAnalyzer,
    format_oidc_discovery,
    format_oidc_token,
    load_oidc_provider,
)
from jwt_analyzer.exceptions import (
    BatchError,
    CompareError,
    JWTParseError,
    JwksError,
    OidcError,
    RemoteFetchError,
    ReporterError,
)
from jwt_analyzer.findings import Finding, Severity
from jwt_analyzer.parser import parse_jwt


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for the JWKS and OIDC commands."""
    parser = argparse.ArgumentParser(
        prog="jwt-analyzer",
        description="Analyze JWTs, a JSON Web Key Set, or an OpenID Provider.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Analyze one JWT and report the findings")
    analyze.add_argument("token", help="Compact JWT or a file that contains one")
    analyze.add_argument(
        "--format",
        default="text",
        choices=("text", "json", "html", "markdown", "csv"),
        help="Report format. text is the console report",
    )
    analyze.add_argument("--json", action="store_true", help="Write the JSON report")
    analyze.add_argument("--html", nargs="?", const="-", help="Write the HTML report, optionally to a path")
    analyze.add_argument("--output", "-o", help="Write the report to this path instead of the console")
    analyze.add_argument("--color", action="store_true", help="Color the text report")
    analyze.add_argument("--no-color", action="store_true", help="Do not color the text report")

    jwks = commands.add_parser("jwks", help="Analyze a JWKS URL or a local JWKS file")
    jwks.add_argument("location", help="HTTPS URL or path of a JWKS document")
    jwks.add_argument("--token", help="JWT to match by kid and verify against this JWKS")

    oidc = commands.add_parser("oidc", help="Fetch and analyze OpenID Provider metadata")
    oidc.add_argument("issuer", help="Issuer URL, for example https://auth.example.com")
    oidc.add_argument("--token", help="JWT whose iss and alg are compared with the provider")

    verify = commands.add_parser("verify", help="Verify a JWT with a JWKS document")
    verify.add_argument("token", help="Compact JWT or a file that contains one")
    verify.add_argument("--jwks-url", help="JWKS URL. The key is selected by kid")
    verify.add_argument("--jwks-file", help="Local JWKS file. The key is selected by kid")

    compare = commands.add_parser("compare", help="Diff two or more JWTs and flag privilege changes")
    compare.add_argument("tokens", nargs="+", help="Compact JWTs or files that contain one each")
    compare.add_argument("--color", action="store_true", help="Color changed values even when stdout is not a terminal")
    compare.add_argument("--no-color", action="store_true", help="Do not color the diff")

    batch = commands.add_parser("batch", help="Analyze a directory or a file of JWTs")
    batch.add_argument("path", nargs="?", help="Directory of token files, or a file with one JWT per line")
    batch.add_argument("--file", help="Text file with one JWT per line")
    batch.add_argument("--workers", type=int, default=4, help="How many tokens to analyze at once")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Run the CLI and exit with its status code."""
    sys.exit(run(argv))


def run(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Run one command and return the process status code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return 2 if code is None else int(code)

    try:
        if args.command == "analyze":
            return _cmd_analyze(args, out, err)
        if args.command == "jwks":
            return _cmd_jwks(args.location, args.token, out)
        if args.command == "oidc":
            return _cmd_oidc(args.issuer, args.token, out)
        if args.command == "verify":
            return _cmd_verify(args.token, args.jwks_url, args.jwks_file, out, err)
        if args.command == "compare":
            return _cmd_compare(args.tokens, args.color, args.no_color, out, err)
        if args.command == "batch":
            return _cmd_batch(args.path, args.file, args.workers, out, err)
    except (
        JwksError,
        OidcError,
        RemoteFetchError,
        JWTParseError,
        CompareError,
        BatchError,
        ReporterError,
        OSError,
    ) as exc:
        print(str(exc), file=err)
        return 2
    print(f"Unknown command: {args.command}", file=err)
    return 2


def _cmd_analyze(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    if args.color and args.no_color:
        print("Pass only one of --color or --no-color.", file=err)
        return 2
    try:
        fmt, output = _report_target(args)
    except ReporterError as exc:
        print(str(exc), file=err)
        return 2
    result = AnalyzerEngine().run(_read_token(args.token))
    document = AnalyzerEngine().render(result, fmt, color=_use_color(out, args.color, args.no_color))
    if output:
        Path(output).write_text(document, encoding="utf-8")
    else:
        print(document, file=out)
    failed = result.risk.critical > 0 or result.risk.high > 0
    return _status(result.findings, failed=failed)


def _report_target(args: argparse.Namespace) -> tuple[str, Optional[str]]:
    selected: list[str] = []
    if args.json:
        selected.append("json")
    if args.html is not None:
        selected.append("html")
    if args.format != "text":
        selected.append(args.format)
    if len(set(selected)) > 1:
        raise ReporterError("Pass only one report format.", code="INVALID_FORMAT")
    fmt = selected[0] if selected else "text"
    output = args.output
    if args.html not in (None, "-"):
        if output and output != args.html:
            raise ReporterError("Pass the HTML path once, either with --html or --output.", code="INVALID_FORMAT")
        output = args.html
    return fmt, output


def _cmd_jwks(location: str, token: Optional[str], out: TextIO) -> int:
    document = load_jwks(location)
    match = None
    if token:
        match = match_token(parse_jwt(_read_token(token)), document)
    print(format_jwks_analysis(document, match), file=out)
    findings = list(document.all_findings)
    if match is not None:
        findings.extend(match.findings)
    failed = match is not None and match.signature_valid is False
    unresolved = match is not None and match.matched and match.signature_valid is None and match.signing_key is not False
    if match is not None and not match.matched:
        unresolved = True
    return _status(findings, failed=failed or unresolved or (match is not None and match.signing_key is False))


def _cmd_oidc(issuer: str, token: Optional[str], out: TextIO) -> int:
    provider = load_oidc_provider(issuer)
    print(format_oidc_discovery(provider), file=out)
    findings = list(provider.findings)
    failed = False
    if token:
        parsed = parse_jwt(_read_token(token))
        report = OidcTokenAnalyzer(OidcAnalysisConfig(discovery=provider)).inspect(parsed)
        print("", file=out)
        print(format_oidc_token(report), file=out)
        findings.extend(report.findings)
        failed = any(item.id == "JWT-OIDC-008" for item in report.findings)
    return _status(findings, failed=failed)


def _cmd_verify(
    token: str,
    jwks_url: Optional[str],
    jwks_file: Optional[str],
    out: TextIO,
    err: TextIO,
) -> int:
    if bool(jwks_url) == bool(jwks_file):
        print("Pass exactly one of --jwks-url or --jwks-file.", file=err)
        return 2
    document = load_jwks(jwks_url or jwks_file or "")
    match = match_token(parse_jwt(_read_token(token)), document)
    print(format_jwks_analysis(document, match), file=out)
    failed = match.signature_valid is not True
    return _status(list(document.all_findings) + list(match.findings), failed=failed)


def _cmd_compare(
    tokens: Sequence[str],
    force_color: bool,
    disable_color: bool,
    out: TextIO,
    err: TextIO,
) -> int:
    if force_color and disable_color:
        print("Pass only one of --color or --no-color.", file=err)
        return 2
    parsed = [parse_jwt(_read_token(value)) for value in tokens]
    labels = [_token_label(value, index) for index, value in enumerate(tokens)]
    report = compare_tokens(parsed, labels)
    print(format_comparison(report, color=_use_color(out, force_color, disable_color)), file=out)
    return _status(report.findings, failed=False)


def _cmd_batch(
    path: Optional[str],
    file_path: Optional[str],
    workers: int,
    out: TextIO,
    err: TextIO,
) -> int:
    if bool(path) == bool(file_path):
        message = "Pass a path or --file, not both." if path and file_path else "Pass a directory, a token file, or --file."
        print(message, file=err)
        return 2

    def on_progress(done: int, total: int) -> None:
        if not getattr(err, "isatty", lambda: False)():
            return
        print("\r" + format_progress(done, total), end="", file=err, flush=True)
        if done == total:
            print(file=err)

    report = analyze_batch(load_token_source(file_path or path or ""), max_workers=workers, on_progress=on_progress)
    print(format_batch_report(report), file=out)
    failed = any(item.status in {"critical", "invalid"} for item in report.items)
    return _status(report.findings, failed=failed)


def _token_label(value: str, index: int) -> str:
    path = Path(value)
    if path.is_file():
        return path.name
    return f"token{index + 1}"


def _use_color(out: TextIO, force_color: bool, disable_color: bool) -> bool:
    if disable_color:
        return False
    if force_color:
        return True
    return bool(getattr(out, "isatty", lambda: False)())


def _read_token(value: str) -> str:
    path = Path(value)
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return value.strip()


def _status(findings: Sequence[Finding], *, failed: bool) -> int:
    if failed:
        return 1
    if any(item.severity in {Severity.CRITICAL, Severity.HIGH} for item in findings):
        return 1
    return 0
