"""Command-line facade for analysis, verification, and reporting.

``analyze`` is fast mode and stays offline. ``assess`` is assessment mode
and contacts an issuer the operator named. ``verify`` checks a signature
with a local key or a JWKS document. Configuration from ``--config`` or
``~/.jwt-analyzer.yaml`` supplies defaults, and explicit flags replace them.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO
from urllib.parse import urlsplit

from jwt_analyzer import __version__
from jwt_analyzer.analyzers.batch import analyze_batch, format_batch_report, format_progress, load_token_source
from jwt_analyzer.analyzers.compare import compare_tokens, format_comparison
from jwt_analyzer.analyzers.crypto import CryptoAnalysisConfig, CryptoAnalyzer, SignatureStatus
from jwt_analyzer.analyzers.header import HeaderAnalysisConfig
from jwt_analyzer.analyzers.jwks import JwksAnalysisConfig, format_jwks_analysis, load_jwks, match_token
from jwt_analyzer.analyzers.oidc import (
    OidcAnalysisConfig,
    OidcTokenAnalyzer,
    format_oidc_discovery,
    format_oidc_token,
    load_oidc_provider,
)
from jwt_analyzer.analyzers.payload import PayloadAnalysisConfig
from jwt_analyzer.config import Settings, apply_cli, configure, default_config_path, load_settings, setup_logging, severity_at_least
from jwt_analyzer.engine import AnalysisConfig, AnalyzerEngine, analysis_result_from_dict
from jwt_analyzer.exceptions import (
    BatchError,
    CompareError,
    ConfigError,
    JWTParseError,
    JwksError,
    OidcError,
    RemoteFetchError,
    ReporterError,
)
from jwt_analyzer.findings import Finding, Severity
from jwt_analyzer.http_client import read_remote
from jwt_analyzer.parser import parse_jwt

logger = logging.getLogger("jwt_analyzer.cli")

_EPILOG = """
commands:
  decode    Decode one JWT and print its header, payload, and metadata
  analyze   Fast mode: offline header, claim, and structure checks
  assess    Assessment mode: OIDC discovery, JWKS, and signature checks
  verify    Verify a signature with a public key, HMAC secret, or JWKS
  compare   Diff two or more JWTs and flag privilege changes
  batch     Analyze every JWT in a directory or a line-oriented file
  jwks      Inspect a local or remote JSON Web Key Set
  oidc      Inspect OpenID Provider discovery metadata
  report    Render a saved JSON analysis as text, HTML, Markdown, or CSV
  version   Print the jwt-analyzer version

modes:
  fast         Offline checks only. This is the default for analyze.
  passive      Same as fast. No remote requests are made.
  assessment   Contact the issuer named by the operator.

shared flags, placed after the command:
  --config PATH              YAML or JSON defaults. Flags below override the file
  --ignore ID                Suppress a finding id such as JWT-EXP-001
  --ignore-rule ID           Suppress a finding id
  --severity-threshold LEVEL Exit 1 at this severity or above. Default: HIGH
  --verbose                  Log progress to stderr
  --debug                    Log debug details to stderr
  --log-level LEVEL          ERROR, WARN, INFO, DEBUG, or TRACE

exit status:
  0  no finding at or above the severity threshold
  1  a finding meets the severity threshold
  2  invalid input
  3  configuration error
  4  runtime error
""".strip()


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for every jwt-analyzer command."""
    parser = argparse.ArgumentParser(
        prog="jwt-analyzer",
        description=(
            "Analyze JSON Web Tokens offline, verify signatures, and write "
            "text, JSON, or standalone HTML reports."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    common = _common_parser()

    decode = commands.add_parser(
        "decode",
        parents=[common],
        help="Decode one JWT and print its header, payload, and metadata",
        description="Decode a compact JWT without contacting a network or scoring findings.",
    )
    decode.add_argument("token", help="Compact JWT or a file that contains one")

    analyze = commands.add_parser(
        "analyze",
        parents=[common],
        help="Fast mode: analyze one JWT offline and report the findings",
        description=(
            "Run header, claim, and local structure checks. Fast mode does not "
            "fetch JWKS or OpenID Provider metadata."
        ),
    )
    _add_token_report_args(analyze)
    analyze.add_argument(
        "--mode",
        choices=("fast", "passive", "assessment"),
        help="fast and passive stay offline. assessment contacts --issuer",
    )

    assess = commands.add_parser(
        "assess",
        parents=[common],
        help="Assessment mode: discover OIDC and JWKS, then analyze the JWT",
        description=(
            "Contact the issuer named by the operator, load its signing keys, "
            "and include those remote checks in the report."
        ),
    )
    _add_token_report_args(assess)

    verify = commands.add_parser(
        "verify",
        parents=[common],
        help="Verify a JWT signature with a local key or a JWKS document",
        description="Check the signature with --public-key, --secret, --jwks-url, or --jwks-file.",
    )
    verify.add_argument("token", help="Compact JWT or a file that contains one")
    verify.add_argument("--jwks-url", help="JWKS URL. The key is selected by kid")
    verify.add_argument("--jwks-file", help="Local JWKS file. The key is selected by kid")
    verify.add_argument("--public-key", help="PEM public key or certificate file")
    verify.add_argument("--secret", help="HMAC secret for HS256, HS384, or HS512")

    compare = commands.add_parser(
        "compare",
        parents=[common],
        help="Diff two or more JWTs and flag privilege changes",
        description="Compare a baseline JWT with one or more later tokens.",
    )
    compare.add_argument("tokens", nargs="+", help="Compact JWTs or files that contain one each")
    compare.add_argument("--color", action="store_true", help="Color changed values even when stdout is not a terminal")
    compare.add_argument("--no-color", action="store_true", help="Do not color the diff")

    batch = commands.add_parser(
        "batch",
        parents=[common],
        help="Analyze a directory or a file of JWTs",
        description="Analyze many tokens and print one aggregate report.",
    )
    batch.add_argument("path", nargs="?", help="Directory of token files, or a file with one JWT per line")
    batch.add_argument("--file", help="Text file with one JWT per line")
    batch.add_argument("--workers", type=int, default=4, help="How many tokens to analyze at once")

    jwks = commands.add_parser(
        "jwks",
        parents=[common],
        help="Analyze a JWKS URL or a local JWKS file",
        description="Print key metadata and suspicious-key findings for a JSON Web Key Set.",
    )
    jwks.add_argument("location", help="HTTPS URL or path of a JWKS document")
    jwks.add_argument("--token", help="JWT to match by kid and verify against this JWKS")

    oidc = commands.add_parser(
        "oidc",
        parents=[common],
        help="Fetch and analyze OpenID Provider metadata",
        description="Fetch /.well-known/openid-configuration and print the advertised algorithms.",
    )
    oidc.add_argument("issuer", help="Issuer URL, for example https://auth.example.com")
    oidc.add_argument("--token", help="JWT whose iss and alg are compared with the provider")

    report = commands.add_parser(
        "report",
        parents=[common],
        help="Render a saved JSON analysis as text, HTML, Markdown, or CSV",
        description="Read a JSON report written by analyze --format json and render another format.",
    )
    report.add_argument("path", help="JSON report file")
    report.add_argument(
        "--format",
        choices=("text", "json", "html", "markdown", "csv"),
        help="Output format. The default is the format from configuration, or text",
    )
    report.add_argument("--output", "-o", help="Write the report to this path instead of the console")
    report.add_argument("--color", action="store_true", help="Color the text report")
    report.add_argument("--no-color", action="store_true", help="Do not color the text report")

    commands.add_parser(
        "version",
        help="Print the jwt-analyzer version",
        description="Print the installed jwt-analyzer version and exit.",
    )
    return parser


def _common_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="YAML or JSON file that supplies default options")
    common.add_argument("--verbose", action="store_true", help="Log informational progress to stderr")
    common.add_argument("--debug", action="store_true", help="Log debug details to stderr")
    common.add_argument(
        "--log-level",
        choices=("ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE"),
        help="Logging level. TRACE is more detailed than DEBUG",
    )
    common.add_argument("--ignore", action="append", help="Suppress a finding id, for example JWT-EXP-001")
    common.add_argument("--ignore-rule", action="append", dest="ignore_rule", help="Suppress a finding id")
    common.add_argument(
        "--severity-threshold",
        choices=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        help="Lowest severity that makes the process exit 1. The default is HIGH",
    )
    return common


def _add_token_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("token", help="Compact JWT or a file that contains one")
    parser.add_argument("--issuer", help="Issuer URL used by assessment mode")
    parser.add_argument("--jwks-url", help="JWKS URL used by assessment mode")
    parser.add_argument(
        "--format",
        choices=("text", "json", "html", "markdown", "csv", "terminal"),
        help="Report format. Overrides the format in the configuration file",
    )
    parser.add_argument("--json", action="store_true", help="Write the JSON report")
    parser.add_argument("--html", nargs="?", const="-", help="Write the HTML report, optionally to a path")
    parser.add_argument("--output", "-o", help="Write the report to this path instead of the console")
    parser.add_argument("--color", action="store_true", help="Color the text report")
    parser.add_argument("--no-color", action="store_true", help="Do not color the text report")


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

    if args.command == "version":
        print(__version__, file=out)
        return 0

    try:
        settings = _resolve_settings(args)
    except ConfigError as exc:
        print(str(exc), file=err)
        return 3
    setup_logging(settings.log_level, err)
    configure(settings)
    logger.info("command=%s mode=%s config=%s", args.command, settings.mode, settings.source or "-")

    try:
        if args.command == "decode":
            return _cmd_decode(args.token, out)
        if args.command == "analyze":
            return _cmd_analyze(args, settings, out, err)
        if args.command == "assess":
            return _cmd_assess(args, settings, out, err)
        if args.command == "report":
            return _cmd_report(args, settings, out, err)
        if args.command == "jwks":
            return _cmd_jwks(args.location, args.token, out)
        if args.command == "oidc":
            return _cmd_oidc(args.issuer, args.token, out)
        if args.command == "verify":
            return _cmd_verify(args.token, args.jwks_url, args.jwks_file, args.public_key, args.secret, out, err)
        if args.command == "compare":
            return _cmd_compare(args.tokens, args.color, args.no_color, out, err)
        if args.command == "batch":
            return _cmd_batch(args.path, args.file, args.workers, out, err)
    except ConfigError as exc:
        logger.error("%s", exc)
        print(str(exc), file=err)
        return 3
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
        logger.error("%s", exc)
        print(str(exc), file=err)
        return 2
    except Exception as exc:
        logger.error("%s", exc)
        print(str(exc), file=err)
        return 4
    print(f"Unknown command: {args.command}", file=err)
    return 2


def _resolve_settings(args: argparse.Namespace) -> Settings:
    if args.config:
        loaded = load_settings(args.config)
    else:
        found = default_config_path()
        loaded = load_settings(found) if found is not None else Settings()
    return apply_cli(loaded, args)


def _cmd_decode(token: str, out: TextIO) -> int:
    print(parse_jwt(_read_token(token)).to_readable(), file=out)
    return 0


def _cmd_analyze(args: argparse.Namespace, settings: Settings, out: TextIO, err: TextIO) -> int:
    if settings.mode == "assessment":
        return _cmd_assess(args, settings, out, err)
    logger.info("mode=fast; remote fetches disabled")
    return _emit_analysis(args, settings, _analysis_config(settings), out, err)


def _cmd_assess(args: argparse.Namespace, settings: Settings, out: TextIO, err: TextIO) -> int:
    issuer = args.issuer or settings.issuer
    jwks_url = args.jwks_url
    if not issuer and not jwks_url:
        print("Assessment mode needs --issuer or --jwks-url.", file=err)
        return 2
    logger.info("mode=assessment; issuer=%s", issuer or "-")
    provider = load_oidc_provider(issuer) if issuer else None
    location = jwks_url or (provider.jwks_uri if provider is not None else None)
    document = load_jwks(location) if location else None
    header = None
    host = urlsplit(issuer).hostname if issuer else None
    if host:
        header = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({host}),
            key_fetcher=lambda url: read_remote(url),
        )
    config = _analysis_config(
        settings,
        header=header,
        jwks=JwksAnalysisConfig(document=document) if document is not None else None,
        oidc=OidcAnalysisConfig(discovery=provider) if provider is not None else None,
    )
    return _emit_analysis(args, settings, config, out, err)


def _cmd_report(args: argparse.Namespace, settings: Settings, out: TextIO, err: TextIO) -> int:
    try:
        data = json.loads(Path(args.path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReporterError(f"Report JSON is invalid: {exc.msg}", code="INVALID_REPORT") from exc
    result = analysis_result_from_dict(data)
    fmt, output = _report_target(args, settings)
    document = AnalyzerEngine().render(result, fmt, color=_color_enabled(out, args, settings))
    _write_document(document, output, out)
    return 0


def _emit_analysis(
    args: argparse.Namespace,
    settings: Settings,
    config: AnalysisConfig,
    out: TextIO,
    err: TextIO,
) -> int:
    fmt, output = _report_target(args, settings)
    result = AnalyzerEngine(config).run(_read_token(args.token))
    for finding in result.findings:
        logger.debug("finding %s severity=%s", finding.id, finding.severity.value)
    document = AnalyzerEngine(config).render(result, fmt, color=_color_enabled(out, args, settings))
    _write_document(document, output, out)
    if any(severity_at_least(item.severity, settings.severity_threshold) for item in result.findings):
        return 1
    return 0


def _analysis_config(
    settings: Settings,
    *,
    header: Optional[HeaderAnalysisConfig] = None,
    jwks: Optional[JwksAnalysisConfig] = None,
    oidc: Optional[OidcAnalysisConfig] = None,
) -> AnalysisConfig:
    return AnalysisConfig(
        header=header,
        payload=PayloadAnalysisConfig(
            max_lifetime_seconds=settings.max_token_lifetime,
            check_sensitive_claims=settings.check_sensitive_claims,
            check_duplicate_claims=settings.check_duplicate_claims,
        ),
        jwks=jwks,
        oidc=oidc,
        ignore=frozenset(settings.ignore),
    )


def _report_target(args: argparse.Namespace, settings: Settings) -> tuple[str, Optional[str]]:
    if args.color and args.no_color:
        raise ReporterError("Pass only one of --color or --no-color.", code="INVALID_FORMAT")
    selected: list[str] = []
    if getattr(args, "json", False):
        selected.append("json")
    if getattr(args, "html", None) is not None:
        selected.append("html")
    if getattr(args, "format", None):
        from jwt_analyzer.config import normalize_format

        selected.append(normalize_format(args.format))
    if len(set(selected)) > 1:
        raise ReporterError("Pass only one report format.", code="INVALID_FORMAT")
    fmt = selected[0] if selected else settings.report_format
    output = getattr(args, "output", None)
    html_path = getattr(args, "html", None)
    if html_path not in (None, "-"):
        if output and output != html_path:
            raise ReporterError("Pass the HTML path once, either with --html or --output.", code="INVALID_FORMAT")
        output = html_path
    return fmt, output


def _color_enabled(out: TextIO, args: argparse.Namespace, settings: Settings) -> bool:
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "color", False):
        return True
    if settings.color is False:
        return False
    if settings.color is True:
        return True
    return bool(getattr(out, "isatty", lambda: False)())


def _write_document(document: str, output: Optional[str], out: TextIO) -> None:
    if output:
        Path(output).write_text(document, encoding="utf-8")
    else:
        print(document, file=out)


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
    public_key: Optional[str],
    secret: Optional[str],
    out: TextIO,
    err: TextIO,
) -> int:
    selected = [item for item in (jwks_url, jwks_file, public_key, secret) if item]
    if len(selected) != 1:
        print("Pass exactly one of --jwks-url, --jwks-file, --public-key, or --secret.", file=err)
        return 2
    parsed = parse_jwt(_read_token(token))
    if public_key or secret:
        pem = Path(public_key).read_bytes() if public_key else None
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(
                public_key_pem=pem,
                secret=secret,
                key_label=public_key or "secret",
            )
        ).inspect(parsed)
        print(report.message, file=out)
        for finding in report.findings:
            print(f"[{finding.severity.value}] {finding.id} {finding.title}", file=out)
        return 0 if report.signature_status is SignatureStatus.VALID else 1
    document = load_jwks(jwks_url or jwks_file or "")
    match = match_token(parsed, document)
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
    try:
        is_file = path.is_file()
    except OSError:
        is_file = False
    if is_file:
        return path.name
    return f"token{index + 1}"


def _use_color(out: TextIO, force_color: bool, disable_color: bool) -> bool:
    if disable_color:
        return False
    if force_color:
        return True
    return bool(getattr(out, "isatty", lambda: False)())


def _read_token(value: str) -> str:
    text = value.strip()
    path = Path(text)
    try:
        is_file = path.is_file()
    except OSError:
        # A compact JWT can be longer than the OS file-name limit.
        return text
    if is_file:
        return path.read_text(encoding="utf-8").strip()
    return text


def _status(findings: Sequence[Finding], *, failed: bool) -> int:
    if failed:
        return 1
    if any(item.severity in {Severity.CRITICAL, Severity.HIGH} for item in findings):
        return 1
    return 0
