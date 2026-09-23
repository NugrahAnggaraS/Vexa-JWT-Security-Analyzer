"""Command-line facade for JWKS and OIDC analysis.

``jwt-analyzer jwks`` prints key metadata and suspicious-key findings.
``jwt-analyzer oidc`` prints OpenID Provider metadata and advertised
signing algorithms. ``jwt-analyzer verify --jwks-url`` selects the key
by ``kid`` and checks the signature without a separate public-key file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from jwt_analyzer.analyzers.jwks import format_jwks_analysis, load_jwks, match_token
from jwt_analyzer.analyzers.oidc import (
    OidcAnalysisConfig,
    OidcTokenAnalyzer,
    format_oidc_discovery,
    format_oidc_token,
    load_oidc_provider,
)
from jwt_analyzer.exceptions import JWTParseError, JwksError, OidcError, RemoteFetchError
from jwt_analyzer.findings import Finding, Severity
from jwt_analyzer.parser import parse_jwt


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for the JWKS and OIDC commands."""
    parser = argparse.ArgumentParser(
        prog="jwt-analyzer",
        description="Analyze a JSON Web Key Set, an OpenID Provider, or a token signature.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

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
        if args.command == "jwks":
            return _cmd_jwks(args.location, args.token, out)
        if args.command == "oidc":
            return _cmd_oidc(args.issuer, args.token, out)
        if args.command == "verify":
            return _cmd_verify(args.token, args.jwks_url, args.jwks_file, out, err)
    except (JwksError, OidcError, RemoteFetchError, JWTParseError, OSError) as exc:
        print(str(exc), file=err)
        return 2
    print(f"Unknown command: {args.command}", file=err)
    return 2


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
