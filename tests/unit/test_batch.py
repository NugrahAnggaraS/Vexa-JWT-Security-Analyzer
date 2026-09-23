"""Unit tests for concurrent batch analysis and aggregate reports."""

from __future__ import annotations

import base64
import json
import threading
import time
from typing import Any

import pytest

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.batch import (
    BatchAnalyzer,
    TokenSource,
    analyze_batch,
    format_batch_report,
    format_progress,
    load_token_source,
)
from jwt_analyzer.exceptions import BatchError
from jwt_analyzer.findings import Finding
from jwt_analyzer.parser import ParsedJWT


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def token(header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def secure_payload(**extra: Any) -> dict[str, Any]:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": "https://auth.example.com",
        "sub": "user",
        "aud": "api",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": "id-1",
    }
    payload.update(extra)
    return payload


def by_label(report, label: str):
    return next(item for item in report.items if item.label == label)


class TestBatchAnalysis:
    def test_summary_distinguishes_secure_warning_and_critical(self) -> None:
        missing = secure_payload()
        del missing["exp"]
        sources = [
            TokenSource("token-001", token({"alg": "RS256", "typ": "JWT"}, secure_payload())),
            TokenSource("token-002", token({"alg": "HS256", "typ": "JWT"}, secure_payload())),
            TokenSource("token-003", token({"alg": "none", "typ": "JWT"}, secure_payload())),
            TokenSource("token-004", token({"alg": "RS256", "typ": "JWT"}, missing)),
        ]

        report = analyze_batch(sources, max_workers=2)
        text = format_batch_report(report)

        assert by_label(report, "token-001").status == "secure"
        assert by_label(report, "token-001").glyph == "✓"
        assert by_label(report, "token-002").status == "secure"
        assert by_label(report, "token-002").algorithm == "HS256"
        assert by_label(report, "token-003").status == "critical"
        assert by_label(report, "token-003").glyph == "✗"
        assert 'Algorithm "none" detected' in by_label(report, "token-003").summary
        assert by_label(report, "token-004").status == "warning"
        assert by_label(report, "token-004").glyph == "⚠"
        assert "Token has no expiration claim" in by_label(report, "token-004").summary
        assert "TOKEN ANALYSIS" in text
        assert "Tokens     : 4" in text
        assert "Secure     : 2" in text
        assert "Warning    : 1" in text
        assert "Critical   : 1" in text
        assert "RS256=2" in text
        assert "none=1" in text

    def test_one_hundred_tokens_keep_input_order_and_report_progress(self) -> None:
        sources = []
        for index in range(100):
            algorithm = "none" if index == 99 else "RS256"
            sources.append(
                TokenSource(
                    f"token-{index:03d}",
                    token({"alg": algorithm, "typ": "JWT"}, secure_payload(jti=f"id-{index}")),
                )
            )
        progress: list[tuple[int, int]] = []
        report = analyze_batch(sources, max_workers=4, on_progress=lambda done, total: progress.append((done, total)))

        assert len(report.items) == 100
        assert [item.label for item in report.items] == [f"token-{index:03d}" for index in range(100)]
        assert sum(1 for item in report.items if item.status == "secure") == 99
        assert report.items[-1].status == "critical"
        assert progress[0] == (1, 100)
        assert progress[-1] == (100, 100)
        assert len(progress) == 100
        assert "Tokens     : 100" in format_batch_report(report)

    def test_invalid_token_does_not_stop_the_batch(self) -> None:
        sources = [
            TokenSource("good", token({"alg": "RS256", "typ": "JWT"}, secure_payload())),
            TokenSource("bad", "aaa.bbb.ccc"),
            TokenSource("also-good", token({"alg": "RS256", "typ": "JWT"}, secure_payload(jti="id-2"))),
        ]
        report = analyze_batch(sources)
        assert [item.status for item in report.items] == ["secure", "invalid", "secure"]
        assert by_label(report, "bad").glyph == "!"
        assert by_label(report, "bad").findings == ()

    def test_workers_run_on_more_than_one_thread(self) -> None:
        class RecordingAnalyzer(BaseAnalyzer):
            def __init__(self) -> None:
                self.idents: list[int] = []
                self._lock = threading.Lock()

            @property
            def name(self) -> str:
                return "recording"

            def analyze(self, token: ParsedJWT) -> list[Finding]:
                del token
                time.sleep(0.02)
                with self._lock:
                    self.idents.append(threading.get_ident())
                return []

        analyzer = RecordingAnalyzer()
        sources = [
            TokenSource(f"t{index}", token({"alg": "RS256", "typ": "JWT"}, {"sub": "user"}))
            for index in range(8)
        ]
        BatchAnalyzer(analyzers=(analyzer,), max_workers=4).analyze(sources)
        assert len(set(analyzer.idents)) >= 2

    def test_result_order_survives_uneven_work(self) -> None:
        class SlowFirst(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "slow-first"

            def analyze(self, token: ParsedJWT) -> list[Finding]:
                if token.payload.get("sub") == "first":
                    time.sleep(0.05)
                return []

        sources = [
            TokenSource("first", token({"alg": "RS256"}, {"sub": "first"})),
            TokenSource("second", token({"alg": "HS256"}, {"sub": "second"})),
        ]
        report = BatchAnalyzer(analyzers=(SlowFirst(),), max_workers=2).analyze(sources)
        assert [item.label for item in report.items] == ["first", "second"]
        assert [item.algorithm for item in report.items] == ["RS256", "HS256"]

    def test_progress_bar_text(self) -> None:
        assert format_progress(1, 4, width=4) == "[#---] 1/4"
        assert format_progress(4, 4, width=4) == "[####] 4/4"

    def test_workers_must_be_positive(self) -> None:
        with pytest.raises(BatchError) as caught:
            BatchAnalyzer(max_workers=0)
        assert caught.value.code == "INVALID_WORKERS"


class TestTokenLoading:
    def test_file_with_one_token_per_line(self, tmp_path) -> None:
        first = token({"alg": "RS256", "typ": "JWT"}, secure_payload())
        second = token({"alg": "none", "typ": "JWT"}, secure_payload())
        path = tmp_path / "tokens.txt"
        path.write_text(f"# comment\n\n{first}\nnot a jwt\n{second}\n", encoding="utf-8")
        sources = load_token_source(str(path))
        assert [source.label for source in sources] == ["tokens.txt:3", "tokens.txt:5"]
        report = analyze_batch(sources)
        assert [item.status for item in report.items] == ["secure", "critical"]

    def test_directory_of_token_files(self, tmp_path) -> None:
        folder = tmp_path / "tokens"
        folder.mkdir()
        (folder / "token-001.jwt").write_text(
            token({"alg": "RS256", "typ": "JWT"}, secure_payload()),
            encoding="utf-8",
        )
        (folder / "token-002.jwt").write_text(
            token({"alg": "none", "typ": "JWT"}, secure_payload()),
            encoding="utf-8",
        )
        (folder / ".hidden.jwt").write_text("ignored.token.value", encoding="utf-8")
        sources = load_token_source(str(folder))
        assert [source.label for source in sources] == ["token-001.jwt", "token-002.jwt"]

    def test_missing_path_is_rejected(self, tmp_path) -> None:
        with pytest.raises(BatchError) as caught:
            load_token_source(str(tmp_path / "missing"))
        assert caught.value.code == "NOT_FOUND"

    def test_empty_directory_is_rejected(self, tmp_path) -> None:
        folder = tmp_path / "empty"
        folder.mkdir()
        with pytest.raises(BatchError) as caught:
            load_token_source(str(folder))
        assert caught.value.code == "EMPTY_BATCH"
