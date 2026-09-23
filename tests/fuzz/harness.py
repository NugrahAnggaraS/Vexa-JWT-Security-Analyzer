"""Fuzz the JWT parser and the header and claim validators.

Every input is either rejected with ``JWTParseError`` or analyzed. Any other
exception is a crash. Inputs are capped so a case cannot allocate without bound.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

from jwt_analyzer.analyzers.header import HeaderAnalyzer
from jwt_analyzer.analyzers.payload import PayloadAnalyzer
from jwt_analyzer.exceptions import JWTParseError
from jwt_analyzer.parser import decode_base64url, decode_json_object, parse_jwt

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
MAX_INPUT_BYTES = 8_192


def load_corpus(directory: Path = CORPUS_DIR) -> tuple[bytes, ...]:
    """Return every file in the malformed-token corpus."""
    samples = tuple(path.read_bytes() for path in sorted(directory.iterdir()) if path.is_file())
    if not samples:
        raise FileNotFoundError(f"Fuzz corpus is empty: {directory}")
    return samples


def probe(data: bytes) -> None:
    """Feed one input to the decoders, parser, and local analyzers."""
    sample = data[:MAX_INPUT_BYTES]
    text = sample.decode("utf-8", errors="surrogateescape")
    for label in ("header", "payload", "signature"):
        _accept(decode_base64url, text, label)
    _accept(decode_json_object, sample, "payload")
    try:
        parsed = parse_jwt(text)
    except JWTParseError:
        return
    HeaderAnalyzer().analyze(parsed)
    PayloadAnalyzer().analyze(parsed)


def mutate(rng: random.Random, seed: bytes) -> bytes:
    """Return one small mutation of ``seed``."""
    data = bytearray(seed[:MAX_INPUT_BYTES] or b"x")
    choice = rng.randrange(7)
    if choice == 0 and data:
        index = rng.randrange(len(data))
        data[index] ^= 1 << rng.randrange(8)
    elif choice == 1:
        data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
    elif choice == 2 and len(data) > 1:
        del data[rng.randrange(len(data))]
    elif choice == 3:
        data.extend(b"." + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12))))
    elif choice == 4:
        data.extend(data[:24])
    elif choice == 5:
        data[:0] = b"\xff\xfe"
    else:
        data = bytearray(rng.randbytes(rng.randrange(0, 48)))
    return bytes(data[:MAX_INPUT_BYTES])


def run_fuzz(seconds: float, *, seed: int = 20260923) -> int:
    """Mutate the corpus until ``seconds`` have elapsed. Return the case count."""
    if seconds <= 0:
        raise ValueError("seconds must be positive")
    corpus = load_corpus()
    rng = random.Random(seed)
    deadline = time.monotonic() + seconds
    count = 0
    while time.monotonic() < deadline:
        probe(mutate(rng, corpus[rng.randrange(len(corpus))]))
        count += 1
    return count


def _accept(func, *args: object) -> None:
    try:
        func(*args)
    except JWTParseError:
        return
