"""Corpus and mutation tests for the JWT parser and decoders."""

from __future__ import annotations

import random

from jwt_analyzer.exceptions import JWTParseError
from tests.fuzz.harness import CORPUS_DIR, load_corpus, mutate, probe

REQUIRED = {
    "empty.txt",
    "one-segment.txt",
    "two-segments.txt",
    "jwe-five-segments.txt",
    "bad-base64.txt",
    "invalid-json-header.txt",
    "header-array.txt",
    "payload-string.txt",
    "payload-not-utf8.txt",
    "bad-padding.txt",
    "valid-jwt.txt",
    "duplicate-claim.txt",
}


def test_corpus_contains_malformed_shapes() -> None:
    names = {path.name for path in CORPUS_DIR.iterdir() if path.is_file()}
    assert REQUIRED <= names


def test_corpus_does_not_crash() -> None:
    for sample in load_corpus():
        probe(sample)


def test_mutations_do_not_crash() -> None:
    corpus = load_corpus()
    rng = random.Random(20260923)
    for _ in range(800):
        probe(mutate(rng, corpus[rng.randrange(len(corpus))]))


def test_direct_decoder_rejects_a_corrupt_segment() -> None:
    try:
        probe(b"****")
    except JWTParseError:
        raise AssertionError("probe must contain parse errors") from None
