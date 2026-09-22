"""JWT Security Analyzer core package."""

from jwt_analyzer.analyzers import (
    HeaderAnalysisConfig,
    HeaderAnalyzer,
    PayloadAnalysisConfig,
    PayloadAnalyzer,
)
from jwt_analyzer.exceptions import JWTParseError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import JWTMetadata, JWTParser, ParsedJWT, parse_jwt

__all__ = [
    "Confidence",
    "Finding",
    "HeaderAnalysisConfig",
    "HeaderAnalyzer",
    "JWTParseError",
    "JWTMetadata",
    "JWTParser",
    "ParsedJWT",
    "PayloadAnalysisConfig",
    "PayloadAnalyzer",
    "Severity",
    "parse_jwt",
]

__version__ = "0.1.0"
