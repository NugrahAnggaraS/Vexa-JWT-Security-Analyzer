"""JWT Security Analyzer core package."""

from jwt_analyzer.analyzers import (
    CryptoAnalysisConfig,
    CryptoAnalyzer,
    HeaderAnalysisConfig,
    HeaderAnalyzer,
    PayloadAnalysisConfig,
    PayloadAnalyzer,
    SignatureStatus,
)
from jwt_analyzer.exceptions import JWTParseError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import JWTMetadata, JWTParser, ParsedJWT, parse_jwt

__all__ = [
    "Confidence",
    "CryptoAnalysisConfig",
    "CryptoAnalyzer",
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
    "SignatureStatus",
    "parse_jwt",
]

__version__ = "0.1.0"
