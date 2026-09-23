"""JWT Security Analyzer core package."""

from jwt_analyzer.analyzers import (
    CryptoAnalysisConfig,
    CryptoAnalyzer,
    HeaderAnalysisConfig,
    HeaderAnalyzer,
    JwksAnalysisConfig,
    JwksAnalyzer,
    OidcAnalysisConfig,
    OidcTokenAnalyzer,
    PayloadAnalysisConfig,
    PayloadAnalyzer,
    SignatureStatus,
    TokenRole,
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
    "JwksAnalysisConfig",
    "JwksAnalyzer",
    "JWTParseError",
    "JWTMetadata",
    "JWTParser",
    "OidcAnalysisConfig",
    "OidcTokenAnalyzer",
    "ParsedJWT",
    "PayloadAnalysisConfig",
    "PayloadAnalyzer",
    "Severity",
    "TokenRole",
    "SignatureStatus",
    "parse_jwt",
]

__version__ = "0.1.0"
