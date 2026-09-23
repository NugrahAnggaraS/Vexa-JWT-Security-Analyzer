"""Application entry point for the JWT Security Analyzer CLI."""

from __future__ import annotations

from jwt_analyzer.cli import main

__all__ = ["main"]


if __name__ == "__main__":
    main()
