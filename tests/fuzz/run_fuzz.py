"""Run the parser fuzzer for a fixed duration.

Example:
    python tests/fuzz/run_fuzz.py --seconds 300
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from tests.fuzz.harness import run_fuzz


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuzz the JWT parser until the time limit.")
    parser.add_argument("--seconds", type=float, default=300, help="How long to mutate inputs")
    parser.add_argument("--seed", type=int, default=20260923)
    args = parser.parse_args()
    count = run_fuzz(args.seconds, seed=args.seed)
    print(f"fuzzed {count} inputs in {args.seconds:g} seconds without a crash")


if __name__ == "__main__":
    main()
