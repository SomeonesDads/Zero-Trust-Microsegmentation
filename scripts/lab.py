#!/usr/bin/env python3
"""Run with --help for Host 1 and Host 2 preparation and acceptance commands."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lab.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
