"""Pytest configuration and shared fixtures."""

import sys
from pathlib import Path

# Ensure src is on path so "securegate" package is found
root = Path(__file__).resolve().parent.parent
src = root / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))
