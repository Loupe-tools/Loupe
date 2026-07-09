#!/usr/bin/env python3
"""CLI wrapper for bundle_metrics.py (opt-in make.py step)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build.bundle_metrics import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())