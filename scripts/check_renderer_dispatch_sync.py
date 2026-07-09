#!/usr/bin/env python3
"""CLI wrapper for the dispatch manifest sync gate.

Validates that ``scripts/dispatch-manifest.toml`` matches:
  • ``RendererRegistry.ENTRIES`` ids in ``src/renderer-registry.js``
  • ``App._rendererDispatch`` keys in ``src/app/app-load.js``
  • ``MAX_FILE_BYTES_BY_DISPATCH`` rows in ``src/constants.js``
  • ``APP_JS_FILES`` membership for each manifest module

Run via ``python make.py dispatch-sync`` or directly:
    python scripts/check_renderer_dispatch_sync.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.dispatch_sync import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())