# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Test the 60-second quickstart script to ensure zero external service regressions."""

from __future__ import annotations

import sys
from pathlib import Path


def test_quickstart_execution():
    examples_dir = Path(__file__).resolve().parents[1] / "examples"
    sys.path.insert(0, str(examples_dir))

    try:
        from quickstart import run_quickstart

        success = run_quickstart()
        assert success is True, "Quickstart script must succeed and return True"
    finally:
        if str(examples_dir) in sys.path:
            sys.path.remove(str(examples_dir))
