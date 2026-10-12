#!/usr/bin/env python3
"""Compatibility entry point. Prefer `python -m iphone_forensics.cli` or installed CLI."""

from iphone_forensics.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
