"""Compatibility wrapper so `python -m minicspm.cli` maps to the project CLI."""

from __future__ import annotations

from cli.main import main

__all__ = ["main"]
