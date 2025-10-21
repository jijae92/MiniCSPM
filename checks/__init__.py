"""Check modules and control registry exports."""

from __future__ import annotations

import importlib
from typing import Dict

from .registry import CONTROL_REGISTRY, MODULE_NAMES

__all__ = ["CONTROL_REGISTRY"]

for module_name in MODULE_NAMES:
    module = importlib.import_module(module_name)
    short_name = module_name.rsplit(".", 1)[-1]
    globals()[short_name] = module
    __all__.append(short_name)
