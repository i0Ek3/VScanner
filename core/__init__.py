"""
VScanner Core Framework
Cross-platform vulnerability scanner with geek-style CLI interface
"""

__version__ = "2.0.0"
__author__ = "i0Ek3"

from .base_scanner import BaseScanner
from .config import Config
from .ui import UI
from .reporter import Reporter

__all__ = ["BaseScanner", "Config", "UI", "Reporter"]
