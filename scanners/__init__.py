"""
Scanner Module Package
Auto-discovery and registration of all vulnerability scanners
"""

from typing import List, Type
from core.base_scanner import BaseScanner

# Import all scanner implementations
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLiScanner
from .http_scanner import HTTPScanner
from .redirect_scanner import RedirectScanner

# Scanner registry for auto-discovery
AVAILABLE_SCANNERS: List[Type[BaseScanner]] = [
    XSSScanner,
    SQLiScanner,
    HTTPScanner,
    RedirectScanner,
]


def get_scanner_by_type(scan_type: str) -> Type[BaseScanner]:
    """
    Get scanner class by type identifier
    :param scan_type: Scanner type (e.g., 'xss', 'sqli', 'all')
    :return: Scanner class or None
    """
    for scanner_class in AVAILABLE_SCANNERS:
        scanner_instance = scanner_class()
        if scanner_instance.scan_type == scan_type:
            return scanner_class
    return None


def get_all_scanners() -> List[Type[BaseScanner]]:
    """
    Get all available scanner classes
    :return: List of scanner classes
    """
    return AVAILABLE_SCANNERS


__all__ = [
    "XSSScanner",
    "SQLiScanner",
    "HTTPScanner",
    "RedirectScanner",
    "AVAILABLE_SCANNERS",
    "get_scanner_by_type",
    "get_all_scanners",
]
