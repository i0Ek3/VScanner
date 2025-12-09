"""
Base Scanner Abstract Class
All vulnerability scanners inherit from this class
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners
    Provides common functionality and enforces interface contract
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize base scanner
        :param timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.vulnerabilities: List[Dict[str, Any]] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner display name (e.g., 'XSS Scanner')"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Scanner description for help text"""
        pass

    @property
    @abstractmethod
    def scan_type(self) -> str:
        """Scanner type identifier (e.g., 'xss', 'sqli')"""
        pass

    @abstractmethod
    def scan(self, target_url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Main scanning method - must be implemented by subclasses
        :param target_url: Target URL to scan
        :param params: Optional URL parameters
        :return: List of found vulnerabilities
        """
        pass

    def extract_params(self, target_url: str) -> Dict[str, str]:
        """
        Extract URL parameters from target URL
        :param target_url: URL to parse
        :return: Dictionary of parameters
        """
        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query)
        # Convert parse_qs output (list values) to single string
        return {k: v[0] for k, v in params.items()} if params else {}

    def get_base_url(self, target_url: str) -> str:
        """
        Get base URL without query parameters
        :param target_url: Full URL
        :return: Base URL
        """
        return target_url.split("?")[0]

    def reset(self):
        """Reset scanner state (clear vulnerabilities)"""
        self.vulnerabilities = []
