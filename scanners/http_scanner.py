"""
HTTP Misconfiguration Scanner
Detects missing security headers and insecure HTTP methods
"""

import requests
from typing import List, Dict, Any
from core.base_scanner import BaseScanner
from core.config import Config


class HTTPScanner(BaseScanner):
    """HTTP misconfiguration scanner"""

    @property
    def name(self) -> str:
        return "HTTP Misconfig Scanner"

    @property
    def description(self) -> str:
        return "Detects missing security headers and insecure HTTP methods"

    @property
    def scan_type(self) -> str:
        return "http"

    def scan(self, target_url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Scan for HTTP misconfigurations
        :param target_url: Target URL to scan
        :param params: Not used for HTTP scanner
        :return: List of HTTP misconfigurations
        """
        self.reset()

        try:
            # 1. Check for missing security headers
            response = requests.get(target_url, timeout=self.timeout, allow_redirects=True)
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            for header in Config.REQUIRED_SECURITY_HEADERS:
                if header.lower() not in response_headers:
                    vulnerability = {
                        "type": "HTTP Misconfiguration",
                        "issue": "Missing Security Header",
                        "details": f"Header '{header}' is missing (critical for security hardening)",
                        "url": target_url,
                        "status_code": response.status_code
                    }
                    self.vulnerabilities.append(vulnerability)

            # 2. Check for insecure HTTP methods (TRACE/TRACK)
            try:
                options_response = requests.options(target_url, timeout=self.timeout)
                allowed_methods = options_response.headers.get("Allow", "").split(", ")

                for method in Config.FORBIDDEN_HTTP_METHODS:
                    if method in allowed_methods:
                        vulnerability = {
                            "type": "HTTP Misconfiguration",
                            "issue": "Insecure HTTP Method Enabled",
                            "details": f"Method '{method}' is allowed (can be used for cross-site tracing attacks)",
                            "url": target_url,
                            "status_code": options_response.status_code
                        }
                        self.vulnerabilities.append(vulnerability)
            except requests.exceptions.RequestException:
                pass

        except requests.exceptions.RequestException:
            pass

        return self.vulnerabilities
