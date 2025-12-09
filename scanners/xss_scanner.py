"""
XSS (Cross-Site Scripting) Scanner
Detects reflected XSS vulnerabilities
"""

import requests
from typing import List, Dict, Any
from core.base_scanner import BaseScanner
from core.config import Config


class XSSScanner(BaseScanner):
    """XSS vulnerability scanner"""

    @property
    def name(self) -> str:
        return "XSS Scanner"

    @property
    def description(self) -> str:
        return "Detects reflected Cross-Site Scripting (XSS) vulnerabilities"

    @property
    def scan_type(self) -> str:
        return "xss"

    def scan(self, target_url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Scan for reflected XSS vulnerabilities
        :param target_url: Target URL to scan
        :param params: URL parameters (if any) to inject payloads into
        :return: List of found XSS vulnerabilities
        """
        self.reset()
        
        # Extract params from URL if not provided
        if not params:
            params = self.extract_params(target_url)

        # If no params exist (static URL), skip (XSS requires user-controlled input)
        if not params:
            return self.vulnerabilities

        # Test each XSS payload against every parameter
        for payload in Config.XSS_PAYLOADS:
            for param in params:
                # Create modified params with payload injected
                modified_params = params.copy()
                modified_params[param] = payload

                try:
                    # Send GET request with injected payload
                    response = requests.get(
                        self.get_base_url(target_url),
                        params=modified_params,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    # Check if payload is reflected UNESCAPED in response
                    if payload in response.text:
                        vulnerability = {
                            "type": "XSS (Reflected)",
                            "payload": payload,
                            "parameter": param,
                            "url": response.url,
                            "status_code": response.status_code,
                            "description": "Unescaped XSS payload reflected in response"
                        }
                        self.vulnerabilities.append(vulnerability)

                except requests.exceptions.RequestException:
                    # Silently continue on request errors
                    continue

        return self.vulnerabilities
