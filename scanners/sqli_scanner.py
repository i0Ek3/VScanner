"""
SQL Injection Scanner
Detects error-based and boolean-based SQL injection vulnerabilities
"""

import requests
from typing import List, Dict, Any
from core.base_scanner import BaseScanner
from core.config import Config


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner"""

    @property
    def name(self) -> str:
        return "SQLi Scanner"

    @property
    def description(self) -> str:
        return "Detects SQL Injection vulnerabilities (error-based and boolean-based)"

    @property
    def scan_type(self) -> str:
        return "sqli"

    def scan(self, target_url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Scan for SQL injection vulnerabilities
        :param target_url: Target URL to scan
        :param params: URL parameters to inject payloads into
        :return: List of found SQLi vulnerabilities
        """
        self.reset()
        
        # Extract params from URL if not provided
        if not params:
            params = self.extract_params(target_url)

        if not params:
            return self.vulnerabilities

        # Test each SQLi payload against every parameter
        for payload in Config.SQLI_PAYLOADS:
            for param in params:
                modified_params = params.copy()
                modified_params[param] = payload

                try:
                    response = requests.get(
                        self.get_base_url(target_url),
                        params=modified_params,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    # Check for SQL errors in response (error-based SQLi)
                    for error_pattern in Config.SQL_ERROR_PATTERNS:
                        if error_pattern in response.text:
                            vulnerability = {
                                "type": "SQL Injection (Error-Based)",
                                "payload": payload,
                                "parameter": param,
                                "url": response.url,
                                "status_code": response.status_code,
                                "description": f"SQL error detected: {error_pattern}"
                            }
                            self.vulnerabilities.append(vulnerability)
                            break  # Avoid duplicate entries for same payload/param

                    # Check for boolean-based SQLi (response length change)
                    try:
                        original_response = requests.get(
                            self.get_base_url(target_url),
                            params={param: params[param]},
                            timeout=self.timeout
                        )
                        length_diff = abs(len(response.text) - len(original_response.text))
                        
                        if length_diff > Config.RESPONSE_LENGTH_THRESHOLD:
                            vulnerability = {
                                "type": "SQL Injection (Boolean-Based)",
                                "payload": payload,
                                "parameter": param,
                                "url": response.url,
                                "status_code": response.status_code,
                                "description": f"Significant response length change ({length_diff} bytes)"
                            }
                            self.vulnerabilities.append(vulnerability)
                    except requests.exceptions.RequestException:
                        pass

                except requests.exceptions.RequestException:
                    continue

        return self.vulnerabilities
