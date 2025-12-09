"""
Open Redirect Scanner
Detects unvalidated redirect vulnerabilities
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, urlencode
from core.base_scanner import BaseScanner
from core.config import Config


class RedirectScanner(BaseScanner):
    """Open redirect vulnerability scanner"""

    @property
    def name(self) -> str:
        return "Open Redirect Scanner"

    @property
    def description(self) -> str:
        return "Detects unvalidated redirect vulnerabilities"

    @property
    def scan_type(self) -> str:
        return "redirect"

    def scan(self, target_url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Scan for open redirect vulnerabilities
        :param target_url: Target URL to scan
        :param params: Not used (tests common redirect parameters)
        :return: List of open redirect vulnerabilities
        """
        self.reset()
        
        parsed_base_url = urlparse(target_url)
        base_domain = parsed_base_url.netloc

        # Test common redirect parameters with malicious target
        for param in Config.REDIRECT_PARAMS:
            # Build URL with redirect parameter pointing to malicious domain
            redirect_params = {param: Config.MALICIOUS_REDIRECT_TARGET}
            test_url = f"{self.get_base_url(target_url)}?{urlencode(redirect_params)}"

            try:
                response = requests.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=True  # Follow redirects to check final destination
                )

                # Check if final URL is the malicious target (open redirect confirmed)
                final_redirect_url = response.url
                parsed_final_url = urlparse(final_redirect_url)
                final_domain = parsed_final_url.netloc

                if final_domain == urlparse(Config.MALICIOUS_REDIRECT_TARGET).netloc:
                    vulnerability = {
                        "type": "Open Redirect",
                        "parameter": param,
                        "url": test_url,
                        "redirected_to": final_redirect_url,
                        "status_code": response.status_code,
                        "description": "Unvalidated redirect parameter allows navigation to malicious domain"
                    }
                    self.vulnerabilities.append(vulnerability)

            except requests.exceptions.RequestException:
                continue

        return self.vulnerabilities
