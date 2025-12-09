"""
Report Generation Module
Generate JSON, HTML, and terminal-friendly reports
"""

import json
import datetime
import os
from typing import List, Dict, Any
from .ui import UI


class Reporter:
    """Report generator for scan results"""

    def __init__(self, ui: UI = None):
        """
        Initialize reporter
        :param ui: UI instance for terminal output
        """
        self.ui = ui or UI()

    def generate_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        output_path: str,
        format: str = "json"
    ) -> None:
        """
        Generate scan report in specified format
        :param vulnerabilities: List of found vulnerabilities
        :param target_url: Scanned target URL
        :param output_path: Report save path (without extension)
        :param format: Report format (json/html)
        """
        # Construct report metadata
        report = {
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "target_url": target_url,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

        # Create output directory if needed
        dir_path = os.path.dirname(output_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        # Generate report based on format
        if format.lower() == "json":
            self._generate_json_report(report, output_path)
        elif format.lower() == "html":
            self._generate_html_report(report, output_path)
        else:
            self.ui.print_error(f"Unsupported report format: {format} (supported: json/html)")

    def _generate_json_report(self, report: Dict[str, Any], output_path: str) -> None:
        """
        Generate JSON format report
        :param report: Report data
        :param output_path: Output file path
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        self.ui.print_success(f"JSON report saved to {output_path}")

    def _generate_html_report(self, report: Dict[str, Any], output_path: str) -> None:
        """
        Generate HTML format report
        :param report: Report data
        :param output_path: Output file path
        """
        vulnerabilities = report["vulnerabilities"]
        
        # Build HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VScanner Report - {report['target_url']}</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 20px;
                    min-height: 100vh;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    font-size: 2.5em;
                    margin-bottom: 10px;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                }}
                .metadata {{
                    background: #f8f9fa;
                    padding: 20px 30px;
                    border-bottom: 3px solid #667eea;
                }}
                .metadata-item {{
                    margin: 10px 0;
                    font-size: 1.1em;
                }}
                .metadata-item strong {{
                    color: #667eea;
                    margin-right: 10px;
                }}
                .content {{
                    padding: 30px;
                }}
                .vuln-card {{
                    background: white;
                    border-left: 5px solid #dc3545;
                    margin: 20px 0;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }}
                .vuln-card:hover {{
                    transform: translateX(5px);
                }}
                .vuln-card h3 {{
                    color: #dc3545;
                    margin-bottom: 15px;
                    font-size: 1.3em;
                }}
                .vuln-detail {{
                    margin: 10px 0;
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                }}
                .vuln-detail:last-child {{
                    border-bottom: none;
                }}
                .vuln-detail strong {{
                    color: #495057;
                    display: inline-block;
                    width: 150px;
                }}
                .no-vulns {{
                    text-align: center;
                    padding: 40px;
                    color: #28a745;
                    font-size: 1.5em;
                }}
                .badge {{
                    display: inline-block;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    font-weight: bold;
                }}
                .badge-danger {{
                    background: #dc3545;
                    color: white;
                }}
                .badge-success {{
                    background: #28a745;
                    color: white;
                }}
                code {{
                    background: #f8f9fa;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    color: #e83e8c;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 VScanner Security Report</h1>
                    <p>Comprehensive Vulnerability Assessment</p>
                </div>
                
                <div class="metadata">
                    <div class="metadata-item">
                        <strong>🎯 Target URL:</strong> {report['target_url']}
                    </div>
                    <div class="metadata-item">
                        <strong>📅 Scan Time:</strong> {report['scan_timestamp']}
                    </div>
                    <div class="metadata-item">
                        <strong>🔢 Vulnerabilities Found:</strong>
                        <span class="badge {'badge-danger' if report['total_vulnerabilities'] > 0 else 'badge-success'}">
                            {report['total_vulnerabilities']}
                        </span>
                    </div>
                </div>
                
                <div class="content">
        """

        # Add vulnerability cards
        if vulnerabilities:
            html_content += "<h2 style='color: #dc3545; margin-bottom: 20px;'>⚠️ Detected Vulnerabilities</h2>"
            for idx, vuln in enumerate(vulnerabilities, 1):
                html_content += f"""
                <div class="vuln-card">
                    <h3>#{idx} - {vuln.get('type', 'Unknown Vulnerability')}</h3>
                    <div class="vuln-detail">
                        <strong>Description:</strong> {vuln.get('description', vuln.get('details', 'N/A'))}
                    </div>
                    <div class="vuln-detail">
                        <strong>URL/Parameter:</strong> <code>{vuln.get('url', 'N/A')}</code>
                        {f" (Parameter: <code>{vuln.get('parameter', 'N/A')}</code>)" if vuln.get('parameter') else ''}
                    </div>
                    <div class="vuln-detail">
                        <strong>Payload/Issue:</strong> <code>{vuln.get('payload', vuln.get('issue', 'N/A'))}</code>
                    </div>
                    <div class="vuln-detail">
                        <strong>Status Code:</strong> {vuln.get('status_code', 'N/A')}
                    </div>
                </div>
                """
        else:
            html_content += """
            <div class="no-vulns">
                ✅ No vulnerabilities detected! Target appears secure.
            </div>
            """

        # Close HTML
        html_content += """
                </div>
            </div>
        </body>
        </html>
        """

        # Save HTML report
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        self.ui.print_success(f"HTML report saved to {output_path}")
