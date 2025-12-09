#!/usr/bin/env python3
"""
VScanner - Geek-Style Vulnerability Scanner
Cross-platform security testing tool with modular architecture

Supports: XSS | SQLi | HTTP Misconfig | Open Redirect
Platform: macOS | Linux | Windows
"""

import sys
import argparse
import datetime
from urllib.parse import urlparse
from typing import List

# Core framework imports
from core import UI, Reporter, Config
from core.base_scanner import BaseScanner

# Scanner imports
from scanners import get_all_scanners, get_scanner_by_type


def parse_arguments():
    """
    Parse CLI arguments
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="VScanner - Geek-Style Vulnerability Scanner",
        epilog="Example: python main.py -u https://example.com?param=1 -s all -f json",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to scan (e.g., https://example.com?param=1)"
    )

    # Optional arguments
    parser.add_argument(
        "-s", "--scan-type",
        choices=["xss", "sqli", "http", "redirect", "all"],
        default="all",
        help="Type of scan to perform (default: all)"
    )

    parser.add_argument(
        "-o", "--output",
        default=f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output file path (without extension, default: scan_report_TIMESTAMP)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["json", "html"],
        default="json",
        help="Report format (default: json)"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=Config.DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {Config.DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable ASCII banner display"
    )

    return parser.parse_args()


def validate_url(url: str) -> bool:
    """
    Validate target URL format
    :param url: URL to validate
    :return: True if valid, False otherwise
    """
    parsed_url = urlparse(url)
    return bool(parsed_url.scheme and parsed_url.netloc)


def get_scanners_to_run(scan_type: str, timeout: int) -> List[BaseScanner]:
    """
    Get list of scanner instances to run based on scan type
    :param scan_type: Scan type ('xss', 'sqli', 'http', 'redirect', 'all')
    :param timeout: HTTP timeout setting
    :return: List of scanner instances
    """
    if scan_type == "all":
        # Run all available scanners
        return [scanner_class(timeout=timeout) for scanner_class in get_all_scanners()]
    else:
        # Run specific scanner
        scanner_class = get_scanner_by_type(scan_type)
        if scanner_class:
            return [scanner_class(timeout=timeout)]
        return []


def main():
    """Main execution function"""
    
    # Parse arguments
    args = parse_arguments()
    
    # Initialize UI
    ui = UI()
    
    # Show banner (unless disabled)
    if not args.no_banner:
        ui.show_banner(version="2.0.0")
    
    # Validate URL
    if not validate_url(args.url):
        ui.print_error("Invalid URL format (must include http/https and domain)")
        ui.print_info("Example: https://example.com or http://testsite.com?param=value")
        sys.exit(1)
    
    # Display scan configuration
    ui.print_info(f"Target: {args.url}")
    ui.print_info(f"Scan Type: {args.scan_type}")
    ui.print_info(f"Timeout: {args.timeout}s")
    ui.show_divider()
    
    # Get scanners to run
    scanners = get_scanners_to_run(args.scan_type, args.timeout)
    
    if not scanners:
        ui.print_error(f"No scanner found for type: {args.scan_type}")
        sys.exit(1)
    
    # Initialize results
    all_vulnerabilities = []
    scan_types_performed = []
    
    # Create progress bar
    progress = ui.create_progress_bar()
    
    with progress:
        # Create main progress task
        total_scanners = len(scanners)
        main_task = progress.add_task(
            f"[cyan]Scanning with {total_scanners} scanner(s)...",
            total=total_scanners
        )
        
        # Run each scanner
        for scanner in scanners:
            # Update progress description
            progress.update(main_task, description=f"[cyan]Running {scanner.name}...")
            
            # Run scan
            try:
                vulnerabilities = scanner.scan(args.url)
                all_vulnerabilities.extend(vulnerabilities)
                scan_types_performed.append(scanner.name)
                
                # Show results for this scanner
                if vulnerabilities:
                    ui.print_vulnerability(
                        scanner.name,
                        f"Found {len(vulnerabilities)} issue(s)"
                    )
                else:
                    ui.print_success(f"{scanner.name}: No vulnerabilities detected")
                    
            except Exception as e:
                ui.print_error(f"{scanner.name} failed: {str(e)}")
            
            # Update progress
            progress.advance(main_task)
    
    ui.show_divider()
    
    # Display vulnerability table if any found
    if all_vulnerabilities:
        ui.show_vulnerability_table(all_vulnerabilities)
    
    # Show scan summary
    ui.show_scan_summary(
        target_url=args.url,
        scan_types=scan_types_performed,
        total_vulns=len(all_vulnerabilities)
    )
    
    # Generate report
    reporter = Reporter(ui)
    output_path_with_ext = f"{args.output}.{args.format}"
    
    ui.print_info(f"Generating {args.format.upper()} report...")
    reporter.generate_report(
        vulnerabilities=all_vulnerabilities,
        target_url=args.url,
        output_path=output_path_with_ext,
        format=args.format
    )
    
    # Final summary
    ui.show_divider()
    if all_vulnerabilities:
        ui.print_warning(f"Scan completed! {len(all_vulnerabilities)} vulnerabilities detected")
        ui.print_info("Review the report for detailed information")
    else:
        ui.print_success("Scan completed! No vulnerabilities detected")
    
    # Exit with appropriate code
    sys.exit(1 if all_vulnerabilities else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ui = UI()
        ui.print_warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        ui = UI()
        ui.print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)
