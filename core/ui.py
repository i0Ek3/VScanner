"""
Geek-Style Terminal UI Components
ASCII art, progress bars, color-coded output, and live panels
"""

import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box
import pyfiglet
from colorama import init as colorama_init, Fore, Style

# Initialize colorama for cross-platform color support (Windows compatibility)
colorama_init(autoreset=True)


class UI:
    """Geek-style terminal UI manager"""

    def __init__(self):
        """Initialize UI components"""
        self.console = Console()
        self.progress: Optional[Progress] = None

    def show_banner(self, version: str = "2.0.0"):
        """
        Display ASCII art banner with tool info
        :param version: Tool version number
        """
        # Generate ASCII art using pyfiglet
        ascii_art = pyfiglet.figlet_format("VScanner", font="slant")
        
        # Create styled banner
        banner_text = Text()
        banner_text.append(ascii_art, style="bold cyan")
        banner_text.append(f"\n  Vulnerability Scanner v{version}\n", style="bold white")
        banner_text.append("  Cross-Platform Security Testing Tool\n", style="dim white")
        banner_text.append("  Supports: XSS | SQLi | HTTP Misconfig | Open Redirect\n", style="yellow")
        
        # Display in panel
        panel = Panel(
            banner_text,
            box=box.DOUBLE,
            border_style="cyan",
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()

    def print_info(self, message: str):
        """Print info message (cyan)"""
        self.console.print(f"[cyan][INFO][/cyan] {message}")

    def print_success(self, message: str):
        """Print success message (green)"""
        self.console.print(f"[green][SUCCESS][/green] {message}")

    def print_warning(self, message: str):
        """Print warning message (yellow)"""
        self.console.print(f"[yellow][WARNING][/yellow] {message}")

    def print_error(self, message: str):
        """Print error message (red)"""
        self.console.print(f"[red][ERROR][/red] {message}")

    def print_vulnerability(self, vuln_type: str, details: str):
        """Print vulnerability found (red, bold)"""
        self.console.print(f"[bold red][VULN FOUND][/bold red] {vuln_type}: {details}")

    def create_progress_bar(self) -> Progress:
        """
        Create animated progress bar for scanning
        :return: Progress object
        """
        self.progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        )
        return self.progress

    def show_scan_summary(self, target_url: str, scan_types: list, total_vulns: int):
        """
        Display scan summary in a panel
        :param target_url: Scanned URL
        :param scan_types: List of scan types performed
        :param total_vulns: Total vulnerabilities found
        """
        # Create summary table
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column("Key", style="bold cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Target URL", target_url)
        table.add_row("Scan Types", ", ".join(scan_types))
        table.add_row("Vulnerabilities Found", 
                     f"[bold red]{total_vulns}[/bold red]" if total_vulns > 0 else "[green]0[/green]")
        
        # Display in panel
        panel = Panel(
            table,
            title="[bold white]Scan Summary[/bold white]",
            border_style="cyan" if total_vulns == 0 else "red",
            box=box.ROUNDED
        )
        self.console.print()
        self.console.print(panel)

    def show_vulnerability_table(self, vulnerabilities: list):
        """
        Display vulnerabilities in a formatted table
        :param vulnerabilities: List of vulnerability dictionaries
        """
        if not vulnerabilities:
            return

        table = Table(
            title="[bold red]Detected Vulnerabilities[/bold red]",
            box=box.ROUNDED,
            show_lines=True,
            border_style="red"
        )
        
        table.add_column("Type", style="bold yellow", no_wrap=True)
        table.add_column("Parameter", style="cyan")
        table.add_column("Payload/Issue", style="magenta")
        table.add_column("Status", style="white")
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            param = vuln.get("parameter", vuln.get("issue", "N/A"))
            payload = vuln.get("payload", vuln.get("details", "N/A"))
            status = str(vuln.get("status_code", "N/A"))
            
            # Truncate long payloads
            if len(payload) > 50:
                payload = payload[:47] + "..."
            
            table.add_row(vuln_type, param, payload, status)
        
        self.console.print()
        self.console.print(table)

    def show_divider(self, char: str = "─", style: str = "dim white"):
        """
        Show horizontal divider
        :param char: Character to use for divider
        :param style: Rich style string
        """
        width = self.console.width
        self.console.print(char * width, style=style)

    def prompt_confirmation(self, message: str) -> bool:
        """
        Prompt user for yes/no confirmation
        :param message: Confirmation message
        :return: True if confirmed, False otherwise
        """
        response = self.console.input(f"[yellow]{message} (y/n):[/yellow] ").strip().lower()
        return response in ["y", "yes"]
