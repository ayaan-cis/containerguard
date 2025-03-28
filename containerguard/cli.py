"""
Command-line interface for ContainerGuard.
"""
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from containerguard.analyzer.remediation import RemediationGenerator
from containerguard.analyzer.risk import RiskAnalyzer
from containerguard.config import ConfigManager
from containerguard.report.generator import ReportGenerator
from containerguard.scanner.misconfig import MisconfigurationScanner
from containerguard.scanner.vulnerability import VulnerabilityScanner
from containerguard.utils.logger import setup_logging

# Set up the app
app = typer.Typer(
    name="containerguard",
    help="A comprehensive container security scanner",
    add_completion=False,
)

# Create console for rich output
console = Console()

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

# ASCII art logo
LOGO = """
 ____            _        _                  ____                      _ 
/ ___|___  _ __ | |_ __ _(_)_ __   ___ _ __|  _ \ _   _  __ _ _ __ __| |
| |   / _ \| '_ \| __/ _` | | '_ \ / _ \ '__| | | | | | |/ _` | '__/ _` |
| |__| (_) | | | | || (_| | | | | |  __/ |  | |_| | |_| | (_| | | | (_| |
 \____\___/|_| |_|\__\__,_|_|_| |_|\___|_|  |____/ \__,_|\__,_|_|  \__,_|

      (v0.1.0) - A comprehensive container security scanner
"""


def _display_header():
    """Display application header with logo."""
    console.print(Panel.fit(LOGO, border_style="blue"))
    console.print("")


async def _run_scan(
        target: str,
        config: Dict,
        scan_vulnerabilities: bool,
        scan_misconfigurations: bool,
        scan_secrets: bool,
        quiet: bool,
) -> None:
    """
    Run the security scan with the specified options.

    Args:
        target: Container image, Dockerfile, or directory to scan
        config: Scan configuration
        scan_vulnerabilities: Whether to scan for vulnerabilities
        scan_misconfigurations: Whether to scan for misconfigurations
        scan_secrets: Whether to scan for secrets
        quiet: Whether to suppress output
    """
    results = []
    start_time = time.time()

    # Check if target exists
    if not (os.path.exists(target) or ":" in target):  # ":" is used in Docker image names
        raise FileNotFoundError(f"Target not found: {target}")

    # Display scan start information
    if not quiet:
        console.print(f"[bold]Target:[/bold] {target}")
        console.print(f"[bold]Scan started at:[/bold] {time.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print("")

    # Run vulnerability scan
    if scan_vulnerabilities:
        if not quiet:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Running vulnerability scan...[/bold blue]"),
                    TimeElapsedColumn(),
                    console=console,
            ) as progress:
                task = progress.add_task("Scanning", total=None)
                vuln_result = await VulnerabilityScanner(config).scan(target)
                progress.update(task, completed=True)
        else:
            vuln_result = await VulnerabilityScanner(config).scan(target)

        results.append(vuln_result)

        if not quiet:
            _display_vulnerability_summary(vuln_result)

    # Run misconfiguration scan
    if scan_misconfigurations:
        if not quiet:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Running misconfiguration scan...[/bold blue]"),
                    TimeElapsedColumn(),
                    console=console,
            ) as progress:
                task = progress.add_task("Scanning", total=None)
                misconfig_result = await MisconfigurationScanner(config).scan(target)
                progress.update(task, completed=True)
        else:
            misconfig_result = await MisconfigurationScanner(config).scan(target)

        results.append(misconfig_result)

        if not quiet:
            _display_misconfiguration_summary(misconfig_result)

    # Run secrets scan (placeholder)
    if scan_secrets:
        if not quiet:
            console.print("[yellow]Secret scanning is not implemented in this example[/yellow]")

    # Generate comprehensive report
    if not quiet:
        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Generating report...[/bold blue]"),
                TimeElapsedColumn(),
                console=console,
        ) as progress:
            task = progress.add_task("Generating", total=None)
            report_path = ReportGenerator(config).generate_multi_report(results)
            progress.update(task, completed=True)
    else:
        report_path = ReportGenerator(config).generate_multi_report(results)

    # Generate remediation recommendations
    if not quiet:
        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Generating remediation suggestions...[/bold blue]"),
                TimeElapsedColumn(),
                console=console,
        ) as progress:
            task = progress.add_task("Analyzing", total=None)
            # This is a placeholder for actual remediation generation
            remediations = {"placeholder": "Remediation would be generated here"}
            progress.update(task, completed=True)

    # Display scan completion information
    scan_time = time.time() - start_time
    if not quiet:
        console.print("")
        console.print(f"[bold green]Scan completed in {scan_time:.2f} seconds[/bold green]")
        console.print(f"[bold]Report saved to:[/bold] {os.path.abspath(report_path)}")

        # Display overall risk level
        risk_level = _calculate_risk_level(results)
        risk_color = {
            "Critical": "red",
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
            "None": "green",
        }.get(risk_level, "yellow")

        console.print("")
        console.print(f"[bold]Overall Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}]")


def _display_vulnerability_summary(result):
    """Display a summary of vulnerability findings."""
    if result.total_count == 0:
        console.print("[green]No vulnerabilities found[/green]")
        return

    console.print("[bold]Vulnerability Summary:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count")

    table.add_row("Critical", f"[red]{result.critical_count}[/red]")
    table.add_row("High", f"[orange3]{result.high_count}[/orange3]")
    table.add_row("Medium", f"[yellow]{result.medium_count}[/yellow]")
    table.add_row("Low", f"[green]{result.low_count}[/green]")
    table.add_row("Info", f"[blue]{result.info_count}[/blue]")
    table.add_row("Total", str(result.total_count))

    console.print(table)
    console.print("")


def _display_misconfiguration_summary(result):
    """Display a summary of misconfiguration findings."""
    if result.total_count == 0:
        console.print("[green]No misconfigurations found[/green]")
        return

    console.print("[bold]Misconfiguration Summary:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count")

    table.add_row("Critical", f"[red]{result.critical_count}[/red]")
    table.add_row("High", f"[orange3]{result.high_count}[/orange3]")
    table.add_row("Medium", f"[yellow]{result.medium_count}[/yellow]")
    table.add_row("Low", f"[green]{result.low_count}[/green]")
    table.add_row("Info", f"[blue]{result.info_count}[/blue]")
    table.add_row("Total", str(result.total_count))

    console.print(table)
    console.print("")


def _calculate_risk_level(results):
    """Calculate overall risk level based on findings."""
    if any(result.critical_count > 0 for result in results):
        return "Critical"
    elif any(result.high_count > 0 for result in results):
        return "High"
    elif any(result.medium_count > 0 for result in results):
        return "Medium"
    elif any(result.low_count > 0 for result in results):
        return "Low"
    else:
        return "None"


@app.command()
def scan(
        target: str = typer.Argument(..., help="Container image, Dockerfile, or directory to scan"),
        config_file: Optional[Path] = typer.Option(
            None, "--config", "-c", help="Path to configuration file"
        ),
        output_format: str = typer.Option(
            "html", "--format", "-f", help="Report format: html, md, json, pdf"
        ),
        output_dir: Path = typer.Option(
            "reports", "--output", "-o", help="Output directory for reports"
        ),
        scan_vulnerabilities: bool = typer.Option(
            True, "--vuln/--no-vuln", help="Scan for vulnerabilities"
        ),
        scan_misconfigurations: bool = typer.Option(
            True, "--misconfig/--no-misconfig", help="Scan for misconfigurations"
        ),
        scan_secrets: bool = typer.Option(
            False, "--secrets/--no-secrets", help="Scan for secrets (experimental)"
        ),
        severity: str = typer.Option(
            "medium", "--severity", "-s", help="Minimum severity to report (critical, high, medium, low, info)"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all output except errors"),
):
    """
    Scan a container image, Dockerfile, or directory for security issues.
    """
    # Configure logging based on verbosity
    log_level = logging.DEBUG if verbose else logging.INFO
    if quiet:
        log_level = logging.ERROR
    logging.getLogger().setLevel(log_level)

    # Load configuration
    config_manager = ConfigManager()
    if config_file:
        config = config_manager.load_config(config_file)
    else:
        config = config_manager.default_config()

    # Override config with command-line options
    config["output_format"] = output_format
    config["output_dir"] = str(output_dir)
    config["severity_threshold"] = severity

    # Display header
    if not quiet:
        _display_header()

    # Run the scan
    try:
        asyncio.run(_run_scan(
            target=target,
            config=config,
            scan_vulnerabilities=scan_vulnerabilities,
            scan_misconfigurations=scan_misconfigurations,
            scan_secrets=scan_secrets,
            quiet=quiet,
        ))
    except KeyboardInterrupt:
        if not quiet:
            console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        if not quiet:
            console.print(f"\n[bold red]Error during scan: {e}[/bold red]")
        logger.exception("Error during scan")
        sys.exit(1)


@app.command()
def version():
    """Display version information."""
    console.print(LOGO)
    console.print("[bold]ContainerGuard[/bold] version 0.1.0")
    console.print("A comprehensive container security scanner")
    console.print("")
    console.print("Created by Ayaan Syed")
    console.print("Source: https://github.com/ayaan-cis/containerguard")

@app.command()
def dashboard(port: int = 8080):
    """Start the ContainerGuard dashboard server."""
    from containerguard.frontend.server import start_server
    start_server(port=port)

def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()