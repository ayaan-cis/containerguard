#!/usr/bin/env python3
"""
Basic scanning example for ContainerGuard.
This example shows how to use ContainerGuard to scan a Docker image for security issues.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from containerguard.analyzer.remediation import RemediationGenerator
from containerguard.analyzer.risk import RiskAnalyzer
from containerguard.report.generator import ReportGenerator
from containerguard.scanner.misconfiguration import MisconfigurationScanner
from containerguard.scanner.vulnerability import VulnerabilityScanner
from containerguard.utils.logger import setup_logging

# Configure logging
setup_logging(log_file="containerguard.log")


async def scan_image(image_name, output_dir="reports"):
    """
    Scan a Docker image for security issues.

    Args:
        image_name: Name of the Docker image to scan
        output_dir: Directory to save reports
    """
    print(f"Scanning image: {image_name}")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Configure scanners
    config = {
        "severity_threshold": "low",
        "output_dir": output_dir,
        "output_format": "html",
    }

    # Run vulnerability scan
    print("Running vulnerability scan...")
    try:
        vuln_scanner = VulnerabilityScanner(config)
        vuln_result = await vuln_scanner.scan(image_name)
        print(f"Found {vuln_result.total_count} vulnerabilities")
        print(f"- Critical: {vuln_result.critical_count}")
        print(f"- High: {vuln_result.high_count}")
        print(f"- Medium: {vuln_result.medium_count}")
        print(f"- Low: {vuln_result.low_count}")
        print(f"- Info: {vuln_result.info_count}")
    except Exception as e:
        print(f"Error during vulnerability scan: {e}")
        vuln_result = None

    # Run misconfiguration scan
    print("\nRunning misconfiguration scan...")
    try:
        misconfig_scanner = MisconfigurationScanner(config)
        misconfig_result = await misconfig_scanner.scan(image_name)
        print(f"Found {misconfig_result.total_count} misconfigurations")
        print(f"- Critical: {misconfig_result.critical_count}")
        print(f"- High: {misconfig_result.high_count}")
        print(f"- Medium: {misconfig_result.medium_count}")
        print(f"- Low: {misconfig_result.low_count}")
        print(f"- Info: {misconfig_result.info_count}")
    except Exception as e:
        print(f"Error during misconfiguration scan: {e}")
        misconfig_result = None

    # Combine results
    results = []
    if vuln_result:
        results.append(vuln_result)
    if misconfig_result:
        results.append(misconfig_result)

    if not results:
        print("No scan results available")
        return

    # Analyze risks
    print("\nAnalyzing security risks...")
    risk_analyzer = RiskAnalyzer()
    all_findings = []
    for result in results:
        all_findings.extend(result.findings)

    risk_analysis = risk_analyzer.analyze_findings(all_findings)

    # Print top 5 risks
    if risk_analysis:
        print("\nTop 5 Security Risks:")
        for i, risk in enumerate(risk_analysis[:5], 1):
            print(f"{i}. [{risk['risk_label'].upper()}] {risk['title']} (Score: {risk['risk_score']})")

    # Generate remediation recommendations
    print("\nGenerating remediation recommendations...")
    remediation_generator = RemediationGenerator()
    remediations = remediation_generator.generate_remediations(all_findings)

    # Generate report
    print("\nGenerating security report...")
    report_config = {
        "title": f"Security Scan Report - {image_name}",
        "output_format": "html",
        "output_dir": output_dir,
        "include_charts": True,
    }

    report_generator = ReportGenerator(report_config)
    report_path = report_generator.generate_multi_report(results)

    print(f"\nReport saved to: {os.path.abspath(report_path)}")

    # Save risk analysis and remediations as JSON
    analysis_path = os.path.join(output_dir, f"{image_name.replace(':', '_')}_analysis.json")
    with open(analysis_path, "w") as f:
        json.dump({
            "risks": risk_analysis,
            "remediations": remediations,
        }, f, indent=2)

    print(f"Risk analysis saved to: {os.path.abspath(analysis_path)}")


async def main():
    """Main function."""
    # Get image name from command line
    if len(sys.argv) > 1:
        image_name = sys.argv[1]
    else:
        # Default to a public image for demonstration
        image_name = "python:latest"

    await scan_image(image_name)


if __name__ == "__main__":
    asyncio.run(main())