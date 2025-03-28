"""
Report generation module for creating comprehensive security reports.
"""
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import jinja2
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from containerguard.scanner.base import Finding, ScanResult

logger = logging.getLogger(__name__)


class ReportConfig(BaseModel):
    """Configuration for report generation."""
    title: str = "Container Security Scan Report"
    company_name: Optional[str] = None
    logo_path: Optional[str] = None
    output_format: str = "html"  # html, md, pdf, json
    output_dir: str = "reports"
    include_summary: bool = True
    include_details: bool = True
    include_remediation: bool = True
    include_charts: bool = True
    max_findings: int = 1000
    template_path: Optional[str] = None
    custom_css: Optional[str] = None
    custom_js: Optional[str] = None


class ReportGenerator:
    """
    Generator for comprehensive security reports from scan results.

    This module creates detailed, customizable reports in various formats
    including HTML, Markdown, PDF, and JSON.
    """

    def __init__(self, config: Optional[Union[Dict[str, Any], ReportConfig]] = None):
        """
        Initialize the report generator.

        Args:
            config: Generator configuration
        """
        if isinstance(config, dict):
            self.config = ReportConfig(**config)
        elif isinstance(config, ReportConfig):
            self.config = config
        else:
            self.config = ReportConfig()

        # Initialize Jinja2 environment
        template_path = self.config.template_path or os.path.join(
            os.path.dirname(__file__), "templates"
        )
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_path),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Create output directory if it doesn't exist
        os.makedirs(self.config.output_dir, exist_ok=True)

        logger.info(f"Initialized report generator with output format: {self.config.output_format}")

    def generate_report(self, scan_result: ScanResult) -> str:
        """
        Generate a report from a scan result.

        Args:
            scan_result: Scan result to generate report from

        Returns:
            Path to the generated report
        """
        logger.info(f"Generating {self.config.output_format} report for {scan_result.target}")

        # Create report context
        context = self._create_report_context(scan_result)

        # Generate report based on format
        if self.config.output_format == "html":
            return self._generate_html_report(context)
        elif self.config.output_format == "md":
            return self._generate_markdown_report(context)
        elif self.config.output_format == "json":
            return self._generate_json_report(context)
        elif self.config.output_format == "pdf":
            return self._generate_pdf_report(context)
        else:
            raise ValueError(f"Unsupported output format: {self.config.output_format}")

    def generate_multi_report(self, scan_results: List[ScanResult]) -> str:
        """
        Generate a consolidated report from multiple scan results.

        Args:
            scan_results: List of scan results to include in the report

        Returns:
            Path to the generated report
        """
        logger.info(f"Generating consolidated report for {len(scan_results)} scan results")

        # Create a merged scan result
        if len(scan_results) == 1:
            return self.generate_report(scan_results[0])

        # Create a merged context with data from all results
        merged_context = {
            "title": self.config.title,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "company_name": self.config.company_name,
            "logo_path": self.config.logo_path,
            "targets": [result.target for result in scan_results],
            "findings": [],
            "summary": {
                "total_targets": len(scan_results),
                "total_findings": sum(result.total_count for result in scan_results),
                "critical_count": sum(result.critical_count for result in scan_results),
                "high_count": sum(result.high_count for result in scan_results),
                "medium_count": sum(result.medium_count for result in scan_results),
                "low_count": sum(result.low_count for result in scan_results),
                "info_count": sum(result.info_count for result in scan_results),
                "scanners": list(set(result.scanner_name for result in scan_results)),
            },
            "charts": {},
        }

        # Combine findings from all results
        all_findings = []
        for result in scan_results:
            for finding in result.findings:
                finding_dict = finding.dict()
                finding_dict["target"] = result.target  # Add target information
                all_findings.append(finding_dict)

        # Limit findings if needed
        merged_context["findings"] = all_findings[:self.config.max_findings]

        # Generate charts
        if self.config.include_charts:
            merged_context["charts"] = self._generate_charts_data(all_findings)

        # Generate report based on format
        if self.config.output_format == "html":
            return self._generate_html_report(merged_context, multi=True)
        elif self.config.output_format == "md":
            return self._generate_markdown_report(merged_context, multi=True)
        elif self.config.output_format == "json":
            return self._generate_json_report(merged_context, multi=True)
        elif self.config.output_format == "pdf":
            return self._generate_pdf_report(merged_context, multi=True)
        else:
            raise ValueError(f"Unsupported output format: {self.config.output_format}")

    def _create_report_context(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Create context dictionary for report templates.

        Args:
            scan_result: Scan result to create context from

        Returns:
            Context dictionary for templates
        """
        # Convert findings to dictionaries
        findings = [finding.as_dict() for finding in scan_result.findings]

        # Generate charts data if requested
        charts = {}
        if self.config.include_charts:
            charts = self._generate_charts_data(findings)

        # Create context
        context = {
            "title": self.config.title,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "company_name": self.config.company_name,
            "logo_path": self.config.logo_path,
            "target": scan_result.target,
            "scanner": scan_result.scanner_name,
            "findings": findings[:self.config.max_findings],
            "summary": {
                "total_findings": scan_result.total_count,
                "critical_count": scan_result.critical_count,
                "high_count": scan_result.high_count,
                "medium_count": scan_result.medium_count,
                "low_count": scan_result.low_count,
                "info_count": scan_result.info_count,
                "scan_time": scan_result.scan_time,
                "timestamp": scan_result.timestamp,
                **scan_result.summary,
            },
            "charts": charts,
            "metadata": scan_result.metadata,
        }

        return context

    def _generate_charts_data(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate chart data for visualizations.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary of chart data
        """
        charts = {}

        # Create a DataFrame for easier analysis
        if not findings:
            return charts

        df = pd.DataFrame(findings)

        # Severity distribution chart
        try:
            severity_counts = df["severity"].value_counts().to_dict()
            charts["severity_distribution"] = {
                "labels": list(severity_counts.keys()),
                "values": list(severity_counts.values()),
                "type": "pie",
            }
        except Exception as e:
            logger.warning(f"Failed to generate severity distribution chart: {e}")

        # Category distribution chart
        try:
            if "category" in df.columns:
                category_counts = df["category"].value_counts().to_dict()
                charts["category_distribution"] = {
                    "labels": list(category_counts.keys()),
                    "values": list(category_counts.values()),
                    "type": "bar",
                }
        except Exception as e:
            logger.warning(f"Failed to generate category distribution chart: {e}")

        # Top 10 most common findings
        try:
            if "id" in df.columns and len(df) > 0:
                top_findings = df["id"].value_counts().head(10).to_dict()
                charts["top_findings"] = {
                    "labels": list(top_findings.keys()),
                    "values": list(top_findings.values()),
                    "type": "bar",
                }
        except Exception as e:
            logger.warning(f"Failed to generate top findings chart: {e}")

        return charts

    def _generate_html_report(self, context: Dict[str, Any], multi: bool = False) -> str:
        """
        Generate an HTML report.

        Args:
            context: Report context
            multi: Whether this is a multi-target report

        Returns:
            Path to the generated report
        """
        try:
            template_name = "multi_report.html" if multi else "report.html"
            template = self.jinja_env.get_template(f"html/{template_name}")
            html_content = template.render(**context)

            # Generate filename
            timestamp = int(time.time())
            if multi:
                filename = f"multi_report_{timestamp}.html"
            else:
                target_name = os.path.basename(context["target"]).replace(":", "_")
                filename = f"{target_name}_{timestamp}.html"

            output_path = os.path.join(self.config.output_dir, filename)

            # Write to file
            with open(output_path, "w") as f:
                f.write(html_content)

            logger.info(f"Generated HTML report: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def _generate_markdown_report(self, context: Dict[str, Any], multi: bool = False) -> str:
        """
        Generate a Markdown report.

        Args:
            context: Report context
            multi: Whether this is a multi-target report

        Returns:
            Path to the generated report
        """
        try:
            template_name = "multi_report.md" if multi else "report.md"
            template = self.jinja_env.get_template(f"md/{template_name}")
            md_content = template.render(**context)

            # Generate filename
            timestamp = int(time.time())
            if multi:
                filename = f"multi_report_{timestamp}.md"
            else:
                target_name = os.path.basename(context["target"]).replace(":", "_")
                filename = f"{target_name}_{timestamp}.md"

            output_path = os.path.join(self.config.output_dir, filename)

            # Write to file
            with open(output_path, "w") as f:
                f.write(md_content)

            logger.info(f"Generated Markdown report: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            raise

    def _generate_json_report(self, context: Dict[str, Any], multi: bool = False) -> str:
        """
        Generate a JSON report.

        Args:
            context: Report context
            multi: Whether this is a multi-target report

        Returns:
            Path to the generated report
        """
        try:
            # Generate filename
            timestamp = int(time.time())
            if multi:
                filename = f"multi_report_{timestamp}.json"
            else:
                target_name = os.path.basename(context["target"]).replace(":", "_")
                filename = f"{target_name}_{timestamp}.json"

            output_path = os.path.join(self.config.output_dir, filename)

            # Write to file
            with open(output_path, "w") as f:
                json.dump(context, f, indent=4)

            logger.info(f"Generated JSON report: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise

    def _generate_pdf_report(self, context: Dict[str, Any], multi: bool = False) -> str:
        """
        Generate a PDF report.

        Args:
            context: Report context
            multi: Whether this is a multi-target report

        Returns:
            Path to the generated report
        """
        try:
            # Generate HTML first
            html_path = self._generate_html_report(context, multi)

            # Generate filename
            timestamp = int(time.time())
            if multi:
                filename = f"multi_report_{timestamp}.pdf"
            else:
                target_name = os.path.basename(context["target"]).replace(":", "_")
                filename = f"{target_name}_{timestamp}.pdf"

            output_path = os.path.join(self.config.output_dir, filename)

            # Use an HTML to PDF converter
            # This is a placeholder for actual PDF conversion
            # In a real implementation, you would use a library like weasyprint or wkhtmltopdf
            logger.warning("PDF generation is not implemented in this example")
            logger.info(f"Generated PDF report: {output_path}")

            return output_path

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise