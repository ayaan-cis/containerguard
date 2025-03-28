"""
Report visualization module for creating charts and graphs from scan results.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from containerguard.scanner.base import Finding, ScanResult

logger = logging.getLogger(__name__)


class ReportVisualizer:
    """
    Visualizer for creating charts and visual representations of scan results.

    This class generates various visualizations for security findings, including
    severity distributions, trends, and risk visualizations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the report visualizer.

        Args:
            config: Visualizer configuration
        """
        self.config = config or {}
        self.theme = self.config.get("theme", "light")
        self.color_scheme = self._get_color_scheme()

        logger.info("Initialized report visualizer")

    def _get_color_scheme(self) -> Dict[str, str]:
        """
        Get the color scheme based on the theme.

        Returns:
            Dictionary mapping severity levels to colors
        """
        if self.theme == "dark":
            return {
                "critical": "#ff3a33",
                "high": "#ff8800",
                "medium": "#ffcc00",
                "low": "#88cc14",
                "info": "#00bbff",
                "background": "#1e1e1e",
                "text": "#ffffff",
            }
        else:  # Light theme
            return {
                "critical": "#ff3a33",
                "high": "#ff8800",
                "medium": "#ffcc00",
                "low": "#88cc14",
                "info": "#00bbff",
                "background": "#ffffff",
                "text": "#333333",
            }

    def create_severity_distribution(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Create a severity distribution pie chart.

        Args:
            scan_result: Scan result to visualize

        Returns:
            Plotly figure data
        """
        try:
            # Get severity counts
            data = {
                "Severity": ["Critical", "High", "Medium", "Low", "Info"],
                "Count": [
                    scan_result.critical_count,
                    scan_result.high_count,
                    scan_result.medium_count,
                    scan_result.low_count,
                    scan_result.info_count,
                ],
            }

            # Create DataFrame
            df = pd.DataFrame(data)

            # Create pie chart
            fig = px.pie(
                df,
                names="Severity",
                values="Count",
                title="Findings by Severity",
                color="Severity",
                color_discrete_map={
                    "Critical": self.color_scheme["critical"],
                    "High": self.color_scheme["high"],
                    "Medium": self.color_scheme["medium"],
                    "Low": self.color_scheme["low"],
                    "Info": self.color_scheme["info"],
                },
            )

            # Update layout
            fig.update_layout(
                paper_bgcolor=self.color_scheme["background"],
                font_color=self.color_scheme["text"],
            )

            return {
                "figure": fig,
                "data": data,
                "type": "pie",
            }

        except Exception as e:
            logger.error(f"Error creating severity distribution chart: {e}")
            return {"error": str(e)}

    def create_category_distribution(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Create a category distribution bar chart.

        Args:
            scan_result: Scan result to visualize

        Returns:
            Plotly figure data
        """
        try:
            # Get findings by category
            categories = {}
            for finding in scan_result.findings:
                category = finding.category
                if category not in categories:
                    categories[category] = 0
                categories[category] += 1

            # Create DataFrame
            df = pd.DataFrame({
                "Category": list(categories.keys()),
                "Count": list(categories.values()),
            })

            # Create bar chart
            fig = px.bar(
                df,
                x="Category",
                y="Count",
                title="Findings by Category",
                color="Category",
            )

            # Update layout
            fig.update_layout(
                paper_bgcolor=self.color_scheme["background"],
                font_color=self.color_scheme["text"],
                xaxis_title="Category",
                yaxis_title="Count",
            )

            return {
                "figure": fig,
                "data": df.to_dict(orient="records"),
                "type": "bar",
            }

        except Exception as e:
            logger.error(f"Error creating category distribution chart: {e}")
            return {"error": str(e)}

    def create_top_findings(self, scan_result: ScanResult, top_n: int = 10) -> Dict[str, Any]:
        """
        Create a horizontal bar chart of top findings.

        Args:
            scan_result: Scan result to visualize
            top_n: Number of top findings to include

        Returns:
            Plotly figure data
        """
        try:
            # Count findings by ID
            findings_count = {}
            for finding in scan_result.findings:
                finding_id = finding.id
                if finding_id not in findings_count:
                    findings_count[finding_id] = {
                        "id": finding_id,
                        "title": finding.title,
                        "count": 0,
                        "severity": finding.severity,
                    }
                findings_count[finding_id]["count"] += 1

            # Sort by count and take top N
            top_findings = sorted(
                findings_count.values(),
                key=lambda x: x["count"],
                reverse=True,
            )[:top_n]

            # Create DataFrame
            df = pd.DataFrame(top_findings)

            # Create horizontal bar chart
            fig = px.bar(
                df,
                y="id",
                x="count",
                title=f"Top {top_n} Findings",
                color="severity",
                color_discrete_map={
                    "critical": self.color_scheme["critical"],
                    "high": self.color_scheme["high"],
                    "medium": self.color_scheme["medium"],
                    "low": self.color_scheme["low"],
                    "info": self.color_scheme["info"],
                },
                hover_data=["title"],
                orientation="h",
            )

            # Update layout
            fig.update_layout(
                paper_bgcolor=self.color_scheme["background"],
                font_color=self.color_scheme["text"],
                xaxis_title="Count",
                yaxis_title="Finding ID",
            )

            return {
                "figure": fig,
                "data": df.to_dict(orient="records"),
                "type": "bar_horizontal",
            }

        except Exception as e:
            logger.error(f"Error creating top findings chart: {e}")
            return {"error": str(e)}

    def create_risk_matrix(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Create a risk matrix bubble chart based on findings.

        Args:
            findings: List of findings to visualize

        Returns:
            Plotly figure data
        """
        try:
            # Map severity to impact score (1-5)
            severity_impact = {
                "critical": 5,
                "high": 4,
                "medium": 3,
                "low": 2,
                "info": 1,
            }

            # Assume likelihood based on metadata if available
            # Otherwise, use mid-range values
            data = []
            for finding in findings:
                # Use metadata for likelihood if available
                likelihood = finding.metadata.get("likelihood", 3)
                if isinstance(likelihood, str):
                    likelihood = {"high": 4, "medium": 3, "low": 2}.get(likelihood.lower(), 3)

                # Get impact from severity
                impact = severity_impact.get(finding.severity.lower(), 3)

                # Calculate risk score
                risk_score = impact * likelihood

                data.append({
                    "id": finding.id,
                    "title": finding.title,
                    "impact": impact,
                    "likelihood": likelihood,
                    "risk_score": risk_score,
                    "severity": finding.severity,
                    "category": finding.category,
                })

            # Create DataFrame
            df = pd.DataFrame(data)

            # Create bubble chart
            fig = px.scatter(
                df,
                x="likelihood",
                y="impact",
                size="risk_score",
                color="severity",
                hover_name="title",
                hover_data=["id", "category", "risk_score"],
                title="Risk Matrix",
                color_discrete_map={
                    "critical": self.color_scheme["critical"],
                    "high": self.color_scheme["high"],
                    "medium": self.color_scheme["medium"],
                    "low": self.color_scheme["low"],
                    "info": self.color_scheme["info"],
                },
            )

            # Update layout
            fig.update_layout(
                paper_bgcolor=self.color_scheme["background"],
                font_color=self.color_scheme["text"],
                xaxis_title="Likelihood",
                yaxis_title="Impact",
                xaxis=dict(
                    tickmode="array",
                    tickvals=[1, 2, 3, 4, 5],
                    ticktext=["Very Low", "Low", "Medium", "High", "Very High"],
                ),
                yaxis=dict(
                    tickmode="array",
                    tickvals=[1, 2, 3, 4, 5],
                    ticktext=["Very Low", "Low", "Medium", "High", "Very High"],
                ),
            )

            return {
                "figure": fig,
                "data": df.to_dict(orient="records"),
                "type": "scatter",
            }

        except Exception as e:
            logger.error(f"Error creating risk matrix: {e}")
            return {"error": str(e)}

    def create_multi_target_comparison(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """
        Create a comparison chart for multiple scan targets.

        Args:
            scan_results: List of scan results to compare

        Returns:
            Plotly figure data
        """
        try:
            # Extract data for each target
            data = []
            for result in scan_results:
                data.append({
                    "target": result.target,
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                    "low": result.low_count,
                    "info": result.info_count,
                    "total": result.total_count,
                })

            # Create DataFrame
            df = pd.DataFrame(data)

            # Create grouped bar chart
            fig = go.Figure()

            # Add bars for each severity
            fig.add_trace(go.Bar(
                x=df["target"],
                y=df["critical"],
                name="Critical",
                marker_color=self.color_scheme["critical"],
            ))
            fig.add_trace(go.Bar(
                x=df["target"],
                y=df["high"],
                name="High",
                marker_color=self.color_scheme["high"],
            ))
            fig.add_trace(go.Bar(
                x=df["target"],
                y=df["medium"],
                name="Medium",
                marker_color=self.color_scheme["medium"],
            ))
            fig.add_trace(go.Bar(
                x=df["target"],
                y=df["low"],
                name="Low",
                marker_color=self.color_scheme["low"],
            ))
            fig.add_trace(go.Bar(
                x=df["target"],
                y=df["info"],
                name="Info",
                marker_color=self.color_scheme["info"],
            ))

            # Update layout
            fig.update_layout(
                title="Comparison of Findings Across Targets",
                xaxis_title="Target",
                yaxis_title="Number of Findings",
                paper_bgcolor=self.color_scheme["background"],
                font_color=self.color_scheme["text"],
                barmode="stack",
            )

            return {
                "figure": fig,
                "data": df.to_dict(orient="records"),
                "type": "bar_stacked",
            }

        except Exception as e:
            logger.error(f"Error creating multi-target comparison chart: {e}")
            return {"error": str(e)}

    def create_dashboard(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Create a comprehensive dashboard with multiple visualizations.

        Args:
            scan_result: Scan result to visualize

        Returns:
            Dictionary of Plotly figures
        """
        try:
            # Create subplot figure with 2x2 grid
            fig = make_subplots(
                rows=2,
                cols=2,
                subplot_titles=(
                    "Findings by Severity",
                    "Findings by Category",
                    "Top Findings",
                    "Risk Matrix",
                ),
                specs=[
                    [{"type": "pie"}, {"type": "bar"}],
                    [{"type": "bar"}, {"type": "scatter"}],
                ],
            )

            # Add severity distribution (pie chart)
            severity_data = self.create_severity_distribution(scan_result)
            if "figure" in severity_data:
                for trace in severity_data["figure"]["data"]:
                    fig.add_trace(trace, row=1, col=1)

            # Add category distribution (bar chart)
            category_data = self.create_category_distribution(scan_result)
            if "figure" in category_data:
                for trace in category_data["figure"]["data"]:
                    fig.add_trace(trace, row=1, col=2)

            # Add top findings (horizontal bar chart)
            top_findings_data = self.create_top_findings(scan_result, top_n=5)
            if "figure" in top_findings_data:
                for trace in top_findings_data["figure"]["data"]:
                    fig.add_trace(trace, row=2, col=1)

            # Add risk matrix (scatter plot)
            risk_matrix_data = self.create_risk_matrix(scan_result.findings)
            if "figure" in risk_matrix_data:
                for trace in risk_matrix_data["figure"]["data"]:
                    fig.add_trace(trace, row=2, col=2)

            # Update layout
            fig.update_layout(
                title_text=f"Security Scan Dashboard - {scan_result.target}",
                paper_bgcolor=self.color_scheme["background"],
                font_color=self.color_scheme["text"],
                height=800,
                showlegend=False,
            )

            return {
                "figure": fig,
                "charts": {
                    "severity": severity_data,
                    "category": category_data,
                    "top_findings": top_findings_data,
                    "risk_matrix": risk_matrix_data,
                },
                "type": "dashboard",
            }

        except Exception as e:
            logger.error(f"Error creating dashboard: {e}")
            return {"error": str(e)}

    def figure_to_html(self, figure: Any) -> str:
        """
        Convert a Plotly figure to HTML.

        Args:
            figure: Plotly figure object

        Returns:
            HTML string
        """
        try:
            return figure.to_html(include_plotlyjs=True, full_html=False)
        except Exception as e:
            logger.error(f"Error converting figure to HTML: {e}")
            return f"<div class='error'>Error generating chart: {e}</div>"

    def figure_to_json(self, figure: Any) -> Dict:
        """
        Convert a Plotly figure to JSON.

        Args:
            figure: Plotly figure object

        Returns:
            JSON-serializable dictionary
        """
        try:
            return figure.to_dict()
        except Exception as e:
            logger.error(f"Error converting figure to JSON: {e}")
            return {"error": str(e)}

    def figure_to_image(self, figure: Any, format: str = "png", width: int = 800, height: int = 600) -> bytes:
        """
        Convert a Plotly figure to an image.

        Args:
            figure: Plotly figure object
            format: Image format (png, jpeg, webp, svg, pdf)
            width: Image width in pixels
            height: Image height in pixels

        Returns:
            Image bytes
        """
        try:
            return figure.to_image(format=format, width=width, height=height)
        except Exception as e:
            logger.error(f"Error converting figure to image: {e}")
            return b""