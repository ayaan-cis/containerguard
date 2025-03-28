"""
Risk analyzer module for calculating risk scores and prioritizing findings.
"""
import logging
import math
from typing import Any, Dict, List, Optional, Tuple

from containerguard.scanner.base import Finding, ScanResult

logger = logging.getLogger(__name__)


class RiskAnalyzer:
    """
    Analyzer for calculating risk scores and prioritizing security findings.

    This module provides contextualized risk analysis that goes beyond simple
    severity ratings to help users focus on the most important issues first.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the risk analyzer.

        Args:
            config: Analyzer configuration
        """
        self.config = config or {}

        # Configure risk calculation parameters
        self.severity_weights = self.config.get("severity_weights", {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        })

        self.category_weights = self.config.get("category_weights", {
            "vulnerability": 1.0,
            "misconfiguration": 1.2,  # Misconfigurations are often easier to fix
            "secret": 1.5,  # Exposed secrets are typically high impact
            "compliance": 0.8,  # Compliance issues may have lower immediate risk
        })

        # Exploitability factors increase risk
        self.exploitability_factors = self.config.get("exploitability_factors", {
            "network_exposure": 1.5,  # Exposed to network
            "public_exploit": 2.0,  # Known public exploits exist
            "no_auth": 1.3,  # No authentication required
            "remote_code_execution": 1.8,  # Allows remote code execution
        })

        # Mitigating factors decrease risk
        self.mitigating_factors = self.config.get("mitigating_factors", {
            "not_exploitable": 0.3,  # Not currently exploitable
            "requires_privileges": 0.7,  # Requires elevated privileges
            "mitigated_by_platform": 0.5,  # Mitigated by platform controls
            "defense_in_depth": 0.8,  # Protected by defense-in-depth measures
        })

        logger.info("Initialized risk analyzer")

    def analyze_findings(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Analyze a list of findings to calculate risk scores and priorities.

        Args:
            findings: List of security findings

        Returns:
            List of findings with risk analysis data
        """
        analyzed_findings = []

        for finding in findings:
            analyzed = self.analyze_finding(finding)
            analyzed_findings.append(analyzed)

        # Sort findings by risk score (highest first)
        analyzed_findings.sort(key=lambda f: f["risk_score"], reverse=True)

        return analyzed_findings

    def analyze_finding(self, finding: Finding) -> Dict[str, Any]:
        """
        Analyze a single finding to calculate its risk score and priority.

        Args:
            finding: Security finding

        Returns:
            Finding with risk analysis data
        """
        # Calculate base risk score from severity
        severity = finding.severity.lower()
        base_score = self.severity_weights.get(severity, 5.0)

        # Adjust based on category
        category = finding.category.lower()
        category_multiplier = self.category_weights.get(category, 1.0)

        # Extract relevant metadata
        metadata = finding.metadata or {}

        # Identify exploitability factors
        exploitability_multiplier = 1.0
        for factor, weight in self.exploitability_factors.items():
            if metadata.get(factor, False):
                exploitability_multiplier *= weight

        # Identify mitigating factors
        mitigation_multiplier = 1.0
        for factor, weight in self.mitigating_factors.items():
            if metadata.get(factor, False):
                mitigation_multiplier *= weight

        # Calculate final risk score
        risk_score = base_score * category_multiplier * exploitability_multiplier * mitigation_multiplier

        # Round to 1 decimal place
        risk_score = round(risk_score, 1)

        # Determine risk label based on score
        risk_label = self._get_risk_label(risk_score)

        # Determine priority (1-5, with 1 being highest)
        priority = self._calculate_priority(risk_score)

        # Create analyzed finding
        analyzed = {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "category": finding.category,
            "resource": finding.resource,
            "location": finding.location,
            "recommendation": finding.recommendation,
            "references": finding.references,
            "metadata": finding.metadata,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "priority": priority,
            "exploitability_factors": [factor for factor in self.exploitability_factors.keys()
                                       if metadata.get(factor, False)],
            "mitigating_factors": [factor for factor in self.mitigating_factors.keys()
                                   if metadata.get(factor, False)],
        }

        return analyzed

    def analyze_scan_result(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Analyze a scan result to calculate risk scores and statistics.

        Args:
            scan_result: Scan result to analyze

        Returns:
            Scan result with risk analysis data
        """
        analyzed_findings = self.analyze_findings(scan_result.findings)

        # Get overall risk score (average of top 3 risk scores, or all if fewer than 3)
        top_findings = sorted(analyzed_findings, key=lambda f: f["risk_score"], reverse=True)
        top_risk_scores = [f["risk_score"] for f in top_findings[:min(3, len(top_findings))]]

        overall_risk_score = 0
        if top_risk_scores:
            overall_risk_score = round(sum(top_risk_scores) / len(top_risk_scores), 1)

        # Get risk level distribution
        risk_distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in analyzed_findings:
            risk_distribution[finding["risk_label"]] += 1

        # Get priority distribution
        priority_distribution = {
            1: 0,  # P1 - Highest
            2: 0,  # P2
            3: 0,  # P3
            4: 0,  # P4
            5: 0,  # P5 - Lowest
        }

        for finding in analyzed_findings:
            priority_distribution[finding["priority"]] += 1

        # Calculate risk index (weighted score representing overall risk)
        risk_index = self._calculate_risk_index(analyzed_findings)

        # Generate risk data
        risk_data = {
            "findings": analyzed_findings,
            "overall_risk_score": overall_risk_score,
            "overall_risk_level": self._get_risk_label(overall_risk_score),
            "risk_distribution": risk_distribution,
            "priority_distribution": priority_distribution,
            "risk_index": risk_index,
            "top_risks": top_findings[:5],  # Top 5 risks
        }

        return risk_data

    def _get_risk_label(self, risk_score: float) -> str:
        """
        Get a risk label based on the risk score.

        Args:
            risk_score: Calculated risk score

        Returns:
            Risk label (critical, high, medium, low, info)
        """
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        elif risk_score >= 1.0:
            return "low"
        else:
            return "info"

    def _calculate_priority(self, risk_score: float) -> int:
        """
        Calculate a priority level based on the risk score.

        Args:
            risk_score: Calculated risk score

        Returns:
            Priority level (1-5, with 1 being highest)
        """
        if risk_score >= 9.0:
            return 1  # P1 - Highest priority
        elif risk_score >= 7.0:
            return 2  # P2
        elif risk_score >= 4.0:
            return 3  # P3
        elif risk_score >= 1.0:
            return 4  # P4
        else:
            return 5  # P5 - Lowest priority

    def _calculate_risk_index(self, analyzed_findings: List[Dict[str, Any]]) -> float:
        """
        Calculate a risk index based on analyzed findings.

        The risk index is a weighted score that represents the overall risk,
        taking into account the number and severity of findings.

        Args:
            analyzed_findings: List of analyzed findings

        Returns:
            Risk index score
        """
        if not analyzed_findings:
            return 0.0

        # Sum of (risk_score * weight) for all findings
        weighted_sum = sum(f["risk_score"] * self._get_weight_for_priority(f["priority"])
                           for f in analyzed_findings)

        # Scale based on finding count, using log scale to prevent excessive inflation
        count_factor = 1 + math.log10(max(1, len(analyzed_findings)))

        # Calculate final index
        risk_index = (weighted_sum / len(analyzed_findings)) * count_factor

        # Scale to 0-100 range for easier interpretation
        risk_index = min(100, round(risk_index * 10, 1))

        return risk_index

    def _get_weight_for_priority(self, priority: int) -> float:
        """
        Get a weight factor based on priority level.

        Args:
            priority: Priority level (1-5)

        Returns:
            Weight factor
        """
        # Weights are inversely related to priority level
        weights = {
            1: 1.0,  # P1 - Full weight
            2: 0.8,  # P2
            3: 0.5,  # P3
            4: 0.2,  # P4
            5: 0.1,  # P5
        }

        return weights.get(priority, 0.1)