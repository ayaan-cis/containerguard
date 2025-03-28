"""
Base scanner module that defines the core scanning functionality.
"""
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class Finding(BaseModel):
    """Base model for security findings."""
    id: str
    title: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str  # 'vulnerability', 'misconfiguration', 'secret', etc.
    resource: str  # The affected resource
    location: str  # Where the issue was found
    recommendation: str  # How to fix it
    references: List[str]  # Links to CVEs, documentation, etc.
    metadata: Dict[str, Any] = {}  # Additional scanner-specific information

    def as_dict(self) -> Dict[str, Any]:
        """Convert finding to a dictionary."""
        return self.dict()

    @property
    def is_critical(self) -> bool:
        """Check if the finding is critical."""
        return self.severity.lower() == "critical"

    @property
    def is_high(self) -> bool:
        """Check if the finding is high severity."""
        return self.severity.lower() == "high"

    @property
    def is_medium(self) -> bool:
        """Check if the finding is medium severity."""
        return self.severity.lower() == "medium"

    @property
    def is_low(self) -> bool:
        """Check if the finding is low severity."""
        return self.severity.lower() == "low"

    @property
    def is_info(self) -> bool:
        """Check if the finding is informational."""
        return self.severity.lower() == "info"


class ScanResult(BaseModel):
    """Container for scan results."""
    scanner_name: str
    target: str
    findings: List[Finding]
    summary: Dict[str, Any]
    scan_time: float  # Time taken for scan in seconds
    timestamp: str
    metadata: Dict[str, Any] = {}

    @property
    def critical_count(self) -> int:
        """Count critical findings."""
        return sum(1 for f in self.findings if f.is_critical)

    @property
    def high_count(self) -> int:
        """Count high severity findings."""
        return sum(1 for f in self.findings if f.is_high)

    @property
    def medium_count(self) -> int:
        """Count medium severity findings."""
        return sum(1 for f in self.findings if f.is_medium)

    @property
    def low_count(self) -> int:
        """Count low severity findings."""
        return sum(1 for f in self.findings if f.is_low)

    @property
    def info_count(self) -> int:
        """Count informational findings."""
        return sum(1 for f in self.findings if f.is_info)

    @property
    def total_count(self) -> int:
        """Count all findings."""
        return len(self.findings)

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings of specific severity."""
        severity = severity.lower()
        return [f for f in self.findings if f.severity.lower() == severity]

    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings of specific category."""
        category = category.lower()
        return [f for f in self.findings if f.category.lower() == category]


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the scanner with a name and optional configuration.

        Args:
            name: Human-readable name of the scanner
            config: Scanner-specific configuration
        """
        self.name = name
        self.config = config or {}
        logger.info(f"Initializing {name} scanner")

    @abstractmethod
    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a target for security issues.

        Args:
            target: The target to scan (image name, directory, etc.)
            options: Additional scan options

        Returns:
            ScanResult containing findings and metadata
        """
        pass

    @abstractmethod
    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a specific file for security issues.

        Args:
            file_path: Path to the file to scan
            options: Additional scan options

        Returns:
            ScanResult containing findings and metadata
        """
        pass

    def validate_target(self, target: str) -> bool:
        """
        Validate if the target is scannable by this scanner.

        Args:
            target: The target to validate

        Returns:
            True if the target is valid, False otherwise
        """
        return os.path.exists(target)

    def normalize_severity(self, severity: str) -> str:
        """
        Normalize severity strings from different scanners to a standard format.

        Args:
            severity: The severity string to normalize

        Returns:
            Normalized severity string
        """
        severity = severity.lower()

        # Map various severity formats to our standard
        if severity in ["critical", "crit", "cr"]:
            return "critical"
        elif severity in ["high", "h"]:
            return "high"
        elif severity in ["medium", "med", "m"]:
            return "medium"
        elif severity in ["low", "l"]:
            return "low"
        else:
            return "info"

    def merge_results(self, results: List[ScanResult]) -> ScanResult:
        """
        Merge multiple scan results into a single result.

        Args:
            results: List of scan results to merge

        Returns:
            Merged scan result
        """
        if not results:
            raise ValueError("Cannot merge empty results list")

        # Use the first result as a base
        base_result = results[0]

        # Combine findings from all results
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        # Merge metadata
        merged_metadata = {}
        for result in results:
            merged_metadata.update(result.metadata)

        # Create merged summary
        merged_summary = {
            "scanners": [result.scanner_name for result in results],
            "critical_count": sum(result.critical_count for result in results),
            "high_count": sum(result.high_count for result in results),
            "medium_count": sum(result.medium_count for result in results),
            "low_count": sum(result.low_count for result in results),
            "info_count": sum(result.info_count for result in results),
            "total_count": sum(result.total_count for result in results),
        }

        # Create merged result
        return ScanResult(
            scanner_name=f"merged-{base_result.scanner_name}",
            target=base_result.target,
            findings=all_findings,
            summary=merged_summary,
            scan_time=sum(result.scan_time for result in results),
            timestamp=base_result.timestamp,
            metadata=merged_metadata,
        )