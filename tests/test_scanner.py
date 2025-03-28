"""
Tests for the scanner modules.
"""
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from containerguard.scanner.base import BaseScanner, Finding, ScanResult
from containerguard.scanner.vulnerability import VulnerabilityScanner
from containerguard.scanner.misconfig import MisconfigurationScanner


class TestBaseScanner(unittest.TestCase):
    """Test case for the BaseScanner class."""

    def test_normalize_severity(self):
        """Test normalization of severity strings."""
        scanner = MagicMock(spec=BaseScanner)
        scanner.normalize_severity = BaseScanner.normalize_severity

        # Test various severity formats
        self.assertEqual(scanner.normalize_severity("CRITICAL"), "critical")
        self.assertEqual(scanner.normalize_severity("Crit"), "critical")
        self.assertEqual(scanner.normalize_severity("HIGH"), "high")
        self.assertEqual(scanner.normalize_severity("h"), "high")
        self.assertEqual(scanner.normalize_severity("medium"), "medium")
        self.assertEqual(scanner.normalize_severity("LOW"), "low")
        self.assertEqual(scanner.normalize_severity("INFO"), "info")
        self.assertEqual(scanner.normalize_severity("unknown"), "info")

    def test_merge_results(self):
        """Test merging of scan results."""
        scanner = MagicMock(spec=BaseScanner)
        scanner.merge_results = BaseScanner.merge_results

        # Create sample findings
        finding1 = Finding(
            id="CVE-2021-1234",
            title="Test vulnerability 1",
            description="Test description 1",
            severity="high",
            category="vulnerability",
            resource="test:1.0",
            location="/app/test.py",
            recommendation="Update to latest version",
            references=["https://example.com/cve-2021-1234"],
        )

        finding2 = Finding(
            id="CG-DOCKER-001",
            title="Container running as root",
            description="Container is running as root user",
            severity="medium",
            category="misconfiguration",
            resource="Dockerfile",
            location="/app/Dockerfile",
            recommendation="Use a non-root user",
            references=["https://example.com/docker-best-practices"],
        )

        # Create sample scan results
        result1 = ScanResult(
            scanner_name="vulnerability",
            target="test-image:1.0",
            findings=[finding1],
            summary={"vulnerabilities_found": 1},
            scan_time=1.0,
            timestamp="2023-01-01T00:00:00Z",
        )

        result2 = ScanResult(
            scanner_name="misconfiguration",
            target="test-image:1.0",
            findings=[finding2],
            summary={"misconfigurations_found": 1},
            scan_time=2.0,
            timestamp="2023-01-01T00:00:00Z",
        )

        # Merge results
        merged = scanner.merge_results([result1, result2])

        # Check merged result
        self.assertEqual(merged.scanner_name, "merged-vulnerability")
        self.assertEqual(merged.target, "test-image:1.0")
        self.assertEqual(len(merged.findings), 2)
        self.assertEqual(merged.scan_time, 3.0)
        self.assertEqual(merged.high_count, 1)
        self.assertEqual(merged.medium_count, 1)
        self.assertEqual(merged.total_count, 2)
        self.assertEqual(merged.summary["scanners"], ["vulnerability", "misconfiguration"])

    def test_empty_merge_raises_error(self):
        """Test that merging empty results raises an error."""
        scanner = MagicMock(spec=BaseScanner)
        scanner.merge_results = BaseScanner.merge_results

        with self.assertRaises(ValueError):
            scanner.merge_results([])


@pytest.mark.asyncio
class TestVulnerabilityScanner:
    """Test case for the VulnerabilityScanner class."""

    @patch("containerguard.utils.docker.is_valid_image")
    @patch("containerguard.utils.trivy.scan_image")
    async def test_scan_with_trivy(self, mock_scan_image, mock_is_valid_image):
        """Test scanning with Trivy."""
        # Mock Docker image validation
        mock_is_valid_image.return_value = True

        # Mock Trivy scan result
        mock_trivy_result = {
            "Results": [
                {
                    "Target": "test-image:1.0",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "PkgName": "test-package",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.1.0",
                            "Title": "Test vulnerability",
                            "Description": "Test description",
                            "Severity": "HIGH",
                            "References": ["https://example.com/cve-2021-1234"],
                        }
                    ],
                }
            ],
            "Version": "0.16.0",
        }

        # Mock Trivy scan function
        mock_scan_image.return_value = """
        {
            "Results": [
                {
                    "Target": "test-image:1.0",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "PkgName": "test-package",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.1.0",
                            "Title": "Test vulnerability",
                            "Description": "Test description",
                            "Severity": "HIGH",
                            "References": ["https://example.com/cve-2021-1234"]
                        }
                    ]
                }
            ],
            "Version": "0.16.0"
        }
        """

        # Create scanner and run scan
        scanner = VulnerabilityScanner({"use_trivy": True})
        result = await scanner.scan("test-image:1.0")

        # Check scan result
        assert result.scanner_name == "trivy"
        assert result.target == "test-image:1.0"
        assert len(result.findings) == 1
        assert result.findings[0].id == "CVE-2021-1234"
        assert result.findings[0].severity == "high"
        assert result.findings[0].category == "vulnerability"
        assert result.findings[0].resource == "test-package:1.0.0"


@pytest.mark.asyncio
class TestMisconfigurationScanner:
    """Test case for the MisconfigurationScanner class."""

    @patch("os.path.isfile")
    @patch("builtins.open", new_callable=unittest.mock.mock_open, read_data="FROM python:latest\nUSER root\n")
    async def test_check_dockerfile(self, mock_open, mock_isfile):
        """Test checking a Dockerfile for misconfigurations."""
        # Mock file existence
        mock_isfile.return_value = True

        # Create scanner
        scanner = MisconfigurationScanner()

        # Run scan
        result = await scanner.scan("Dockerfile")

        # Check scan result
        assert result.scanner_name == "misconfiguration"
        assert result.target == "Dockerfile"
        assert len(result.findings) > 0

        # Check for specific findings
        user_root_finding = None
        for finding in result.findings:
            if finding.id == "CG-DOCKER-001":
                user_root_finding = finding
                break

        assert user_root_finding is not None
        assert user_root_finding.severity == "high"
        assert user_root_finding.category == "misconfiguration"


if __name__ == "__main__":
    unittest.main()