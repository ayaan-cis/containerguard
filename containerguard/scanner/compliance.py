"""
Compliance scanner module for validating containers against security standards.
"""
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from containerguard.scanner.base import BaseScanner, Finding, ScanResult

logger = logging.getLogger(__name__)


class ComplianceScanner(BaseScanner):
    """
    Scanner for validating containers against security standards and benchmarks.

    This scanner checks compliance with industry standards like:
    - CIS Docker Benchmark
    - NIST 800-190 (Application Container Security Guide)
    - PCI DSS requirements for containers
    - HIPAA/HITRUST requirements for healthcare
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the compliance scanner.

        Args:
            config: Scanner configuration
        """
        super().__init__("compliance", config)

        # Load available standards
        self.standards = self._load_standards()

        # Configure which standards to check
        self.enabled_standards = self.config.get("standards", ["cis"])

        # Determine which checks are enabled
        self.checks = self._load_compliance_checks()

        # Configure scanner behavior
        self.severity_threshold = self.config.get("severity_threshold", "medium")
        self.max_findings = self.config.get("max_findings", 1000)

        logger.info(
            f"Initialized compliance scanner with {len(self.checks)} checks for {', '.join(self.enabled_standards)} standards")

    def _load_standards(self) -> Dict[str, Dict[str, Any]]:
        """
        Load available compliance standards.

        Returns:
            Dictionary of compliance standards
        """
        # This would typically load from a standards database
        # For this example, we'll define a few common standards
        return {
            "cis": {
                "name": "CIS Docker Benchmark",
                "version": "1.5.0",
                "description": "Center for Internet Security Docker Benchmark",
                "url": "https://www.cisecurity.org/benchmark/docker",
            },
            "nist": {
                "name": "NIST Application Container Security Guide",
                "version": "800-190",
                "description": "National Institute of Standards and Technology guidance for container security",
                "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf",
            },
            "pci": {
                "name": "PCI DSS Container Requirements",
                "version": "3.2.1",
                "description": "Payment Card Industry Data Security Standard requirements for containers",
                "url": "https://www.pcisecuritystandards.org/",
            },
            "hipaa": {
                "name": "HIPAA/HITRUST Container Controls",
                "version": "2023",
                "description": "Health Insurance Portability and Accountability Act requirements for containers",
                "url": "https://hitrustalliance.net/",
            },
        }

    def _load_compliance_checks(self) -> List[Dict[str, Any]]:
        """
        Load compliance checks for enabled standards.

        Returns:
            List of compliance checks
        """
        # These would typically be loaded from a checks database
        # For this example, we'll define some common CIS checks
        all_checks = []

        cis_checks = [
            # Host Configuration
            {
                "id": "CG-CIS-4.1",
                "standard": "cis",
                "section": "4.1",
                "title": "Ensure a user for the container has been created",
                "description": "Create a non-root user for the container in the Dockerfile.",
                "severity": "high",
                "category": "compliance",
                "rule_type": "dockerfile",
                "check_pattern": r"USER\s+(?!root)",
                "check_type": "exists",
                "recommendation": "Add a USER instruction in your Dockerfile that specifies a non-root user.",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
                ],
            },
            # Docker daemon configuration
            {
                "id": "CG-CIS-2.1",
                "standard": "cis",
                "section": "2.1",
                "title": "Ensure network traffic is restricted between containers",
                "description": "By default, all network traffic is allowed between containers on the same host. This could potentially lead to unintended and unauthorized communication.",
                "severity": "medium",
                "category": "compliance",
                "rule_type": "daemon-config",
                "check_pattern": r"icc\"\s*:\s*false",
                "check_type": "exists",
                "recommendation": "Configure the Docker daemon with --icc=false to restrict inter-container communication.",
                "references": [
                    "https://docs.docker.com/engine/reference/commandline/dockerd/",
                ],
            },
            # Docker daemon configuration
            {
                "id": "CG-CIS-2.2",
                "standard": "cis",
                "section": "2.2",
                "title": "Ensure the logging level is set to 'info'",
                "description": "Set Docker daemon log level to 'info'.",
                "severity": "low",
                "category": "compliance",
                "rule_type": "daemon-config",
                "check_pattern": r"log-level\"\s*:\s*\"info\"",
                "check_type": "exists",
                "recommendation": "Configure the Docker daemon with --log-level=info.",
                "references": [
                    "https://docs.docker.com/engine/reference/commandline/dockerd/",
                ],
            },
            # Container runtime
            {
                "id": "CG-CIS-5.12",
                "standard": "cis",
                "section": "5.12",
                "title": "Ensure mount propagation mode is not set to shared",
                "description": "Mount propagation mode allows mounting volumes in shared, slave or private mode. Shared mode mount can be used for privilege escalation.",
                "severity": "high",
                "category": "compliance",
                "rule_type": "compose",
                "check_pattern": r"propagation:\s*shared",
                "check_type": "not_exists",
                "recommendation": "Do not use shared mount propagation mode in container volume definitions.",
                "references": [
                    "https://docs.docker.com/storage/bind-mounts/#configure-bind-propagation",
                ],
            },
            # Docker security operations
            {
                "id": "CG-CIS-6.1",
                "standard": "cis",
                "section": "6.1",
                "title": "Ensure image vulnerability scanning is in place",
                "description": "Vulnerability scanning should be part of the build and deployment process.",
                "severity": "critical",
                "category": "compliance",
                "rule_type": "process",
                "check_function": "_check_vulnerability_scanning",
                "recommendation": "Implement image vulnerability scanning in your CI/CD pipeline using tools like Trivy, Clair, or Grype.",
                "references": [
                    "https://github.com/aquasecurity/trivy",
                    "https://github.com/quay/clair",
                    "https://github.com/anchore/grype",
                ],
            },
            # Container runtime
            {
                "id": "CG-CIS-5.25",
                "standard": "cis",
                "section": "5.25",
                "title": "Ensure the container is restricted from acquiring additional privileges",
                "description": "Restrict the container from acquiring additional privileges via suid or sgid bits.",
                "severity": "high",
                "category": "compliance",
                "rule_type": "compose",
                "check_pattern": r"security_opt:\s*-\s*no-new-privileges",
                "check_type": "exists",
                "recommendation": "Add 'security_opt: [no-new-privileges]' to your Docker Compose file.",
                "references": [
                    "https://docs.docker.com/engine/reference/run/#security-configuration",
                ],
            },
            # Docker security operations
            {
                "id": "CG-CIS-6.5",
                "standard": "cis",
                "section": "6.5",
                "title": "Ensure Content trust for Docker is Enabled",
                "description": "Content trust provides the ability to verify both the integrity and the publisher of all data received over a channel.",
                "severity": "medium",
                "category": "compliance",
                "rule_type": "environment",
                "check_env": "DOCKER_CONTENT_TRUST",
                "check_value": "1",
                "recommendation": "Enable Docker Content Trust by setting the environment variable DOCKER_CONTENT_TRUST=1.",
                "references": [
                    "https://docs.docker.com/engine/security/trust/",
                ],
            },
        ]

        nist_checks = [
            {
                "id": "CG-NIST-4.1.1",
                "standard": "nist",
                "section": "4.1.1",
                "title": "Ensure container images are from trusted sources",
                "description": "Container images should come from trusted and verified sources to reduce the risk of malicious code or backdoors.",
                "severity": "high",
                "category": "compliance",
                "rule_type": "process",
                "check_function": "_check_trusted_registry",
                "recommendation": "Use only official images from trusted registries. Implement image signing and verification.",
                "references": [
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf",
                ],
            },
            {
                "id": "CG-NIST-4.3.1",
                "standard": "nist",
                "section": "4.3.1",
                "title": "Ensure container hosts are hardened",
                "description": "Container hosts should be hardened according to security best practices to prevent compromise.",
                "severity": "high",
                "category": "compliance",
                "rule_type": "process",
                "check_function": "_check_host_hardening",
                "recommendation": "Implement host system hardening measures including minimizing the host OS, using secure configurations, and keeping the system updated.",
                "references": [
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf",
                ],
            },
        ]

        # Add checks based on enabled standards
        if "cis" in self.enabled_standards:
            all_checks.extend(cis_checks)

        if "nist" in self.enabled_standards:
            all_checks.extend(nist_checks)

        # Additional standards would be included here

        return all_checks

    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a container image or environment for compliance issues.

        Args:
            target: Container image name, directory, or file path
            options: Additional scan options

        Returns:
            ScanResult containing compliance findings
        """
        options = options or {}
        logger.info(f"Scanning {target} for compliance with {', '.join(self.enabled_standards)}")
        start_time = time.time()

        findings = []

        # Check if target is a directory containing configuration files
        if os.path.isdir(target):
            findings.extend(await self._scan_directory(target))
        # Check if target is a specific file
        elif os.path.isfile(target):
            findings.extend(await self._scan_file(target))
        # Assume target is a Docker image
        else:
            findings.extend(await self._scan_docker_image(target))

        # Limit findings based on configuration
        findings = findings[:self.max_findings]

        # Get covered compliance sections
        covered_sections = self._get_covered_sections(findings)

        # Create scan result

    async def _scan_directory(self, directory: str) -> List[Finding]:
        """
        Scan a directory for compliance issues.

        Args:
            directory: Path to the directory to scan

        Returns:
            List of findings
        """
        findings = []

        # Look for Dockerfile
        dockerfile_path = os.path.join(directory, "Dockerfile")
        if os.path.isfile(dockerfile_path):
            dockerfile_findings = await self._scan_file(dockerfile_path)
            findings.extend(dockerfile_findings)

        # Look for docker-compose.yml
        compose_path = os.path.join(directory, "docker-compose.yml")
        if os.path.isfile(compose_path):
            compose_findings = await self._scan_file(compose_path)
            findings.extend(compose_findings)

        # Look for other relevant files
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith((".json", ".yaml", ".yml")) and file != "docker-compose.yml":
                    file_path = os.path.join(root, file)
                    file_findings = await self._scan_file(file_path)
                    findings.extend(file_findings)

        return findings

    async def _scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a file for compliance issues.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings
        """
        findings = []

        try:
            # Determine file type
            file_name = os.path.basename(file_path).lower()
            file_ext = os.path.splitext(file_path)[1].lower()

            # Get file content
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Get relevant checks based on file type
            applicable_checks = []

            if file_name == "dockerfile":
                applicable_checks = [c for c in self.checks if c.get("rule_type") == "dockerfile"]
            elif file_name in ("docker-compose.yml", "docker-compose.yaml") or "compose" in file_name:
                applicable_checks = [c for c in self.checks if c.get("rule_type") == "compose"]
            elif file_ext in (".json", ".yaml", ".yml"):
                # Could be Kubernetes manifests or other config
                applicable_checks = [c for c in self.checks if c.get("rule_type") in ("kubernetes", "config")]

            # Apply checks
            for check in applicable_checks:
                check_type = check.get("check_type")
                pattern = check.get("check_pattern")

                if check_type and pattern:
                    import re
                    if check_type == "exists":
                        if re.search(pattern, content):
                            # The pattern exists, which is good for this check
                            continue
                        # Pattern doesn't exist, which is a compliance issue
                        findings.append(self._create_finding_from_check(check, file_path))
                    elif check_type == "not_exists":
                        if not re.search(pattern, content):
                            # The pattern doesn't exist, which is good for this check
                            continue
                        # Pattern exists, which is a compliance issue
                        findings.append(self._create_finding_from_check(check, file_path))

        except Exception as e:
            logger.error(f"Error scanning file {file_path} for compliance: {e}")

        return findings

    async def _scan_docker_image(self, image_name: str) -> List[Finding]:
        """
        Scan a Docker image for compliance issues.

        Args:
            image_name: Name of the Docker image to scan

        Returns:
            List of findings
        """
        findings = []

        try:
            import docker
            from containerguard.utils.docker import get_image_info, extract_layers

            # In a real implementation, we would:
            # 1. Inspect the Docker image configuration
            # 2. Check for compliance issues in the image setup
            # 3. Potentially extract and scan the image filesystem

            # This is a simplified placeholder implementation
            client = docker.from_env()

            try:
                image = client.images.get(image_name)

                # Check for user configuration (CIS 4.1)
                config = image.attrs.get("Config", {})
                user = config.get("User", "")

                if not user or user == "root" or user == "0":
                    # Find the CIS 4.1 check
                    user_check = next((c for c in self.checks if c.get("id") == "CG-CIS-4.1"), None)
                    if user_check:
                        findings.append(self._create_finding_from_check(user_check, image_name))

                # Additional image compliance checks would go here

            except docker.errors.ImageNotFound:
                logger.warning(f"Image {image_name} not found for compliance scanning")

        except ImportError:
            logger.error("Docker library not available. Cannot scan Docker image for compliance.")
        except Exception as e:
            logger.error(f"Error scanning Docker image {image_name} for compliance: {e}")

        return findings

    def _create_finding_from_check(self, check: Dict[str, Any], target: str) -> Finding:
        """
        Create a Finding object from a compliance check definition.

        Args:
            check: Compliance check definition
            target: The target being scanned

        Returns:
            Finding object
        """
        return Finding(
            id=check["id"],
            title=check["title"],
            description=check["description"],
            severity=check["severity"],
            category=check["category"],
            resource=os.path.basename(target),
            location=target,
            recommendation=check["recommendation"],
            references=check["references"],
            metadata={
                "standard": check["standard"],
                "section": check["section"],
                "rule_type": check["rule_type"],
            },
        )

    def _get_covered_sections(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """
        Get the compliance sections covered by the findings.

        Args:
            findings: List of compliance findings

        Returns:
            Dictionary mapping standards to lists of covered sections
        """
        covered = {}

        for finding in findings:
            metadata = finding.metadata
            if not metadata:
                continue

            standard = metadata.get("standard")
            section = metadata.get("section")

            if standard and section:
                if standard not in covered:
                    covered[standard] = []
                if section not in covered[standard]:
                    covered[standard].append(section)

        return covered

    def _calculate_compliance_score(self, findings: List[Finding]) -> float:
        """
        Calculate a compliance score based on findings.

        Args:
            findings: List of compliance findings

        Returns:
            Compliance score (0-100, higher is better)
        """
        # If no checks were performed, we can't calculate a score
        if not self.checks:
            return 0.0

        # Count failed checks
        failed_checks = len(findings)

        # Count total applicable checks
        total_checks = len(self.checks)

        # Calculate compliance percentage
        if total_checks > 0:
            compliance_score = 100 * (1 - (failed_checks / total_checks))
            return round(compliance_score, 1)
        else:
            return 100.0

        return ScanResult(
            scanner_name=self.name,
            target=target,
            findings=findings,
            summary={
                "compliance_issues": len(findings),
                "standards": self.enabled_standards,
                "covered_sections": covered_sections,
                "compliance_score": self._calculate_compliance_score(findings),
            },
            scan_time=time.time() - start_time,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={
                "standards": [self.standards[std] for std in self.enabled_standards if std in self.standards],
            },
        )