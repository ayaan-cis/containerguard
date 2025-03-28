"""
Misconfiguration scanner module for detecting security misconfigurations in containers.
"""
import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from containerguard.scanner.base import BaseScanner, Finding, ScanResult

logger = logging.getLogger(__name__)

class MisconfigurationScanner(BaseScanner):
    """
    Scanner for detecting misconfigurations in container images and Dockerfiles.

    This scanner checks for common security misconfigurations based on best practices
    from NIST, CIS Docker Benchmark, and other security standards.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the misconfiguration scanner.

        Args:
            config: Scanner configuration
        """
        super().__init__("misconfiguration", config)

        # Load built-in rules
        self.rules = self._load_default_rules()

        # Load custom rules if provided
        custom_rules_path = self.config.get("custom_rules_path")
        if custom_rules_path and os.path.exists(custom_rules_path):
            custom_rules = self._load_custom_rules(custom_rules_path)
            self.rules.extend(custom_rules)

        # Configure scanner behavior
        self.check_dockerfile = self.config.get("check_dockerfile", True)
        self.check_compose = self.config.get("check_compose", True)
        self.check_kubernetes = self.config.get("check_kubernetes", True)

        logger.info(f"Initialized misconfiguration scanner with {len(self.rules)} rules")

    def _load_default_rules(self) -> List[Dict[str, Any]]:
        """
        Load the default misconfiguration rules.

        Returns:
            List of rule definitions
        """
        # These are hardcoded rules, but in a real implementation
        # they would be loaded from a rules directory or database
        return [
            # User-related rules
            {
                "id": "CG-DOCKER-001",
                "title": "Container running as root",
                "description": "Container is configured to run as the root user, which can lead to host system compromise if the container is exploited.",
                "severity": "high",
                "category": "misconfiguration",
                "check_type": "dockerfile",
                "check_pattern": r"USER\s+root",
                "check_positive": True,  # Rule triggers when pattern matches
                "recommendation": "Use a non-root user for running containers. Add 'USER nonroot' instruction to your Dockerfile.",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-2-set-a-user",
                ],
            },
            # Privilege-related rules
            {
                "id": "CG-DOCKER-002",
                "title": "Container with privileged mode",
                "description": "Container is running in privileged mode, which gives all capabilities to the container, effectively disabling container isolation.",
                "severity": "critical",
                "category": "misconfiguration",
                "check_type": "compose",
                "check_pattern": r"privileged:\s+true",
                "check_positive": True,
                "recommendation": "Avoid running containers in privileged mode. If specific capabilities are needed, grant only those using the 'cap_add' option.",
                "references": [
                    "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
                ],
            },
            # Network-related rules
            {
                "id": "CG-DOCKER-003",
                "title": "Container exposing sensitive ports",
                "description": "Container is exposing sensitive ports that might allow unauthorized access to services.",
                "severity": "medium",
                "category": "misconfiguration",
                "check_type": "dockerfile",
                "check_pattern": r"EXPOSE\s+(22|23|3389|5432|3306|27017|6379|9200|8080|4444|4333)",
                "check_positive": True,
                "recommendation": "Avoid exposing sensitive ports. If necessary, use non-standard ports and implement proper authentication.",
                "references": [
                    "https://docs.docker.com/engine/reference/builder/#expose",
                ],
            },
            # Resource limits
            {
                "id": "CG-DOCKER-004",
                "title": "Container without resource limits",
                "description": "Container is running without memory or CPU limits, which could lead to resource exhaustion attacks.",
                "severity": "medium",
                "category": "misconfiguration",
                "check_type": "compose",
                "check_pattern": r"(mem_limit|cpus):",
                "check_positive": False,  # Rule triggers when pattern does NOT match
                "recommendation": "Set memory and CPU limits for all containers to prevent resource exhaustion attacks.",
                "references": [
                    "https://docs.docker.com/compose/compose-file/compose-file-v3/#resources",
                ],
            },
            # Security options
            {
                "id": "CG-DOCKER-005",
                "title": "Container without security options",
                "description": "Container is running without recommended security options like no-new-privileges, seccomp, etc.",
                "severity": "high",
                "category": "misconfiguration",
                "check_type": "compose",
                "check_pattern": r"security_opt:",
                "check_positive": False,
                "recommendation": "Enable security options such as no-new-privileges, seccomp profiles, and AppArmor profiles.",
                "references": [
                    "https://docs.docker.com/engine/reference/run/#security-configuration",
                ],
            },
            # Base image
            {
                "id": "CG-DOCKER-006",
                "title": "Container using latest tag",
                "description": "Container is using the 'latest' tag for base images, which can lead to unexpected changes and vulnerabilities.",
                "severity": "medium",
                "category": "misconfiguration",
                "check_type": "dockerfile",
                "check_pattern": r"FROM\s+([^:]+):latest",
                "check_positive": True,
                "recommendation": "Use specific version tags for base images to ensure reproducibility and stability.",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from",
                ],
            },
            # File permissions
            {
                "id": "CG-DOCKER-007",
                "title": "Container with unsafe file permissions",
                "description": "Container has files with overly permissive permissions that might allow unauthorized access.",
                "severity": "medium",
                "category": "misconfiguration",
                "check_type": "dockerfile",
                "check_pattern": r"chmod\s+([0-7]*[0-7][0-7][7])\s",
                "check_positive": True,
                "recommendation": "Use least privilege principles for file permissions. Avoid permissions like 777 or world-writable directories.",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
                ],
            },
        ]

    def _load_custom_rules(self, rules_path: str) -> List[Dict[str, Any]]:
        """
        Load custom rules from a file or directory.

        Args:
            rules_path: Path to rules file or directory

        Returns:
            List of custom rule definitions
        """
        custom_rules = []

        if os.path.isfile(rules_path):
            # Load rules from a single file
            with open(rules_path, "r") as f:
                try:
                    if rules_path.endswith(".json"):
                        rules_data = json.load(f)
                    elif rules_path.endswith((".yaml", ".yml")):
                        rules_data = yaml.safe_load(f)
                    else:
                        logger.warning(f"Unsupported rules file format: {rules_path}")
                        return []

                    if isinstance(rules_data, list):
                        custom_rules.extend(rules_data)
                    elif isinstance(rules_data, dict) and "rules" in rules_data:
                        custom_rules.extend(rules_data["rules"])
                except Exception as e:
                    logger.error(f"Failed to load custom rules from {rules_path}: {e}")

        elif os.path.isdir(rules_path):
            # Load rules from all files in directory
            for filename in os.listdir(rules_path):
                if filename.endswith((".json", ".yaml", ".yml")):
                    file_path = os.path.join(rules_path, filename)
                    custom_rules.extend(self._load_custom_rules(file_path))

        return custom_rules

    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a container image for misconfigurations.

        Args:
            target: Container image name, directory, or file path
            options: Additional scan options

        Returns:
            ScanResult containing misconfiguration findings
        """
        options = options or {}
        logger.info(f"Scanning {target} for misconfigurations")
        start_time = time.time()

        findings = []

        # Check if target is a directory containing configuration files
        if os.path.isdir(target):
            # Scan Dockerfile if present
            dockerfile_path = os.path.join(target, "Dockerfile")
            if self.check_dockerfile and os.path.isfile(dockerfile_path):
                dockerfile_findings = self._check_dockerfile(dockerfile_path)
                findings.extend(dockerfile_findings)

            # Scan docker-compose.yml if present
            compose_path = os.path.join(target, "docker-compose.yml")
            if self.check_compose and os.path.isfile(compose_path):
                compose_findings = self._check_compose_file(compose_path)
                findings.extend(compose_findings)

            # Scan Kubernetes manifests if present
            k8s_dir = os.path.join(target, "kubernetes")
            if self.check_kubernetes and os.path.isdir(k8s_dir):
                k8s_findings = self._check_kubernetes_manifests(k8s_dir)
                findings.extend(k8s_findings)

        # Check if target is a specific file
        elif os.path.isfile(target):
            filename = os.path.basename(target).lower()

            if filename == "dockerfile" and self.check_dockerfile:
                findings.extend(self._check_dockerfile(target))
            elif filename in ("docker-compose.yml", "docker-compose.yaml") and self.check_compose:
                findings.extend(self._check_compose_file(target))
            elif filename.endswith((".yml", ".yaml")) and self.check_kubernetes:
                findings.extend(self._check_kubernetes_manifest(target))

        # For Docker images, extract and scan the image config
        else:
            # This would require extracting image config and scanning it
            # For simplicity, this example only implements file-based scanning
            pass

        # Create scan result
        return ScanResult(
            scanner_name=self.name,
            target=target,
            findings=findings,
            summary={
                "misconfigurations_found": len(findings),
                "scan_target": target,
                "rules_checked": len(self.rules),
            },
            scan_time=time.time() - start_time,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={},
        )

    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a specific file for misconfigurations.

        Args:
            file_path: Path to the file to scan
            options: Additional scan options

        Returns:
            ScanResult containing misconfiguration findings
        """
        return await self.scan(file_path, options)

    def _check_dockerfile(self, dockerfile_path: str) -> List[Finding]:
        """
        Check a Dockerfile for misconfigurations.

        Args:
            dockerfile_path: Path to the Dockerfile

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(dockerfile_path, "r") as f:
                dockerfile_content = f.read()

            # Get dockerfile rules
            dockerfile_rules = [r for r in self.rules if r.get("check_type") == "dockerfile"]

            for rule in dockerfile_rules:
                pattern = rule.get("check_pattern")
                if not pattern:
                    continue

                matched = bool(re.search(pattern, dockerfile_content))
                check_positive = rule.get("check_positive", True)

                # Rule triggers when:
                # - check_positive=True and pattern matches
                # - check_positive=False and pattern does not match
                if matched == check_positive:
                    finding = Finding(
                        id=rule.get("id"),
                        title=rule.get("title"),
                        description=rule.get("description"),
                        severity=rule.get("severity"),
                        category=rule.get("category"),
                        resource=os.path.basename(dockerfile_path),
                        location=dockerfile_path,
                        recommendation=rule.get("recommendation"),
                        references=rule.get("references", []),
                        metadata={
                            "rule_id": rule.get("id"),
                            "check_type": rule.get("check_type"),
                        },
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Error checking Dockerfile {dockerfile_path}: {e}")

        return findings

    def _check_compose_file(self, compose_path: str) -> List[Finding]:
        """
        Check a docker-compose.yml file for misconfigurations.

        Args:
            compose_path: Path to the docker-compose.yml file

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(compose_path, "r") as f:
                compose_content = f.read()

            # Get compose rules
            compose_rules = [r for r in self.rules if r.get("check_type") == "compose"]

            for rule in compose_rules:
                pattern = rule.get("check_pattern")
                if not pattern:
                    continue

                matched = bool(re.search(pattern, compose_content))
                check_positive = rule.get("check_positive", True)

                if matched == check_positive:
                    finding = Finding(
                        id=rule.get("id"),
                        title=rule.get("title"),
                        description=rule.get("description"),
                        severity=rule.get("severity"),
                        category=rule.get("category"),
                        resource=os.path.basename(compose_path),
                        location=compose_path,
                        recommendation=rule.get("recommendation"),
                        references=rule.get("references", []),
                        metadata={
                            "rule_id": rule.get("id"),
                            "check_type": rule.get("check_type"),
                        },
                    )
                    findings.append(finding)

            # Also parse as YAML for structured checks
            try:
                compose_yaml = yaml.safe_load(compose_content)
                # Additional structured checks could be implemented here
            except Exception as yaml_error:
                logger.warning(f"Failed to parse {compose_path} as YAML: {yaml_error}")

        except Exception as e:
            logger.error(f"Error checking compose file {compose_path}: {e}")

        return findings

    def _check_kubernetes_manifest(self, manifest_path: str) -> List[Finding]:
        """
        Check a Kubernetes manifest file for misconfigurations.

        Args:
            manifest_path: Path to the Kubernetes manifest file

        Returns:
            List of findings
        """
        # This would implement Kubernetes-specific checks
        # For brevity, this is a simplified placeholder
        return []

    def _check_kubernetes_manifests(self, manifests_dir: str) -> List[Finding]:
        """
        Check all Kubernetes manifests in a directory.

        Args:
            manifests_dir: Path to directory containing Kubernetes manifests

        Returns:
            List of findings
        """
        findings = []

        for root, _, files in os.walk(manifests_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    file_path = os.path.join(root, file)
                    findings.extend(self._check_kubernetes_manifest(file_path))

        return findings