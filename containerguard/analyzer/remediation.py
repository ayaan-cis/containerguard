"""
Remediation generator module for creating actionable security recommendations.
"""
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from containerguard.scanner.base import Finding, ScanResult

logger = logging.getLogger(__name__)


class RemediationGenerator:
    """
    Generator for security issue remediation suggestions.

    This module analyzes security findings and generates detailed,
    actionable remediation guidance.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the remediation generator.

        Args:
            config: Generator configuration
        """
        self.config = config or {}

        # Load remediation templates
        self.templates = self._load_remediation_templates()

        logger.info(f"Initialized remediation generator with {len(self.templates)} templates")

    def generate_remediations(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """
        Generate remediation suggestions for a list of findings.

        Args:
            findings: List of security findings

        Returns:
            Dictionary mapping finding IDs to remediation details
        """
        remediations = {}

        for finding in findings:
            remediation = self.generate_remediation(finding)
            if remediation:
                remediations[finding.id] = remediation

        return remediations

    def generate_remediation(self, finding: Finding) -> Optional[Dict[str, Any]]:
        """
        Generate a remediation suggestion for a single finding.

        Args:
            finding: Security finding

        Returns:
            Remediation details or None if no remediation is available
        """
        # Check if finding already has a recommendation
        if finding.recommendation and finding.recommendation != "No fix available":
            return {
                "title": "Fix Recommendation",
                "description": finding.recommendation,
                "steps": self._parse_recommendation_steps(finding.recommendation),
                "code_example": self._generate_code_example(finding),
                "references": finding.references,
            }

        # Look for a template matching the finding
        template = self._find_matching_template(finding)
        if template:
            return {
                "title": template.get("title", "Fix Recommendation"),
                "description": template.get("description", ""),
                "steps": template.get("steps", []),
                "code_example": template.get("code_example", ""),
                "references": template.get("references", []),
            }

        # Generate generic recommendation based on finding type
        return self._generate_generic_remediation(finding)

    def _load_remediation_templates(self) -> List[Dict[str, Any]]:
        """
        Load remediation templates.

        Returns:
            List of remediation templates
        """
        # In a full implementation, these would be loaded from a database or file
        # For this example, we'll define some common templates inline
        return [
            # User-related remediations
            {
                "id": "CG-DOCKER-001",
                "title": "Use Non-Root User",
                "description": "Running containers as root increases the risk of container breakout and privilege escalation. Use a non-root user to run your containers.",
                "steps": [
                    "Add a non-root user to your Dockerfile",
                    "Set appropriate file permissions",
                    "Use the USER instruction to switch to the non-root user",
                ],
                "code_example": """# Create a non-root user
RUN addgroup --system --gid 1001 appgroup && \\
    adduser --system --uid 1001 --gid 1001 appuser

# Set appropriate permissions
COPY --chown=appuser:appgroup . /app

# Switch to non-root user
USER appuser""",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-2-set-a-user",
                ],
            },
            # Privilege-related remediations
            {
                "id": "CG-DOCKER-002",
                "title": "Avoid Privileged Mode",
                "description": "Running containers in privileged mode disables container isolation and gives the container full access to the host. This should be avoided in most cases.",
                "steps": [
                    "Remove the 'privileged: true' option from your Docker Compose file",
                    "Use specific capabilities instead of privileged mode if needed",
                    "Evaluate if your container actually needs elevated privileges",
                ],
                "code_example": """# Instead of:
privileged: true

# Use specific capabilities:
cap_add:
  - SPECIFIC_CAPABILITY_NEEDED

# Or better yet, remove privileged mode entirely""",
                "references": [
                    "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
                ],
            },
            # Network-related remediations
            {
                "id": "CG-DOCKER-003",
                "title": "Secure Exposed Ports",
                "description": "Exposing sensitive ports can allow unauthorized access to services. Avoid exposing sensitive ports or implement proper authentication and encryption.",
                "steps": [
                    "Remove unnecessary EXPOSE instructions from your Dockerfile",
                    "Use non-standard ports for services",
                    "Implement proper authentication for exposed services",
                    "Use a reverse proxy or API gateway to add an additional security layer",
                ],
                "code_example": """# Instead of:
EXPOSE 22 3306 27017

# Expose only necessary ports:
EXPOSE 8080

# Or use non-standard ports:
EXPOSE 8306  # For MySQL instead of 3306""",
                "references": [
                    "https://docs.docker.com/engine/reference/builder/#expose",
                ],
            },
            # Resource limit remediations
            {
                "id": "CG-DOCKER-004",
                "title": "Set Resource Limits",
                "description": "Running containers without resource limits can lead to resource exhaustion attacks, where a single container consumes all system resources and affects other containers or the host system.",
                "steps": [
                    "Add memory and CPU limits to your Docker Compose file",
                    "Set appropriate limits based on your application's needs",
                    "Consider using soft limits (reservations) alongside hard limits",
                ],
                "code_example": """services:
  webapp:
    image: myapp:latest
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M""",
                "references": [
                    "https://docs.docker.com/compose/compose-file/compose-file-v3/#resources",
                ],
            },
            # Security options remediations
            {
                "id": "CG-DOCKER-005",
                "title": "Enable Security Options",
                "description": "Docker provides several security options like no-new-privileges, seccomp, and AppArmor profiles that can significantly improve container security.",
                "steps": [
                    "Add security_opt to your Docker Compose file",
                    "Enable no-new-privileges to prevent privilege escalation",
                    "Use seccomp profiles to restrict system calls",
                    "Consider using AppArmor or SELinux profiles",
                ],
                "code_example": """services:
  webapp:
    image: myapp:latest
    security_opt:
      - no-new-privileges:true
      - seccomp:default
      - apparmor:default""",
                "references": [
                    "https://docs.docker.com/engine/reference/run/#security-configuration",
                ],
            },
            # Base image remediations
            {
                "id": "CG-DOCKER-006",
                "title": "Use Specific Image Tags",
                "description": "Using the 'latest' tag for base images can lead to unexpected changes and introduce new vulnerabilities when images are updated.",
                "steps": [
                    "Use specific version tags for base images",
                    "Consider using SHA256 digests for maximum reproducibility",
                    "Regularly update your base images with a controlled process",
                ],
                "code_example": """# Instead of:
FROM python:latest

# Use specific version tag:
FROM python:3.9.7-slim

# Or even better, use digest:
FROM python@sha256:d3f4a9bc21f897894e5d2f4615b962c1d3203c239d4acf8abe254ea335563f8e""",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from",
                ],
            },
            # File permission remediations
            {
                "id": "CG-DOCKER-007",
                "title": "Secure File Permissions",
                "description": "Overly permissive file permissions can allow unauthorized file access and potentially lead to security breaches.",
                "steps": [
                    "Avoid using chmod 777 or world-writable directories",
                    "Use least privilege principle for file permissions",
                    "Set appropriate ownership with chown",
                ],
                "code_example": """# Instead of:
RUN chmod 777 /app

# Use more restrictive permissions:
RUN mkdir /app && chown appuser:appgroup /app && chmod 750 /app""",
                "references": [
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
                ],
            },
        ]

    def _find_matching_template(self, finding: Finding) -> Optional[Dict[str, Any]]:
        """
        Find a remediation template matching the finding.

        Args:
            finding: Security finding

        Returns:
            Matching remediation template or None
        """
        # Look for exact ID match
        for template in self.templates:
            if template.get("id") == finding.id:
                return template

        # Look for category match
        category_templates = [t for t in self.templates if t.get("category") == finding.category]
        if category_templates:
            return category_templates[0]

        return None

    def _parse_recommendation_steps(self, recommendation: str) -> List[str]:
        """
        Parse recommendation text into discrete steps.

        Args:
            recommendation: Recommendation text

        Returns:
            List of steps
        """
        # Split by numbered list items
        numbered_steps = re.findall(r'\d+\.\s*(.*?)(?=\d+\.|$)', recommendation, re.DOTALL)
        if numbered_steps and len(numbered_steps) > 1:
            return [step.strip() for step in numbered_steps]

        # Split by bullet points
        bullet_steps = re.findall(r'[\*\-•]\s*(.*?)(?=[\*\-•]|$)', recommendation, re.DOTALL)
        if bullet_steps and len(bullet_steps) > 1:
            return [step.strip() for step in bullet_steps]

        # Split by sentences if we couldn't find a list
        if len(recommendation) > 100:  # Only split longer recommendations
            sentences = re.findall(r'[^.!?]+[.!?]', recommendation)
            if sentences and len(sentences) > 1:
                return [s.strip() for s in sentences]

        # Return as a single step if we couldn't parse it
        return [recommendation]

    def _generate_code_example(self, finding: Finding) -> str:
        """
        Generate a code example based on the finding.

        Args:
            finding: Security finding

        Returns:
            Code example string
        """
        # Check if the finding has a code example in metadata
        if finding.metadata and finding.metadata.get("code_example"):
            return finding.metadata.get("code_example")

        # Generate based on category and resource
        if finding.category == "misconfiguration" and "Dockerfile" in finding.resource:
            if finding.id == "CG-DOCKER-001":
                return """# Add this to your Dockerfile:
RUN addgroup --system --gid 1001 appgroup && \\
    adduser --system --uid 1001 --gid 1001 appuser
COPY --chown=appuser:appgroup . /app
USER appuser"""
            elif finding.id == "CG-DOCKER-006":
                return """# Instead of:
FROM python:latest

# Use specific version:
FROM python:3.9-slim"""

        elif finding.category == "misconfiguration" and "docker-compose" in finding.resource:
            if finding.id == "CG-DOCKER-002":
                return """# Remove privileged mode:
services:
  webapp:
    # privileged: true  # Remove this line

    # If specific capabilities are needed, use:
    cap_add:
      - NET_ADMIN  # Only add necessary capabilities"""
            elif finding.id == "CG-DOCKER-004":
                return """# Add resource limits:
services:
  webapp:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: '512M'"""

        # Default empty string if no matching code example
        return ""

    def _generate_generic_remediation(self, finding: Finding) -> Dict[str, Any]:
        """
        Generate a generic remediation based on finding category.

        Args:
            finding: Security finding

        Returns:
            Generic remediation details
        """
        if finding.category == "vulnerability":
            return {
                "title": "Update Vulnerable Package",
                "description": f"The package {finding.resource} contains a known vulnerability. Update to a non-vulnerable version.",
                "steps": [
                    f"Update {finding.resource} to the latest secure version",
                    "Run a full test suite to ensure compatibility with the updated package",
                    "Consider implementing automatic security updates for dependencies",
                ],
                "code_example": "",  # No specific code example for generic vulnerabilities
                "references": finding.references,
            }

        elif finding.category == "misconfiguration":
            return {
                "title": "Fix Security Misconfiguration",
                "description": f"The resource {finding.resource} has a security misconfiguration that should be addressed.",
                "steps": [
                    "Review the current configuration",
                    "Update the configuration according to security best practices",
                    "Implement automated configuration checking in your CI/CD pipeline",
                ],
                "code_example": "",  # No specific code example for generic misconfigurations
                "references": finding.references,
            }

        elif finding.category == "secret":
            return {
                "title": "Remove Exposed Secret",
                "description": f"A sensitive secret has been exposed in {finding.resource}.",
                "steps": [
                    "Remove the exposed secret from your code or configuration",
                    "Rotate the compromised credentials immediately",
                    "Use environment variables or a secrets management system",
                    "Add the file containing secrets to .gitignore to prevent future exposure",
                ],
                "code_example": """# Instead of hardcoded secrets:
password = "super_secret_password"

# Use environment variables:
import os
password = os.environ.get("DB_PASSWORD")""",
                "references": [
                    "https://12factor.net/config",
                    "https://docs.docker.com/engine/swarm/secrets/",
                ],
            }

        # Default remediation
        return {
            "title": "Security Issue Remediation",
            "description": finding.recommendation or "Address the security issue found.",
            "steps": [
                "Review the details of the security finding",
                "Address the issue according to security best practices",
                "Verify the fix with a follow-up scan",
            ],
            "code_example": "",
            "references": finding.references,
        }