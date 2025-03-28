"""
Secrets scanner module for detecting credentials and sensitive information in containers.
"""
import asyncio
import json
import logging
import os
import re
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from containerguard.scanner.base import BaseScanner, Finding, ScanResult

logger = logging.getLogger(__name__)


class SecretsScanner(BaseScanner):
    """
    Scanner for detecting secrets and sensitive information in container images and files.

    This scanner looks for patterns of API keys, passwords, tokens, and other sensitive
    information that should not be included in container images or configuration files.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the secrets scanner.

        Args:
            config: Scanner configuration
        """
        super().__init__("secrets", config)

        # Load secret patterns
        self.patterns = self._load_secret_patterns()

        # Configure scanner behavior
        self.severity_threshold = self.config.get("severity_threshold", "medium")
        self.max_findings = self.config.get("max_findings", 100)
        self.scan_env_vars = self.config.get("scan_env_vars", True)
        self.scan_comments = self.config.get("scan_comments", True)

        logger.info(f"Initialized secrets scanner with {len(self.patterns)} patterns")

    def _load_secret_patterns(self) -> List[Dict[str, Any]]:
        """
        Load the default secret detection patterns.

        Returns:
            List of pattern definitions
        """
        # These are hardcoded patterns, but in a real implementation
        # they would be loaded from a patterns directory or database
        return [
            # API keys
            {
                "id": "CG-SECRET-001",
                "name": "Generic API Key",
                "pattern": r"(?i)(api[_-]?key|apikey)[ :='\"]([A-Za-z0-9]{16,64})",
                "severity": "high",
                "description": "API key found in code or configuration",
                "recommendation": "Remove hardcoded API keys. Use environment variables or a secrets management system.",
                "category": "secret",
                "references": [
                    "https://12factor.net/config",
                ],
                "ignore_case": True,
            },
            # AWS keys
            {
                "id": "CG-SECRET-002",
                "name": "AWS Access Key",
                "pattern": r"(?i)(aws)?_?access_?key_?id[ :='\"]([A-Z0-9]{20})",
                "severity": "critical",
                "description": "AWS access key ID found in code or configuration",
                "recommendation": "Remove hardcoded AWS credentials. Use IAM roles or environment variables.",
                "category": "secret",
                "references": [
                    "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
                ],
                "ignore_case": True,
            },
            {
                "id": "CG-SECRET-003",
                "name": "AWS Secret Key",
                "pattern": r"(?i)(aws)?_?secret_?access_?key[ :='\"]([A-Za-z0-9/+]{40})",
                "severity": "critical",
                "description": "AWS secret access key found in code or configuration",
                "recommendation": "Remove hardcoded AWS credentials. Use IAM roles or environment variables.",
                "category": "secret",
                "references": [
                    "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
                ],
                "ignore_case": True,
            },
            # Password patterns
            {
                "id": "CG-SECRET-004",
                "name": "Hardcoded Password",
                "pattern": r"(?i)(password|passwd|pwd)[ :='\"]([^'\"]{8,64})",
                "severity": "high",
                "description": "Hardcoded password found in code or configuration",
                "recommendation": "Remove hardcoded passwords. Use environment variables or a secrets management system.",
                "category": "secret",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                ],
                "ignore_case": True,
            },
            # Database connection strings
            {
                "id": "CG-SECRET-005",
                "name": "Database Connection String",
                "pattern": r"(?i)(jdbc:(?:mysql|postgresql|oracle):(?:.*(?:user|username|userid|passwd|password|pwd)(?:=|:)[^&;]+))",
                "severity": "high",
                "description": "Database connection string with credentials found",
                "recommendation": "Remove hardcoded database credentials. Use environment variables.",
                "category": "secret",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
                ],
                "ignore_case": True,
            },
            # Private keys
            {
                "id": "CG-SECRET-006",
                "name": "Private Key",
                "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----",
                "severity": "critical",
                "description": "Private key found in code or configuration",
                "recommendation": "Remove private keys from code. Store keys securely and outside of version control.",
                "category": "secret",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
                ],
                "ignore_case": False,
            },
            # OAuth tokens
            {
                "id": "CG-SECRET-007",
                "name": "OAuth Token",
                "pattern": r"(?i)(oauth|auth)[ ._-]?token[ :='\"]([A-Za-z0-9_.-]{30,64})",
                "severity": "high",
                "description": "OAuth token found in code or configuration",
                "recommendation": "Remove hardcoded OAuth tokens. Use a secure token storage mechanism.",
                "category": "secret",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                ],
                "ignore_case": True,
            },
            # GitHub tokens
            {
                "id": "CG-SECRET-008",
                "name": "GitHub Token",
                "pattern": r"(?i)github[_\-\.]?token[ :='\"]([A-Za-z0-9_]{35,40})",
                "severity": "high",
                "description": "GitHub token found in code or configuration",
                "recommendation": "Remove hardcoded GitHub tokens. Use GitHub Actions secrets or environment variables.",
                "category": "secret",
                "references": [
                    "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
                ],
                "ignore_case": True,
            },
            # Docker registry credentials
            {
                "id": "CG-SECRET-009",
                "name": "Docker Registry Credentials",
                "pattern": r"(?i)docker[ ._-]?(?:registry|hub)[ ._-]?(?:password|token|key)[ :='\"]([^'\"]{8,64})",
                "severity": "high",
                "description": "Docker registry credentials found in code or configuration",
                "recommendation": "Remove hardcoded Docker registry credentials. Use Docker credential helpers.",
                "category": "secret",
                "references": [
                    "https://docs.docker.com/engine/reference/commandline/login/#credentials-store",
                ],
                "ignore_case": True,
            },
            # Generic token
            {
                "id": "CG-SECRET-010",
                "name": "Generic Secret Token",
                "pattern": r"(?i)(?:secret|token|api|key|passwd|password|access)[ ._-]?(?:key|token|passw?(?:or)?d|secret)[ :='\"]([A-Za-z0-9-_.=]{8,64})",
                "severity": "medium",
                "description": "Potential secret token found in code or configuration",
                "recommendation": "Remove hardcoded secrets. Use environment variables or a secrets management system.",
                "category": "secret",
                "references": [
                    "https://12factor.net/config",
                ],
                "ignore_case": True,
            },
        ]

    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a container image or directory for secrets.

        Args:
            target: Container image name, directory, or file path
            options: Additional scan options

        Returns:
            ScanResult containing secret findings
        """
        options = options or {}
        logger.info(f"Scanning {target} for secrets")
        start_time = time.time()

        findings = []

        # Check if target is a directory
        if os.path.isdir(target):
            findings.extend(await self._scan_directory(target))
        # Check if target is a file
        elif os.path.isfile(target):
            findings.extend(await self._scan_file(target))
        # Assume target is a Docker image
        else:
            findings.extend(await self._scan_docker_image(target))

        # Limit findings based on configuration
        findings = findings[:self.max_findings]

        # Create scan result
        return ScanResult(
            scanner_name=self.name,
            target=target,
            findings=findings,
            summary={
                "secrets_found": len(findings),
                "scan_target": target,
                "patterns_checked": len(self.patterns),
            },
            scan_time=time.time() - start_time,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={},
        )

    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a specific file for secrets.

        Args:
            file_path: Path to the file to scan
            options: Additional scan options

        Returns:
            ScanResult containing secret findings
        """
        options = options or {}
        logger.info(f"Scanning file {file_path} for secrets")
        start_time = time.time()

        findings = await self._scan_file(file_path)

        # Limit findings based on configuration
        findings = findings[:self.max_findings]

        # Create scan result
        return ScanResult(
            scanner_name=self.name,
            target=file_path,
            findings=findings,
            summary={
                "secrets_found": len(findings),
                "scan_target": file_path,
                "patterns_checked": len(self.patterns),
            },
            scan_time=time.time() - start_time,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={},
        )

    async def _scan_directory(self, directory: str) -> List[Finding]:
        """
        Scan a directory for secrets.

        Args:
            directory: Path to the directory to scan

        Returns:
            List of findings
        """
        findings = []

        for root, _, files in os.walk(directory):
            for file in files:
                # Skip binary files and certain directories
                if self._should_skip_file(file):
                    continue

                file_path = os.path.join(root, file)
                file_findings = await self._scan_file(file_path)
                findings.extend(file_findings)

        return findings

    async def _scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a file for secrets.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings
        """
        findings = []

        try:
            # Skip binary files
            if self._is_binary_file(file_path):
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Scan file content for secrets
            line_findings = self._scan_content(content, file_path)
            findings.extend(line_findings)

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")

        return findings

    async def _scan_docker_image(self, image_name: str) -> List[Finding]:
        """
        Scan a Docker image for secrets.

        Args:
            image_name: Name of the Docker image to scan

        Returns:
            List of findings
        """
        findings = []

        try:
            import docker
            from containerguard.utils.docker import get_image_info, extract_layers

            client = docker.from_env()

            # Check if image exists
            try:
                client.images.get(image_name)
            except docker.errors.ImageNotFound:
                logger.warning(f"Image {image_name} not found. Attempting to pull...")
                try:
                    client.images.pull(image_name)
                except Exception as pull_error:
                    logger.error(f"Failed to pull image {image_name}: {pull_error}")
                    return findings

            # Get image information including labels and environment variables
            image_info = get_image_info(image_name)

            # Extract and scan environment variables
            if self.scan_env_vars and "config" in image_info:
                env_vars = image_info["config"].get("Env", [])
                for env_var in env_vars:
                    env_findings = self._scan_content(env_var, f"{image_name}:env_vars")
                    findings.extend(env_findings)

            # In a real implementation, we would extract and scan image layers
            # This is a simplified version
            with tempfile.TemporaryDirectory() as temp_dir:
                # Here we would extract image contents to temp_dir and scan
                # For now, just return what we found from env vars
                pass

        except ImportError:
            logger.error("Docker library not available. Cannot scan Docker image.")
        except Exception as e:
            logger.error(f"Error scanning Docker image {image_name}: {e}")

        return findings

    def _scan_content(self, content: str, location: str) -> List[Finding]:
        """
        Scan text content for secrets.

        Args:
            content: Text content to scan
            location: Location of the content (file path or description)

        Returns:
            List of findings
        """
        findings = []

        # Skip empty content
        if not content:
            return findings

        # Check content against each pattern
        for pattern_def in self.patterns:
            pattern = pattern_def["pattern"]
            flags = re.IGNORECASE if pattern_def.get("ignore_case", False) else 0

            for match in re.finditer(pattern, content, flags):
                secret_value = match.group(1) if len(match.groups()) == 1 else match.group(2)

                # Calculate line number
                line_num = content[:match.start()].count('\n') + 1

                # Create context (redacted)
                context = content[max(0, match.start() - 20):match.start()] + \
                          "[REDACTED]" + \
                          content[match.end():min(len(content), match.end() + 20)]

                # Create finding
                finding = Finding(
                    id=pattern_def["id"],
                    title=pattern_def["name"],
                    description=pattern_def["description"],
                    severity=pattern_def["severity"],
                    category="secret",
                    resource=os.path.basename(location),
                    location=f"{location}:{line_num}",
                    recommendation=pattern_def["recommendation"],
                    references=pattern_def["references"],
                    metadata={
                        "pattern_id": pattern_def["id"],
                        "context": context,
                        "line": line_num,
                    },
                )
                findings.append(finding)

        return findings

    def _is_binary_file(self, file_path: str) -> bool:
        """
        Check if a file is binary.

        Args:
            file_path: Path to the file to check

        Returns:
            True if the file is binary, False otherwise
        """
        try:
            # Check file extension first
            binary_extensions = {
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp',  # Images
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',  # Documents
                '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',  # Archives
                '.bin', '.exe', '.dll', '.so', '.dylib', '.class',  # Binaries
                '.pyc', '.pyo', '.pyd',  # Python bytecode
                '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav',  # Media
            }
            if os.path.splitext(file_path.lower())[1] in binary_extensions:
                return True

            # Read the start of the file and look for binary characters
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
                return bool(chunk.translate(None, text_chars))
        except Exception as e:
            logger.error(f"Error checking if file is binary {file_path}: {e}")
            return True

    def _should_skip_file(self, filename: str) -> bool:
        """
        Check if a file should be skipped.

        Args:
            filename: Name of the file to check

        Returns:
            True if the file should be skipped, False otherwise
        """
        # Skip hidden files
        if filename.startswith('.'):
            return True

        # Skip compiled files and binaries
        skip_extensions = {
            '.pyc', '.pyo', '.pyd',  # Python bytecode
            '.class', '.jar',  # Java bytecode
            '.o', '.a', '.so', '.dll', '.dylib',  # Compiled object files
            '.exe', '.bin',  # Executables
            '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',  # Archives
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',  # Images
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav',  # Media
        }
        if os.path.splitext(filename.lower())[1] in skip_extensions:
            return True

        return False