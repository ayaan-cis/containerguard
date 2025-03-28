"""
Grype integration utilities for ContainerGuard.

Grype is a vulnerability scanner for container images and filesystems.
"""
import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


async def scan_image(image_name: str, options: Optional[Dict] = None) -> str:
    """
    Scan a Docker image using Grype.

    Args:
        image_name: Name of the Docker image to scan
        options: Grype scan options

    Returns:
        JSON output from Grype
    """
    options = options or {}

    # Check if Grype is installed
    if not shutil.which("grype"):
        raise RuntimeError(
            "Grype not found. Please install Grype: https://github.com/anchore/grype#installation")

    # Build command
    cmd = ["grype", image_name]

    # Add options
    if options.get("only_fixed", False):
        cmd.append("--only-fixed")

    # Set severity
    severity = options.get("severity", "medium")
    cmd.extend(["--fail-on", severity.lower()])

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--output", output_format])

    # Set the database auto-update behavior
    if options.get("offline_mode", False) or not options.get("update_db", True):
        cmd.append("--db", "none")

    # Run Grype
    try:
        logger.debug(f"Running Grype command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            if "no such image" in error_message.lower():
                raise ValueError(f"Docker image not found: {image_name}")
            else:
                logger.warning(f"Grype scan returned non-zero exit code: {process.returncode}")
                logger.debug(f"Grype stderr: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Grype scan was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Grype scan: {e}")
        raise


async def scan_directory(directory: str, options: Optional[Dict] = None) -> str:
    """
    Scan a directory using Grype.

    Args:
        directory: Path to the directory to scan
        options: Grype scan options

    Returns:
        JSON output from Grype
    """
    options = options or {}

    # Check if Grype is installed
    if not shutil.which("grype"):
        raise RuntimeError(
            "Grype not found. Please install Grype: https://github.com/anchore/grype#installation")

    # Check if directory exists
    if not os.path.isdir(directory):
        raise ValueError(f"Directory not found: {directory}")

    # Build command
    cmd = ["grype", f"dir:{directory}"]

    # Add options
    if options.get("only_fixed", False):
        cmd.append("--only-fixed")

    # Set severity
    severity = options.get("severity", "medium")
    cmd.extend(["--fail-on", severity.lower()])

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--output", output_format])

    # Set the database auto-update behavior
    if options.get("offline_mode", False) or not options.get("update_db", True):
        cmd.append("--db", "none")

    # Run Grype
    try:
        logger.debug(f"Running Grype command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            logger.warning(f"Grype scan returned non-zero exit code: {process.returncode}")
            logger.debug(f"Grype stderr: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Grype scan was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Grype scan: {e}")
        raise


async def scan_file(file_path: str, options: Optional[Dict] = None) -> str:
    """
    Scan a file using Grype.

    Args:
        file_path: Path to the file to scan
        options: Grype scan options

    Returns:
        JSON output from Grype
    """
    options = options or {}

    # Check if Grype is installed
    if not shutil.which("grype"):
        raise RuntimeError(
            "Grype not found. Please install Grype: https://github.com/anchore/grype#installation")

    # Check if file exists
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path}")

    # Build command
    cmd = ["grype", f"file:{file_path}"]

    # Add options
    if options.get("only_fixed", False):
        cmd.append("--only-fixed")

    # Set severity
    severity = options.get("severity", "medium")
    cmd.extend(["--fail-on", severity.lower()])

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--output", output_format])

    # Set the database auto-update behavior
    if options.get("offline_mode", False) or not options.get("update_db", True):
        cmd.append("--db", "none")

    # Run Grype
    try:
        logger.debug(f"Running Grype command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            logger.warning(f"Grype scan returned non-zero exit code: {process.returncode}")
            logger.debug(f"Grype stderr: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Grype scan was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Grype scan: {e}")
        raise


async def get_grype_version() -> str:
    """
    Get the installed Grype version.

    Returns:
        Grype version string
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "grype", "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        version_output = stdout.decode("utf-8").strip()

        # Extract version number
        if "Version:" in version_output:
            import re
            match = re.search(r"Version:\s+([0-9.]+)", version_output)
            if match:
                return match.group(1)

        return version_output

    except Exception as e:
        logger.error(f"Error getting Grype version: {e}")
        return "unknown"


async def update_grype_database() -> bool:
    """
    Update the Grype vulnerability database.

    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info("Updating Grype vulnerability database")
        process = await asyncio.create_subprocess_exec(
            "grype", "db", "update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            logger.error(f"Failed to update Grype database: {error_message}")
            return False

        logger.info("Grype vulnerability database updated successfully")
        return True

    except Exception as e:
        logger.error(f"Error updating Grype database: {e}")
        return False


async def parse_grype_results(json_output: str) -> Dict:
    """
    Parse Grype JSON output into a more usable format.

    Args:
        json_output: JSON output from Grype

    Returns:
        Dictionary with parsed results
    """
    try:
        data = json.loads(json_output)

        # Format may vary by Grype version
        matches = data.get("matches", [])

        # Create a summary
        summary = {
            "total": len(matches),
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
            },
            "fixed_available": 0,
            "unfixed": 0,
        }

        # Process each vulnerability
        vulnerabilities = []
        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            severity = vuln.get("severity", "unknown").lower()
            if severity in summary["severity_counts"]:
                summary["severity_counts"][severity] += 1
            else:
                summary["severity_counts"]["unknown"] += 1

            if match.get("fix", {}).get("versions"):
                summary["fixed_available"] += 1
            else:
                summary["unfixed"] += 1

            # Create a normalized vulnerability object
            vulnerabilities.append({
                "id": vuln.get("id", ""),
                "severity": severity,
                "package_name": artifact.get("name", ""),
                "package_version": artifact.get("version", ""),
                "fixed_version": next(iter(match.get("fix", {}).get("versions", [])), ""),
                "description": vuln.get("description", ""),
                "cvss": vuln.get("cvss", []),
                "urls": vuln.get("urls", []),
                "path": match.get("artifact", {}).get("locations", [{}])[0].get("path", ""),
            })

        return {
            "summary": summary,
            "vulnerabilities": vulnerabilities,
            "source": data.get("source", {}),
            "distro": data.get("distro", {}),
            "metadata": {
                "grype_version": data.get("descriptor", {}).get("version", ""),
                "db_version": data.get("descriptor", {}).get("db", {}).get("version", ""),
                "scan_time": data.get("descriptor", {}).get("timestamp", ""),
            }
        }

    except json.JSONDecodeError:
        logger.error("Failed to parse Grype output as JSON")
        return {"error": "Invalid JSON output"}
    except Exception as e:
        logger.error(f"Error parsing Grype results: {e}")
        return {"error": str(e)}