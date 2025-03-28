"""
Trivy integration utilities for ContainerGuard.
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
    Scan a Docker image using Trivy.

    Args:
        image_name: Name of the Docker image to scan
        options: Trivy scan options

    Returns:
        JSON output from Trivy
    """
    options = options or {}

    # Check if Trivy is installed
    if not shutil.which("trivy"):
        raise RuntimeError(
            "Trivy not found. Please install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")

    # Build command
    cmd = ["trivy", "image"]

    # Add options
    if options.get("offline_mode", False):
        cmd.append("--offline-scan")

    if not options.get("update_db", True):
        cmd.append("--skip-db-update")

    # Set severity
    severity = options.get("severity", "medium")
    cmd.extend(["--severity", severity.upper()])

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--format", output_format])

    # Add image name
    cmd.append(image_name)

    # Run Trivy
    try:
        logger.debug(f"Running Trivy command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            if "No such image" in error_message:
                raise ValueError(f"Docker image not found: {image_name}")
            else:
                raise RuntimeError(f"Trivy scan failed: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Trivy scan was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Trivy scan: {e}")
        raise


async def scan_filesystem(directory: str, options: Optional[Dict] = None) -> str:
    """
    Scan a filesystem directory using Trivy.

    Args:
        directory: Path to the directory to scan
        options: Trivy scan options

    Returns:
        JSON output from Trivy
    """
    options = options or {}

    # Check if Trivy is installed
    if not shutil.which("trivy"):
        raise RuntimeError(
            "Trivy not found. Please install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")

    # Check if directory exists
    if not os.path.isdir(directory):
        raise ValueError(f"Directory not found: {directory}")

    # Build command
    cmd = ["trivy", "filesystem"]

    # Add options
    if options.get("offline_mode", False):
        cmd.append("--offline-scan")

    if not options.get("update_db", True):
        cmd.append("--skip-db-update")

    # Set severity
    severity = options.get("severity", "medium")
    cmd.extend(["--severity", severity.upper()])

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--format", output_format])

    # Add directory path
    cmd.append(directory)

    # Run Trivy
    try:
        logger.debug(f"Running Trivy command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            raise RuntimeError(f"Trivy scan failed: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Trivy scan was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Trivy scan: {e}")
        raise


async def scan_config(config_file: str, options: Optional[Dict] = None) -> str:
    """
    Scan a configuration file using Trivy.

    Args:
        config_file: Path to the configuration file to scan
        options: Trivy scan options

    Returns:
        JSON output from Trivy
    """
    options = options or {}

    # Check if Trivy is installed
    if not shutil.which("trivy"):
        raise RuntimeError(
            "Trivy not found. Please install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")

    # Check if file exists
    if not os.path.isfile(config_file):
        raise ValueError(f"File not found: {config_file}")

    # Build command
    cmd = ["trivy", "config"]

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--format", output_format])

    # Add file path
    cmd.append(config_file)

    # Run Trivy
    try:
        logger.debug(f"Running Trivy command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            raise RuntimeError(f"Trivy config scan failed: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Trivy scan was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Trivy config scan: {e}")
        raise


async def get_trivy_version() -> str:
    """
    Get the installed Trivy version.

    Returns:
        Trivy version string
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "trivy", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        version_output = stdout.decode("utf-8").strip()

        # Extract version number
        version_parts = version_output.split()
        if len(version_parts) >= 2:
            return version_parts[1]
        else:
            return version_output

    except Exception as e:
        logger.error(f"Error getting Trivy version: {e}")
        return "unknown"