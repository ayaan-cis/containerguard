"""
Syft integration utilities for ContainerGuard.

Syft is a tool for generating Software Bill of Materials (SBOM) from container images.
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


async def generate_sbom(target: str, options: Optional[Dict] = None) -> str:
    """
    Generate a Software Bill of Materials (SBOM) for a target using Syft.

    Args:
        target: The target to generate SBOM for (image, directory, file)
        options: Syft options

    Returns:
        JSON output from Syft
    """
    options = options or {}

    # Check if Syft is installed
    if not shutil.which("syft"):
        raise RuntimeError(
            "Syft not found. Please install Syft: https://github.com/anchore/syft#installation")

    # Build command
    cmd = ["syft", target]

    # Set output format
    output_format = options.get("output_format", "json")
    cmd.extend(["--output", output_format])

    # Add additional options
    if options.get("scope"):
        cmd.extend(["--scope", options.get("scope")])

    # Run Syft
    try:
        logger.debug(f"Running Syft command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            if "no such image" in error_message.lower():
                raise ValueError(f"Target not found: {target}")
            else:
                raise RuntimeError(f"Syft SBOM generation failed: {error_message}")

        return stdout.decode("utf-8")

    except asyncio.CancelledError:
        logger.warning("Syft SBOM generation was cancelled")
        raise
    except Exception as e:
        logger.error(f"Error running Syft: {e}")
        raise


async def generate_sbom_for_image(image_name: str, options: Optional[Dict] = None) -> str:
    """
    Generate a Software Bill of Materials (SBOM) for a container image.

    Args:
        image_name: Name of the container image
        options: Syft options

    Returns:
        JSON output from Syft
    """
    return await generate_sbom(image_name, options)


async def generate_sbom_for_directory(directory: str, options: Optional[Dict] = None) -> str:
    """
    Generate a Software Bill of Materials (SBOM) for a directory.

    Args:
        directory: Path to the directory
        options: Syft options

    Returns:
        JSON output from Syft
    """
    # Check if directory exists
    if not os.path.isdir(directory):
        raise ValueError(f"Directory not found: {directory}")

    return await generate_sbom(f"dir:{directory}", options)


async def generate_sbom_for_file(file_path: str, options: Optional[Dict] = None) -> str:
    """
    Generate a Software Bill of Materials (SBOM) for a file.

    Args:
        file_path: Path to the file
        options: Syft options

    Returns:
        JSON output from Syft
    """
    # Check if file exists
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path}")

    return await generate_sbom(f"file:{file_path}", options)


async def get_syft_version() -> str:
    """
    Get the installed Syft version.

    Returns:
        Syft version string
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "syft", "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        version_output = stdout.decode("utf-8").strip()

        # Extract version number
        import re
        match = re.search(r"Version:\s+([0-9.]+)", version_output)
        if match:
            return match.group(1)
        else:
            return version_output

    except Exception as e:
        logger.error(f"Error getting Syft version: {e}")
        return "unknown"


async def convert_sbom_format(sbom_json: str, output_format: str) -> str:
    """
    Convert a Syft SBOM from JSON to another format.

    Args:
        sbom_json: SBOM in JSON format
        output_format: Target format (spdx, cyclonedx, etc.)

    Returns:
        SBOM in the requested format
    """
    # Save JSON to temporary file
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w") as temp_file:
        temp_file.write(sbom_json)
        temp_file.flush()

        # Run syft convert command
        cmd = ["syft", "convert", temp_file.name, "--output", output_format]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode("utf-8")
            raise RuntimeError(f"Syft conversion failed: {error_message}")

        return stdout.decode("utf-8")


async def parse_syft_sbom(sbom_json: str) -> Dict:
    """
    Parse Syft SBOM JSON output into a more usable format.

    Args:
        sbom_json: SBOM in JSON format

    Returns:
        Dictionary with parsed SBOM data
    """
    try:
        data = json.loads(sbom_json)

        # Extract packages
        packages = []
        for artifact in data.get("artifacts", []):
            package = {
                "name": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "type": artifact.get("type", ""),
                "foundBy": artifact.get("foundBy", ""),
                "locations": artifact.get("locations", []),
                "licenses": artifact.get("licenses", []),
                "language": artifact.get("language", ""),
                "cpes": artifact.get("cpes", []),
                "purl": artifact.get("purl", ""),
                "metadataType": artifact.get("metadataType", ""),
                "metadata": artifact.get("metadata", {}),
            }
            packages.append(package)

        # Extract source information
        source = data.get("source", {})

        # Create a summary
        summary = {
            "total_packages": len(packages),
            "package_types": {},
            "languages": {},
            "licenses": set(),
        }

        # Calculate statistics
        for package in packages:
            # Count by package type
            pkg_type = package["type"]
            if pkg_type not in summary["package_types"]:
                summary["package_types"][pkg_type] = 0
            summary["package_types"][pkg_type] += 1

            # Count by language
            language = package["language"]
            if language:
                if language not in summary["languages"]:
                    summary["languages"][language] = 0
                summary["languages"][language] += 1

            # Collect unique licenses
            for license in package["licenses"]:
                summary["licenses"].add(license)

        # Convert set to list for JSON serialization
        summary["licenses"] = list(summary["licenses"])

        return {
            "summary": summary,
            "packages": packages,
            "source": source,
            "metadata": {
                "syft_version": data.get("descriptor", {}).get("version", ""),
                "schema_version": data.get("descriptor", {}).get("schemaVersion", ""),
                "scan_time": data.get("descriptor", {}).get("timestamp", ""),
            }
        }

    except json.JSONDecodeError:
        logger.error("Failed to parse Syft output as JSON")
        return {"error": "Invalid JSON output"}
    except Exception as e:
        logger.error(f"Error parsing Syft SBOM: {e}")
        return {"error": str(e)}


async def find_packages_with_license(sbom_json: str, license_pattern: str) -> List[Dict]:
    """
    Find packages with a specific license in a Syft SBOM.

    Args:
        sbom_json: SBOM in JSON format
        license_pattern: License pattern to search for (regex)

    Returns:
        List of packages with matching licenses
    """
    try:
        import re
        data = json.loads(sbom_json)

        matching_packages = []
        for artifact in data.get("artifacts", []):
            for license in artifact.get("licenses", []):
                if re.search(license_pattern, license, re.IGNORECASE):
                    matching_packages.append({
                        "name": artifact.get("name", ""),
                        "version": artifact.get("version", ""),
                        "type": artifact.get("type", ""),
                        "license": license,
                    })
                    break  # Only add each package once

        return matching_packages

    except Exception as e:
        logger.error(f"Error finding packages with license: {e}")
        return []


async def find_outdated_packages(sbom_json: str) -> List[Dict]:
    """
    Identify potentially outdated packages in a Syft SBOM.

    This is a placeholder implementation. In a real-world scenario,
    this would require external package repository data.

    Args:
        sbom_json: SBOM in JSON format

    Returns:
        List of potentially outdated packages
    """
    # In a real implementation, this would check against package databases
    # For now, return an empty list as a placeholder
    return []


def sbom_to_csv(parsed_sbom: Dict) -> str:
    """
    Convert a parsed SBOM to CSV format.

    Args:
        parsed_sbom: Parsed SBOM dictionary

    Returns:
        CSV string
    """
    try:
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(["Name", "Version", "Type", "Language", "Licenses", "PURL"])

        # Write packages
        for package in parsed_sbom.get("packages", []):
            writer.writerow([
                package.get("name", ""),
                package.get("version", ""),
                package.get("type", ""),
                package.get("language", ""),
                ", ".join(package.get("licenses", [])),
                package.get("purl", ""),
            ])

        return output.getvalue()

    except Exception as e:
        logger.error(f"Error converting SBOM to CSV: {e}")
        return ""