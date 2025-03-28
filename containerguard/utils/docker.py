"""
Docker utilities for ContainerGuard.
"""
import logging
import subprocess
from typing import Dict, List, Optional, Tuple

import docker

logger = logging.getLogger(__name__)


def is_valid_image(image_name: str) -> bool:
    """
    Check if a Docker image exists locally or can be pulled.

    Args:
        image_name: Name of the Docker image to check

    Returns:
        True if the image exists or can be pulled, False otherwise
    """
    try:
        client = docker.from_env()

        # Check if image exists locally
        try:
            client.images.get(image_name)
            return True
        except docker.errors.ImageNotFound:
            pass

        # Try to pull the image
        try:
            client.images.pull(image_name)
            return True
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logger.warning(f"Error pulling image {image_name}: {e}")
            return False

    except Exception as e:
        logger.error(f"Error checking Docker image: {e}")
        return False


def get_image_info(image_name: str) -> Dict:
    """
    Get information about a Docker image.

    Args:
        image_name: Name of the Docker image

    Returns:
        Dictionary containing image information
    """
    try:
        client = docker.from_env()
        image = client.images.get(image_name)

        # Extract relevant information
        info = {
            "id": image.id,
            "short_id": image.short_id,
            "tags": image.tags,
            "created": image.attrs.get("Created"),
            "os": image.attrs.get("Os"),
            "architecture": image.attrs.get("Architecture"),
            "size": image.attrs.get("Size"),
            "virtual_size": image.attrs.get("VirtualSize"),
            "config": image.attrs.get("Config", {}),
        }

        return info

    except Exception as e:
        logger.error(f"Error getting image info for {image_name}: {e}")
        return {}


def extract_layers(image_name: str) -> List[str]:
    """
    Extract layers from a Docker image.

    Args:
        image_name: Name of the Docker image

    Returns:
        List of layer IDs
    """
    try:
        client = docker.from_env()
        image = client.images.get(image_name)

        # Get layer IDs
        layers = image.attrs.get("RootFS", {}).get("Layers", [])
        return layers

    except Exception as e:
        logger.error(f"Error extracting layers from {image_name}: {e}")
        return []


def pull_image(image_name: str) -> bool:
    """
    Pull a Docker image.

    Args:
        image_name: Name of the Docker image to pull

    Returns:
        True if successful, False otherwise
    """
    try:
        client = docker.from_env()
        client.images.pull(image_name)
        return True

    except Exception as e:
        logger.error(f"Error pulling image {image_name}: {e}")
        return False


def get_container_config(image_name: str) -> Dict:
    """
    Get container configuration from a Docker image.

    Args:
        image_name: Name of the Docker image

    Returns:
        Dictionary containing container configuration
    """
    try:
        client = docker.from_env()
        image = client.images.get(image_name)

        # Extract container configuration
        config = image.attrs.get("Config", {})
        return config

    except Exception as e:
        logger.error(f"Error getting container config for {image_name}: {e}")
        return {}


def get_image_history(image_name: str) -> List[Dict]:
    """
    Get the build history of a Docker image.

    Args:
        image_name: Name of the Docker image

    Returns:
        List of history items
    """
    try:
        client = docker.from_env()
        image = client.images.get(image_name)

        # Get history
        history = image.history()
        return history

    except Exception as e:
        logger.error(f"Error getting image history for {image_name}: {e}")
        return []


def run_docker_command(command: List[str], capture_output: bool = True) -> Tuple[int, str, str]:
    """
    Run a Docker command using subprocess.

    Args:
        command: Docker command to run as a list of strings
        capture_output: Whether to capture command output

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        if capture_output:
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            return result.returncode, result.stdout, result.stderr
        else:
            result = subprocess.run(command, check=False)
            return result.returncode, "", ""

    except Exception as e:
        logger.error(f"Error running Docker command {' '.join(command)}: {e}")
        return -1, "", str(e)