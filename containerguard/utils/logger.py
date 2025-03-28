"""
Logging utilities for ContainerGuard.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def setup_logging(log_level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """
    Set up logging configuration.

    Args:
        log_level: Logging level
        log_file: Path to log file (if None, logs to stderr only)
    """
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Create console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Create file handler if requested
    if log_file:
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        # Create rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        root_logger.addHandler(file_handler)

    # Suppress verbose logging from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_log_level(level: int) -> None:
    """
    Set the log level for the root logger.

    Args:
        level: Logging level
    """
    logging.getLogger().setLevel(level)

    # Update all handlers
    for handler in logging.getLogger().handlers:
        handler.setLevel(level)


def log_environment_info() -> None:
    """Log information about the environment."""
    logger = logging.getLogger(__name__)

    try:
        import platform
        import sys

        logger.info(f"Python version: {sys.version}")
        logger.info(f"Platform: {platform.platform()}")
        logger.info(f"System: {platform.system()} {platform.release()}")

        # Log Docker version if available
        try:
            import docker
            client = docker.from_env()
            version = client.version()
            logger.info(f"Docker version: {version.get('Version', 'unknown')}")
        except Exception as e:
            logger.warning(f"Failed to get Docker version: {e}")

        # Log Trivy version if available
        try:
            import subprocess
            result = subprocess.run(["trivy", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Trivy version: {result.stdout.strip()}")
            else:
                logger.warning("Trivy not found")
        except Exception as e:
            logger.warning(f"Failed to get Trivy version: {e}")

    except Exception as e:
        logger.warning(f"Failed to log environment info: {e}")