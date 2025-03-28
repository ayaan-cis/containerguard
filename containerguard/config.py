"""
Configuration management for ContainerGuard.
"""
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Manager for ContainerGuard configuration.

    This class handles loading, saving, and managing configuration settings
    for the ContainerGuard application.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.

        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = {}

        # Load configuration if path is provided
        if config_path and os.path.exists(config_path):
            self.config = self.load_config(config_path)
        else:
            self.config = self.default_config()

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from a file.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration dictionary
        """
        logger.info(f"Loading configuration from {config_path}")

        try:
            with open(config_path, "r") as f:
                if config_path.endswith(".json"):
                    config = json.load(f)
                elif config_path.endswith((".yaml", ".yml")):
                    config = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported configuration file format: {config_path}")

            # Merge with default configuration to ensure all keys are present
            merged_config = self.default_config()
            self._merge_dicts(merged_config, config)

            logger.debug(f"Loaded configuration: {merged_config}")
            return merged_config

        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            logger.warning("Using default configuration")
            return self.default_config()

    def save_config(self, config_path: Optional[str] = None) -> bool:
        """
        Save configuration to a file.

        Args:
            config_path: Path to configuration file (uses self.config_path if None)

        Returns:
            True if successful, False otherwise
        """
        config_path = config_path or self.config_path
        if not config_path:
            logger.error("No configuration path specified")
            return False

        logger.info(f"Saving configuration to {config_path}")

        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)

            with open(config_path, "w") as f:
                if config_path.endswith(".json"):
                    json.dump(self.config, f, indent=2)
                elif config_path.endswith((".yaml", ".yml")):
                    yaml.dump(self.config, f)
                else:
                    raise ValueError(f"Unsupported configuration file format: {config_path}")

            logger.debug(f"Saved configuration to {config_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save configuration to {config_path}: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            key: Configuration key
            default: Default value if key is not found

        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.

        Args:
            key: Configuration key
            value: Configuration value
        """
        self.config[key] = value

    def update(self, config: Dict[str, Any]) -> None:
        """
        Update configuration with a dictionary.

        Args:
            config: Configuration dictionary
        """
        self._merge_dicts(self.config, config)

    def default_config(self) -> Dict[str, Any]:
        """
        Get the default configuration.

        Returns:
            Default configuration dictionary
        """
        return {
            # General configuration
            "log_level": "info",
            "log_file": "logs/containerguard.log",
            "output_dir": "reports",
            "output_format": "html",
            "company_name": "",
            "logo_path": "",

            # Scanner configuration
            "scanners": {
                "vulnerability": {
                    "enabled": True,
                    "severity_threshold": "medium",
                    "ignored_vulnerabilities": [],
                    "use_trivy": True,
                    "use_grype": False,
                    "use_clair": False,
                    "offline_mode": False,
                    "update_databases": True,
                    "max_findings": 1000,
                },
                "misconfiguration": {
                    "enabled": True,
                    "severity_threshold": "medium",
                    "check_dockerfile": True,
                    "check_compose": True,
                    "check_kubernetes": True,
                    "custom_rules_path": "",
                    "max_findings": 1000,
                },
                "secret": {
                    "enabled": False,
                    "severity_threshold": "medium",
                    "max_findings": 100,
                },
                "compliance": {
                    "enabled": False,
                    "standards": ["cis"],
                    "max_findings": 1000,
                },
            },

            # Report configuration
            "report": {
                "title": "Container Security Scan Report",
                "include_summary": True,
                "include_details": True,
                "include_remediation": True,
                "include_charts": True,
                "max_findings": 1000,
                "template_path": "",
                "custom_css": "",
                "custom_js": "",
            },
        }

    def _merge_dicts(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        Recursively merge two dictionaries.

        Args:
            target: Target dictionary (modified in place)
            source: Source dictionary
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._merge_dicts(target[key], value)
            else:
                target[key] = value