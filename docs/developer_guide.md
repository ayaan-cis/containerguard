# ContainerGuard Developer Guide

This guide provides information for developers who want to contribute to the ContainerGuard project or extend its functionality.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Project Structure](#project-structure)
- [Adding New Features](#adding-new-features)
- [Core Components](#core-components)
- [Testing](#testing)
- [Code Style](#code-style)
- [Documentation](#documentation)
- [Release Process](#release-process)
- [Architecture Decisions](#architecture-decisions)

## Development Environment Setup

### Prerequisites

- Python 3.8 or higher
- Docker
- Git
- Trivy (optional, for enhanced vulnerability scanning)

### Setup Steps

1. Clone the repository:
```bash
git clone https://github.com/ayaan-cis/containerguard.git
cd containerguard
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Verify the installation:
```bash
containerguard version
```

### Development Tools

The project uses several development tools:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking
- **pytest**: Testing framework

You can run all these tools with the following commands:

```bash
# Code formatting
black containerguard tests

# Import sorting
isort containerguard tests

# Linting
flake8 containerguard tests

# Type checking
mypy containerguard

# Running tests
pytest
```

## Project Structure

The project is organized as follows:

```
containerguard/
├── containerguard/          # Main package
│   ├── __init__.py
│   ├── analyzer/            # Analysis modules
│   │   ├── __init__.py
│   │   ├── remediation.py   # Remediation generator
│   │   └── risk.py          # Risk analyzer
│   ├── cli.py               # Command-line interface
│   ├── config.py            # Configuration management
│   ├── report/              # Reporting modules
│   │   ├── __init__.py
│   │   ├── generator.py     # Report generation
│   │   ├── templates/       # Report templates
│   │   └── visualizer.py    # Data visualization
│   ├── scanner/             # Scanner modules
│   │   ├── __init__.py
│   │   ├── base.py          # Base scanner
│   │   ├── compliance.py    # Compliance scanner
│   │   ├── misconfig.py     # Misconfiguration scanner
│   │   ├── secrets.py       # Secrets scanner
│   │   └── vulnerability.py # Vulnerability scanner
│   └── utils/               # Utility modules
│       ├── __init__.py
│       ├── docker.py        # Docker utilities
│       ├── grype.py         # Grype integration
│       ├── logger.py        # Logging utilities
│       ├── syft.py          # Syft integration
│       └── trivy.py         # Trivy integration
├── docs/                    # Documentation
├── examples/                # Example scripts
├── tests/                   # Test suite
├── .github/                 # GitHub configuration
├── README.md                # Project readme
├── LICENSE                  # License file
├── setup.py                 # Package setup
├── requirements.txt         # Dependencies
└── Dockerfile               # Docker build file
```

## Adding New Features

### Creating a New Scanner

1. Create a new scanner module in `containerguard/scanner/`:

```python
"""
Example new scanner module.
"""
import logging
from typing import Any, Dict, List, Optional

from containerguard.scanner.base import BaseScanner, Finding, ScanResult

logger = logging.getLogger(__name__)

class NewScanner(BaseScanner):
    """A new scanner implementation."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the scanner."""
        super().__init__("new-scanner", config)
        
    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a target."""
        # Implementation here
        return ScanResult(...)
        
    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a specific file."""
        # Implementation here
        return ScanResult(...)
```

2. Add the scanner to the CLI in `containerguard/cli.py`:

```python
# Inside scan function:
if scan_new_feature:
    with Progress(...) as progress:
        task = progress.add_task("Scanning", total=None)
        new_result = await NewScanner(config).scan(target)
        progress.update(task, completed=True)
    
    results.append(new_result)
```

3. Add configuration options in `containerguard/config.py`:

```python
# In default_config method:
"scanners": {
    # Add your scanner configuration
    "new_scanner": {
        "enabled": True,
        "severity_threshold": "medium",
        "custom_option": "value",
    },
}
```

4. Add tests in `tests/`:

```python
"""Test for the new scanner."""
from containerguard.scanner.new_scanner import NewScanner

def test_new_scanner():
    # Test implementation
```

### Integration with External Tools

To integrate with external security tools:

1. Create a utility module in `containerguard/utils/`:

```python
"""
Integration with external tool.
"""
import asyncio
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

async def scan_with_tool(target: str, options: Optional[Dict] = None) -> str:
    """Scan target with external tool."""
    # Implementation
    return result
```

2. Use the utility in your scanner:

```python
from containerguard.utils.external_tool import scan_with_tool

# In your scanner:
tool_output = await scan_with_tool(target, options)
# Parse the output and convert to findings
```

## Core Components

### Scanner Base Class

The `BaseScanner` class in `containerguard/scanner/base.py` provides the foundation for all scanners:

```python
class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    @abstractmethod
    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a target for security issues."""
        pass

    @abstractmethod
    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a specific file for security issues."""
        pass
```

### Finding Model

The `Finding` class in `containerguard/scanner/base.py` represents a security finding:

```python
class Finding(BaseModel):
    """Base model for security findings."""
    id: str
    title: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str  # 'vulnerability', 'misconfiguration', 'secret', etc.
    resource: str  # The affected resource
    location: str  # Where the issue was found
    recommendation: str  # How to fix it
    references: List[str]  # Links to CVEs, documentation, etc.
    metadata: Dict[str, Any] = {}  # Additional scanner-specific information
```

### ScanResult Model

The `ScanResult` class in `containerguard/scanner/base.py` represents the results of a scan:

```python
class ScanResult(BaseModel):
    """Container for scan results."""
    scanner_name: str
    target: str
    findings: List[Finding]
    summary: Dict[str, Any]
    scan_time: float  # Time taken for scan in seconds
    timestamp: str
    metadata: Dict[str, Any] = {}
```

### Configuration Management

The `ConfigManager` class in `containerguard/config.py` handles configuration loading and management:

```python
# Get configuration
config_manager = ConfigManager()
config = config_manager.load_config("config.yml")

# Use configuration
severity = config.get("scanners", {}).get("vulnerability", {}).get("severity_threshold", "medium")
```

## Testing

### Running Tests

Run the test suite with pytest:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=containerguard

# Run specific test files
pytest tests/test_scanner.py
```

### Writing Tests

1. Create a test file in the `tests/` directory:

```python
"""Test module for feature."""
import pytest

from containerguard.feature import Feature

def test_feature_functionality():
    """Test that the feature works correctly."""
    feature = Feature()
    result = feature.process("test")
    assert result == "expected"
```

2. Use fixtures for reusable setup:

```python
@pytest.fixture
def feature_instance():
    """Create a Feature instance for testing."""
    return Feature(config={"option": "value"})

def test_with_fixture(feature_instance):
    """Use the fixture in a test."""
    assert feature_instance.is_configured()
```

3. Test async code:

```python
@pytest.mark.asyncio
async def test_async_feature():
    """Test async functionality."""
    result = await async_function()
    assert result
```

## Code Style

The project follows these code style guidelines:

1. Use [Black](https://black.readthedocs.io/) for code formatting
2. Sort imports with [isort](https://pycqa.github.io/isort/)
3. Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) conventions
4. Add docstrings to all modules, classes, and functions
5. Use type annotations

### Docstring Format

We use the Google style for docstrings:

```python
def function(param1: str, param2: int) -> bool:
    """
    Brief description of function.

    Longer description explaining the function's behavior.

    Args:
        param1: Description of parameter 1
        param2: Description of parameter 2

    Returns:
        Description of return value

    Raises:
        ValueError: When an invalid value is provided
    """
    ...
```

## Documentation

### Building Documentation

The project uses [MkDocs](https://www.mkdocs.org/) with the [Material theme](https://squidfunk.github.io/mkdocs-material/) for documentation:

```bash
# Install documentation dependencies
pip install mkdocs mkdocs-material

# Run the documentation server locally
mkdocs serve

# Build the documentation
mkdocs build
```

### Adding Documentation

1. Add Markdown files in the `docs/` directory
2. Update `mkdocs.yml` to include new pages
3. Add code examples and screenshots as needed

## Release Process

1. Update version in `setup.py` and `containerguard/__init__.py`
2. Update the changelog in `CHANGELOG.md`
3. Create a new Git tag:
```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```
4. The GitHub Actions workflow will:
   - Run tests
   - Build the package
   - Publish to PyPI
   - Build and push Docker images

## Architecture Decisions

### Asynchronous Design

ContainerGuard uses asyncio for better performance during scanning operations, allowing parallel scan execution.

### Modular Structure

Each scanner is a separate module that extends the `BaseScanner` class, making it easy to add new scan types.

### Plugin System

The scanner and analyzer components use a plugin-like architecture to enable easy extension.