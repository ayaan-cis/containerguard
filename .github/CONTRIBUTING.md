# Contributing to ContainerGuard

Thank you for your interest in contributing to ContainerGuard! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report:

1. Check the [existing issues](https://github.com/yourusername/containerguard/issues) to see if the problem has already been reported
2. If you're unable to find an existing issue, create a new one using the bug report template

When filing a bug report, please include:

- A clear and descriptive title
- Detailed steps to reproduce the bug
- Expected behavior and actual behavior
- Relevant logs or screenshots
- Your environment details (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please:

1. Use the feature request template
2. Provide a clear and detailed explanation of the feature
3. Explain why this enhancement would be useful to ContainerGuard users

### Code Contributions

#### Setting Up Your Development Environment

1. Fork the repository
2. Clone your fork to your local machine
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

#### Making Changes

1. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Add tests for your changes
4. Run tests to make sure everything passes:
   ```bash
   pytest
   ```
5. Follow the code style guidelines (we use black, isort, and flake8)
   ```bash
   black containerguard tests
   isort containerguard tests
   flake8 containerguard tests
   ```

#### Submitting a Pull Request

1. Push your changes to your fork
2. Submit a pull request to the main repository
3. In your pull request description, explain the changes and reference any related issues
4. Wait for the maintainers to review your pull request
5. Make any requested changes
6. Once approved, your pull request will be merged

## Development Guidelines

### Code Style

- We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) and use [Black](https://black.readthedocs.io/en/stable/) for code formatting
- Sort imports using [isort](https://pycqa.github.io/isort/)
- Use meaningful variable names and add docstrings to all functions and classes
- Add type hints to function signatures

### Testing

- Write tests for all new functionality
- Maintain or improve test coverage with your changes
- Tests are run with pytest

### Documentation

- Update documentation to reflect your changes
- Add docstrings to all public functions, classes, and methods
- Follow the [Google style for docstrings](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html)

### Commit Messages

- Use clear and meaningful commit messages
- Start with a short summary line (50 chars max)
- Optionally include a more detailed explanation after a blank line
- Reference issue numbers at the end of the summary line (e.g., "Add new feature #123")

## Additional Resources

- [Project README](../README.md)
- [Python Documentation Standards](https://docs.python.org/3/documenting/index.html)
- [Pytest Documentation](https://docs.pytest.org/)

Thank you for contributing to ContainerGuard!