# ContainerGuard User Guide

This guide provides comprehensive instructions for using ContainerGuard to scan and secure your container images and infrastructure.

## Table of Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
- [Basic Commands](#basic-commands)
- [Scanning Docker Images](#scanning-docker-images)
- [Scanning Dockerfiles](#scanning-dockerfiles)
- [Scanning Docker Compose Files](#scanning-docker-compose-files)
- [Understanding Scan Results](#understanding-scan-results)
- [Configuration Options](#configuration-options)
- [Integrating with CI/CD](#integrating-with-cicd)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

Before installing ContainerGuard, ensure you have:

- Python 3.8 or higher
- Docker (for container scanning)
- [Trivy](https://github.com/aquasecurity/trivy) (optional, for enhanced vulnerability scanning)

### Install from PyPI

```bash
pip install containerguard
```

### Install from Source

```bash
git clone https://github.com/ayaan-cis/containerguard.git
cd containerguard
pip install -e .
```

### Docker Installation

You can also run ContainerGuard as a Docker container:

```bash
docker pull ayaan-cis/containerguard:latest
docker run -v /var/run/docker.sock:/var/run/docker.sock yourusername/containerguard scan nginx:latest
```

## Getting Started

After installation, verify that ContainerGuard is working correctly:

```bash
containerguard version
```

You should see the current version displayed.

## Basic Commands

ContainerGuard offers several commands:

- `scan`: Scan a container image, Dockerfile, or directory
- `version`: Display version information

### Command Options

The `scan` command accepts various options:

```
Usage: containerguard scan [OPTIONS] TARGET

  Scan a container image, Dockerfile, or directory for security issues.

Arguments:
  TARGET  Container image, Dockerfile, or directory to scan  [required]

Options:
  -c, --config PATH               Path to configuration file
  -f, --format [html|md|json|pdf] Report format  [default: html]
  -o, --output DIRECTORY          Output directory for reports  [default: reports]
  --vuln / --no-vuln              Scan for vulnerabilities  [default: vuln]
  --misconfig / --no-misconfig    Scan for misconfigurations  [default: misconfig]
  --secrets / --no-secrets        Scan for secrets (experimental)  [default: no-secrets]
  -s, --severity [critical|high|medium|low|info]
                                  Minimum severity to report  [default: medium]
  -v, --verbose                   Enable verbose output
  -q, --quiet                     Suppress all output except errors
  --help                          Show this message and exit.
```

## Scanning Docker Images

To scan a Docker image for security issues:

```bash
containerguard scan nginx:latest
```

This will scan the `nginx:latest` image for vulnerabilities and misconfigurations.

## Scanning Dockerfiles

To scan a Dockerfile:

```bash
containerguard scan path/to/Dockerfile
```

This will analyze the Dockerfile for security best practices and potential misconfigurations.

## Scanning Docker Compose Files

To scan a directory containing Docker Compose files:

```bash
containerguard scan path/to/project/
```

This will check all relevant files in the directory, including Docker Compose files, Dockerfiles, and related configurations.

## Understanding Scan Results

After a scan completes, ContainerGuard generates a report in the format specified (HTML by default). 

The report includes:

1. **Summary**: Overall statistics of findings
2. **Vulnerability Findings**: Details of discovered vulnerabilities
3. **Misconfiguration Findings**: Configuration issues and best practice violations
4. **Remediation Guidance**: Suggestions for fixing identified issues
5. **Visualization**: Charts and graphs representing the findings

### Severity Levels

Findings are categorized by severity:

- **Critical**: Severe issues that require immediate attention
- **High**: Significant security risks
- **Medium**: Moderate security concerns
- **Low**: Minor issues with limited impact
- **Info**: Informational findings with no direct security impact

## Configuration Options

You can customize ContainerGuard behavior through a configuration file:

```bash
containerguard scan nginx:latest --config my-config.yml
```

### Sample Configuration File

Create a file named `containerguard-config.yml`:

```yaml
# General configuration
log_level: info
output_dir: reports
output_format: html

# Scanner configuration
scanners:
  vulnerability:
    enabled: true
    severity_threshold: medium
    ignored_vulnerabilities: []
    use_trivy: true
    use_grype: false
  
  misconfiguration:
    enabled: true
    severity_threshold: medium
    check_dockerfile: true
    check_compose: true
    check_kubernetes: true
  
  secret:
    enabled: false
    severity_threshold: medium

# Report configuration
report:
  title: Custom Security Scan Report
  include_summary: true
  include_details: true
  include_remediation: true
  include_charts: true
```

## Integrating with CI/CD

### GitHub Actions

Here's an example GitHub Actions workflow:

```yaml
name: Container Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install ContainerGuard
        run: pip install containerguard
        
      - name: Build Docker image
        run: docker build -t myapp:test .
        
      - name: Scan Docker image
        run: containerguard scan myapp:test --format json --output ./security-reports
        
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: ./security-reports
```

### GitLab CI

Here's an example GitLab CI configuration:

```yaml
stages:
  - build
  - test
  - security

build:
  stage: build
  script:
    - docker build -t myapp:test .

security-scan:
  stage: security
  script:
    - pip install containerguard
    - containerguard scan myapp:test --format json --output ./security-reports
  artifacts:
    paths:
      - ./security-reports
```

## Best Practices

1. **Scan Early and Often**: Integrate scanning into your development workflow
2. **Fix Critical and High Vulnerabilities**: Prioritize critical and high severity issues
3. **Use Custom Configuration**: Create a consistent configuration file for your organization
4. **Update Base Images**: Regularly update base images to get security patches
5. **Follow Least Privilege Principle**: Run containers with minimal permissions
6. **Implement Secure Defaults**: Apply security hardening to all containers

## Troubleshooting

### Common Issues

1. **Docker Socket Permission Issues**

If you encounter Docker socket permission errors:

```
Error: Got permission denied while trying to connect to the Docker daemon socket
```

Solution:
```bash
sudo usermod -aG docker $USER
```

Then log out and log back in.

2. **Trivy Not Found**

If ContainerGuard cannot find Trivy:

```
Error: Trivy not found. Please install Trivy
```

Solution:
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

3. **Slow Scans**

If scans are taking too long:

- Update vulnerability databases: `trivy image --download-db-only`
- Use `--severity high,critical` to focus on important issues
- Scan smaller base images

### Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/yourusername/containerguard/issues)
2. Join our [Community Slack](https://example.com/slack) (placeholder)
3. Email support at support@example.com (placeholder)