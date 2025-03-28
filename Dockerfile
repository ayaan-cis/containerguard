# Dockerfile for ContainerGuard container security scanner

# Use a specific Python version
FROM python:3.10-slim

# Set environment variables (no sensitive data)
ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PYTHONDONTWRITEBYTECODE=1

# Create a non-root user
RUN groupadd -g 1001 containerguard && \
    useradd -u 1001 -g containerguard -m -s /bin/bash containerguard

# Create working directory and set ownership
WORKDIR /app
RUN chown containerguard:containerguard /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    docker.io \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (container scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.29.2

# Copy requirements first to leverage Docker cache
COPY --chown=containerguard:containerguard requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY --chown=containerguard:containerguard . .

# Switch to non-root user
USER containerguard

# Set resource limits
ENV CONTAINER_MEMORY_LIMIT="512m" \
    CONTAINER_CPU_LIMIT="1.0"

# Expose API port
EXPOSE 8080

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/health || exit 1

# Set entry point
ENTRYPOINT ["python", "-m", "containerguard.cli"]

# Default command
CMD ["--help"]