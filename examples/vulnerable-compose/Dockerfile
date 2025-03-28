# Example vulnerable Dockerfile for testing ContainerGuard
# This Dockerfile intentionally contains security issues for demonstration purposes

# Using a base image with the latest tag (unpredictable)
FROM python:latest

# Setting environment variables with sensitive data
ENV DB_PASSWORD="super_secret_password"
ENV API_KEY="1234567890abcdef"

# Running as root (security issue)
USER root

# Installing packages without version pinning and not cleaning the cache
RUN apt-get update && apt-get install -y \
    curl \
    vim \
    netcat \
    nmap \
    && pip install flask redis requests

# Creating world-writable directories
RUN mkdir /app && chmod 777 /app

# Copying application code
COPY . /app

# Exposing sensitive ports
EXPOSE 22 8080 3306

# Running with excessive privileges
ENTRYPOINT ["python", "/app/app.py"]