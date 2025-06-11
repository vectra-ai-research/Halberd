# Define build arguments
ARG HALBERD_VERSION=0.0.0

# Build stage
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Manual Azure CLI installation
RUN mkdir -p /etc/apt/keyrings \
    && curl -sLS https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/microsoft.gpg \
    && AZ_DIST=$(lsb_release -cs) \
    && echo "Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\nSuites: ${AZ_DIST}\nComponents: main\nArchitectures: $(dpkg --print-architecture)\nSigned-by: /etc/apt/keyrings/microsoft.gpg" \
    | tee /etc/apt/sources.list.d/azure-cli.sources \
    && apt-get update \
    && apt-get install -y azure-cli \
    && az --version

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies
COPY requirements.txt version.py ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Extract version
RUN python -c "exec(open('version.py').read()); print(__version__)" > /tmp/version_value && \
    echo "HALBERD_VERSION=$(cat /tmp/version_value)" > /tmp/version.env

# Final stage
FROM python:3.11-slim

# Copy and set version
COPY --from=builder /tmp/version.env /tmp/version.env
ARG HALBERD_VERSION
RUN . /tmp/version.env && \
    echo "HALBERD_VERSION=$HALBERD_VERSION" > /etc/environment

# Add metadata labels
LABEL maintainer="Arpan Sarkar (@openrec0n)" \
      version="${HALBERD_VERSION}" \
      description="Halberd Multi-Cloud Agentic Attack Tool" \
      repository="https://github.com/vectra-ai-research/Halberd" \
      org.opencontainers.image.title="Halberd" \
      org.opencontainers.image.description="Multi-Cloud Agentic Attack Tool" \
      org.opencontainers.image.version="${HALBERD_VERSION}" \
      org.opencontainers.image.source="https://github.com/vectra-ai-research/Halberd" \
      org.opencontainers.image.vendor="Vectra AI Research" \
      org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HALBERD_HOST=0.0.0.0 \
    HALBERD_PORT=8050 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app" \
    AZURE_CONFIG_DIR="/home/halberd/.azure"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Manual Azure CLI installation (same as build stage)
RUN mkdir -p /etc/apt/keyrings \
    && curl -sLS https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/microsoft.gpg \
    && AZ_DIST=$(lsb_release -cs) \
    && echo "Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\nSuites: ${AZ_DIST}\nComponents: main\nArchitectures: $(dpkg --print-architecture)\nSigned-by: /etc/apt/keyrings/microsoft.gpg" \
    | tee /etc/apt/sources.list.d/azure-cli.sources \
    && apt-get update \
    && apt-get install -y azure-cli \
    && az --version

# Create non-root user for security
RUN groupadd -r halberd && useradd -r -g halberd -m -d /home/halberd halberd

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=halberd:halberd . .

# Create necessary directories with proper permissions
RUN mkdir -p local output report /home/halberd/.azure \
    && chown -R halberd:halberd /app /home/halberd

# Switch to non-root user
USER halberd

# Final verification that Azure CLI works for non-root user
RUN az --version

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${HALBERD_PORT}/ || exit 1

EXPOSE 8050
CMD ["python", "run.py"]