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
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

# Add metadata labels for container registry
LABEL maintainer="Arpan Sarkar (@openrec0n)" \
      version="2.2.0" \
      description="Halberd Multi-Cloud Attack Tool" \
      repository="https://github.com/vectra-ai-research/Halberd" \
      org.opencontainers.image.title="Halberd" \
      org.opencontainers.image.description="Multi-Cloud Attack Tool" \
      org.opencontainers.image.version="2.2.0" \
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
    PYTHONPATH="/app"

# Create non-root user for security with home directory
RUN groupadd -r halberd && useradd -r -g halberd -m -d /home/halberd halberd

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=halberd:halberd . .

# Create necessary directories with proper permissions
RUN mkdir -p local output report \
    && chown -R halberd:halberd /app \
    && mkdir -p /home/halberd/.azure \
    && chown -R halberd:halberd /home/halberd

# Switch to non-root user
USER halberd

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${HALBERD_PORT}/ || exit 1

# Expose the port
EXPOSE 8050

# Command to run the application
CMD ["python", "run.py"]