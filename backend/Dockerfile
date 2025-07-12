FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install security scanning tools
RUN mkdir -p /tools

# Install Subfinder
RUN curl -L -o /tmp/subfinder.tar.gz \
    "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).tar.gz" && \
    tar -xzf /tmp/subfinder.tar.gz -C /tools/ && \
    chmod +x /tools/subfinder && \
    rm /tmp/subfinder.tar.gz

# Install HTTPX
RUN curl -L -o /tmp/httpx.tar.gz \
    "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).tar.gz" && \
    tar -xzf /tmp/httpx.tar.gz -C /tools/ && \
    chmod +x /tools/httpx && \
    rm /tmp/httpx.tar.gz

# Install Nuclei
RUN curl -L -o /tmp/nuclei.tar.gz \
    "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).tar.gz" && \
    tar -xzf /tmp/nuclei.tar.gz -C /tools/ && \
    chmod +x /tools/nuclei && \
    rm /tmp/nuclei.tar.gz

# Install Naabu
RUN curl -L -o /tmp/naabu.tar.gz \
    "https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).tar.gz" && \
    tar -xzf /tmp/naabu.tar.gz -C /tools/ && \
    chmod +x /tools/naabu && \
    rm /tmp/naabu.tar.gz

# Install Amass
RUN curl -L -o /tmp/amass.zip \
    "https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_$(uname -m).zip" && \
    cd /tmp && unzip amass.zip && \
    mv amass_*/amass /tools/ && \
    chmod +x /tools/amass && \
    rm -rf /tmp/amass*

# Add tools to PATH
ENV PATH="/tools:${PATH}"

# Update Nuclei templates
RUN nuclei -update-templates

# Copy application code
COPY . .

# Create scan results directory
RUN mkdir -p /app/scan_results

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /tools
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]