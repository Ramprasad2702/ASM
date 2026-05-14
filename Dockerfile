FROM node:20-bookworm

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production
ENV PATH="/usr/local/go/bin:/root/go/bin:/usr/local/bin:${PATH}"
ENV UV_THREADPOOL_SIZE=64
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Install system packages & cleanup
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    dnsutils \
    whois \
    openssl \
    whatweb \
    nmap \
    python3 \
    python3-pip \
    build-essential \
    ca-certificates \
    perl \
    libnet-ssleay-perl \
    libwhisker2-perl \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz && \
    rm go1.24.2.linux-amd64.tar.gz

# Install Recon & Vuln Tools (Naabu removed as nmap is used)
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/tomnomnom/assetfinder@latest

# Compatibility symlink
RUN ln -sf /root/go/bin/httpx /root/go/bin/httpx-toolkit

# Update nuclei templates
RUN nuclei -update-templates

# Verify tools exist
RUN subfinder -version && \
    httpx -version && \
    whatweb --version && \
    nuclei -version && \
    nmap --version && \
    nikto -Version

# App directory
WORKDIR /app

# Copy project files
COPY . .

# Install node dependencies
RUN npm install

# Create results directory
RUN mkdir -p results && \
    mkdir -p /root/.config/subfinder

# Make script executable
RUN chmod +x generate-config.sh

# Expose web port
EXPOSE 3000

# Start server (Generate config then start node)
CMD ["sh", "-c", "mkdir -p /root/.config/subfinder && ./generate-config.sh /root/.config/subfinder/provider-config.yaml && node server.js"]
