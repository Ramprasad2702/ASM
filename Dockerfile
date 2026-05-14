FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production
ENV PATH="/usr/local/go/bin:/root/go/bin:/usr/local/bin:${PATH}"
ENV UV_THREADPOOL_SIZE=64
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Install system packages
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

# Install Recon & Vuln Tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/owasp-amass/amass/v4/...@master

# Install Searchsploit
RUN git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    chmod +x /opt/exploitdb/searchsploit

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
    nikto -Version && \
    searchsploit -h

# App directory
WORKDIR /app

# Copy project
COPY . .

# Install node dependencies
RUN npm install

# Create directories
RUN mkdir -p results && \
    mkdir -p /root/.config/subfinder

# Make config generator executable
RUN chmod +x generate-config.sh

# Expose Render port
EXPOSE 3000

# Start server
CMD ["sh", "-c", "./generate-config.sh /root/.config/subfinder/provider-config.yaml && node server.js"]
