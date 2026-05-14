FROM node:20-bookworm

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    dnsutils \
    whois \
    openssl \
    nmap \
    nikto \
    exploitdb \
    python3 \
    python3-pip \
    build-essential \
    ca-certificates

# Install Go
RUN wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz && \
    rm go1.24.2.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install Recon Tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/owasp-amass/amass/v4/...@master

# Create symlink for httpx-toolkit to match code
RUN ln -s /root/go/bin/httpx /root/go/bin/httpx-toolkit

# Update Nuclei Templates
RUN nuclei -update-templates

# Setup Subfinder Config
RUN mkdir -p /root/.config/subfinder
COPY provider-config.yaml /root/.config/subfinder/provider-config.yaml

# Create app directory
WORKDIR /app

# Copy project files
COPY . .

# Install Node dependencies
RUN npm install

# Create results directory
RUN mkdir -p results

# Expose web port
EXPOSE 3000

# Environment
ENV NODE_ENV=production

# Make script executable
RUN chmod +x generate-config.sh

# Start server (Generate config then start node)
CMD ["sh", "-c", "./generate-config.sh /root/.config/subfinder/provider-config.yaml && node server.js"]
