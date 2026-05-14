FROM node:20-bookworm

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system packages & cleanup
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    dnsutils \
    whois \
    openssl \
    nmap \
    python3 \
    python3-pip \
    build-essential \
    ca-certificates \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz && \
    rm go1.24.2.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install Recon Tools (Consolidated for smaller image)
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/owasp-amass/amass/v4/...@master

# Install Nikto from source
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Install ExploitDB / Searchsploit from source
RUN git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb && \
    ln -s /opt/exploitdb/searchsploit/searchsploit /usr/local/bin/searchsploit

# Create symlink for httpx-toolkit to match code
RUN ln -s /root/go/bin/httpx /root/go/bin/httpx-toolkit

# Update Nuclei Templates
RUN nuclei -update-templates

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
# We ensure the config directory exists before generating
CMD ["sh", "-c", "mkdir -p /root/.config/subfinder && ./generate-config.sh /root/.config/subfinder/provider-config.yaml && node server.js"]
