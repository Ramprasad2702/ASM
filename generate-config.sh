#!/bin/bash

# This script generates a subfinder provider configuration from environment variables
# to avoid committing secrets to the repository.

CONFIG_PATH=${1:-"provider-config.yaml"}

cat <<EOF > "$CONFIG_PATH"
censys:
  - ${CENSYS_API_KEY}
chaos:
  - ${CHAOS_API_KEY}
github:
  - ${GITHUB_API_KEY}
shodan:
  - ${SHODAN_API_KEY}
EOF

echo "✅ Generated $CONFIG_PATH"
