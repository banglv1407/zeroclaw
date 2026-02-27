#!/bin/bash
# ZeroClaw Deployment Script
# Automates: Build -> Transfer -> Remote Restart

set -e

# Configuration
REMOTE_USER="bang"
REMOTE_HOST="103.188.82.231"
BINARY_NAME="zeroclaw"
REMOTE_PATH="/usr/local/bin/${BINARY_NAME}"
LOCAL_BINARY="target/release/${BINARY_NAME}"

echo "----------------------------------------"
echo "🚀 1/3: Building ${BINARY_NAME} (Release)..."
echo "----------------------------------------"

# Note: Ensure you are running this from WSL or a Linux environment
# to ensure the binary is compatible with the target server.
cargo build --release

if [ ! -f "$LOCAL_BINARY" ]; then
    echo "❌ Build failed! Binary not found at ${LOCAL_BINARY}"
    exit 1
fi

echo "----------------------------------------"
echo "📤 2/3: Transferring binary to ${REMOTE_HOST}..."
echo "----------------------------------------"

# Copy to /tmp first to avoid permission issues during scp
scp -P 1477 "$LOCAL_BINARY" "${REMOTE_USER}@${REMOTE_HOST}:/tmp/${BINARY_NAME}"

echo "----------------------------------------"
echo "⚙️  3/3: Deploying and Restarting Service..."
echo "----------------------------------------"

# Move binary to path, set permissions, and restart systemd service
# SSH -t is used in case sudo requires a password prompt
ssh -p 1477 -t "${REMOTE_USER}@${REMOTE_HOST}" "
    sudo mv /tmp/${BINARY_NAME} ${REMOTE_PATH} && \
    sudo chmod +x ${REMOTE_PATH} && \
    sudo systemctl restart ${BINARY_NAME} && \
    systemctl status ${BINARY_NAME} --no-pager
"

echo "----------------------------------------"
echo "✅ Deployment Successful!"
echo "----------------------------------------"
