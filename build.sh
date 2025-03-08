#!/bin/bash

# Build script for HTTP Traffic Listener

# Set the output binary name
BINARY_NAME="http_traffic_listener"

# Ensure we're in the project root
cd "$(dirname "$0")"

echo "Building HTTP Traffic Listener..."

# Build the application
go build -o $BINARY_NAME ./cmd/http_traffic_listener

if [ $? -eq 0 ]; then
    echo "Build successful! Binary created: $BINARY_NAME"
    echo "Run with: ./$BINARY_NAME [options]"
else
    echo "Build failed."
    exit 1
fi
