#!/bin/bash
# Quick start script for MattStash API Server

set -e

echo "🚀 MattStash API Server - Quick Start"
echo "======================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  Creating .env from .env.example..."
    cp .env.example .env
    echo "✅ Created .env - please edit it with your configuration"
    echo ""
fi

# Check if secrets exist
if [ ! -f secrets/api_keys.txt ]; then
    echo "⚠️  No API keys found!"
    echo "Please create secrets/api_keys.txt with your API keys (one per line)"
    echo "Example: cp secrets/api_keys.txt.example secrets/api_keys.txt"
    echo ""
fi

if [ ! -f secrets/kdbx_password.txt ]; then
    echo "⚠️  No KeePass password found!"
    echo "Please create secrets/kdbx_password.txt with your database password"
    echo "Example: echo 'your-password' > secrets/kdbx_password.txt"
    echo ""
fi

if [ ! -f data/mattstash.kdbx ]; then
    echo "⚠️  No KeePass database found!"
    echo "Please copy your database to data/mattstash.kdbx"
    echo ""
fi

# Check if all required files exist
if [ -f secrets/api_keys.txt ] && [ -f secrets/kdbx_password.txt ] && [ -f data/mattstash.kdbx ]; then
    echo "✅ All required files present"
    echo ""
    echo "Starting services with Docker Compose..."
    docker-compose up -d
    echo ""
    echo "✅ Server started!"
    echo ""
    echo "🔗 API Documentation: http://localhost:8000/api/v1/docs"
    echo "🔗 Health Check: http://localhost:8000/health"
    echo ""
    echo "Test with:"
    echo "  curl http://localhost:8000/health"
    echo "  curl -H 'X-API-Key: your-key' http://localhost:8000/api/v1/credentials"
    echo ""
    echo "View logs:"
    echo "  docker-compose logs -f"
else
    echo "❌ Missing required files. Please set up:"
    echo "  1. secrets/api_keys.txt (API keys)"
    echo "  2. secrets/kdbx_password.txt (KeePass password)"
    echo "  3. data/mattstash.kdbx (KeePass database)"
    echo ""
    exit 1
fi
