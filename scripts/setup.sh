#!/bin/bash

set -e

echo "Setting up Volatility3 IOC Extraction System..."

mkdir -p data/dumps
mkdir -p data/symbols
mkdir -p data/reports
mkdir -p data/cache
mkdir -p config

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "Created .env from .env.example"
    else
        cat > .env << 'EOF'
VT_API_KEY=
ABUSEIPDB_KEY=
REDIS_URL=redis://localhost:6379
LOG_LEVEL=INFO
EOF
        echo "Created default .env file"
    fi
fi

if command -v python3 &> /dev/null; then
    echo "Installing Python dependencies..."
    pip install -r requirements.txt
else
    echo "Python3 not found. Please install Python 3.11+"
fi

if command -v volatility3 &> /dev/null || python3 -c "import volatility3" 2>/dev/null; then
    echo "Volatility3 is installed"
else
    echo "Installing Volatility3..."
    pip install volatility3
fi

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Add your API keys to .env file"
echo "2. Place memory dumps in data/dumps/"
echo "3. Run: python -m src.mcp_server"