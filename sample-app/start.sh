#!/bin/bash

# Start script for Notes Sample App
# Serves the sample app on http://localhost:3001

PORT=3001

echo "🚀 Starting Notes Sample App on http://localhost:${PORT}"
echo ""
echo "📝 Make sure to:"
echo "   1. Configure CLIENT_ID in config.js"
echo "   2. Backend is running on http://localhost:8000"
echo ""

# Check if Python 3 is available
if command -v python3 &> /dev/null; then
    echo "Using Python 3 HTTP server..."
    python3 -m http.server $PORT
elif command -v python &> /dev/null; then
    echo "Using Python 2 HTTP server..."
    python -m SimpleHTTPServer $PORT
else
    echo "❌ Python not found. Please install Python or use another HTTP server."
    echo ""
    echo "Alternative: Install Node.js and run:"
    echo "   npx http-server -p ${PORT}"
    exit 1
fi
