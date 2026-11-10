#!/bin/bash
echo "========================================================"
echo "  ☕ Roma Cafe Dual Loyalty System - Production Server"
echo "========================================================"

if ! command -v node &> /dev/null
then
    echo "[ERROR] Node.js is not installed!"
    echo "Please install Node.js (v18+) from https://nodejs.org"
    exit 1
fi

if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing production dependencies..."
    npm install --production
fi

echo "[INFO] Starting Roma Cafe Production Server..."
node server.js

