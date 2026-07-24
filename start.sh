#!/bin/bash

# Set colors (optional, mimics 'color B')
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}Growtopia Private Server HTTP${NC}"

# Check if Node is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js is not installed or not in PATH!${NC}"
    echo "Please install Node.js using your package manager (apt, dnf, etc.)"
    exit 1
fi

# Check if Config exists
if [ ! -f "config/config.json" ]; then
    echo -e "${RED}[ERROR] config/config.json not found!${NC}"
    exit 1
fi

# 1. Check if express exists in the DB folder
if [ -d "db/node_modules/express" ]; then
    echo -e "[INFO] Node modules found in db/node_modules. Skipping installation."
else
    echo -e "${YELLOW}[WARN] Modules missing or incomplete. Installing dependencies...${NC}"
    
    # 2. Check if package.json exists
    if [ -f "db/packages/package.json" ]; then
        echo "[INFO] Installing dependencies from db/packages..."
        cd db/packages || exit
        npm install
        cd ../..
        
        # 3. Move the installed modules to db/node_modules
        if [ -d "db/packages/node_modules" ]; then
            echo "[INFO] Moving node_modules to correct location db/..."
            rm -rf db/node_modules
            mv db/packages/node_modules db/
        fi
    else
        echo -e "${RED}[ERROR] package.json not found in db/packages. Skipping install.${NC}"
    fi
fi

echo "[INFO] Starting Server..."

# CRITICAL FIX: Tell Node.js to look in db/node_modules for packages
# $(pwd) ensures it uses the full absolute path
export NODE_PATH="$(pwd)/db/node_modules"

# 4. Run the main file from the src folder
node src/main.js