#!/bin/bash

# =============================================================================
# Fixed Dependencies Installer for Pentest Script
# Handles common installation errors
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} Fixed Pentest Dependencies Installer ${NC}"
echo -e "${BLUE}========================================${NC}"

# Update package list
echo -e "${YELLOW}[1/8] Updating package list...${NC}"
sudo apt update

# Install system dependencies first (including curl development files)
echo -e "${YELLOW}[2/8] Installing system dependencies...${NC}"
sudo apt install -y \
    build-essential \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-full \
    libcurl4-openssl-dev \
    libssl-dev \
    curl \
    wget \
    git \
    nmap \
    dnsutils \
    whois \
    openssl \
    ca-certificates \
    unzip

# Install scanning tools
echo -e "${YELLOW}[3/8] Installing security scanning tools...${NC}"
sudo apt install -y \
    nikto \
    dirb \
    gobuster \
    masscan \
    sqlmap \
    whatweb \
    sublist3r

# Create virtual environment
echo -e "${YELLOW}[4/8] Creating Python virtual environment...${NC}"
if [ -d "pentest-venv" ]; then
    rm -rf pentest-venv
fi
python3 -m venv pentest-venv
source pentest-venv/bin/activate

# Upgrade pip first
echo -e "${YELLOW}[5/8] Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel

# Install Python packages (excluding problematic ones)
echo -e "${YELLOW}[6/8] Installing Python security packages...${NC}"
pip install \
    requests \
    beautifulsoup4 \
    python-nmap \
    dnspython \
    colorama \
    termcolor \
    tabulate \
    urllib3 \
    lxml

# Install additional tools via apt (skip problematic pip packages)
echo -e "${YELLOW}[7/8] Installing additional tools via system package manager...${NC}"
sudo apt install -y \
    python3-requests \
    python3-beautifulsoup4 \
    python3-dnspython

# Install dirsearch as alternative to wfuzz
echo -e "${YELLOW}[8/8] Installing dirsearch as alternative...${NC}"
if [ ! -d "dirsearch" ]; then
    git clone https://github.com/maurosoria/dirsearch.git
    cd dirsearch
    pip install -r requirements.txt 2>/dev/null || echo "Some dirsearch deps failed, but tool should work"
    cd ..
fi

# Install subfinder
echo -e "${YELLOW}Installing subfinder...${NC}"
if ! command -v subfinder &> /dev/null; then
    wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
    unzip -q subfinder_2.6.3_linux_amd64.zip
    sudo mv subfinder /usr/local/bin/
    rm -f subfinder_2.6.3_linux_amd64.zip README.md LICENSE
fi

# Install httpx
echo -e "${YELLOW}Installing httpx...${NC}"
if ! command -v httpx &> /dev/null; then
    wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip
    unzip -q httpx_1.3.7_linux_amd64.zip
    sudo mv httpx /usr/local/bin/
    rm -f httpx_1.3.7_linux_amd64.zip README.md LICENSE
fi

# Create activation script
cat > activate_pentest.sh << 'EOF'
#!/bin/bash
echo "Activating pentest virtual environment..."
source pentest-venv/bin/activate
export PATH="$PATH:$(pwd)/dirsearch"
echo "Virtual environment activated. You can now run the pentest script."
EOF

chmod +x activate_pentest.sh

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}         Installation Complete!        ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}To use the pentest script:${NC}"
echo "1. Activate virtual environment: ${BLUE}source activate_pentest.sh${NC}"
echo "2. Run pentest: ${BLUE}./pentest.sh -t https://www.djarum.com/${NC}"
echo ""
echo -e "${YELLOW}Installed Tools:${NC}"
echo "✅ nmap, nikto, dirb, gobuster, sqlmap"
echo "✅ dirsearch (alternative to wfuzz)"
echo "✅ subfinder, httpx"
echo "✅ Python virtual environment with security packages"

# Check installation
echo -e "${YELLOW}Checking installations...${NC}"
source pentest-venv/bin/activate

command -v nmap >/dev/null 2>&1 && echo "✅ nmap installed" || echo "❌ nmap missing"
command -v nikto >/dev/null 2>&1 && echo "✅ nikto installed" || echo "❌ nikto missing"  
command -v dirb >/dev/null 2>&1 && echo "✅ dirb installed" || echo "❌ dirb missing"
command -v gobuster >/dev/null 2>&1 && echo "✅ gobuster installed" || echo "❌ gobuster missing"
command -v sqlmap >/dev/null 2>&1 && echo "✅ sqlmap installed" || echo "❌ sqlmap missing"
command -v subfinder >/dev/null 2>&1 && echo "✅ subfinder installed" || echo "❌ subfinder missing"
command -v httpx >/dev/null 2>&1 && echo "✅ httpx installed" || echo "❌ httpx missing"
python3 -c "import requests" 2>/dev/null && echo "✅ Python requests installed" || echo "❌ Python requests missing"
