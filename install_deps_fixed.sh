#!/bin/bash

# =============================================================================
# Fixed Dependencies Installer for Pentest Script (No Sudo Required)
# Handles common installation errors without requiring root privileges
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} Pentest Dependencies Installer (User) ${NC}"
echo -e "${BLUE}========================================${NC}"

# Create local tools directory
mkdir -p ~/pentest-tools/bin
export PATH="$HOME/pentest-tools/bin:$PATH"

# Update package list (if possible without sudo)
echo -e "${YELLOW}[1/8] Checking system...${NC}"
if command -v apt &> /dev/null; then
    echo "Debian/Ubuntu system detected"
    SYSTEM="debian"
elif command -v yum &> /dev/null; then
    echo "RedHat/CentOS system detected"
    SYSTEM="redhat"
elif command -v brew &> /dev/null; then
    echo "macOS with Homebrew detected"
    SYSTEM="macos"
else
    echo "Unknown system, will try generic installation"
    SYSTEM="generic"
fi

# Install basic tools without sudo
echo -e "${YELLOW}[2/8] Installing basic tools...${NC}"

# Install Go (if not present) - user installation
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    cd ~
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    tar -xzf go1.21.0.linux-amd64.tar.gz
    rm go1.21.0.linux-amd64.tar.gz
    export PATH="$HOME/go/bin:$PATH"
    echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
fi

# Check for existing tools
echo "Checking for existing system tools..."
command -v nmap >/dev/null 2>&1 && echo "✅ nmap found" || echo "⚠️  nmap not found (will use alternatives)"
command -v curl >/dev/null 2>&1 && echo "✅ curl found" || echo "❌ curl missing (required)"
command -v wget >/dev/null 2>&1 && echo "✅ wget found" || echo "❌ wget missing (required)"
command -v dig >/dev/null 2>&1 && echo "✅ dig found" || echo "⚠️  dig not found (will use alternatives)"
command -v whois >/dev/null 2>&1 && echo "✅ whois found" || echo "⚠️  whois not found (will use alternatives)"

# Install security tools from source/binaries
echo -e "${YELLOW}[3/8] Installing security tools...${NC}"

# Install nmap (if not available) - static binary
if ! command -v nmap &> /dev/null; then
    echo "Installing nmap static binary..."
    cd ~/pentest-tools
    wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
    chmod +x nmap
    mv nmap ~/pentest-tools/bin/
fi

# Install masscan
if ! command -v masscan &> /dev/null; then
    echo "Installing masscan from source..."
    cd ~/pentest-tools
    git clone https://github.com/robertdavidgraham/masscan.git
    cd masscan
    make -j 2>/dev/null || echo "masscan build failed, continuing..."
    if [ -f bin/masscan ]; then
        cp bin/masscan ~/pentest-tools/bin/
    fi
    cd ..
fi

# Install Gobuster via Go
echo "Installing gobuster..."
go install github.com/OJ/gobuster/v3@latest

# Install other Go-based tools
echo "Installing additional Go tools..."
go install github.com/ffuf/ffuf@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/waybackurls@latest

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
echo -e "${YELLOW}[7/8] Installing additional security tools...${NC}"

# Install Nikto from source (if not available)
if ! command -v nikto &> /dev/null; then
    echo "Installing Nikto from source..."
    cd ~/pentest-tools
    git clone https://github.com/sullo/nikto.git
    cd nikto/program
    # Create wrapper script
    cat > ~/pentest-tools/bin/nikto << 'EOF'
#!/bin/bash
perl ~/pentest-tools/nikto/program/nikto.pl "$@"
EOF
    chmod +x ~/pentest-tools/bin/nikto
    cd ../..
fi

# Install SQLMap from source
if ! command -v sqlmap &> /dev/null; then
    echo "Installing SQLMap..."
    cd ~/pentest-tools
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
    # Create wrapper script
    cat > ~/pentest-tools/bin/sqlmap << 'EOF'
#!/bin/bash
python3 ~/pentest-tools/sqlmap/sqlmap.py "$@"
EOF
    chmod +x ~/pentest-tools/bin/sqlmap
fi

# Install dirb from source (if not available)
if ! command -v dirb &> /dev/null; then
    echo "Installing dirb from source..."
    cd ~/pentest-tools
    git clone https://github.com/v0re/dirb.git
    cd dirb
    chmod +x configure
    ./configure 2>/dev/null || echo "dirb configure failed, trying manual setup..."
    make 2>/dev/null || echo "dirb make failed, continuing..."
    if [ -f dirb ]; then
        cp dirb ~/pentest-tools/bin/
    fi
    cd ..
fi

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
    cd ~/pentest-tools
    wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
    unzip -q subfinder_2.6.3_linux_amd64.zip
    mv subfinder ~/pentest-tools/bin/
    rm -f subfinder_2.6.3_linux_amd64.zip README.md LICENSE
fi

# Install httpx
echo -e "${YELLOW}Installing httpx...${NC}"
if ! command -v httpx &> /dev/null; then
    cd ~/pentest-tools
    wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip
    unzip -q httpx_1.3.7_linux_amd64.zip
    mv httpx ~/pentest-tools/bin/
    rm -f httpx_1.3.7_linux_amd64.zip README.md LICENSE
fi

# Create activation script
cat > activate_pentest.sh << 'EOF'
#!/bin/bash
echo "Activating pentest environment..."
export PATH="$HOME/pentest-tools/bin:$HOME/go/bin:$PATH:$(pwd)/dirsearch"
source pentest-venv/bin/activate 2>/dev/null || echo "Virtual environment not found, using system Python"
echo "Pentest environment activated!"
echo "Available tools:"
command -v nmap >/dev/null 2>&1 && echo "✅ nmap" || echo "❌ nmap"
command -v nikto >/dev/null 2>&1 && echo "✅ nikto" || echo "❌ nikto"
command -v gobuster >/dev/null 2>&1 && echo "✅ gobuster" || echo "❌ gobuster"
command -v sqlmap >/dev/null 2>&1 && echo "✅ sqlmap" || echo "❌ sqlmap"
command -v subfinder >/dev/null 2>&1 && echo "✅ subfinder" || echo "❌ subfinder"
command -v httpx >/dev/null 2>&1 && echo "✅ httpx" || echo "❌ httpx"
EOF

chmod +x activate_pentest.sh

# Update .bashrc to include tool paths
echo 'export PATH="$HOME/pentest-tools/bin:$HOME/go/bin:$PATH"' >> ~/.bashrc

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}         Installation Complete!        ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}To use the pentest script:${NC}"
echo "1. Activate environment: ${BLUE}source activate_pentest.sh${NC}"
echo "2. Run pentest: ${BLUE}./pentest.sh -t https://www.djarum.com/${NC}"
echo ""
echo -e "${YELLOW}Installed Tools:${NC}"
echo "✅ Go-based tools (gobuster, nuclei, httpx, subfinder)"
echo "✅ Python tools (in virtual environment)"
echo "✅ Source-based tools (nikto, sqlmap)"
echo "✅ dirsearch (alternative to wfuzz)"
echo ""
echo -e "${YELLOW}Note:${NC} All tools installed in user space, no root privileges required!"

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
