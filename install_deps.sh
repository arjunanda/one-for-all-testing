#!/bin/bash

# =============================================================================
# Complete Dependency Installation Script for Pentest Tools (Windows/WSL)
# =============================================================================

echo "=================================================="
echo "  PENETRATION TESTING TOOLS INSTALLER"
echo "  Complete Setup for Windows Environment"
echo "=================================================="

# Function to check if running on Windows
check_environment() {
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ -n "$WINDIR" ]]; then
        echo "Detected Windows environment"
        WINDOWS=true
    else
        echo "Detected Linux/Unix environment"
        WINDOWS=false
    fi
}

# Function to install Chocolatey (Windows package manager)
install_chocolatey() {
    echo "Installing Chocolatey package manager..."
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
}

# Function to install Python
install_python() {
    echo "Installing Python..."
    if [ "$WINDOWS" = true ]; then
        # Install Python via Chocolatey
        choco install python -y
        # Add Python to PATH
        export PATH="/c/Python39:/c/Python39/Scripts:$PATH"
    else
        # Linux installation
        apt update
        apt install -y python3 python3-pip
    fi
    
    # Verify installation
    python --version || python3 --version
}

# Function to install Git (if not present)
install_git() {
    echo "Installing Git..."
    if [ "$WINDOWS" = true ]; then
        choco install git -y
    else
        apt install -y git
    fi
}

# Function to install curl and wget
install_basic_tools() {
    echo "Installing basic networking tools..."
    if [ "$WINDOWS" = true ]; then
        choco install curl wget -y
        # Install Windows Subsystem for Linux tools
        choco install nmap -y
        choco install openssl.light -y
    else
        apt install -y curl wget nmap openssl dnsutils whois netcat telnet
    fi
}

# Function to install Node.js and npm
install_nodejs() {
    echo "Installing Node.js..."
    if [ "$WINDOWS" = true ]; then
        choco install nodejs -y
    else
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
        apt install -y nodejs
    fi
}

# Function to install Ruby (for some pentest tools)
install_ruby() {
    echo "Installing Ruby..."
    if [ "$WINDOWS" = true ]; then
        choco install ruby -y
    else
        apt install -y ruby ruby-dev
    fi
}

# Function to install Go (for modern tools)
install_go() {
    echo "Installing Go language..."
    if [ "$WINDOWS" = true ]; then
        choco install golang -y
    else
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
}

# Function to install web testing tools
install_web_testing_tools() {
    echo "Installing web testing tools..."
    
    # Python-based tools
    pip install --user requests beautifulsoup4 selenium paramiko urllib3 lxml
    pip install --user sqlmap
    
    # Install Nikto
    if [ "$WINDOWS" = true ]; then
        echo "Downloading Nikto for Windows..."
        mkdir -p /c/pentest-tools
        cd /c/pentest-tools
        git clone https://github.com/sullo/nikto.git
        cd nikto/program
        echo "Nikto installed in /c/pentest-tools/nikto"
    else
        apt install -y nikto
    fi
    
    # Install Dirb/Gobuster alternatives
    echo "Installing directory enumeration tools..."
    if [ "$WINDOWS" = true ]; then
        # Install Gobuster via Go
        go install github.com/OJ/gobuster/v3@latest
        # Install ffuf
        go install github.com/ffuf/ffuf@latest
    else
        apt install -y dirb gobuster
        go install github.com/ffuf/ffuf@latest
    fi
}

# Function to install additional security tools
install_additional_tools() {
    echo "Installing additional security tools..."
    
    # Install Nuclei
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    
    # Install httpx
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    # Install subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    # Install waybackurls
    go install github.com/tomnomnom/waybackurls@latest
    
    # Additional Python tools
    pip install --user dirsearch wfuzz shodan
}

# Function to create tool aliases
create_aliases() {
    echo "Creating tool aliases..."
    
    # Create a tools directory
    mkdir -p ~/pentest-tools
    
    # Create wrapper scripts for Windows
    if [ "$WINDOWS" = true ]; then
        cat > ~/pentest-tools/nikto.sh << 'EOF'
#!/bin/bash
perl /c/pentest-tools/nikto/program/nikto.pl "$@"
EOF
        chmod +x ~/pentest-tools/nikto.sh
        
        # Add tools to PATH
        echo 'export PATH="$HOME/pentest-tools:$HOME/go/bin:$PATH"' >> ~/.bashrc
    fi
}

# Function to install wordlists
install_wordlists() {
    echo "Installing wordlists..."
    mkdir -p ~/wordlists
    cd ~/wordlists
    
    # Download common wordlists
    wget -q https://github.com/danielmiessler/SecLists/archive/master.zip -O seclists.zip
    unzip -q seclists.zip
    mv SecLists-master SecLists
    rm seclists.zip
    
    # Download dirb wordlists
    git clone https://github.com/v0re/dirb.git
    
    echo "Wordlists installed in ~/wordlists"
}

# Function to setup report tools
install_report_tools() {
    echo "Installing report generation tools..."
    
    # Install pandoc for report conversion
    if [ "$WINDOWS" = true ]; then
        choco install pandoc -y
        # Install MiKTeX for PDF generation
        choco install miktex -y
    else
        apt install -y pandoc texlive-latex-base texlive-fonts-recommended
    fi
    
    # Install additional Python libraries for reports
    pip install --user markdown jinja2 weasyprint
}

# Main installation function
main() {
    echo "Starting complete penetration testing environment setup..."
    
    check_environment
    
    if [ "$WINDOWS" = true ] && ! command -v choco &> /dev/null; then
        echo "Chocolatey not found. Installing..."
        install_chocolatey
        echo "Please restart your terminal and run this script again."
        exit 0
    fi
    
    install_python
    install_git
    install_basic_tools
    install_nodejs
    install_ruby
    install_go
    install_web_testing_tools
    install_additional_tools
    create_aliases
    install_wordlists
    install_report_tools
    
    # Source bashrc to reload PATH
    source ~/.bashrc 2>/dev/null || true
    
    echo ""
    echo "=================================================="
    echo "  INSTALLATION COMPLETED!"
    echo "=================================================="
    echo ""
    echo "Installed tools:"
    echo "✓ Python with security libraries"
    echo "✓ Node.js and npm"
    echo "✓ Go language and Go-based tools"
    echo "✓ Ruby"
    echo "✓ Nmap, curl, wget"
    echo "✓ Nikto, SQLMap, Gobuster"
    echo "✓ Nuclei, httpx, subfinder"
    echo "✓ Wordlists (SecLists, dirb)"
    echo "✓ Report generation tools (pandoc)"
    echo ""
    echo "Tools location:"
    echo "- Go tools: ~/go/bin/"
    echo "- Python tools: ~/.local/bin/ (or Python Scripts/)"
    echo "- Custom tools: ~/pentest-tools/"
    echo "- Wordlists: ~/wordlists/"
    echo ""
    echo "Please restart your terminal to ensure all PATH changes take effect."
    echo "Then you can run: bash pentest.sh -t <target_url>"
}

# Run main function
main
