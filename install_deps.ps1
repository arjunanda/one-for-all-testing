# =============================================================================
# Windows PowerShell Installer for Pentest Tools
# Run this in PowerShell as Administrator
# =============================================================================

Write-Host "=================================================="
Write-Host "  PENETRATION TESTING TOOLS INSTALLER (Windows)"
Write-Host "  PowerShell Version"
Write-Host "=================================================="

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Function to install Chocolatey
function Install-Chocolatey {
    Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    
    # Refresh environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Function to install Python
function Install-Python {
    Write-Host "Installing Python..." -ForegroundColor Yellow
    choco install python -y
    
    # Refresh PATH
    refreshenv
    
    Write-Host "Installing Python security libraries..." -ForegroundColor Yellow
    pip install requests beautifulsoup4 selenium urllib3 lxml paramiko
    pip install sqlmap dirsearch wfuzz shodan
}

# Function to install basic tools
function Install-BasicTools {
    Write-Host "Installing basic networking tools..." -ForegroundColor Yellow
    choco install nmap curl wget openssl.light -y
    choco install git -y
}

# Function to install Node.js
function Install-NodeJS {
    Write-Host "Installing Node.js..." -ForegroundColor Yellow
    choco install nodejs -y
    refreshenv
}

# Function to install Go
function Install-Go {
    Write-Host "Installing Go language..." -ForegroundColor Yellow
    choco install golang -y
    refreshenv
    
    # Install Go-based tools
    Write-Host "Installing Go-based security tools..." -ForegroundColor Yellow
    go install github.com/OJ/gobuster/v3@latest
    go install github.com/ffuf/ffuf@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/tomnomnom/waybackurls@latest
}

# Function to install Nikto
function Install-Nikto {
    Write-Host "Installing Nikto..." -ForegroundColor Yellow
    $pentestDir = "C:\pentest-tools"
    New-Item -ItemType Directory -Force -Path $pentestDir
    Set-Location $pentestDir
    
    git clone https://github.com/sullo/nikto.git
    
    # Create nikto wrapper script
    $niktoWrapper = @"
@echo off
perl C:\pentest-tools\nikto\program\nikto.pl %*
"@
    $niktoWrapper | Out-File -FilePath "C:\Windows\System32\nikto.bat" -Encoding ASCII
    
    Write-Host "Nikto installed and added to PATH" -ForegroundColor Green
}

# Function to install report tools
function Install-ReportTools {
    Write-Host "Installing report generation tools..." -ForegroundColor Yellow
    choco install pandoc miktex -y
    
    # Install Python report libraries
    pip install markdown jinja2 weasyprint
}

# Function to download wordlists
function Install-Wordlists {
    Write-Host "Downloading wordlists..." -ForegroundColor Yellow
    $wordlistDir = "$env:USERPROFILE\wordlists"
    New-Item -ItemType Directory -Force -Path $wordlistDir
    Set-Location $wordlistDir
    
    # Download SecLists
    Invoke-WebRequest -Uri "https://github.com/danielmiessler/SecLists/archive/master.zip" -OutFile "seclists.zip"
    Expand-Archive -Path "seclists.zip" -DestinationPath "."
    Rename-Item "SecLists-master" "SecLists"
    Remove-Item "seclists.zip"
    
    # Download dirb wordlists
    git clone https://github.com/v0re/dirb.git
    
    Write-Host "Wordlists installed in $wordlistDir" -ForegroundColor Green
}

# Function to setup environment variables
function Setup-Environment {
    Write-Host "Setting up environment variables..." -ForegroundColor Yellow
    
    # Add Go bin to PATH
    $goPath = "$env:USERPROFILE\go\bin"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$goPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$goPath", "User")
    }
    
    # Add pentest tools to PATH
    $pentestPath = "C:\pentest-tools"
    if ($currentPath -notlike "*$pentestPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$pentestPath", "User")
    }
}

# Function to verify installations
function Verify-Installation {
    Write-Host "Verifying installations..." -ForegroundColor Yellow
    
    $tools = @("python", "pip", "go", "git", "nmap", "curl")
    foreach ($tool in $tools) {
        try {
            $null = & $tool --version 2>$null
            Write-Host "✓ $tool - OK" -ForegroundColor Green
        } catch {
            Write-Host "✗ $tool - NOT FOUND" -ForegroundColor Red
        }
    }
}

# Main installation function
function Main {
    Write-Host "Starting installation..." -ForegroundColor Green
    
    # Check and install Chocolatey if needed
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Install-Chocolatey
    }
    
    Install-BasicTools
    Install-Python
    Install-NodeJS
    Install-Go
    Install-Nikto
    Install-ReportTools
    Install-Wordlists
    Setup-Environment
    
    Write-Host ""
    Write-Host "=================================================="
    Write-Host "  INSTALLATION COMPLETED!"
    Write-Host "=================================================="
    Write-Host ""
    Write-Host "Installed components:"
    Write-Host "✓ Python with security libraries" -ForegroundColor Green
    Write-Host "✓ Node.js and npm" -ForegroundColor Green
    Write-Host "✓ Go language and Go-based tools" -ForegroundColor Green
    Write-Host "✓ Nmap, curl, wget, openssl" -ForegroundColor Green
    Write-Host "✓ Nikto, SQLMap, Gobuster" -ForegroundColor Green
    Write-Host "✓ Nuclei, httpx, subfinder" -ForegroundColor Green
    Write-Host "✓ Wordlists (SecLists, dirb)" -ForegroundColor Green
    Write-Host "✓ Report generation tools" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please restart PowerShell to refresh environment variables"
    Write-Host "Then run: bash pentest.sh -t [target_url]"
    
    Verify-Installation
    
    Read-Host "Press Enter to exit"
}

# Run main function
Main
