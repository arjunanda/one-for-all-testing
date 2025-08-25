#!/bin/bash

# =============================================================================
# Dependency Installation Script for Pentest Tools
# =============================================================================

echo "Installing Penetration Testing Tools..."

# Update package lists
sudo apt update

# Install basic networking tools
sudo apt install -y \
    nmap \
    curl \
    wget \
    dnsutils \
    whois \
    netcat \
    telnet

# Install web testing tools
sudo apt install -y \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    wfuzz

# Install additional security tools
sudo apt install -y \
    openssl \
    ncat \
    masscan \
    zmap

# Install Python tools via pip
pip3 install --user \
    requests \
    beautifulsoup4 \
    selenium \
    paramiko

echo "Installation completed!"
echo "You can now run the pentest script."
