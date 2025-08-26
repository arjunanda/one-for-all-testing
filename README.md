# Pentest Website Suite

Comprehensive penetration testing framework with modular vulnerability assessment, CVE identification, and professional reporting capabilities.

## 🚀 Features

### Core Capabilities
- **Information Gathering**: DNS enumeration, WHOIS, subdomain discovery
- **Port Scanning**: Service detection, version identification  
- **Directory Enumeration**: Hidden files, admin panels, backup discovery
- **Security Headers Analysis**: HSTS, CSP, X-Frame-Options validation
- **SSL/TLS Assessment**: Certificate validation, cipher analysis
- **Vulnerability Detection**: OWASP Top 10, CVE mapping, exploit guidance

### Advanced Security Testing
- **XSS Testing**: 10+ payloads for reflected/stored XSS
- **SQL Injection**: 15+ attack vectors with blind/union techniques
- **File Inclusion**: Local/remote file inclusion testing
- **Command Injection**: OS command execution vulnerability detection
- **Directory Traversal**: Path traversal and file access testing
- **Authentication Bypass**: Login mechanism vulnerability assessment

### Professional Reporting
- **Executive Summary**: Risk scoring, impact assessment
- **Technical Details**: Vulnerability evidence, proof-of-concept
- **CVE References**: MITRE database integration
- **Remediation Guidance**: Step-by-step fix recommendations
- **Multiple Formats**: Markdown, HTML, PDF export

## 📋 Requirements

- **OS**: Linux, Unix, Windows (WSL recommended)
- **Python**: 3.6+ with virtual environment support
- **Network**: Internet access for tool updates and CVE data
- **Disk Space**: ~500MB for tools and wordlists
- **Memory**: 2GB+ RAM recommended for large scans

## 🛠️ Installation & Setup

### 1. Quick Installation
```bash
# Clone or extract the pentest suite
cd lk21-scrapping

# Install all dependencies (no sudo required)
chmod +x install_deps_fixed.sh
./install_deps_fixed.sh

# Activate pentest environment  
source activate_pentest.sh
```

### 2. Windows PowerShell Installation
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
.\install_deps.ps1
```

### 3. Manual Setup Verification
```bash
# Check tool installation status
./pentest_suite.sh
# Select option 5: "Check Tool Status"
```

## 🎯 Usage Guide

### Interactive Menu System
```bash
# Start the main interface
chmod +x pentest_suite.sh
./pentest_suite.sh
```

**Available Options:**
1. **🚀 Quick Scan** (5-10 minutes) - Basic security assessment
2. **🔍 Comprehensive Scan** (15-30 minutes) - Full penetration test
3. **⚡ Advanced Vulnerability Assessment** (20-40 minutes) - Deep CVE analysis
4. **🛠️ Install Dependencies** - Tool installation and updates
5. **🔧 Check Tool Status** - Verify installation health
6. **📊 Convert Report** - Export to PDF/HTML
7. **🧪 Demo Mode** - Test with safe targets
8. **❓ Help** - Detailed usage information

### Command Line Usage

#### Basic Penetration Test
```bash
./pentest.sh -t https://example.com
```

#### Custom Output Directory
```bash
./pentest.sh -t https://target.com -o company_pentest_2024
```

#### Advanced Assessment with CVE Detection
```bash
# Activate environment first
source activate_pentest.sh

# Run comprehensive scan
./pentest.sh -t https://target.com -o detailed_assessment

# The advanced vulnerability scanner runs automatically
# for comprehensive CVE identification and exploit mapping
```

## 📊 Output & Reports

### Report Structure
```
pentest_results_YYYY-MM-DD_HH-MM-SS/
├── pentest_report_YYYY-MM-DD_HH-MM-SS.md  # Main report
├── pentest_report_YYYY-MM-DD_HH-MM-SS.html # HTML version
├── raw_data/                               # Raw scan outputs  
│   ├── nmap_scan.txt
│   ├── nikto_results.txt
│   ├── dirb_results.txt
│   └── vulnerability_details.json
├── evidence/                               # Vulnerability proof
│   ├── xss_evidence.html
│   ├── sql_injection_attempts.txt
│   └── screenshot_vulnerabilities.png
└── cve_references.txt                      # CVE mappings
```

### Report Sections
1. **Executive Summary**
   - Risk assessment overview
   - Critical findings summary
   - Business impact analysis
   - Compliance status (OWASP Top 10)

2. **Technical Assessment**
   - Vulnerability details with CVSS scores
   - Proof-of-concept demonstrations
   - Attack vector explanations
   - CVE references and links

3. **Evidence & Validation**
   - HTTP request/response captures
   - Screenshot evidence
   - Code samples and payloads
   - Exploitation timeline

4. **Recommendations**
   - Immediate remediation steps
   - Long-term security improvements
   - Implementation priority matrix
   - Developer guidelines

## 🔧 Script Components

### Core Scripts
- **`pentest_suite.sh`** - Main interactive interface
- **`pentest.sh`** - Comprehensive penetration testing engine
- **`advanced_vuln_scanner.sh`** - Modular vulnerability assessment
- **`quick_scan.sh`** - Rapid security assessment
- **`install_deps_fixed.sh`** - Dependency installer (no sudo)

### Utility Scripts  
- **`activate_pentest.sh`** - Environment activation
- **`convert_report.sh`** - Report format conversion
- **`demo.sh`** - Safe testing demonstrations
- **`run_pentest.sh`** - Batch processing wrapper

### Configuration Files
- **`style.css`** - HTML report styling
- **`install_deps.ps1`** - Windows PowerShell installer

## 🛡️ Security Testing Modules

### Information Gathering
- DNS enumeration (A, AAAA, MX, NS, TXT records)
- WHOIS data extraction
- Subdomain discovery with subfinder
- HTTP header analysis
- Robots.txt and sitemap parsing
- Technology stack identification

### Network Assessment
- Port scanning (TCP/UDP)
- Service version detection  
- OS fingerprinting
- Network topology mapping
- Firewall detection
- Load balancer identification

### Web Application Testing
- **Directory Enumeration**
  - Admin panels discovery
  - Backup file identification
  - Configuration file hunting
  - API endpoint discovery

- **Authentication Testing**
  - Login mechanism analysis
  - Session management review
  - Password policy assessment
  - Multi-factor authentication bypass

- **Input Validation Testing**  
  - XSS (Reflected, Stored, DOM-based)
  - SQL injection (Union, Boolean, Time-based)
  - Command injection testing
  - File inclusion vulnerabilities
  - XML/XXE injection attempts

### Infrastructure Testing
- **SSL/TLS Analysis**
  - Certificate validation
  - Cipher suite assessment  
  - Protocol version testing
  - Perfect Forward Secrecy check
  - Certificate chain verification

- **Security Headers**
  - HSTS implementation
  - Content Security Policy
  - X-Frame-Options validation
  - X-Content-Type-Options check
  - Referrer Policy assessment

## 📈 Vulnerability Assessment

### Risk Classification
- **Critical** (9.0-10.0 CVSS): Remote code execution, data breach
- **High** (7.0-8.9 CVSS): Authentication bypass, sensitive data exposure  
- **Medium** (4.0-6.9 CVSS): Information disclosure, weak encryption
- **Low** (0.1-3.9 CVSS): Security misconfigurations, information leakage
- **Informational**: Best practices, hardening recommendations

### CVE Integration
- Automatic CVE identification from vulnerability signatures
- MITRE CVE database references
- Exploit availability assessment
- Patch status verification
- Risk timeline analysis

### OWASP Top 10 Mapping
1. Broken Access Control
2. Cryptographic Failures  
3. Injection Vulnerabilities
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Authentication Failures
8. Software Integrity Failures
9. Logging/Monitoring Failures
10. Server-Side Request Forgery

## ⚡ Performance & Optimization

### Scan Duration Estimates
- **Quick Scan**: 5-10 minutes (basic assessment)
- **Comprehensive Scan**: 15-30 minutes (full testing)
- **Advanced Assessment**: 20-40 minutes (CVE analysis)
- **Custom Deep Scan**: 30-60 minutes (extensive testing)

### Resource Requirements
- **CPU**: Multi-core recommended for parallel scanning
- **Memory**: 2GB+ for large target analysis
- **Network**: Stable connection for tool updates
- **Storage**: 500MB for tools, 100MB per target assessment

### Optimization Tips
- Use quick scan for initial reconnaissance
- Run comprehensive scan during off-peak hours
- Implement rate limiting for production targets
- Cache DNS resolutions for faster repeated scans
- Use wordlist optimization for directory enumeration

## 🚨 Legal & Ethical Guidelines

### Authorization Requirements
- **Written Permission**: Always obtain explicit written authorization
- **Scope Definition**: Clearly define testing boundaries and limitations
- **Time Windows**: Respect designated testing timeframes
- **Data Handling**: Follow data protection and privacy regulations
- **Reporting**: Provide detailed findings with remediation guidance

### Responsible Disclosure
1. **Initial Report**: Notify organization of critical vulnerabilities within 24 hours
2. **Detailed Assessment**: Provide comprehensive report within 5 business days
3. **Remediation Support**: Offer guidance and verification testing
4. **Public Disclosure**: Follow coordinated disclosure timeline (90 days standard)
5. **Documentation**: Maintain audit trail of all testing activities

### Best Practices
- Start with passive reconnaissance
- Minimize impact on production systems
- Respect rate limits and server resources
- Avoid data modification or destruction
- Document all testing activities
- Provide clear remediation guidance
- Follow industry standards (NIST, OWASP, PTES)

## 🔍 Troubleshooting Guide

### Common Issues
1. **Permission Errors**
   ```bash
   chmod +x *.sh
   ```

2. **Missing Dependencies**
   ```bash
   ./install_deps_fixed.sh
   ./pentest_suite.sh  # Option 5: Check Tool Status
   ```

3. **Network Connectivity**
   ```bash
   curl -I https://google.com  # Test internet connection
   dig google.com              # Test DNS resolution
   ```

4. **Python Environment Issues**
   ```bash
   python3 --version
   source activate_pentest.sh
   pip list | grep -E "(requests|beautifulsoup4)"
   ```

5. **Tool Installation Problems**
   ```bash
   # Check Go installation for gobuster/subfinder
   go version
   echo $GOPATH
   
   # Verify tool locations
   which nmap nikto dirb gobuster sqlmap
   ```

### Performance Issues
- **Slow Scans**: Reduce thread count, use smaller wordlists
- **Memory Usage**: Close unnecessary applications, use swap if needed
- **Network Timeouts**: Increase timeout values, check firewall settings
- **Large Reports**: Split assessment into smaller target segments

### Error Resolution
- **Tool Not Found**: Check PATH, reinstall specific tools
- **Certificate Errors**: Update certificates, use --insecure flag for testing
- **Python Errors**: Verify virtual environment, reinstall packages
- **Report Generation**: Check write permissions, verify pandoc installation

## 📚 Additional Resources

### Learning Materials
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)

### Tool Documentation
- [Nmap Reference Guide](https://nmap.org/book/)
- [Nikto Documentation](https://github.com/sullo/nikto/wiki)
- [SQLMap User Manual](https://github.com/sqlmapproject/sqlmap/wiki)

### CVE Databases
- [MITRE CVE](https://cve.mitre.org/)
- [NVD NIST](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)

## 🤝 Contributing

We welcome contributions to improve the pentest suite:

1. **Bug Reports**: Submit detailed issue reports with reproduction steps
2. **Feature Requests**: Propose new testing modules or improvements
3. **Code Contributions**: Follow coding standards and include documentation
4. **Documentation**: Help improve guides, examples, and troubleshooting
5. **Testing**: Validate tools on different platforms and environments

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

---

**⚠️ DISCLAIMER**: This tool is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. Unauthorized testing is illegal and unethical.
