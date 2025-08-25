# Web Penetration Testing Scripts

Collection of automated penetration testing scripts for web security assessment.

## Scripts Overview

### 1. `pentest.sh` - Comprehensive Penetration Testing Script
Full-featured penetration testing script that performs:
- Information gathering (DNS, WHOIS, HTTP headers)
- Port scanning with Nmap
- Directory enumeration
- Vulnerability assessment with Nikto
- SSL/TLS security assessment
- Security headers analysis
- Comprehensive markdown report generation

### 2. `quick_scan.sh` - Quick Security Scanner
Lightweight script for rapid security assessment:
- Basic HTTP information
- Security headers check
- Quick port scan
- Common directory discovery

### 3. `install_deps.sh` - Dependency Installation
Installs all required tools for penetration testing.

## Installation

1. **Make scripts executable:**
```bash
chmod +x *.sh
```

2. **Install dependencies:**
```bash
./install_deps.sh
```

## Usage

### Comprehensive Pentest
```bash
./pentest.sh -t https://example.com -o results_folder
```

**Options:**
- `-t, --target URL`: Target website URL (required)
- `-o, --output DIR`: Output directory (optional)
- `-h, --help`: Show help message

### Quick Scan
```bash
./quick_scan.sh https://example.com
```

## Output

### Comprehensive Pentest Output:
- **Markdown Report**: `pentest_report_YYYY-MM-DD_HH-MM-SS.md`
- **Raw Data Files**:
  - `dns_info.txt` - DNS information
  - `whois_info.txt` - WHOIS data
  - `http_headers.txt` - HTTP headers
  - `robots.txt` - Robots.txt content
  - `nmap_scan.txt` - Port scan results
  - `service_detection.txt` - Service information
  - `dirb_results.txt` - Directory enumeration
  - `nikto_results.txt` - Vulnerability scan
  - `xss_test.html` - XSS test results

### Quick Scan Output:
- Text file: `quick_scan_YYYYMMDD_HHMMSS.txt`

## Report Features

The comprehensive report includes:
- Executive summary
- Information gathering results
- Port scanning and service detection
- Directory enumeration findings
- Vulnerability assessment
- Security headers analysis
- Recommendations and summary

## Required Tools

- `nmap` - Network scanning
- `curl` - HTTP client
- `wget` - File retrieval
- `dig` - DNS lookup
- `whois` - Domain information
- `nikto` - Web vulnerability scanner
- `dirb` / `gobuster` - Directory brute forcing
- `sqlmap` - SQL injection testing
- `openssl` - SSL/TLS testing

## Security Notice

⚠️ **IMPORTANT**: These scripts are for authorized penetration testing only. 

- Only use on systems you own or have explicit permission to test
- Unauthorized scanning/testing is illegal and unethical
- Always follow responsible disclosure practices
- Respect rate limits and server resources

## Examples

### Basic usage:
```bash
./pentest.sh -t https://testphp.vulnweb.com
```

### With custom output directory:
```bash
./pentest.sh -t https://example.com -o my_pentest_results
```

### Quick scan for initial assessment:
```bash
./quick_scan.sh https://example.com
```

## Customization

You can customize the scripts by:
- Adding more wordlists for directory enumeration
- Including additional vulnerability tests
- Modifying report templates
- Adding custom payload tests

## Troubleshooting

1. **Permission denied**: Make sure scripts are executable (`chmod +x *.sh`)
2. **Missing tools**: Run `./install_deps.sh` to install dependencies
3. **Network timeout**: Increase timeout values in script or check connectivity
4. **False positives**: Review results manually, automated tools may have false positives

## Legal Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of these scripts.
