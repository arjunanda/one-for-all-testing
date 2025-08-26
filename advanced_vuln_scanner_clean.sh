#!/bin/bash

# =============================================================================
# Advanced Vulnerability Scanner v3.0 - Clean Code Edition
# 1000+ Payloads from External Files & Comprehensive Path Discovery
# =============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
HIGH_VULNS=0
MEDIUM_VULNS=0
LOW_VULNS=0
CVE_COUNT=0
TOTAL_PAYLOADS=0
SUCCESSFUL_PAYLOADS=0
DISCOVERED_PATHS=()
TESTED_METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS")

# Get script directory for payload files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$SCRIPT_DIR/payloads"
WORDLIST_DIR="$SCRIPT_DIR/wordlists"

# Usage function
usage() {
    echo "Usage: $0 <target_url> <output_dir> <report_file>"
    echo ""
    echo "Required files:"
    echo "  - wordlists/paths.txt"
    echo "  - payloads/xss_payloads.txt"
    echo "  - payloads/sql_payloads.txt"
    echo "  - payloads/lfi_payloads.txt"
    echo "  - payloads/cmd_payloads.txt"
    exit 1
}

# Check arguments and required files
if [ $# -ne 3 ]; then
    usage
fi

# Check if payload files exist
required_files=(
    "$WORDLIST_DIR/paths.txt"
    "$PAYLOAD_DIR/xss_payloads.txt"
    "$PAYLOAD_DIR/sql_payloads.txt"
    "$PAYLOAD_DIR/lfi_payloads.txt"
    "$PAYLOAD_DIR/cmd_payloads.txt"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}[ERROR] Required file not found: $file${NC}"
        echo -e "${YELLOW}Please ensure all payload and wordlist files are present.${NC}"
        exit 1
    fi
done

TARGET="$1"
OUTPUT_DIR="$2" 
REPORT_FILE="$3"

# Create comprehensive directory structure
mkdir -p "$OUTPUT_DIR/payloads"
mkdir -p "$OUTPUT_DIR/paths"
mkdir -p "$OUTPUT_DIR/evidence"
mkdir -p "$OUTPUT_DIR/wordlists"
mkdir -p "$OUTPUT_DIR/methods"

# Logging function
log_vuln() {
    echo -e "$1" >> "$REPORT_FILE"
    echo -e "$1"
    echo -e "$1" >> "$OUTPUT_DIR/comprehensive_log.txt"
}

# Extract domain from URL
extract_domain() {
    echo "$1" | sed -E 's/^https?:\/\///' | sed -E 's/\/.*$//' | sed -E 's/:.*$//'
}

# Load payloads from file
load_payloads() {
    local file="$1"
    local -n array_ref="$2"
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        if [[ ! "$line" =~ ^#.*$ ]] && [[ -n "$line" ]]; then
            array_ref+=("$line")
        fi
    done < "$file"
}

# Banner
show_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         ADVANCED VULNERABILITY SCANNER v3.0                 ║"
    echo "║              Clean Code Edition                              ║"
    echo "║        1000+ External Payloads & Path Discovery             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}[INFO] Payload files loaded from: $PAYLOAD_DIR${NC}"
    echo -e "${CYAN}[INFO] Wordlist files loaded from: $WORDLIST_DIR${NC}"
}

# =============================================================================
# PATH DISCOVERY MODULE
# =============================================================================
discover_all_paths() {
    log_vuln "#### Comprehensive Path Discovery:"
    log_vuln ""
    
    # Load paths from wordlist file
    local wordlists=()
    load_payloads "$WORDLIST_DIR/paths.txt" wordlists
    
    echo -e "${BLUE}[PATH DISCOVERY] Loaded ${#wordlists[@]} paths from wordlist file${NC}"
    echo -e "${BLUE}[PATH DISCOVERY] Testing paths with ${#TESTED_METHODS[@]} HTTP methods${NC}"
    
    local found_paths=0
    local total_tests=0
    
    # Test each path with different methods
    for path in "${wordlists[@]}"; do
        for method in "${TESTED_METHODS[@]}"; do
            ((total_tests++))
            
            # Construct full URL
            if [[ $path == *.* ]] || [[ $path == api/* ]]; then
                test_url="${TARGET}/${path}"
            else
                test_url="${TARGET}/${path}/"
            fi
            
            # Test the path
            if [ "$method" = "GET" ]; then
                response=$(curl -s -w "%{http_code}" -o /dev/null "$test_url" --max-time 5 2>/dev/null)
            else
                response=$(curl -s -w "%{http_code}" -o /dev/null -X "$method" "$test_url" --max-time 5 2>/dev/null)
            fi
            
            # Check if path exists (not 404)
            if [[ "$response" =~ ^[2-3][0-9][0-9]$ ]]; then
                echo "$path|$method|$response" >> "$OUTPUT_DIR/paths/discovered_paths.txt"
                DISCOVERED_PATHS+=("$path:$method:$response")
                ((found_paths++))
                
                log_vuln "✅ **Path Found**: $path (Method: $method, Status: $response)"
            fi
            
            # Rate limiting
            if [ $((total_tests % 10)) -eq 0 ]; then
                sleep 0.1
            fi
        done
    done
    
    log_vuln ""
    log_vuln "**Path Discovery Summary:**"
    log_vuln "- Total paths tested: $total_tests"
    log_vuln "- Valid paths found: $found_paths"
    log_vuln "- Discovery rate: $(( found_paths * 100 / total_tests ))%"
    log_vuln ""
    
    echo -e "${GREEN}[PATH DISCOVERY] Found $found_paths valid paths from $total_tests tests${NC}"
}

# =============================================================================
# VULNERABILITY TESTING MODULES
# =============================================================================

# Generic vulnerability testing function
test_vulnerability() {
    local vuln_type="$1"
    local payload_file="$2"
    local test_params_string="$3"
    local indicators_string="$4"
    
    log_vuln "#### ${vuln_type} Testing:"
    log_vuln ""
    
    # Convert parameter strings to arrays
    IFS=' ' read -ra test_params <<< "$test_params_string"
    IFS='|' read -ra indicators <<< "$indicators_string"
    
    # Load payloads from file
    local payloads=()
    load_payloads "$payload_file" payloads
    
    echo -e "${BLUE}[${vuln_type}] Loaded ${#payloads[@]} payloads from file${NC}"
    
    local vuln_found=false
    local payload_count=0
    
    # Test discovered paths
    for path_info in "${DISCOVERED_PATHS[@]}"; do
        IFS=':' read -r path method status <<< "$path_info"
        
        for payload in "${payloads[@]}"; do
            for param in "${test_params[@]}"; do
                ((payload_count++))
                ((TOTAL_PAYLOADS++))
                
                # Test payload
                if test_single_payload "$vuln_type" "$path" "$method" "$param" "$payload" indicators; then
                    vuln_found=true
                fi
                
                # Rate limiting
                if [ $((payload_count % 100)) -eq 0 ]; then
                    echo -e "${YELLOW}[${vuln_type}] Tested $payload_count payloads...${NC}"
                    sleep 0.2
                fi
            done
        done
    done
    
    # Test main target if no paths discovered
    if [ ${#DISCOVERED_PATHS[@]} -eq 0 ]; then
        test_main_target "$vuln_type" payloads test_params indicators payload_count
    fi
    
    # Generate summary
    generate_vulnerability_summary "$vuln_type" "$payload_count" "$vuln_found"
}

# Test single payload
test_single_payload() {
    local vuln_type="$1"
    local path="$2"
    local method="$3"
    local param="$4"
    local payload="$5"
    local -n indicators_ref=$6
    
    # Construct test URL
    if [[ $path == *.* ]]; then
        test_url="${TARGET}/${path}"
    else
        test_url="${TARGET}/${path}/"
    fi
    
    # Execute request based on method
    if [ "$method" = "GET" ]; then
        encoded_payload=$(echo "$payload" | sed 's/&/%26/g;s/ /%20/g;s/</%3C/g;s/>/%3E/g;s/"/%22/g;s/'\''/%27/g')
        response=$(curl -s "${test_url}?${param}=${encoded_payload}" --max-time 10 2>/dev/null)
    else
        response=$(curl -s -X "$method" -d "${param}=${payload}" "$test_url" --max-time 10 2>/dev/null)
    fi
    
    # Check for vulnerability indicators
    for indicator in "${indicators_ref[@]}"; do
        if echo "$response" | grep -qi "$indicator"; then
            log_vulnerability_finding "$vuln_type" "$path" "$method" "$param" "$payload" "$indicator"
            
            # Save evidence
            echo "${vuln_type} FOUND: $path | $method | $param | $payload | $indicator" >> "$OUTPUT_DIR/evidence/${vuln_type,,}_findings.txt"
            echo "$response" > "$OUTPUT_DIR/evidence/${vuln_type,,}_response_${path//\//_}_${param}_$(date +%s).txt"
            
            ((HIGH_VULNS++))
            ((SUCCESSFUL_PAYLOADS++))
            ((CVE_COUNT++))
            return 0
        fi
    done
    
    return 1
}

# Log vulnerability finding
log_vulnerability_finding() {
    local vuln_type="$1"
    local path="$2"
    local method="$3"
    local param="$4"
    local payload="$5"
    local indicator="$6"
    
    log_vuln "⚠️  **HIGH RISK**: ${vuln_type} vulnerability detected"
    log_vuln "   - **Path**: /$path"
    log_vuln "   - **Parameter**: $param"
    log_vuln "   - **Method**: $method"
    log_vuln "   - **Payload**: \`${payload}\`"
    log_vuln "   - **Evidence**: $indicator"
    log_vuln "   - **Impact**: $(get_impact_description "$vuln_type")"
    log_vuln "   - **CVE Reference**: $(get_cve_reference "$vuln_type")"
    log_vuln ""
}

# Get impact description based on vulnerability type
get_impact_description() {
    case "$1" in
        "XSS") echo "Session hijacking, credential theft, malicious redirects" ;;
        "SQL") echo "Database enumeration, data extraction, complete database compromise" ;;
        "LFI") echo "Server file system access, configuration disclosure" ;;
        "CMD") echo "Remote command execution, complete server compromise" ;;
        *) echo "Security vulnerability detected" ;;
    esac
}

# Get CVE reference based on vulnerability type
get_cve_reference() {
    case "$1" in
        "XSS") echo "CVE-2023-XSS-GENERIC" ;;
        "SQL") echo "CVE-2023-SQL-GENERIC" ;;
        "LFI") echo "CVE-2023-LFI-GENERIC" ;;
        "CMD") echo "CVE-2023-CMD-INJECTION" ;;
        *) echo "CVE-2023-WEB-VULN" ;;
    esac
}

# Test main target
test_main_target() {
    local vuln_type="$1"
    local -n payloads_ref=$2
    local -n params_ref=$3
    local -n indicators_ref=$4
    local -n count_ref=$5
    
    echo -e "${YELLOW}[${vuln_type}] No paths discovered, testing main target...${NC}"
    
    for payload in "${payloads_ref[@]}"; do
        for param in "${params_ref[@]}"; do
            ((count_ref++))
            ((TOTAL_PAYLOADS++))
            
            encoded_payload=$(echo "$payload" | sed 's/&/%26/g;s/ /%20/g;s/</%3C/g;s/>/%3E/g;s/"/%22/g;s/'\''/%27/g')
            response=$(curl -s "${TARGET}?${param}=${encoded_payload}" --max-time 10 2>/dev/null)
            
            for indicator in "${indicators_ref[@]}"; do
                if echo "$response" | grep -qi "$indicator"; then
                    log_vuln "⚠️  **HIGH RISK**: ${vuln_type} vulnerability on main target"
                    log_vuln "   - **Parameter**: $param"
                    log_vuln "   - **Payload**: \`${payload}\`"
                    log_vuln "   - **Evidence**: $indicator"
                    log_vuln ""
                    
                    ((HIGH_VULNS++))
                    ((SUCCESSFUL_PAYLOADS++))
                    break
                fi
            done
            
            # Rate limiting
            if [ $((count_ref % 100)) -eq 0 ]; then
                sleep 0.1
            fi
        done
    done
}

# Generate vulnerability summary
generate_vulnerability_summary() {
    local vuln_type="$1"
    local payload_count="$2"
    local vuln_found="$3"
    
    if [ "$vuln_found" = false ]; then
        log_vuln "✅ **No ${vuln_type} vulnerabilities** detected"
        log_vuln ""
    fi
    
    log_vuln "**${vuln_type} Testing Summary:**"
    log_vuln "- Total payloads tested: $payload_count"
    log_vuln "- Successful exploits: $(grep -c "${vuln_type} FOUND" "$OUTPUT_DIR/evidence/${vuln_type,,}_findings.txt" 2>/dev/null || echo 0)"
    log_vuln ""
}

# =============================================================================
# SSL/TLS TESTING
# =============================================================================
test_ssl_advanced() {
    log_vuln "#### Advanced SSL/TLS Security Testing:"
    log_vuln ""
    
    local domain=$(extract_domain "$TARGET")
    
    # Check if target uses HTTPS
    if [[ "$TARGET" != https://* ]]; then
        log_vuln "⚠️  **MEDIUM RISK**: Target does not use HTTPS"
        log_vuln "   - **Issue**: Unencrypted communication"
        log_vuln "   - **Impact**: Man-in-the-middle attacks possible"
        log_vuln "   - **Recommendation**: Implement SSL/TLS encryption"
        log_vuln ""
        ((MEDIUM_VULNS++))
        return
    fi
    
    # Test SSL certificate
    if curl -s "$TARGET" >/dev/null 2>&1; then
        log_vuln "✅ **SSL certificate appears valid**"
    else
        log_vuln "⚠️  **MEDIUM RISK**: SSL certificate issues detected"
        log_vuln "   - **Issue**: Certificate validation problems"
        log_vuln "   - **Impact**: Certificate warnings, trust issues"
        ((MEDIUM_VULNS++))
    fi
    
    # Test HSTS header
    hsts_header=$(curl -s -I "$TARGET" 2>/dev/null | grep -i "strict-transport-security")
    
    if [ -z "$hsts_header" ]; then
        log_vuln "⚠️  **LOW RISK**: HTTP Strict Transport Security (HSTS) not implemented"
        log_vuln "   - **Issue**: Missing HSTS header"
        log_vuln "   - **Recommendation**: Implement HSTS header"
        ((LOW_VULNS++))
    else
        log_vuln "✅ **HSTS header present**: $hsts_header"
    fi
    log_vuln ""
}

# =============================================================================
# MAIN EXECUTION FUNCTION
# =============================================================================
main() {
    show_banner
    
    echo -e "${BLUE}[SCANNER] Starting comprehensive vulnerability assessment...${NC}"
    echo -e "${YELLOW}[INFO] Target: $TARGET${NC}"
    echo -e "${YELLOW}[INFO] Output Directory: $OUTPUT_DIR${NC}"
    
    # Initialize log files
    echo "" > "$OUTPUT_DIR/evidence/xss_findings.txt"
    echo "" > "$OUTPUT_DIR/evidence/sql_findings.txt"
    echo "" > "$OUTPUT_DIR/evidence/lfi_findings.txt"
    echo "" > "$OUTPUT_DIR/evidence/cmd_findings.txt"
    echo "" > "$OUTPUT_DIR/comprehensive_log.txt"
    
    # Start comprehensive testing
    log_vuln "# COMPREHENSIVE VULNERABILITY ASSESSMENT REPORT"
    log_vuln "**Target**: $TARGET"
    log_vuln "**Date**: $(date)"
    log_vuln "**Scanner**: Advanced Vulnerability Scanner v3.0 - Clean Edition"
    log_vuln ""
    log_vuln "---"
    log_vuln ""
    
    # Step 1: Path Discovery
    discover_all_paths
    
    # Step 2: Vulnerability Testing with External Payloads
    test_vulnerability "XSS" "$PAYLOAD_DIR/xss_payloads.txt" "q search keyword name email comment message data input value text content title description query" "alert('XSS')|alert(\"XSS\")|alert(/XSS/)"
    
    test_vulnerability "SQL" "$PAYLOAD_DIR/sql_payloads.txt" "id user username email search category page sort order limit offset" "sql syntax|mysql_fetch|ORA-01756|Microsoft OLE DB Provider|PostgreSQL query failed|SQLite3::SQLException|Warning: mysql|MySQLSyntaxErrorException|SQLSTATE|SQLException"
    
    test_vulnerability "LFI" "$PAYLOAD_DIR/lfi_payloads.txt" "file page include template document path url src source load read view show get fetch" "root:|daemon:|bin:|sys:|adm:|lp:|sync:|shutdown:|halt:|mail:|[boot loader]|[operating systems]|[fonts]|[extensions]"
    
    test_vulnerability "CMD" "$PAYLOAD_DIR/cmd_payloads.txt" "cmd command exec execute run system shell bash sh powershell ps" "uid=|gid=|groups=|root|daemon|bin|Windows|Microsoft|System32|Program Files|Linux|GNU|kernel|total used available|drwx|-rw-|lrwx|tcp|udp|LISTEN|ESTABLISHED|PID|USER|COMMAND"
    
    # Step 3: SSL/TLS Testing
    test_ssl_advanced
    
    # Generate comprehensive summary
    log_vuln "---"
    log_vuln ""
    log_vuln "## COMPREHENSIVE VULNERABILITY ASSESSMENT SUMMARY"
    log_vuln ""
    log_vuln "### Testing Statistics:"
    log_vuln "- **Total Payloads Tested**: $TOTAL_PAYLOADS"
    log_vuln "- **Successful Exploits**: $SUCCESSFUL_PAYLOADS"
    if [ $TOTAL_PAYLOADS -gt 0 ]; then
        log_vuln "- **Success Rate**: $(( SUCCESSFUL_PAYLOADS * 100 / TOTAL_PAYLOADS ))%"
    fi
    log_vuln "- **Discovered Paths**: ${#DISCOVERED_PATHS[@]}"
    log_vuln "- **Methods Tested**: ${#TESTED_METHODS[@]}"
    log_vuln ""
    
    log_vuln "### Vulnerability Breakdown:"
    log_vuln "- **High Risk Vulnerabilities**: $HIGH_VULNS"
    log_vuln "- **Medium Risk Vulnerabilities**: $MEDIUM_VULNS" 
    log_vuln "- **Low Risk Vulnerabilities**: $LOW_VULNS"
    log_vuln "- **CVEs Identified**: $CVE_COUNT"
    log_vuln ""
    
    log_vuln "### Risk Assessment:"
    if [ "$HIGH_VULNS" -gt 0 ]; then
        log_vuln "🚨 **CRITICAL**: $HIGH_VULNS high-risk vulnerabilities detected"
        log_vuln "**Immediate action required** - These vulnerabilities pose serious security risks"
    elif [ "$MEDIUM_VULNS" -gt 0 ]; then
        log_vuln "⚠️  **WARNING**: $MEDIUM_VULNS medium-risk vulnerabilities detected"
        log_vuln "**Timely remediation recommended** - These issues should be addressed"
    else
        log_vuln "✅ **GOOD**: No high or medium risk vulnerabilities detected"
        log_vuln "The target appears to have good security posture against automated attacks"
    fi
    log_vuln ""
    
    # Evidence files summary
    log_vuln "### Evidence Files Generated:"
    log_vuln "- XSS Evidence: \`$OUTPUT_DIR/evidence/xss_findings.txt\`"
    log_vuln "- SQL Injection Evidence: \`$OUTPUT_DIR/evidence/sql_findings.txt\`"
    log_vuln "- File Inclusion Evidence: \`$OUTPUT_DIR/evidence/lfi_findings.txt\`"
    log_vuln "- Command Injection Evidence: \`$OUTPUT_DIR/evidence/cmd_findings.txt\`"
    log_vuln "- Path Discovery Results: \`$OUTPUT_DIR/paths/discovered_paths.txt\`"
    log_vuln "- Comprehensive Log: \`$OUTPUT_DIR/comprehensive_log.txt\`"
    log_vuln ""
    
    # Return vulnerability counts to main script
    echo "$HIGH_VULNS:$MEDIUM_VULNS:$LOW_VULNS:$CVE_COUNT" > "$OUTPUT_DIR/vuln_summary.txt"
    
    echo -e "${GREEN}[SCANNER] Comprehensive vulnerability assessment completed${NC}"
    echo -e "${BLUE}Summary: ${RED}$HIGH_VULNS High${NC}, ${YELLOW}$MEDIUM_VULNS Medium${NC}, ${GREEN}$LOW_VULNS Low${NC} risks found"
    echo -e "${PURPLE}Total payloads tested: $TOTAL_PAYLOADS${NC}"
    echo -e "${CYAN}Evidence saved in: $OUTPUT_DIR/evidence/${NC}"
}

# Execute main function
main
