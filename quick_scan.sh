#!/bin/bash

# =============================================================================
# Quick Web Security Scanner
# Lightweight version for rapid testing
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

TARGET="$1"
OUTPUT_FILE="quick_scan_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${BLUE}Quick Security Scan for: $TARGET${NC}" | tee "$OUTPUT_FILE"
echo "=================================================" | tee -a "$OUTPUT_FILE"

# Basic HTTP info
echo -e "\n${YELLOW}[1] HTTP Headers:${NC}" | tee -a "$OUTPUT_FILE"
curl -I "$TARGET" 2>/dev/null | tee -a "$OUTPUT_FILE"

# Check robots.txt
echo -e "\n${YELLOW}[2] Robots.txt:${NC}" | tee -a "$OUTPUT_FILE"
curl -s "${TARGET}/robots.txt" | head -10 | tee -a "$OUTPUT_FILE"

# Security headers check
echo -e "\n${YELLOW}[3] Security Headers Check:${NC}" | tee -a "$OUTPUT_FILE"
HEADERS=$(curl -I -s "$TARGET")

if echo "$HEADERS" | grep -qi "strict-transport-security"; then
    echo "✅ HSTS: Present" | tee -a "$OUTPUT_FILE"
else
    echo "❌ HSTS: Missing" | tee -a "$OUTPUT_FILE"
fi

if echo "$HEADERS" | grep -qi "x-frame-options"; then
    echo "✅ X-Frame-Options: Present" | tee -a "$OUTPUT_FILE"
else
    echo "❌ X-Frame-Options: Missing" | tee -a "$OUTPUT_FILE"
fi

if echo "$HEADERS" | grep -qi "x-xss-protection"; then
    echo "✅ X-XSS-Protection: Present" | tee -a "$OUTPUT_FILE"
else
    echo "❌ X-XSS-Protection: Missing" | tee -a "$OUTPUT_FILE"
fi

# Quick port scan
echo -e "\n${YELLOW}[4] Quick Port Scan:${NC}" | tee -a "$OUTPUT_FILE"
DOMAIN=$(echo "$TARGET" | sed -E 's/^https?:\/\///' | sed -E 's/\/.*$//')
nmap -F "$DOMAIN" 2>/dev/null | tee -a "$OUTPUT_FILE"

# Common directories
echo -e "\n${YELLOW}[5] Common Directories:${NC}" | tee -a "$OUTPUT_FILE"
for dir in admin login dashboard config backup test dev api wp-admin phpmyadmin; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/${dir}")
    if [ "$STATUS" != "404" ]; then
        echo "Found: /${dir} (Status: $STATUS)" | tee -a "$OUTPUT_FILE"
    fi
done

echo -e "\n${GREEN}Quick scan completed! Results saved to: $OUTPUT_FILE${NC}"
