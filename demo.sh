#!/bin/bash

# =============================================================================
# Demo Script - Test pentest tools on safe targets
# =============================================================================

echo "========================================="
echo "   PENETRATION TESTING DEMO"
echo "========================================="
echo ""

# Safe targets for testing
SAFE_TARGETS=(
    "http://testphp.vulnweb.com"
    "http://demo.testfire.net"
    "https://httpbin.org"
    "http://scanme.nmap.org"
)

echo "Available safe testing targets:"
for i in "${!SAFE_TARGETS[@]}"; do
    echo "$((i+1)). ${SAFE_TARGETS[i]}"
done

echo ""
read -p "Select target (1-${#SAFE_TARGETS[@]}): " choice

if [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "${#SAFE_TARGETS[@]}" ]]; then
    echo "Invalid selection!"
    exit 1
fi

TARGET="${SAFE_TARGETS[$((choice-1))]}"

echo ""
echo "Selected target: $TARGET"
echo ""

# Ask for scan type
echo "Select scan type:"
echo "1. Quick Scan (fast)"
echo "2. Comprehensive Scan (slow but detailed)"
echo ""
read -p "Enter choice (1-2): " scan_type

case $scan_type in
    1)
        echo "Running quick scan..."
        ./quick_scan.sh "$TARGET"
        ;;
    2)
        echo "Running comprehensive scan..."
        ./pentest.sh -t "$TARGET" -o "demo_results"
        ;;
    *)
        echo "Invalid choice!"
        exit 1
        ;;
esac

echo ""
echo "Demo completed!"
echo "Note: These are intentionally vulnerable test sites for educational purposes."
