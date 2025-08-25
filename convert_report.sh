#!/bin/bash

# =============================================================================
# Report Converter - Convert Markdown Reports to PDF/HTML
# =============================================================================

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <markdown_report_file>"
    exit 1
fi

REPORT_FILE="$1"
BASE_NAME=$(basename "$REPORT_FILE" .md)
OUTPUT_DIR=$(dirname "$REPORT_FILE")

# Check if pandoc is installed
if ! command -v pandoc &> /dev/null; then
    echo "Installing pandoc..."
    sudo apt install -y pandoc texlive-latex-base texlive-fonts-recommended
fi

# Convert to HTML
echo "Converting to HTML..."
pandoc "$REPORT_FILE" -o "${OUTPUT_DIR}/${BASE_NAME}.html" \
    --standalone \
    --css=style.css \
    --metadata title="Penetration Test Report"

# Convert to PDF
echo "Converting to PDF..."
pandoc "$REPORT_FILE" -o "${OUTPUT_DIR}/${BASE_NAME}.pdf" \
    --pdf-engine=xelatex \
    --metadata title="Penetration Test Report"

echo "Conversion completed!"
echo "HTML: ${OUTPUT_DIR}/${BASE_NAME}.html"
echo "PDF: ${OUTPUT_DIR}/${BASE_NAME}.pdf"
