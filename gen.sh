#!/bin/bash

# Generate rules CRD from all rules in the rules directory

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
RULES_DIR="pkg/rules"
OUTPUT_FILE="rules-crd.yaml"
TEMP_DIR=$(mktemp -d)

echo -e "${GREEN}Generating Rules CRD...${NC}"

# Function to cleanup temp files
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Create the Rule instance header
cat > "$TEMP_DIR/rule-header.yaml" << 'EOF'
apiVersion: kubescape.io/v1
kind: Rules
metadata:
  name: kubescape-rules
  namespace: kubescape
  labels:
    app: kubescape
spec:
  rules:
EOF

# Find all rule YAML files and combine them
echo -e "${YELLOW}Scanning for rule files in $RULES_DIR...${NC}"

# Check if rules directory exists
if [ ! -d "$RULES_DIR" ]; then
    echo -e "${RED}Error: Rules directory $RULES_DIR not found${NC}"
    exit 1
fi

# Find all YAML files in rule directories
RULE_FILES=$(find "$RULES_DIR" -name "*.yaml" -type f | sort)

if [ -z "$RULE_FILES" ]; then
    echo -e "${RED}Error: No YAML files found in $RULES_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}Found $(echo "$RULE_FILES" | wc -l) rule files${NC}"

# Start with the Rule instance header
cp "$TEMP_DIR/rule-header.yaml" "$OUTPUT_FILE"

# Process each rule file and extract the spec.rules content
for rule_file in $RULE_FILES; do
    echo -e "${YELLOW}Processing: $(basename "$rule_file")${NC}"
    
    # Extract the spec.rules array content from each rule file
    # We need to get the content under spec.rules: and add it to our combined spec.rules array
    if command -v yq >/dev/null 2>&1; then
        # Use yq to extract the spec.rules content and format it properly
        yq eval '.spec.rules' "$rule_file" >> "$OUTPUT_FILE"
    else
        # Fallback to sed/awk if yq is not available
        # Extract everything between "rules:" and the end of the file
        awk '/^  rules:/ {p=1; next} /^[a-zA-Z]/ && p {p=0} p {print}' "$rule_file" >> "$OUTPUT_FILE"
    fi
done

echo -e "${GREEN}Successfully generated $OUTPUT_FILE with $(echo "$RULE_FILES" | wc -l) rules${NC}"
echo -e "${GREEN}Output file: $OUTPUT_FILE${NC}"

# Validate the generated YAML
if command -v yq >/dev/null 2>&1; then
    echo -e "${YELLOW}Validating generated YAML...${NC}"
    if yq eval '.' "$OUTPUT_FILE" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ YAML validation passed${NC}"
    else
        echo -e "${RED}✗ YAML validation failed${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Note: yq not found, skipping YAML validation${NC}"
fi

echo -e "${GREEN}Rules CRD generation completed successfully!${NC}"

