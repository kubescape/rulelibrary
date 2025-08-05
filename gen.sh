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
  annotations:
    kubescape.io/namespace: kubescape
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
    if [ -f "$HOME/go/bin/yq" ]; then
        # Use Go yq to extract each rule and format it as an array item
        "$HOME/go/bin/yq" eval '.spec.rules[]' "$rule_file" | sed '1s/^/  - /' | sed '2,$s/^/    /' >> "$OUTPUT_FILE"
    else
        # Fallback to awk if yq is not available
        # Extract everything after "rules:" and format as array items
        awk '
        BEGIN { first_line = 1 }
        /^  rules:/ { 
            in_rules = 1
            next 
        }
        /^[a-zA-Z]/ && in_rules { 
            in_rules = 0 
        }
        in_rules && /^- / {
            # This is already a rule array item, print as-is
            print "  " $0
            first_line = 0
            next
        }
        in_rules && /^  / {
            # This is content under rules, need to format it
            if (first_line && /^  [a-zA-Z]/) {
                # First property of a rule, make it an array item
                print "  - " substr($0, 3)
                first_line = 0
            } else {
                # Subsequent properties, indent properly
                print "    " substr($0, 3)
            }
        }
        ' "$rule_file" >> "$OUTPUT_FILE"
    fi
done

echo -e "${GREEN}Successfully generated $OUTPUT_FILE with $(echo "$RULE_FILES" | wc -l) rules${NC}"
echo -e "${GREEN}Output file: $OUTPUT_FILE${NC}"

# Validate the generated YAML
if [ -f "$HOME/go/bin/yq" ]; then
    echo -e "${YELLOW}Validating generated YAML...${NC}"
    if "$HOME/go/bin/yq" eval '.' "$OUTPUT_FILE" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ YAML validation passed${NC}"
    else
        echo -e "${RED}✗ YAML validation failed${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Note: yq not found, skipping YAML validation${NC}"
fi

echo -e "${GREEN}Rules CRD generation completed successfully!${NC}"