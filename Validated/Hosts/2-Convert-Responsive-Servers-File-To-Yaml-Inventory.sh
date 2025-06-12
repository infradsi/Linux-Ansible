#!/bin/bash

INPUT_FILE="responsive_servers.txt"
OUTPUT_FILE="inventory.yaml"
GROUP_NAME="responsive_hosts"

# Start writing YAML inventory
echo "---" > "$OUTPUT_FILE"
echo "all:" >> "$OUTPUT_FILE"
echo "  children:" >> "$OUTPUT_FILE"
echo "    $GROUP_NAME:" >> "$OUTPUT_FILE"
echo "      hosts:" >> "$OUTPUT_FILE"

# Append each responsive host
while IFS= read -r host; do
    [[ -z "$host" || "$host" =~ ^# ]] && continue
    echo "        $host:" >> "$OUTPUT_FILE"
done < "$INPUT_FILE"

echo "Ansible inventory written to $OUTPUT_FILE"
