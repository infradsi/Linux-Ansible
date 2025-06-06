#!/bin/bash

INPUT_FILE="servers.txt"
OUTPUT_FILE="responsive_servers.txt"

# Clear output file
> "$OUTPUT_FILE"

# Loop through each line (server) in the input file
while IFS= read -r server; do
    # Skip empty lines or comments
    [[ -z "$server" || "$server" =~ ^# ]] && continue

    echo "Pinging $server..."
    if ping -c 1 -W 1 "$server" &> /dev/null; then
        echo "$server is responsive"
        echo "$server" >> "$OUTPUT_FILE"
    else
        echo "$server is not responsive"
    fi
done < "$INPUT_FILE"

echo "Responsive servers saved to $OUTPUT_FILE"
