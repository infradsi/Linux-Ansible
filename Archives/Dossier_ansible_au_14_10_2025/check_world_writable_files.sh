#!/bin/bash

# Output file
REPORT_HTML="world_writable_report.html"

# Find all world-writable files excluding /proc, /sys, /dev
echo "Searching for world-writable files..."
FILES=$(find / -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null)

if [ -z "$FILES" ]; then
    echo "✅ No world-writable files found."
    exit 0
fi

# Start HTML report
echo "<!DOCTYPE html>
<html>
<head>
    <meta charset=\"UTF-8\">
    <title>World-Writable Files Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f44336; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
<h2>World-Writable Files Report</h2>
<p>Generated on: $(date)</p>
<table>
<tr>
    <th>Filename</th>
    <th>Path</th>
    <th>Owner</th>
    <th>Permissions</th>
</tr>" > "$REPORT_HTML"

# Append each file's details to the HTML report
while IFS= read -r file; do
    OWNER=$(stat -c "%U" "$file")
    PERMS=$(stat -c "%A" "$file")
    NAME=$(basename "$file")
    DIR=$(dirname "$file")

    echo "<tr><td>$NAME</td><td>$DIR</td><td>$OWNER</td><td>$PERMS</td></tr>" >> "$REPORT_HTML"
done <<< "$FILES"

# Close HTML tags
echo "</table></body></html>" >> "$REPORT_HTML"

echo "⚠️  World-writable files found."
echo "📄 Report saved to: $REPORT_HTML"
