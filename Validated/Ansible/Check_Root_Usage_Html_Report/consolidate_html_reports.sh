#!/bin/bash
# Consolidation des rapports HTML dans un rapport global

INPUT_DIR="reports"
OUTPUT_FILE="rapport_global_root_audit.html"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

echo "📦 Consolidation des rapports HTML depuis $INPUT_DIR..."

# Démarrage du HTML global
cat <<EOF > "$OUTPUT_FILE"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport Global Root Audit</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        nav { margin-bottom: 30px; }
        nav ul { list-style-type: none; padding: 0; }
        nav ul li { margin-bottom: 5px; }
        iframe { width: 100%; height: 600px; border: 1px solid #ccc; margin-bottom: 50px; }
    </style>
</head>
<body>
    <h1>Rapport Global - Root Audit</h1>
    <p><strong>Date de génération :</strong> $TIMESTAMP</p>

    <nav>
        <h2>Table des machines auditées :</h2>
        <ul>
EOF

# Créer les entrées de sommaire
for file in "$INPUT_DIR"/*.html; do
    [ -e "$file" ] || continue
    base=$(basename "$file")
    host="${base%_report.html}"
    anchor_id="${host//[^a-zA-Z0-9]/_}"  # safe anchor
    echo "        <li><a href=\"#$anchor_id\">$host</a></li>" >> "$OUTPUT_FILE"
done

cat <<EOF >> "$OUTPUT_FILE"
        </ul>
    </nav>
EOF

# Insérer chaque rapport dans une section iframe
for file in "$INPUT_DIR"/*.html; do
    [ -e "$file" ] || continue
    base=$(basename "$file")
    host="${base%_report.html}"
    anchor_id="${host//[^a-zA-Z0-9]/_}"
    echo "    <h2 id=\"$anchor_id\">Rapport pour $host</h2>" >> "$OUTPUT_FILE"
    echo "    <iframe src=\"$INPUT_DIR/$base\"></iframe>" >> "$OUTPUT_FILE"
done

# Fin du HTML
cat <<EOF >> "$OUTPUT_FILE"
</body>
</html>
EOF

echo "✅ Rapport global généré : $OUTPUT_FILE"
