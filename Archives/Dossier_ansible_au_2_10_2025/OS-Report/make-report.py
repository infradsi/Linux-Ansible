#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Relit /tmp/ansible_os_tmp* et produit un CSV + HTML consolidés, tolérant aux lignes vides/incomplètes.

Champs attendus (7 colonnes) :
server;os;os_version;kernel;arch;uptime;patchlevel
"""

import glob
import os
import csv
import re
from datetime import datetime

# Réglages
GLOB_PATTERN = "/tmp/ansible_os_tmp*"
OUTPUT_DIR = "/tmp"
CSV_PATH = os.path.join(OUTPUT_DIR, "os_report.csv")
HTML_PATH = os.path.join(OUTPUT_DIR, "os_report.html")
EXPECTED_HEADERS = ["server", "os", "os_version", "kernel", "arch", "uptime", "patchlevel"]
EXPECTED_COLS = len(EXPECTED_HEADERS)

# Split tolérant : privilégie ';', sinon ',' si aucun ';' trouvé
def smart_split(line: str):
    line = line.strip().rstrip("\r")
    if not line:
        return []
    if ";" in line:
        parts = line.split(";")
    elif "," in line:
        parts = line.split(",")
    else:
        parts = [line]
    # Nettoyage de base des champs
    return [p.strip() for p in parts]

def looks_like_header(parts):
    # Détecte une éventuelle ligne d'en-tête dans les fichiers d'entrée
    lower = [p.lower() for p in parts]
    return all(x in lower for x in ["server", "os"]) and any(x in lower for x in ["os_version","version"])

def pad_to_expected(parts, n=EXPECTED_COLS):
    if len(parts) < n:
        parts = parts + [""] * (n - len(parts))
    else:
        parts = parts[:n]
    return parts

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def read_all_rows():
    files = sorted(glob.glob(GLOB_PATTERN))
    rows = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    # ignore lignes vides / commentaires
                    if re.match(r"^\s*(#|$)", raw):
                        continue
                    parts = smart_split(raw)
                    if not parts:
                        continue
                    # ignore header éventuel contenu dans un fichier
                    if looks_like_header(parts):
                        continue
                    # pad pour éviter les index errors
                    parts = pad_to_expected(parts, EXPECTED_COLS)
                    rows.append(parts)
        except Exception as e:
            # On continue malgré un fichier illisible
            print(f"[WARN] Lecture échouée pour {path}: {e}")
    return rows

def write_csv(rows):
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
        w.writerow(EXPECTED_HEADERS)
        w.writerows(rows)

def html_escape(text: str) -> str:
    return (text
            .replace("&","&amp;")
            .replace("<","&lt;")
            .replace(">","&gt;")
            .replace('"',"&quot;")
            .replace("'","&#39;"))

def write_html(rows):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Petite feuille de style intégrée
    css = """
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
    h1 { font-size: 22px; margin-bottom: 8px; }
    .meta { color:#555; margin-bottom:16px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f4f6f8; text-align: left; }
    tr:nth-child(even) td { background: #fbfbfb; }
    .count { margin-top: 10px; color:#333; }
    """
    thead = "<tr>" + "".join(f"<th>{html_escape(h)}</th>" for h in EXPECTED_HEADERS) + "</tr>"
    tbody_rows = []
    for r in rows:
        tds = "".join(f"<td>{html_escape(c)}</td>" for c in r)
        tbody_rows.append(f"<tr>{tds}</tr>")
    tbody = "\n".join(tbody_rows)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>OS Inventory Report</title>
<style>{css}</style>
</head>
<body>
<h1>OS Inventory Report</h1>
<div class="meta">Généré le {html_escape(ts)} à partir de {html_escape(GLOB_PATTERN)}</div>
<table>
<thead>{thead}</thead>
<tbody>
{tbody}
</tbody>
</table>
<div class="count">{len(rows)} enregistrements</div>
</body>
</html>
"""
    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    ensure_output_dir()
    rows = read_all_rows()
    # Déduplication basique optionnelle (même tuple complet)
    # rows = list(dict.fromkeys(tuple(r) for r in rows))
    write_csv(rows)
    write_html(rows)
    print(f"[OK] CSV : {CSV_PATH}")
    print(f"[OK] HTML: {HTML_PATH}")
    if not rows:
        print("[INFO] Aucun enregistrement lu. Vérifiez le motif /tmp/ansible_os_tmp* et le contenu des fichiers.")

if __name__ == "__main__":
    main()
