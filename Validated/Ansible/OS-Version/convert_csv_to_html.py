# MGH
# Convertisseur du rapport CSV en version HTML
# Maj le 28/10 - 17h45
# Resultat Ok

import pandas as pd
from datetime import datetime

csv_file = "linux_versions.csv"
html_file = "linux_versions_report.html"

obsolete_versions = {
    "Ubuntu": ["16.04", "18.04"],
    "Debian": ["9", "10"],
    "CentOS": ["6.10", "7"],
    "Red Hat Enterprise Linux": ["6", "7", "7.9", "8.6"],
}

# Lire le CSV
df = pd.read_csv(csv_file, names=["Hostname", "OS", "Version"])

# Fonction pour déterminer si la version est obsolète
def is_obsolete(row):
    os_name = str(row["OS"]).strip()
    version = str(row["Version"]).strip()
    if os_name in obsolete_versions:
        return version in obsolete_versions[os_name]
    return False

# Ajouter la colonne "Obsolete"
df["Obsolete"] = df.apply(is_obsolete, axis=1)

# Supprimer la colonne avant le styling
df_display = df.drop(columns=["Obsolete"])

# Fonction de style par ligne
def highlight_obsolete(row):
    color = "background-color: #ffcccc" if df.loc[row.name, "Obsolete"] else ""
    return [color] * len(row)

# Appliquer le style et exporter en HTML
styled_html = (
    df_display.style
    .apply(highlight_obsolete, axis=1)
    .set_table_attributes('border="1" cellspacing="0" cellpadding="5"')
    .set_caption("Rapport des versions Linux - généré le " + datetime.now().strftime('%Y-%m-%d'))
    .render()
)

# Écrire le rapport HTML
with open(html_file, "w") as f:
    f.write(styled_html)

print(f"✅ Rapport généré : {html_file}")

