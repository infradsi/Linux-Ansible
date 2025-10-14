import pandas as pd
from datetime import datetime

csv_file = "linux_versions_reports/linux_versions.csv"
html_file = "linux_versions_reports/linux_versions_report.html"

obsolete_versions = {
    "Ubuntu": ["16.04", "18.04"],
    "Debian": ["9", "10"],
    "CentOS": ["6.10", "7"],
    "Red Hat Enterprise Linux": ["6", "7", "7.9", "8.6"],
}

df = pd.read_csv(csv_file, names=["Hostname", "OS", "Version"])

def is_obsolete(row):
    os_name = row["OS"]
    version = row["Version"]
    if os_name in obsolete_versions:
        return version in obsolete_versions[os_name]
    return False

df["Obsolete"] = df.apply(is_obsolete, axis=1)

def row_style(row):
    return 'background-color: #ffcccc;' if row.Obsolete else ''

styled_html = (
    df.style
    .apply(lambda x: [row_style(x) for _ in x], axis=1)
    .hide_columns(["Obsolete"])
    .set_table_attributes('border="1" cellspacing="0" cellpadding="5"')
    .set_caption("Rapport des versions Linux - généré le " + datetime.now().strftime('%Y-%m-%d'))
    .to_html()
)

with open(html_file, "w") as f:
    f.write(styled_html)
