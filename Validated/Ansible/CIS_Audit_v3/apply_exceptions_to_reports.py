#!/usr/bin/env python3
import os, sys, glob
import pandas as pd

PLAYBOOK_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEL_PATH   = os.path.join(PLAYBOOK_DIR, "cis_exceptions.xlsx")

def html_from_csv(df: pd.DataFrame) -> str:
    return df.to_html(index=False, escape=True)

def main():
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(PLAYBOOK_DIR, "reports")
    if not os.path.exists(reports_dir):
        print(f"ERROR: Répertoire de rapports introuvable: {reports_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        exc = pd.read_excel(EXCEL_PATH, engine="openpyxl")[["CIS Test ID","Exception Reason"]].copy()
    except Exception as e:
        print(f"ERROR: Lecture Excel: {e}", file=sys.stderr)
        sys.exit(2)

    # Normalisation légère côté exceptions
    exc["CIS Test ID"] = exc["CIS Test ID"].astype(str).str.strip()

    csv_files = glob.glob(os.path.join(reports_dir, "*.csv"))
    if not csv_files:
        print(f"INFO: Aucun CSV trouvé dans {reports_dir}")
        sys.exit(0)

    for path in csv_files:
        try:
            df = pd.read_csv(path, dtype=str).fillna("")
        except Exception as e:
            print(f"SKIP: {path} lecture échouée: {e}", file=sys.stderr)
            continue

        # Détecte la colonne ID
        id_col = None
        for c in df.columns:
            if c.strip().lower() in ("cis test id", "test id", "cis_id", "cis id"):
                id_col = c
                break
        if id_col is None:
            print(f"SKIP: {path} sans colonne 'CIS Test ID' / 'Test ID'", file=sys.stderr)
            continue

        left = df.copy()
        left[id_col] = left[id_col].astype(str).str.strip()

        merged = left.merge(exc.rename(columns={"Exception Reason":"Exception"}),
                            how="left", left_on=id_col, right_on="CIS Test ID") \
                    .drop(columns=["CIS Test ID"], errors="ignore")

        # Si la colonne Exception existait, on la remplace par la nouvelle
        if "Exception_x" in merged.columns and "Exception_y" in merged.columns:
            merged["Exception"] = merged["Exception_y"].fillna(merged["Exception_x"])
            merged = merged.drop(columns=["Exception_x","Exception_y"])

        # Écrit CSV enrichi et HTML voisin
        base, _ = os.path.splitext(path)
        out_csv  = base + "_with_exceptions.csv"
        out_html = base + "_with_exceptions.html"
        merged.to_csv(out_csv, index=False)
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html_from_csv(merged))
        print(f"OK: {os.path.basename(out_csv)} / {os.path.basename(out_html)}")

if __name__ == "__main__":
    main()
