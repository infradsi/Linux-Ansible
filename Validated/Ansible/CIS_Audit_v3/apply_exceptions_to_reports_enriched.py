#!/usr/bin/env python3
import os, sys, glob
import pandas as pd

PLAYBOOK_DIR = os.path.dirname(os.path.abspath(__file__))
# Preferred enterprise Excel (Option 2). Fallback to basic cis_exceptions.xlsx.
ENTERPRISE_EXCEL = os.path.join(PLAYBOOK_DIR, "cis_exceptions_enterprise_en.xlsx")
BASIC_EXCEL      = os.path.join(PLAYBOOK_DIR, "cis_exceptions.xlsx")

# Columns we try to import from the Excel
EXC_COL_MAP = {
    "CIS Test ID": "CIS Test ID",
    "Exception Reason": "Exception",
    "Mitigation Summary": "Mitigation Summary",
    "Residual Risk": "Residual Risk",
    "Severity": "Severity",
    "Policy Status": "Policy Status",
    "Weight": "Weight",
}

def load_exceptions(excel_path: str) -> pd.DataFrame:
    # Load enterprise first, otherwise fallback to basic file
    path = excel_path if excel_path else (ENTERPRISE_EXCEL if os.path.exists(ENTERPRISE_EXCEL) else BASIC_EXCEL)
    if not os.path.exists(path):
        raise SystemExit(f"ERROR: Exceptions Excel not found: {path} (looked for enterprise then basic)")
    try:
        df = pd.read_excel(path, engine="openpyxl")
    except Exception:
        df = pd.read_excel(path)

    # Normalize columns (case-insensitive mapping)
    cols_lower = {c.lower(): c for c in df.columns}
    out = pd.DataFrame()
    for src, dst in EXC_COL_MAP.items():
        key = src.lower()
        if key in cols_lower:
            out[dst] = df[cols_lower[key]]
    # Ensure CIS Test ID exists
    if "CIS Test ID" not in out.columns:
        raise SystemExit("ERROR: 'CIS Test ID' column not found in exceptions Excel.")
    # Basic normalization
    out["CIS Test ID"] = out["CIS Test ID"].astype(str).str.strip()
    return out

def html_from_df(df: pd.DataFrame) -> str:
    return df.to_html(index=False, escape=True)

def main():
    # Usage:
    #   apply_exceptions_to_reports_enriched.py [reports_dir] [excel_override_path]
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(PLAYBOOK_DIR, "reports")
    excel_override = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(reports_dir):
        print(f"ERROR: Reports directory not found: {reports_dir}", file=sys.stderr)
        sys.exit(1)

    exc = load_exceptions(excel_override)

    csv_files = glob.glob(os.path.join(reports_dir, "*.csv"))
    if not csv_files:
        print(f"INFO: No CSV found in {reports_dir}")
        sys.exit(0)

    for path in csv_files:
        try:
            df = pd.read_csv(path, dtype=str).fillna("")
        except Exception as e:
            print(f"SKIP: {path} read failed: {e}", file=sys.stderr)
            continue

        # Detect the CIS ID column name used in the CSV (case-insensitive)
        id_col = None
        for c in df.columns:
            if c.strip().lower() in ("cis test id", "test id", "cis_id", "cis id", "id"):
                id_col = c
                break
        if id_col is None:
            print(f"SKIP: {path} has no 'CIS Test ID'/'Test ID' column", file=sys.stderr)
            continue

        left = df.copy()
        left[id_col] = left[id_col].astype(str).str.strip()

        # Merge keeping left order
        merged = left.merge(exc, how="left", left_on=id_col, right_on="CIS Test ID")

        # Drop helper key if duplicated
        if "CIS Test ID_y" in merged.columns and id_col != "CIS Test ID_y":
            merged = merged.drop(columns=["CIS Test ID_y"])
        if "CIS Test ID_x" in merged.columns and id_col != "CIS Test ID_x":
            merged = merged.rename(columns={"CIS Test ID_x": id_col})

        # If the CSV already had an Exception column, prefer Excel values when present
        if set(["Exception","Exception_x","Exception_y"]).issubset(set(merged.columns)):
            merged["Exception"] = merged["Exception_y"].fillna(merged["Exception_x"])
            merged = merged.drop(columns=["Exception_x","Exception_y"])

        # Output files
        base, _ = os.path.splitext(path)
        out_csv  = base + "_enriched.csv"
        out_html = base + "_enriched.html"

        merged.to_csv(out_csv, index=False)
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html_from_df(merged))

        print(f"OK: {os.path.basename(out_csv)} / {os.path.basename(out_html)}")

if __name__ == "__main__":
    main()
