#!/usr/bin/env python3
import csv, sys, json
from pathlib import Path
from datetime import datetime

def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        return list(r), r.fieldnames

def write_csv(rows, headers, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in rows:
            w.writerow(row)

def write_html(rows, headers, out_path, title, summary):
    dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>")
        f.write("<style>body{font-family:sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px}th{position:sticky;top:0;background:#f7f7f7}tr:nth-child(even){background:#fafafa}</style>")
        f.write("</head><body>")
        f.write(f"<h1>{title}</h1><p>Generated: {dt}</p>")
        f.write("<h2>Summary</h2><ul>")
        for k,v in summary.items():
            f.write(f"<li><b>{k}</b>: {v}</li>")
        f.write("</ul>")
        f.write("<table><thead><tr>")
        for h in headers:
            f.write(f"<th>{h}</th>")
        f.write("</tr></thead><tbody>")
        for row in rows:
            f.write("<tr>")
            for h in headers:
                v = row.get(h, "")
                f.write(f"<td>{v}</td>")
            f.write("</tr>")
        f.write("</tbody></table></body></html>")

def main():
    if len(sys.argv) < 4:
        print("Usage: consolidate_unused_accounts.py <reports_root> <out_csv> <out_html>", file=sys.stderr)
        sys.exit(1)
    reports_root = Path(sys.argv[1]).resolve()
    out_csv = Path(sys.argv[2]).resolve()
    out_html = Path(sys.argv[3]).resolve()

    csv_paths = sorted(reports_root.glob("*/unused_accounts_enriched.csv"))
    rows_all = []
    headers_base = ["host","user","uid","gid","threshold_days","days_since_last_activity","last_login","last_password_change","activity_source","status","account_state","shell","home"]
    hosts = set()
    for p in csv_paths:
        host = p.parent.name
        hosts.add(host)
        rows, headers = load_csv(p)
        for r in rows:
            out = {"host": host}
            for h in headers:
                out[h] = r.get(h, "")
            rows_all.append(out)

    summary = {
        "hosts_scanned": len(hosts),
        "rows_total": len(rows_all),
        "OK": sum(1 for r in rows_all if r.get("status")=="OK"),
        "STALE": sum(1 for r in rows_all if r.get("status")=="STALE"),
        "LOCKED": sum(1 for r in rows_all if r.get("status")=="LOCKED"),
        "EXPIRED": sum(1 for r in rows_all if r.get("status")=="EXPIRED"),
    }

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    write_csv(rows_all, headers_base, out_csv)

    title = "Unused Accounts – Consolidated Report"
    write_html(rows_all, headers_base, out_html, title, summary)

    print(f"Consolidated CSV: {out_csv}")
    print(f"Consolidated HTML: {out_html}")
    print(f"Summary: {json.dumps(summary, indent=2)}")

if __name__ == "__main__":
    main()
