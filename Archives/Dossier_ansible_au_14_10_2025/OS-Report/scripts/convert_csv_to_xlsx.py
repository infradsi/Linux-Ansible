#!/usr/bin/env python3
"""
Convert a CSV report to XLSX using openpyxl.
Usage: python3 scripts/convert_csv_to_xlsx.py ./reports/os_report.csv ./reports/os_report.xlsx
"""
import sys, csv
from openpyxl import Workbook

if len(sys.argv) != 3:
    print("Usage: convert_csv_to_xlsx.py input.csv output.xlsx")
    sys.exit(2)

infile, outfile = sys.argv[1], sys.argv[2]
wb = Workbook()
ws = wb.active
ws.title = 'OS Report'

with open(infile, newline='') as f:
    reader = csv.reader(f)
    for row in reader:
        ws.append(row)

wb.save(outfile)
print(f"Saved {outfile}")
