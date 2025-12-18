
from openpyxl import Workbook
import sys

print("Starting openpyxl test...", flush=True)
try:
    wb = Workbook()
    ws = wb.active
    ws['A1'] = "Hello"
    wb.save("test_direct.xlsx")
    print("Saved test_direct.xlsx", flush=True)
except Exception as e:
    print(f"Error: {e}", flush=True)
