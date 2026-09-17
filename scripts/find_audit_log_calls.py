import re
from pathlib import Path

app_dir = Path("backend/app")
for py_file in app_dir.rglob("*.py"):
    content = py_file.read_text(encoding="utf-8")
    matches = re.findall(r"(\w*(?:audit|Audit)\w*\.log\([^)]*\))", content, re.DOTALL)
    if matches:
        print(f"=== {py_file} ===")
        for m in matches[:3]:
            print(m.strip()[:150])
