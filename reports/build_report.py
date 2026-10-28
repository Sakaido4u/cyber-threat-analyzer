"""
Convert reports/report.md into reports/report.docx (Word) with all charts embedded.

Usage (from the project folder, venv active):
    python reports/build_report.py

Re-run it whenever you edit report.md or add screenshots. Missing screenshots are
listed so you know what is still to be captured.
"""
import re
from pathlib import Path

import pypandoc  # pip install pypandoc_binary  (bundles pandoc, no separate install)

HERE = Path(__file__).resolve().parent
SRC, OUT = HERE / "report.md", HERE / "report.docx"

text = SRC.read_text(encoding="utf-8")
missing = [p for p in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text) if not (HERE / p).exists()]
if missing:
    print("[!] Images not found yet (they will appear as captions only):")
    for p in missing:
        print("    ", (HERE / p).resolve())

pypandoc.convert_file(str(SRC), "docx", outputfile=str(OUT),
                      extra_args=[f"--resource-path={HERE}", "--toc", "--toc-depth=2"])
print(f"[OK] Wrote {OUT}")
