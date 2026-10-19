"""Prints the CHANGELOG.md section for a tag (used by the release workflow)."""
import re
import sys

tag = sys.argv[1]
text = open("CHANGELOG.md", encoding="utf-8").read()
m = re.search(rf"^## {re.escape(tag)}\b.*?\n(.*?)(?=^## |\Z)", text, re.S | re.M)
print(m.group(1).strip() if m else "See CHANGELOG.md")
