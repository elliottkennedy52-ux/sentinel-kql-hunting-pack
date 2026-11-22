#!/usr/bin/env python3
"""
KQL Detection Rule Metadata & Syntax Hygiene Validator
Audits all .kql files in the repository to verify required MITRE ATT&CK headers,
data source declarations, and non-empty Kusto query bodies.
"""

from pathlib import Path
import sys

REQUIRED_HEADERS = ("// Title:", "// MITRE ATT&CK:", "// Data Source:")


def validate_repo(root: Path) -> int:
    kql_files = sorted(root.rglob("*.kql"))
    if not kql_files:
        print("[!] No .kql files found.")
        return 1

    errors = 0
    for kql in kql_files:
        content = kql.read_text(encoding="utf-8")
        missing = [h for h in REQUIRED_HEADERS if h not in content]
        has_pipe = "|" in content
        if missing or not has_pipe:
            print(f"[FAIL] {kql}: missing={missing}, valid_pipeline={has_pipe}")
            errors += 1
        else:
            print(f"[PASS] {kql}")

    print(f"\nValidated {len(kql_files)} KQL detection rule(s) with {errors} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(validate_repo(Path(".")))
