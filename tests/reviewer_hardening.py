#!/usr/bin/env python3
"""Run the reviewer-hardening gates and validate the persisted report."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "reviewer-hardening.json"
subprocess.run(
    [sys.executable, str(ROOT / "src" / "reviewer_hardening.py"), "--artifact-root", str(ROOT), "--output", str(OUT)],
    check=True,
    cwd=ROOT,
)
report = json.loads(OUT.read_text(encoding="utf-8"))
assert report["schema"] == "pcl-reviewer-hardening/v1"
assert report["status"] == "passed"
assert report["small_model"]["oracle_disagreements"] == 0
assert report["small_model"]["cases"] == 14400
assert report["mutation_campaign"]["mutants_killed"] == report["mutation_campaign"]["mutants_total"]
assert report["mutation_campaign"]["mutants_total"] >= 12
assert report["transform_bridge"]["cases"] >= 60
assert min(report["transform_bridge"]["cases_by_family"].values()) >= 12
assert report["transform_bridge"]["rewritten_endpoint_scan_passes"] == report["transform_bridge"]["cases"]
assert report["transform_bridge"]["lineage_blocks"] == report["transform_bridge"]["cases"]
assert len(report["scaling"]["records"]) == 3 * 8 * 11
print("reviewer-hardening: passed")
