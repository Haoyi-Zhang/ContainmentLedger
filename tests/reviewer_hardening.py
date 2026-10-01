#!/usr/bin/env python3
"""Run the additional bounded checks inside the unified supervisor."""
from __future__ import annotations
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import reviewer_hardening


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    report = reviewer_hardening.run(ROOT)
    require(report["schema"] == "pcl-reviewer-hardening/v1" and report["status"] == "passed", "schema/status")
    require(report["small_model"]["oracle_disagreements"] == 0 and report["small_model"]["cases"] == 14400, "small-model oracle")
    mutations = report["mutation_campaign"]
    require(mutations["mutants_killed"] == mutations["mutants_total"] == 12, "mutation coverage")
    bridge = report["transform_bridge"]
    require(bridge["cases"] >= 60 and min(bridge["cases_by_family"].values()) >= 12, "transform coverage")
    require(bridge["rewritten_endpoint_scan_passes"] == bridge["lineage_blocks"] == bridge["cases"], "transform decisions")
    require(len(report["scaling"]["records"]) == 3 * 8 * 11, "timing repetitions")
    (ROOT / "results/reviewer-hardening.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "passed", "small_model_cases": report["small_model"]["cases"],
                      "mutants_killed": mutations["mutants_killed"], "transform_cases": bridge["cases"],
                      "timing_records": len(report["scaling"]["records"])}))

if __name__ == "__main__":
    main()
