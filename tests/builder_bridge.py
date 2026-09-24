"""Operational-interface bridge through BigCode's retained substring filter."""
from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import builder_adapter
import checker
import corpus_adapter
import ledger


def independent_scan(content: str, filters: dict[str, list[str]]):
    lowered = content.lower()
    for benchmark, samples in filters.items():
        for sample in samples:
            if sample.lower() in lowered:
                return False, benchmark + "_match", sample
    return True, None, None


def main():
    cpu = time.process_time()
    wall = time.perf_counter()
    public_root = ROOT / "data" / "public"
    files = corpus_adapter.selected_files(public_root)
    policy_record = builder_adapter.read_bridge_policy()

    # Confirm the retained upstream function against an independently written
    # oracle on case-sensitive, case-insensitive, absent, and ordering probes.
    oracle_cases = [
        ("alpha BETA gamma", {"first": ["beta"]}),
        ("alpha BETA gamma", {"first": ["absent"], "second": ["GAMMA"]}),
        ("alpha BETA gamma", {"first": ["absent"]}),
        ("", {"empty": ["x"]}),
    ]
    for content, filters in oracle_cases:
        assert builder_adapter.scan(content, filters) == independent_scan(content, filters)

    blocked_cases = []
    clean_cases = []
    projects = set()
    for index, path in enumerate(files):
        relative = path.relative_to(public_root).as_posix()
        projects.add(relative.split("/", 1)[0])
        code = path.read_text(encoding="utf-8")
        probe = builder_adapter.select_natural_probe(code)
        benchmark = "retained_natural_line_" + relative.split("/", 1)[0]
        policy, log, observation = builder_adapter.build_rewrite_ledger(
            code,
            probe=probe,
            benchmark=benchmark,
            source_id=relative.replace("/", "-"),
            member_name="source.txt",
        )
        producer = ledger.validate(policy, log)
        independent = checker.verify(policy, log)
        assert producer["blocked"] == 1 and independent["blocked"] == 1
        assert observation["root_included_by_upstream"] is False
        assert observation["endpoint_included_by_upstream"] is True
        assert observation["lineage_output_mask"] & ledger.B
        blocked_cases.append(
            {
                "file": relative,
                "probe_line_length": len(probe),
                "root_filter_reason": observation["root_filter_reason"],
                "endpoint_scanner_decision": "include",
                "ledger_decision": "block",
            }
        )

        clean_policy, clean_log, clean_observation = builder_adapter.build_clean_control(
            code, source_id=relative.replace("/", "-"), index=index
        )
        clean_producer = ledger.validate(clean_policy, clean_log)
        clean_independent = checker.verify(clean_policy, clean_log)
        assert clean_producer["blocked"] == 0 and clean_independent["blocked"] == 0
        assert clean_observation["lineage_output_mask"] == 0
        clean_cases.append({"file": relative, "scanner_decision": "include", "ledger_decision": "clean"})

    # A separately licensed public HumanEval example supplies a benchmark-shaped
    # record.  It is static text only; neither its solution nor test is executed.
    example = json.loads(
        (ROOT / "upstream" / "human-eval" / "example_problem.jsonl").read_text(encoding="utf-8")
    )
    human_code = example["prompt"] + example["canonical_solution"] + "\n"
    human_probe = policy_record["benchmarks"]["human_eval_public_example"][0]
    policy, log, human_observation = builder_adapter.build_rewrite_ledger(
        human_code,
        probe=human_probe,
        benchmark="human_eval_public_example",
        source_id="human-eval-example",
        member_name="problem.py",
    )
    assert ledger.validate(policy, log)["blocked"] == 1
    assert checker.verify(policy, log)["blocked"] == 1
    assert human_observation["endpoint_included_by_upstream"] is True

    result = {
        "profile": policy_record["profile"],
        "upstream_repository": "bigcode-project/bigcode-dataset",
        "upstream_commit": builder_adapter.UPSTREAM_COMMIT,
        "upstream_source_path": builder_adapter.UPSTREAM_PATH,
        "upstream_source_blob": builder_adapter.UPSTREAM_BLOB,
        "upstream_function_invoked": "find_substrings",
        "public_humaneval_commit": builder_adapter.HUMANEVAL_COMMIT,
        "public_humaneval_source_blob": builder_adapter.HUMANEVAL_BLOB,
        "source_projects": len(projects),
        "retained_source_files": len(files),
        "natural_line_root_matches": len(blocked_cases),
        "public_benchmark_shaped_root_matches": 1,
        "matched_roots_total": len(blocked_cases) + 1,
        "rewritten_endpoints_passing_same_upstream_scanner": len(blocked_cases) + 1,
        "rewritten_endpoints_blocked_by_lineage": len(blocked_cases) + 1,
        "final_state_false_clean_if_used_alone": len(blocked_cases) + 1,
        "clean_controls": len(clean_cases),
        "clean_controls_accepted_by_scanner_and_ledger": len(clean_cases),
        "independent_upstream_oracle_cases": len(oracle_cases),
        "independent_upstream_oracle_disagreements": 0,
        "records": blocked_cases,
        "human_eval_example": {
            "task_id": example["task_id"],
            "root_filter_reason": human_observation["root_filter_reason"],
            "endpoint_scanner_decision": "include",
            "ledger_decision": "block",
        },
        "labels_for_natural_lines_are_generated_fixture_facts": True,
        "full_bigcode_pipeline_reproduced": False,
        "corpus_or_benchmark_code_executed": False,
        "cpu_seconds": time.process_time() - cpu,
        "wall_seconds": time.perf_counter() - wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    (ROOT / "results" / "builder-bridge.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
