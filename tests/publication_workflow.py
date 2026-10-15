"""Source-bound complete publication checks on owned benign text only.

The file-entrypoint comparison is five discriminating controls, not a workload
population or a speed benchmark. Both methods parse the same two files, admit
and authenticate every pinned member, compose, reconstruct, publish (or refuse),
and read back actual ZIP bytes. The reference differs only in closure strategy.
Persistent freshness and the POSIX process-death profile are not run here.
"""
import argparse
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import time
import unittest

from test_consumption import (ROOT, AUTHORITY, CHECKER_KEY, chain, readback,
                              records, registry_context)
from test_summary_reuse import literal_oracle
from consumption_comparison import FixedPointConsumer
import capsule
import checker
import consumer
import merge
import release

SCHEMA = "containment-ledger/owned-publication-workflow/v1"
STAGES = {"test_summary_reuse.py": 6, "test_consumption.py": 10,
          "test_release.py": 7, "test_default_publication.py": 3}
METHODS = ("file-release-worklist", "same-information-fixed-point")
EXPECTED = {"clean": [0, 0], "late-content": [1, 1],
            "occurrence-does-not-alias": [0, 0], "different-intent-pair": [0, 0],
            "after-repair-pair": [4, 4]}
SOURCE_FILES = ("reproduce.py", "src/consumer.py", "src/release.py", "src/capsule.py",
                "src/checker.py", "src/emitter.py", "src/ledger.py", "src/merge.py",
                "tests/test_summary_reuse.py", "tests/test_consumption.py",
                "tests/test_release.py", "tests/test_default_publication.py",
                "tests/consumption_comparison.py", "tests/publication_workflow.py")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identity():
    return {name: sha(ROOT / name) for name in SOURCE_FILES}


def write_json(path, value):
    # Diagnostic timings are ordinary finite JSON numbers, not capsule bodies.
    # Keep the protocol's narrower canonical type/MAC rules unchanged.
    Path(path).write_text(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False) + "\n", encoding="utf-8")


def elapsed(start):
    return {"wall_seconds": time.perf_counter() - start[0],
            "process_cpu_seconds": time.process_time() - start[1]}


def clock():
    return time.perf_counter(), time.process_time()


def owned_contexts():
    for name, mask, intent in (("clean", 0, "before"), ("late-content", 1, "before"),
                              ("occurrence-does-not-alias", 2, "before"),
                              ("different-intent-pair", 4, "different")):
        start = clock()
        target = chain("file-control", payload=2, depth=3)
        middle = target[1]["units"][2]
        # The second member has a root but no exports; it is still mandatory.
        pairs = [target, registry_context(middle["code"], intent, mask)]
        yield name, pairs, elapsed(start)
    start = clock()
    target = chain("file-repair", payload=2, depth=3, root_mask=4, repair=True)
    end = target[1]["units"][-1]
    pairs = [target, registry_context(end["code"], "after", 4)]
    yield "after-repair-pair", pairs, elapsed(start)


def reference_publish_files(manifest_path, inputs_path, shard, destination):
    """Same files, parser, admission, authentication and publisher as release."""
    manifest = checker.read_json(manifest_path)
    inputs = checker.read_json(inputs_path)
    gate = FixedPointConsumer(manifest, AUTHORITY, CHECKER_KEY)
    consumer.require(type(inputs) is list and len(inputs) <= 20000, "release input list")
    for item in inputs:
        consumer.require(type(item) is dict and set(item) == {"policy", "ledger", "capsule"},
                         "release input fields")
        gate.admit(item["policy"], item["ledger"], item["capsule"])
    gate.seal()
    return gate.publish(shard, destination)


def run_controls(directory):
    rows = []
    for name, pairs, generation in owned_contexts():
        case = directory / name
        case.mkdir()
        start = clock()
        manifest, inputs = records(pairs)
        manifest_path, inputs_path = case / "manifest.json", case / "inputs.json"
        write_json(manifest_path, manifest)
        write_json(inputs_path, list(reversed(inputs)))
        setup = elapsed(start)
        start = clock()
        joined_policy, joined_log = merge.combine_logs(deepcopy(pairs))
        raw = literal_oracle(joined_policy, joined_log)
        oracle_masks = [raw["result"]["labels"][item["unit"]]
                        for item in joined_log["outputs"]]
        require(oracle_masks == EXPECTED[name], "raw-record oracle disagrees: " + name)
        # Decision checks are separate from the timed file publication. Neither
        # timed method receives these decisions or a caller-supplied verdict.
        decisions = []
        for kind in (consumer.Consumer, FixedPointConsumer):
            gate = kind(manifest, AUTHORITY, CHECKER_KEY)
            for item in reversed(inputs):
                gate.admit(item["policy"], item["ledger"], item["capsule"])
            decisions.append(gate.seal())
        require(decisions[0] == decisions[1], "same-information decision mismatch")
        require([o["mask"] for s in decisions[0] for o in s["outputs"]] == oracle_masks,
                "composed decision differs from raw-record oracle")
        reference_check = elapsed(start)
        write_json(case / "oracle-and-decisions.json", {"masks": oracle_masks,
                   "ordered_decisions": decisions[0]})
        row = {"case": name, "target": "s0", "members": len(inputs),
               "member_exports": [len(item["ledger"]["outputs"]) for item in inputs],
               "expected_masks": oracle_masks,
               "manifest_bytes": manifest_path.stat().st_size,
               "inputs_bytes": inputs_path.stat().st_size,
               "input_file_sha256": {"manifest.json": sha(manifest_path), "inputs.json": sha(inputs_path)},
               "policy_bytes": sum(len(capsule.canonical_bytes(p)) for p, _ in pairs),
               "ledger_bytes": sum(len(capsule.canonical_bytes(l)) for _, l in pairs),
               "summary_bytes": sum(len(capsule.canonical_bytes(item["capsule"]["summary"])) for item in inputs),
               "capsule_bytes": sum(len(capsule.canonical_bytes(item["capsule"])) for item in inputs),
               "selected_export_payload_bytes": sum(len(o[f].encode("utf-8"))
                    for o in pairs[0][1]["outputs"] for f in ("code", "intent")),
               "fixture_generation": generation,
               "setup_issuance_serialization_and_input_write": setup,
               "separate_oracle_and_two_full_decision_checks": reference_check, "methods": {}}
        for method in METHODS:
            destination = case / (method + ".zip")
            start = clock()
            try:
                if method == METHODS[0]:
                    stats = release.publish_files(manifest_path, inputs_path, "s0", destination,
                                                  AUTHORITY, CHECKER_KEY)
                else:
                    stats = reference_publish_files(manifest_path, inputs_path, "s0", destination)
            except consumer.AdmissionError as exc:
                require(str(exc) == "composed blocked export" and any(oracle_masks),
                        "unexpected publication refusal: " + str(exc))
                require(not destination.exists(), "blocked destination created")
                result = {"outcome": "refused", "reason": str(exc), "archive_bytes": 0,
                          "archive_sha256": None, "stats": None}
            else:
                require(not any(oracle_masks), "blocked publication admitted")
                readback(destination, pairs[0][1]["outputs"])
                result = {"outcome": "published-and-read-back", "archive_bytes": destination.stat().st_size,
                          "archive_sha256": sha(destination), "stats": stats}
                # Preserve exact emitted bytes as hex text, keeping the clean
                # packet's no-nested-archive rule. This is not extraction.
                (case / (method + ".zip.hex")).write_text(destination.read_bytes().hex() + "\n",
                                                         encoding="ascii")
                destination.unlink()
            # Charge serialization of the protocol outcome, separately from the
            # diagnostic timing fields and report-file persistence.
            result["protocol_outcome_bytes"] = len(capsule.canonical_bytes(result))
            result.update(elapsed(start))
            row["methods"][method] = result
            write_json(case / (method + ".json"), result)
        comparable = ("outcome", "archive_bytes", "archive_sha256", "stats", "protocol_outcome_bytes")
        require(all(row["methods"][METHODS[0]][k] == row["methods"][METHODS[1]][k]
                    for k in comparable), "file-path same-information outcomes differ")
        require(not any(p.name.endswith(".tmp") for p in case.iterdir()), "temporary file remained")
        rows.append(row)
    return rows


def verify_receipt(directory):
    directory = Path(directory)
    report = json.loads((directory / "receipt.json").read_text(encoding="utf-8"))
    require(report.get("schema") == SCHEMA and report.get("status") == "passed", "publication receipt status/schema")
    require(report["source_sha256"] == source_identity(), "publication receipt source binding stale")
    require(set(report["stages"]) == set(STAGES), "publication stage coverage")
    for name, count in STAGES.items():
        stage = report["stages"][name]
        require(stage["tests_run"] == count and stage["successful"] and
                stage["failures"] == stage["errors"] == stage["skips"] == 0,
                "publication regression failed or silently omitted: " + name)
    require(report["tests_run"] == sum(STAGES.values()), "publication test accounting")
    require(report["pipeline_executions"] == 10 and report["publications_read_back"] == 6 and
            report["blocked_refusals"] == 4, "publication outcome accounting")
    require([row["case"] for row in report["controls"]] == list(EXPECTED), "publication control identity")
    for row in report["controls"]:
        require(row["expected_masks"] == EXPECTED[row["case"]] and row["member_exports"] == [2, 0],
                "publication control obligations")
        require(set(row["methods"]) == set(METHODS), "publication reference absent")
        for method in METHODS:
            result = row["methods"][method]
            encoded = directory / row["case"] / (method + ".zip.hex")
            if any(EXPECTED[row["case"]]):
                require(result["outcome"] == "refused" and result["archive_bytes"] == 0 and
                        not encoded.exists(), "blocked file outcome")
            else:
                raw = bytes.fromhex(encoded.read_text(encoding="ascii"))
                require(result["outcome"] == "published-and-read-back" and
                        len(raw) == result["archive_bytes"] and
                        hashlib.sha256(raw).hexdigest() == result["archive_sha256"],
                        "published raw archive bytes")
    files = {p.relative_to(directory).as_posix(): sha(p) for p in directory.rglob("*")
             if p.is_file() and p != directory / "receipt.json"}
    require(files == report["raw_sha256"], "publication raw input/output inventory changed")
    return report


def run(directory):
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / "results").resolve()), "publication output must stay in artifact/results")
    # A default re-run does not overwrite its previous evidence bundle.
    directory.mkdir(parents=True, exist_ok=False)
    start = clock()
    identity = source_identity()
    report = {"schema": SCHEMA, "status": "running", "source_sha256": identity,
              "host": {"platform": platform.platform(), "python": platform.python_version(), "executable": sys.executable},
              "environment": {"python_hash_seed": os.environ.get("PYTHONHASHSEED"),
                              "bytecode_disabled": sys.dont_write_bytecode},
              "stages": {}, "scope": "Owned benign fixtures only; no corpus execution or external targets"}
    write_json(directory / "receipt.json", report)
    try:
        for pattern, count in STAGES.items():
            log = io.StringIO()
            stage_start = clock()
            suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=pattern)
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
            (directory / (pattern + ".log")).write_text(log.getvalue(), encoding="utf-8")
            report["stages"][pattern] = {"tests_run": result.testsRun, "successful": result.wasSuccessful(),
                    "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped),
                    **elapsed(stage_start)}
            require(result.testsRun == count and result.wasSuccessful() and not result.skipped,
                    "publication unit stage failed: " + pattern)
        report["controls"] = run_controls(directory)
        require(identity == source_identity(), "source changed during publication checks")
        report.update({"tests_run": sum(s["tests_run"] for s in report["stages"].values()),
                       "pipeline_executions": 10, "publications_read_back": 6, "blocked_refusals": 4,
                       "accounting": "Whole receipt timer includes all four unittest suites, five fixture setups/issuance/input writes, independent oracle checks, both file pipelines, readback, comparison, and intermediate log/report writes. Per-pipeline timer starts before both bounded file reads and ends after publication/refusal, readback, digest, exact archive-byte hex recording/removal, and protocol-outcome serialization. Final receipt serialization/verification, paper build, old campaigns, POSIX freshness and process-death tests are excluded.",
                       "publication_profile": "Owned stable directory on this host; Windows does not claim directory-handle/no-follow race or directory-fsync guarantees",
                       "interpretation": "Same-information outcomes tie. Single ordered runs are regression costs, not speed/precision gains or deployment evidence.",
                       "status": "passed"})
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        report["whole_workflow"] = elapsed(start)
        report["raw_sha256"] = {p.relative_to(directory).as_posix(): sha(p) for p in directory.rglob("*")
                                if p.is_file() and p != directory / "receipt.json"}
        write_json(directory / "receipt.json", report)
    return verify_receipt(directory)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    choices = ap.add_mutually_exclusive_group(required=True)
    choices.add_argument("--output", type=Path)
    choices.add_argument("--verify", type=Path)
    args = ap.parse_args()
    report = verify_receipt(args.verify) if args.verify else run(args.output)
    print(json.dumps({key: report[key] for key in ("status", "tests_run", "pipeline_executions",
                                                  "publications_read_back", "blocked_refusals", "whole_workflow")}))


if __name__ == "__main__":
    main()
