"""Same-information closure/gate comparison on owned benign text.

Both paths use identical trusted manifests, admission/replay/authentication,
serialized inputs, output reconstruction and create-if-absent publication.
Only quotient worklist closure versus straightforward repeated edge relaxation
differs. No upstream source is executed and no deployment advantage is inferred.
"""
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time

from test_consumption import (ROOT, AUTHORITY, CHECKER_KEY, admitted, chain,
                              readback, records, registry_context)
import capsule
import checker
import consumer
import merge

SOURCE_FILES = ("src/consumer.py", "src/capsule.py", "src/checker.py", "src/emitter.py",
                "src/ledger.py", "src/merge.py", "tests/test_consumption.py",
                "tests/consumption_comparison.py")


def source_identity():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


class FixedPointConsumer(consumer.Consumer):
    def _compose(self, records):
        checked = [capsule.verify(record, self._authority_key, self._checker_key,
                                  expected_epoch=self._epoch,
                                  expected_shard=member,
                                  minimum_sequence=self._expected[member]["sequence"])
                   for member, record in zip(self._expected, records)]
        masks = [list(item["summary"]["origin_labels"]) for item in checked]
        for scope, bit in enumerate((1, 4)):
            reached = set()
            arcs = []
            outputs = []
            for item in checked:
                component = item["summary"]["components"][scope]
                keys = [tuple(key) for key in component["keys"]]
                reached.update(keys[index] for index in component["seeds"])
                arcs.extend((keys[a], keys[b]) for a, b in component["arcs"])
                outputs.append([keys[index] for index in component["outputs"]])
            changed = True
            while changed:
                changed = False
                for source, destination in arcs:
                    if source in reached and destination not in reached:
                        reached.add(destination)
                        changed = True
            for shard, keys in enumerate(outputs):
                for output, key in enumerate(keys):
                    if key in reached:
                        masks[shard][output] |= bit
        return [{"shard": item["shard"], "epoch": item["epoch"], "sequence": item["sequence"],
                 "outputs": [{"name": name, "mask": mask}
                             for name, mask in zip(item["output_names"], local)]}
                for item, local in zip(checked, masks)]


def joined_masks(pairs):
    policy, log = merge.combine_logs(deepcopy(pairs))
    # Recompute claims for the larger context; local claims cannot be copied.
    import ledger
    ledger.annotate(policy, log)
    result = checker.verify(policy, log)
    return [result["labels"][item["unit"]] for item in log["outputs"]]


def run(repetitions=5):
    all_rows = []
    for count in (2, 4, 8, 16):
        for blocked in (False, True):
            cpu = time.process_time()
            wall = time.perf_counter()
            payload = 32 * count
            pairs = [chain("target", payload=payload)]
            intermediate = pairs[0][1]["units"][2]
            pairs.append(registry_context(intermediate["code"], "before", int(blocked)))
            pairs.extend(chain("other" + str(k), payload=payload) for k in range(2, count))
            manifest, inputs = records(pairs)
            input_document = {"manifest": manifest, "inputs": inputs, "target": "s0"}
            input_bytes = capsule.canonical_bytes(input_document)
            setup = {"cpu_seconds": time.process_time() - cpu,
                     "wall_seconds": time.perf_counter() - wall}
            expected = joined_masks(pairs)
            row = {"shards": count, "case": "late-content-label" if blocked else "clean-control",
                   "payload_scalar_values": payload, "repetitions": repetitions,
                   "input_bytes": len(input_bytes),
                   "policy_bytes": sum(len(capsule.canonical_bytes(p)) for p, _ in pairs),
                   "ledger_bytes": sum(len(capsule.canonical_bytes(l)) for _, l in pairs),
                   "summary_bytes": sum(len(capsule.canonical_bytes(i["capsule"]["summary"])) for i in inputs),
                   "capsule_bytes": sum(len(capsule.canonical_bytes(i["capsule"])) for i in inputs),
                   "manifest_bytes": len(capsule.canonical_bytes(manifest)),
                   "selected_export_payload_bytes": sum(len(o[f].encode("utf-8"))
                                                        for o in pairs[0][1]["outputs"] for f in ("code", "intent")),
                   "setup_generation_and_issuance": setup, "methods": {}}
            with tempfile.TemporaryDirectory(prefix=".consumption-compare-", dir=ROOT) as directory:
                directory = Path(directory)
                input_path = directory / "input.json"
                input_path.write_bytes(input_bytes)
                samples = {name: [] for name in ("quotient-worklist-gate", "fixed-point-gate")}
                raw_decisions = {}
                # Alternate execution order to limit systematic first-run bias.
                for repetition in range(repetitions):
                    methods = [("quotient-worklist-gate", consumer.Consumer),
                               ("fixed-point-gate", FixedPointConsumer)]
                    if repetition % 2:
                        methods.reverse()
                    for name, kind in methods:
                        destination = directory / (name + "-" + str(repetition) + ".zip")
                        cpu = time.process_time()
                        wall = time.perf_counter()
                        document = checker.read_json(input_path)
                        gate = admitted(document["manifest"], document["inputs"], kind)
                        decision = gate.seal()
                        actual = [item["mask"] for shard in decision for item in shard["outputs"]]
                        if actual != expected:
                            raise AssertionError("same-information reference disagrees with joined replay")
                        if blocked:
                            try:
                                gate.publish(document["target"], destination)
                            except consumer.AdmissionError as error:
                                if str(error) != "composed blocked export":
                                    raise
                            else:
                                raise AssertionError("blocked release returned successfully")
                            if destination.exists():
                                raise AssertionError("blocked release created destination")
                            archive_bytes = 0
                        else:
                            stats = gate.publish(document["target"], destination)
                            archive_bytes = stats["bytes"]
                            readback(destination, pairs[0][1]["outputs"])
                        verdict_bytes = capsule.canonical_bytes(decision)
                        sample = {"cpu_seconds": time.process_time() - cpu,
                                  "wall_seconds": time.perf_counter() - wall,
                                  "verdict_bytes": len(verdict_bytes), "archive_bytes": archive_bytes,
                                  "total_output_bytes": len(verdict_bytes) + archive_bytes}
                        samples[name].append(sample)
                        if name in raw_decisions and raw_decisions[name] != verdict_bytes:
                            raise AssertionError("unstable ordered decision")
                        raw_decisions[name] = verdict_bytes
                if len(set(raw_decisions.values())) != 1:
                    raise AssertionError("reference output ordering mismatch")
                for name, measurements in samples.items():
                    row["methods"][name] = {
                        "samples": measurements,
                        "median_cpu_ms": 1000 * statistics.median(s["cpu_seconds"] for s in measurements),
                        "median_wall_ms": 1000 * statistics.median(s["wall_seconds"] for s in measurements),
                        "wall_ms_range": [1000 * min(s["wall_seconds"] for s in measurements),
                                          1000 * max(s["wall_seconds"] for s in measurements)],
                    }
            all_rows.append(row)
    return {"status": "passed", "host": {"platform": platform.platform(),
             "python": platform.python_version(), "executable": sys.executable},
            "source_sha256": source_identity(),
            "context_cases": len(all_rows), "repetitions_per_method_case": repetitions,
            "pipeline_executions": len(all_rows) * repetitions * 2,
            "clean_publications_read_back": 4 * repetitions * 2,
            "composed_blocked_publications_refused": 4 * repetitions * 2,
            "all_ordered_masks_equal_joined_replay": True,
            "same_serialized_input_and_output_bytes": True, "rows": all_rows,
            "scope": "Owned benign generated text; full input JSON read/parse, bound admission, authentication, "
                     "complete composition, selected export reconstruction, actual ZIP publication and readback. "
                     "Generation/issuance recorded separately; no warmups, process-isolated peaks, persistent "
                     "freshness, production policy, exploit reproduction or upstream source execution. "
                     "Windows assumes a trusted stable directory and claims no directory-handle race resistance "
                     "or power-loss durability. Timings are five sequential observations per cell, not a speedup claim."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path, help="Check saved source bindings and recorded cost invariants; do not rerun")
    args = parser.parse_args()
    if args.verify is None:
        print(json.dumps(run(), indent=2, sort_keys=True))
    else:
        saved = checker.read_json(args.verify)
        if saved["status"] != "passed" or saved["source_sha256"] != source_identity():
            raise RuntimeError("saved consumption measurement source binding is stale")
        if len(saved["rows"]) != 8 or saved["pipeline_executions"] != 80:
            raise RuntimeError("saved consumption experiment count mismatch")
        for row in saved["rows"]:
            left, right = (row["methods"][name]["samples"]
                           for name in ("quotient-worklist-gate", "fixed-point-gate"))
            if len(left) != 5 or len(right) != 5:
                raise RuntimeError("saved consumption repetition count mismatch")
            costs = {(sample["verdict_bytes"], sample["archive_bytes"]) for sample in left + right}
            if len(costs) != 1 or any(sample["total_output_bytes"] !=
                                    sample["verdict_bytes"] + sample["archive_bytes"] for sample in left + right):
                raise RuntimeError("saved consumption output costs disagree")
        print(json.dumps({"status": "passed", "source_files_checked": len(SOURCE_FILES),
                          "recorded_pipeline_executions": 80,
                          "scope": "Saved source and cost invariants only; not an experiment rerun."}))
