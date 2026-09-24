"""Natural exact-line equality workload over all retained public source files."""
import itertools
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import capsule
import checker
import corpus_adapter
import ledger
import merge

AUTHORITY_KEY = bytes.fromhex("11" * 32)
CHECKER_KEY = bytes.fromhex("22" * 32)


def main():
    cpu = time.process_time()
    wall = time.perf_counter()
    public_root = ROOT / "data" / "public"
    classes = corpus_adapter.duplicate_line_classes(public_root, minimum_length=8)
    contexts = 0
    cross_project_contexts = 0
    complete_exact = 0
    endpoint_false_clean = 0
    authenticated_exact = 0
    capsule_bytes = []
    capsule_wrapper_bytes = []
    class_sizes = []
    examples = []

    for canonical_line, occurrences in classes.items():
        class_sizes.append(len(occurrences))
        for left, right in itertools.combinations(occurrences, 2):
            index = contexts
            policy_a, log_a = corpus_adapter.build_line_shard(
                public_root, left, labelled=True, suffix="labelled-" + str(index)
            )
            policy_b, log_b = corpus_adapter.build_line_shard(
                public_root, right, labelled=False, suffix="clean-" + str(index)
            )
            # Both paths independently replay their actual retained file slices.
            answer_a = ledger.validate(policy_a, log_a)
            answer_b = ledger.validate(policy_b, log_b)
            checker.verify(policy_a, log_a)
            checker.verify(policy_b, log_b)
            assert answer_a["blocked"] == 1 and answer_b["blocked"] == 0
            summary_a = merge.summarize(policy_a, log_a)
            summary_b = merge.summarize(policy_b, log_b)
            assert summary_a == checker.verify(policy_a, log_a, summary=True)
            assert summary_b == checker.verify(policy_b, log_b, summary=True)

            joined_policy, joined_log = merge.combine_logs([(policy_a, log_a), (policy_b, log_b)])
            joined = ledger.annotate(joined_policy, joined_log)
            checker.verify(joined_policy, joined_log)
            expected = [joined["labels"][item["unit"]] for item in joined_log["outputs"]]
            composed = [mask for shard in merge.compose([summary_a, summary_b]) for mask in shard]
            assert expected == [1, 1] and composed == expected
            complete_exact += 1
            # The exported descendants carry different suffixes, so an endpoint-only
            # equality cache retains the locally clean second output.
            assert log_a["outputs"][0]["code"] != log_b["outputs"][0]["code"]
            endpoint_false_clean += 1

            cap_a = capsule.issue(
                policy_a,
                log_a,
                AUTHORITY_KEY,
                CHECKER_KEY,
                shard="left" + str(index),
                epoch="natural",
                sequence=2 * index,
            )
            cap_b = capsule.issue(
                policy_b,
                log_b,
                AUTHORITY_KEY,
                CHECKER_KEY,
                shard="right" + str(index),
                epoch="natural",
                sequence=2 * index + 1,
            )
            authenticated = capsule.compose(
                [cap_a, cap_b], AUTHORITY_KEY, CHECKER_KEY, expected_epoch="natural"
            )
            authenticated_masks = [
                output["mask"] for shard in authenticated for output in shard["outputs"]
            ]
            assert authenticated_masks == expected
            authenticated_exact += 1
            capsule_bytes.extend(
                (len(capsule.canonical_bytes(cap_a)), len(capsule.canonical_bytes(cap_b)))
            )
            capsule_wrapper_bytes.extend(
                (
                    len(capsule.canonical_bytes(cap_a)) - len(capsule.canonical_bytes(cap_a["summary"])),
                    len(capsule.canonical_bytes(cap_b)) - len(capsule.canonical_bytes(cap_b["summary"])),
                )
            )
            if left["project"] != right["project"]:
                cross_project_contexts += 1
            if len(examples) < 8:
                examples.append(
                    {
                        "canonical_line": canonical_line,
                        "left": {k: left[k] for k in ("file", "line")},
                        "right": {k: right[k] for k in ("file", "line")},
                        "cross_project": left["project"] != right["project"],
                    }
                )
            contexts += 1

    cross_project_classes = sum(
        len({item["project"] for item in occurrences}) >= 2 for occurrences in classes.values()
    )
    sensitivity = {}
    for threshold in (8, 12, 20, 40):
        threshold_classes = corpus_adapter.duplicate_line_classes(public_root, minimum_length=threshold)
        sensitivity[str(threshold)] = {
            "classes": len(threshold_classes),
            "file_pair_contexts": sum(len(items) * (len(items) - 1) // 2 for items in threshold_classes.values()),
            "cross_project_classes": sum(
                len({item["project"] for item in items}) >= 2 for items in threshold_classes.values()
            ),
        }
    result = {
        "source_files": len(corpus_adapter.selected_files(public_root)),
        "minimum_canonical_line_length": 8,
        "duplicate_line_classes": len(classes),
        "cross_project_duplicate_classes": cross_project_classes,
        "pair_contexts": contexts,
        "cross_project_pair_contexts": cross_project_contexts,
        "complete_summary_equal_to_joined_replay": complete_exact,
        "authenticated_capsule_compositions_equal_to_joined_replay": authenticated_exact,
        "endpoint_only_false_clean_outputs": endpoint_false_clean,
        "capsules_issued_and_verified": 2 * contexts,
        "capsule_canonical_bytes_min": min(capsule_bytes),
        "capsule_canonical_bytes_max": max(capsule_bytes),
        "capsule_canonical_bytes_mean": sum(capsule_bytes) / len(capsule_bytes),
        "capsule_wrapper_bytes_min": min(capsule_wrapper_bytes),
        "capsule_wrapper_bytes_max": max(capsule_wrapper_bytes),
        "capsule_wrapper_bytes_mean": sum(capsule_wrapper_bytes) / len(capsule_wrapper_bytes),
        "duplicate_threshold_sensitivity": sensitivity,
        "largest_duplicate_class_files": max(class_sizes),
        "examples": examples,
        "labels_are_generated_fixture_facts": True,
        "source_text_was_not_executed": True,
        "cpu_seconds": time.process_time() - cpu,
        "wall_seconds": time.perf_counter() - wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    (ROOT / "results" / "natural-duplicates.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
