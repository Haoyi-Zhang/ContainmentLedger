"""Complete serialized release gate on owned text and public fixture keys.

The same admitted information is checked by repeated-edge closure and by a
raw-record, all-pairs Boolean oracle. Actual ZIP bytes are read, never executed.
No timing campaign or persistent-freshness protocol is run here.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from test_consumption import (ROOT, AUTHORITY, CHECKER_KEY, admitted, chain,
                              readback, records, registry_context)
from consumption_comparison import FixedPointConsumer
from test_summary_reuse import context_cases, literal_oracle, owned_cases
import capsule
import checker
import consumer
import ledger
import merge
import release


class ReleaseRegression(unittest.TestCase):
    def check_release(self, pairs):
        manifest, inputs = records(pairs)
        # Manifest order, not arrival order, determines the ordered result.
        gate = release.admit_release(manifest, list(reversed(inputs)), AUTHORITY, CHECKER_KEY)
        reference = admitted(manifest, list(reversed(inputs)), FixedPointConsumer)
        decision = gate.seal()
        self.assertEqual(decision, reference.seal())
        policy, log = merge.combine_logs(deepcopy(pairs))
        raw = literal_oracle(policy, log)
        self.assertEqual([item["mask"] for shard in decision for item in shard["outputs"]],
                         [raw["result"]["labels"][item["unit"]] for item in log["outputs"]])
        with tempfile.TemporaryDirectory(prefix=".release-", dir=ROOT) as directory:
            directory = Path(directory)
            manifest_path = directory / "manifest.json"
            inputs_path = directory / "inputs.json"
            manifest_path.write_bytes(capsule.canonical_bytes(manifest))
            inputs_path.write_bytes(capsule.canonical_bytes(list(reversed(inputs))))
            for index, shard in enumerate(decision):
                path = directory / (shard["shard"] + ".zip")
                if any(item["mask"] for item in shard["outputs"]):
                    with self.assertRaisesRegex(consumer.AdmissionError, "composed blocked export"):
                        release.publish_files(manifest_path, inputs_path, shard["shard"], path,
                                              AUTHORITY, CHECKER_KEY)
                    self.assertFalse(path.exists())
                else:
                    stats = release.publish_files(manifest_path, inputs_path, shard["shard"], path,
                                                  AUTHORITY, CHECKER_KEY)
                    self.assertEqual(stats["units"], len(pairs[index][1]["outputs"]))
                    readback(path, pairs[index][1]["outputs"])
            self.assertFalse(any(path.name.endswith(".tmp") for path in directory.iterdir()))

    def test_all_owned_single_shard_scopes_and_empty_exports(self):
        cases = list(owned_cases())
        self.assertEqual(len(cases), 49)
        for name, policy, log in cases:
            with self.subTest(case=name):
                self.check_release([(policy, log)])

    def test_same_information_contexts_and_raw_joined_closure(self):
        cases = list(context_cases())
        self.assertEqual(len(cases), 32)
        for name, pairs in cases:
            with self.subTest(case=name):
                self.check_release(pairs)

    def test_late_canonical_registry_label_in_member_without_exports(self):
        for mask in range(8):
            for same_intent in (True, False):
                with self.subTest(mask=mask, same_intent=same_intent):
                    target = chain("target")
                    middle = target[1]["units"][2]
                    equal_code = middle["code"].replace("\r\n", "\n") + " \t"
                    context = registry_context(equal_code, "before" if same_intent else "different", mask)
                    self.check_release([target, context])

    def test_composed_cycle_and_repaired_pair_restoration(self):
        target = chain("cycle")
        middle = target[1]["units"][2]
        start = target[0]["roots"][0]["code"]
        policy = {"roots": [{"id": "back", "code": middle["code"],
                             "intent": "before", "labels": 0}], "repairs": []}
        log = {"units": [
            {"id": "back", "op": "import", "source": "back", "code": middle["code"], "intent": "before"},
            {"id": "return", "op": "rewrite", "parent": "back", "old": middle["code"],
             "new": start, "code": start, "intent": "before"}],
            "bundles": [{"id": "empty", "op": "collect", "items": []}],
            "final": "empty", "outputs": [], "claims": {}}
        ledger.annotate(policy, log)
        self.check_release([target, (policy, log), registry_context(middle["code"], "before", 5)])
        repaired = chain("repair", root_mask=4, repair=True)
        final = repaired[1]["units"][-1]
        self.check_release([repaired, registry_context(final["code"], "after", 4)])

    def test_missing_extra_duplicate_revision_and_target_denied_before_io(self):
        manifest, inputs = records([chain("target"), chain("other")])
        with tempfile.TemporaryDirectory(prefix=".release-", dir=ROOT) as directory:
            path = Path(directory) / "result.zip"
            manifest_path = Path(directory) / "manifest.json"
            inputs_path = Path(directory) / "inputs.json"
            manifest_path.write_bytes(capsule.canonical_bytes(manifest))
            changed = deepcopy(inputs)
            changed[0]["capsule"]["sequence"] += 1
            for submitted in ([], inputs[:1], inputs + [inputs[0]], changed, {},
                              [{**inputs[0], "extra": 0}, inputs[1]]):
                inputs_path.write_bytes(capsule.canonical_bytes(submitted))
                with self.assertRaises(capsule.CapsuleError):
                    release.publish_files(manifest_path, inputs_path, "s0", path, AUTHORITY, CHECKER_KEY)
                self.assertFalse(path.exists())
            _, extra = records([chain("a"), chain("b"), chain("c")])
            inputs_path.write_bytes(capsule.canonical_bytes(inputs + [extra[2]]))
            with self.assertRaisesRegex(consumer.AdmissionError, "unexpected release member"):
                release.publish_files(manifest_path, inputs_path, "s0", path, AUTHORITY, CHECKER_KEY)
            inputs_path.write_bytes(capsule.canonical_bytes(inputs))
            with self.assertRaisesRegex(consumer.AdmissionError, "unknown release target"):
                release.publish_files(manifest_path, inputs_path, "unknown", path, AUTHORITY, CHECKER_KEY)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["inputs.json", "manifest.json"])

    def test_json_ingress_and_authentication_preserved(self):
        manifest, inputs = records([chain("target")])
        with tempfile.TemporaryDirectory(prefix=".release-", dir=ROOT) as directory:
            directory = Path(directory)
            manifest_path, inputs_path = directory / "manifest.json", directory / "inputs.json"
            valid_manifest = capsule.canonical_bytes(manifest)
            valid_inputs = capsule.canonical_bytes(inputs)
            destination = directory / "result.zip"
            for bad in (b'{"epoch":"x","epoch":"y","members":[]}', b'NaN', b'[' * 65 + b']' * 65):
                for path in (manifest_path, inputs_path):
                    manifest_path.write_bytes(valid_manifest)
                    inputs_path.write_bytes(valid_inputs)
                    path.write_bytes(bad)
                    with self.assertRaises(checker.Rejected):
                        release.publish_files(manifest_path, inputs_path, "s0", destination, AUTHORITY, CHECKER_KEY)
                    self.assertFalse(destination.exists())
            manifest_path.write_bytes(valid_manifest)
            inputs_path.write_bytes(valid_inputs)
            with self.assertRaisesRegex(capsule.CapsuleError, "policy authentication"):
                release.publish_files(manifest_path, inputs_path, "s0", destination, b"W" * 32, CHECKER_KEY)
            changed = deepcopy(inputs)
            changed[0]["capsule"]["checker_tag"] = "0" * 64
            pinned = deepcopy(manifest)
            pinned["members"][0]["capsule_digest"] = capsule.digest(changed[0]["capsule"])
            manifest_path.write_bytes(capsule.canonical_bytes(pinned))
            inputs_path.write_bytes(capsule.canonical_bytes(changed))
            with self.assertRaisesRegex(capsule.CapsuleError, "checker authentication"):
                release.publish_files(manifest_path, inputs_path, "s0", destination, AUTHORITY, CHECKER_KEY)
            self.assertFalse(destination.exists())
            malformed = deepcopy(inputs)
            malformed[0]["capsule"]["output_names"] = [[]]
            pinned = deepcopy(manifest)
            pinned["members"][0]["capsule_digest"] = capsule.digest(malformed[0]["capsule"])
            manifest_path.write_bytes(capsule.canonical_bytes(pinned))
            inputs_path.write_bytes(capsule.canonical_bytes(malformed))
            with self.assertRaisesRegex(capsule.CapsuleError, "capsule outputs"):
                release.publish_files(manifest_path, inputs_path, "s0", destination,
                                      AUTHORITY, CHECKER_KEY)
            self.assertFalse(destination.exists())

    def test_file_entrypoint_preserves_existing_destination(self):
        manifest, inputs = records([chain("clean")])
        with tempfile.TemporaryDirectory(prefix=".release-", dir=ROOT) as directory:
            directory = Path(directory)
            manifest_path, inputs_path = directory / "manifest.json", directory / "inputs.json"
            manifest_path.write_bytes(capsule.canonical_bytes(manifest))
            inputs_path.write_bytes(capsule.canonical_bytes(inputs))
            destination = directory / "result.zip"
            release.publish_files(manifest_path, inputs_path, "s0", destination, AUTHORITY, CHECKER_KEY)
            before = destination.read_bytes()
            with self.assertRaises(FileExistsError):
                release.publish_files(manifest_path, inputs_path, "s0", destination, AUTHORITY, CHECKER_KEY)
            self.assertEqual(destination.read_bytes(), before)
            readback(destination, inputs[0]["ledger"]["outputs"])
            # Revision pinning is not a persistent single-use token. A second
            # absent destination is allowed without a separate freshness call.
            second_destination = directory / "another.zip"
            release.publish_files(manifest_path, inputs_path, "s0", second_destination,
                                  AUTHORITY, CHECKER_KEY)
            readback(second_destination, inputs[0]["ledger"]["outputs"])


if __name__ == "__main__":
    unittest.main()
