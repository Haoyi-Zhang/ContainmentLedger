"""Owned text only: complete admission, scope gates and actual ZIP readback."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import capsule
import checker
import consumer
import emitter
import ledger
import merge

AUTHORITY = b"A" * 32  # Public fixture bytes, never operational credentials.
CHECKER_KEY = b"C" * 32


def chain(shard, *, payload=32, depth=4, outputs=2, root_mask=0, repair=False):
    body = "owned " + shard + " " + "中" * payload + "\r\n"
    policy = {"roots": [{"id": "root", "code": body, "intent": "before", "labels": root_mask}],
              "repairs": []}
    units = [{"id": "u0", "op": "import", "source": "root", "code": body, "intent": "before"}]
    for step in range(1, depth + 1):
        after = body + "owned step " + str(step) + "\n"
        units.append({"id": "u" + str(step), "op": "rewrite", "parent": units[-1]["id"],
                      "old": body, "new": after, "code": after, "intent": "before"})
        body = after
    if repair:
        policy["repairs"].append({"id": "approval", "code": body, "before": "before", "after": "after"})
        units.append({"id": "repaired", "op": "repair", "parent": units[-1]["id"],
                      "authority": "approval", "code": body, "intent": "after"})
    retained = [{"name": str(k) + ".txt", "unit": units[-1]["id"]} for k in range(outputs)]
    log = {"units": units, "bundles": [{"id": "final", "op": "collect", "items": retained}],
           "final": "final", "outputs": [{**item, "code": body, "intent": units[-1]["intent"]}
                                           for item in retained], "claims": {}}
    ledger.annotate(policy, log)
    return policy, log


def registry_context(code, intent, mask):
    return ({"roots": [{"id": "context", "code": code, "intent": intent, "labels": mask}],
             "repairs": []},
            {"units": [], "bundles": [{"id": "final", "op": "collect", "items": []}],
             "final": "final", "outputs": [], "claims": {}})


def records(pairs, *, epoch="owned-epoch", sequence=3):
    inputs = [{"policy": policy, "ledger": log,
               "capsule": capsule.issue(policy, log, AUTHORITY, CHECKER_KEY,
                                         shard="s" + str(k), epoch=epoch, sequence=sequence)}
              for k, (policy, log) in enumerate(pairs)]
    # In this owned fixture the full context is known to its creator. Production
    # must supply this list from a trusted release controller, not infer it from
    # whatever untrusted subset happens to arrive.
    manifest = {"epoch": epoch,
                "members": [{"shard": item["capsule"]["shard"], "sequence": sequence,
                             "capsule_digest": capsule.digest(item["capsule"])} for item in inputs]}
    return manifest, inputs


def admitted(manifest, inputs, kind=consumer.Consumer):
    gate = kind(manifest, AUTHORITY, CHECKER_KEY)
    for item in inputs:
        gate.admit(item["policy"], item["ledger"], item["capsule"])
    return gate


def readback(path, exports):
    expected = {prefix + item["name"]: item[field].encode("utf-8") for item in exports
                for prefix, field in (("code/", "code"), ("intent/", "intent"))}
    with zipfile.ZipFile(path) as archive:
        actual = {name: archive.read(name) for name in archive.namelist()}
        if archive.namelist() != list(expected) or actual != expected or archive.testzip() is not None:
            raise AssertionError("publication readback mismatch")


class ConsumptionRegression(unittest.TestCase):
    def test_complete_context_scope_masks_match_joined_replay(self):
        # The second shard has no exports, but its full registry still matters.
        for mask in range(8):
            for same_intent in (True, False):
                target = chain("target")
                intermediate = target[1]["units"][2]
                pairs = [target, registry_context(intermediate["code"],
                                                 "before" if same_intent else "different", mask)]
                manifest, inputs = records(pairs)
                gate = admitted(manifest, list(reversed(inputs)))
                joined_policy, joined_log = merge.combine_logs(pairs)
                ledger.annotate(joined_policy, joined_log)
                result = checker.verify(joined_policy, joined_log)
                decision = gate.seal()
                self.assertEqual([o["mask"] for s in decision for o in s["outputs"]],
                                 [result["labels"][o["unit"]] for o in joined_log["outputs"]])
                expected = (mask & 1) | (mask & 4 if same_intent else 0)
                self.assertEqual([o["mask"] for o in decision[0]["outputs"]], [expected] * 2)
                with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
                    path = Path(directory) / "result.zip"
                    if expected:
                        with self.assertRaisesRegex(consumer.AdmissionError, "composed blocked export"):
                            gate.publish("s0", path)
                        self.assertEqual(list(Path(directory).iterdir()), [])
                    else:
                        self.assertEqual(gate.consume("s0"), checker.verify(*target, exports=True))
                        stats = gate.publish("s0", path)
                        self.assertEqual(stats["members"], 4)
                        readback(path, target[1]["outputs"])

    def test_incomplete_context_denies_consumption_and_publication(self):
        manifest, inputs = records([chain("target"), chain("other")])
        gate = admitted(manifest, inputs[:1])
        with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
            path = Path(directory) / "result.zip"
            for call in (gate.seal, lambda: gate.consume("s0"), lambda: gate.publish("s0", path)):
                with self.assertRaisesRegex(consumer.AdmissionError, "incomplete release context"):
                    call()
            self.assertEqual(list(Path(directory).iterdir()), [])
        gate.admit(inputs[1]["policy"], inputs[1]["ledger"], inputs[1]["capsule"])
        self.assertEqual(len(gate.consume("s0")), 2)

    def test_mandatory_authenticated_publisher_context(self):
        manifest, inputs = records([chain("target"), chain("other")])
        item = inputs[0]
        with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
            destination = Path(directory) / "result.zip"
            for supplied in ({}, {"release_manifest": manifest, "composition_inputs": inputs[:1]}):
                with self.assertRaises(consumer.AdmissionError):
                    emitter.emit_authenticated(item["policy"], item["ledger"], item["capsule"],
                                               AUTHORITY, CHECKER_KEY, destination, **supplied)
                self.assertEqual(list(Path(directory).iterdir()), [])
            emitter.emit_authenticated(item["policy"], item["ledger"], item["capsule"],
                                       AUTHORITY, CHECKER_KEY, destination,
                                       release_manifest=manifest, composition_inputs=inputs)
            readback(destination, item["ledger"]["outputs"])

    def test_authenticated_publisher_uses_composed_not_local_masks(self):
        target = chain("target")
        intermediate = target[1]["units"][2]
        manifest, inputs = records([target, registry_context(intermediate["code"], "before", 1)])
        item = inputs[0]
        with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
            path = Path(directory) / "result.zip"
            with self.assertRaisesRegex(consumer.AdmissionError, "composed blocked export"):
                emitter.emit_authenticated(*target, item["capsule"], AUTHORITY, CHECKER_KEY, path,
                                           release_manifest=manifest, composition_inputs=inputs)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_repair_scope_and_independent_after_pair_obligation(self):
        target = chain("repair", root_mask=4, repair=True)
        checker.verify(*target, exports=True)
        final = target[1]["units"][-1]
        manifest, inputs = records([target, registry_context(final["code"], "after", 4)])
        with self.assertRaisesRegex(consumer.AdmissionError, "composed blocked export"):
            admitted(manifest, inputs).consume("s0")
        for mask in (1, 2):
            p, l = chain("blocked", root_mask=mask, repair=True)
            manifest, inputs = records([(p, l)])
            with self.assertRaisesRegex(consumer.AdmissionError, "composed blocked export"):
                admitted(manifest, inputs).consume("s0")

    def test_revision_membership_and_binding_rejections(self):
        manifest, inputs = records([chain("target")])
        original = inputs[0]
        for field in ("code", "intent"):
            changed = deepcopy(original)
            changed["policy"]["roots"][0][field] += "different"
            with self.assertRaises(capsule.CapsuleError):
                admitted(manifest, [changed])
        changed = deepcopy(original)
        changed["ledger"]["claims"]["u0"] = 1
        with self.assertRaises(capsule.CapsuleError):
            admitted(manifest, [changed])
        changed = deepcopy(original)
        changed["capsule"]["checker_tag"] = "0" * 64
        # Pin the changed object in the owned manifest to exercise MAC checking,
        # not merely the revision digest boundary. No authentication bypass.
        bad_manifest = deepcopy(manifest)
        bad_manifest["members"][0]["capsule_digest"] = capsule.digest(changed["capsule"])
        with self.assertRaisesRegex(capsule.CapsuleError, "checker authentication"):
            admitted(bad_manifest, [changed])
        for changed_manifest in (
                {**manifest, "epoch": "other-epoch"},
                {**manifest, "members": [{**manifest["members"][0], "sequence": 4}]},
                {**manifest, "members": [{**manifest["members"][0], "sequence": 2}]}):
            with self.assertRaises(capsule.CapsuleError):
                admitted(changed_manifest, inputs)
        gate = admitted(manifest, inputs)
        with self.assertRaisesRegex(consumer.AdmissionError, "duplicate release admission"):
            gate.admit(original["policy"], original["ledger"], original["capsule"])
        other_manifest, other_inputs = records([chain("a"), chain("b")])
        with self.assertRaisesRegex(consumer.AdmissionError, "unexpected release member"):
            admitted(manifest, [other_inputs[1]])

    def test_manifest_and_records_are_owned_and_sealed(self):
        manifest, inputs = records([chain("target")])
        saved = deepcopy(inputs)
        gate = admitted(manifest, inputs)
        manifest["members"].clear()
        inputs[0]["ledger"]["outputs"].clear()
        decisions = gate.seal()
        decisions[0]["outputs"][0]["mask"] = 7
        self.assertEqual(gate.consume("s0"), saved[0]["ledger"]["outputs"])
        with self.assertRaisesRegex(consumer.AdmissionError, "already sealed"):
            gate.admit(saved[0]["policy"], saved[0]["ledger"], saved[0]["capsule"])

    def test_empty_export_and_repeated_output_order(self):
        for count in (0, 1, 3):
            target = chain("empty", outputs=count)
            manifest, inputs = records([target])
            gate = admitted(manifest, inputs)
            with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
                path = Path(directory) / "result.zip"
                stats = gate.publish("s0", path)
                self.assertEqual(stats["units"], count)
                readback(path, target[1]["outputs"])

    def test_existing_destination_and_eight_owned_publishers(self):
        target = chain("race")
        manifest, inputs = records([target])
        with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
            path = Path(directory) / "result.zip"
            def publish(_):
                try:
                    admitted(manifest, inputs).publish("s0", path)
                    return True
                except FileExistsError:
                    return False
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(sum(pool.map(publish, range(8))), 1)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                admitted(manifest, inputs).publish("s0", path)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["result.zip"])
            readback(path, target[1]["outputs"])

    def test_exception_checkpoints_preserve_pre_post_commit_boundary(self):
        target = chain("checkpoints")
        manifest, inputs = records([target])
        for stage in ("temp-created", "zip-closed", "file-synced", "linked",
                      "directory-synced", "temporary-removed"):
            with tempfile.TemporaryDirectory(prefix=".consumption-", dir=ROOT) as directory:
                path = Path(directory) / "result.zip"
                def checkpoint(current):
                    if current == stage:
                        raise RuntimeError("owned checkpoint")
                with self.assertRaisesRegex(RuntimeError, "owned checkpoint"):
                    admitted(manifest, inputs).publish("s0", path, _checkpoint_callback=checkpoint)
                if stage in ("linked", "directory-synced", "temporary-removed"):
                    readback(path, target[1]["outputs"])
                else:
                    self.assertFalse(path.exists())
                self.assertFalse(any(p.name.endswith(".tmp") for p in Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
