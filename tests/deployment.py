"""Authentication, freshness, hostile-path, race, and process-death checks."""
from __future__ import annotations

import copy
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import capsule
import checker
import emitter
import freshness

AUTHORITY_KEY = bytes.fromhex("a1" * 32)
CHECKER_KEY = bytes.fromhex("b2" * 32)
WRONG_KEY = bytes.fromhex("c3" * 32)


def rejected(fn):
    try:
        fn()
    except (capsule.CapsuleError, checker.Rejected, OSError, ValueError):
        return True
    raise AssertionError("invalid deployment object accepted")


def valid_zip(path: Path, expected_members: int) -> bool:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        return len(names) == expected_members and all(archive.read(name) is not None for name in names)


def mutate_hex(value):
    return ("0" if value[0] != "0" else "1") + value[1:]


def replay_call_boundaries(policy, log):
    """Count real local replay calls without changing their return values."""
    original = checker.verify
    count = 0
    calls = {}
    def observed(*args, **kwargs):
        nonlocal count
        count += 1
        return original(*args, **kwargs)
    checker.verify = observed
    try:
        def invoke(name, fn):
            before = count
            result = fn()
            calls[name] = count - before
            return result
        value = invoke("issue", lambda: capsule.issue(policy, log, AUTHORITY_KEY, CHECKER_KEY,
            shard="example", epoch="policyA", sequence=7))
        invoke("verify", lambda: capsule.verify(value, AUTHORITY_KEY, CHECKER_KEY))
        invoke("compose", lambda: capsule.compose([value], AUTHORITY_KEY, CHECKER_KEY))
        invoke("verify_bound", lambda: capsule.verify_bound(policy, log, value, AUTHORITY_KEY, CHECKER_KEY))
        with tempfile.TemporaryDirectory(prefix="capsule-role-boundary-") as directory:
            path = Path(directory) / "state.json"
            if path.exists():
                raise RuntimeError("unexpected preexisting state")
            invoke("accept_bound", lambda: freshness.accept_bound(path, WRONG_KEY, policy, log, value,
                {"policyA": AUTHORITY_KEY}, {"policyA": CHECKER_KEY}))
            persisted = freshness.read_state(path, WRONG_KEY)["accepted_sequences"] == {"example": 7}
        expected = {"issue": 1, "verify": 0, "compose": 0, "verify_bound": 1, "accept_bound": 1}
        if calls != expected or not persisted:
            raise RuntimeError(f"capsule replay boundary changed: {calls}")
        return {"local_checker_calls": calls, "accept_bound_persisted_freshness": persisted,
                "trust": "Summary-only composition authenticates checker assertions and does not receive or replay original ledgers."}
    finally:
        checker.verify = original


def main():
    cpu = time.process_time()
    wall = time.perf_counter()
    policy = checker.read_json(ROOT / "data" / "example-policy.json")
    log = checker.read_json(ROOT / "data" / "example-ledger.json")
    checker.verify(policy, log, exports=True)
    issued = capsule.issue(
        policy,
        log,
        AUTHORITY_KEY,
        CHECKER_KEY,
        shard="example",
        epoch="policyA",
        sequence=7,
    )
    verified = capsule.verify_bound(
        policy,
        log,
        issued,
        AUTHORITY_KEY,
        CHECKER_KEY,
        expected_epoch="policyA",
        minimum_sequence=7,
        expected_shard="example",
    )
    assert verified["output_names"] == [item["name"] for item in log["outputs"]]

    call_boundaries = replay_call_boundaries(policy, log)
    tamper_cases = []

    def add(name, fn):
        assert rejected(fn)
        tamper_cases.append(name)

    for field in ("policy_digest", "ledger_digest", "summary_digest", "policy_tag", "checker_tag"):
        changed = copy.deepcopy(issued)
        changed[field] = mutate_hex(changed[field])
        add(field + "-mutation", lambda changed=changed: capsule.verify(changed, AUTHORITY_KEY, CHECKER_KEY))
    changed = copy.deepcopy(issued)
    changed["summary"]["components"][0]["keys"][0][0] += "x"
    add("summary-content-mutation", lambda: capsule.verify(changed, AUTHORITY_KEY, CHECKER_KEY))
    changed = copy.deepcopy(issued)
    changed["output_names"][0] = "different.txt"
    add("output-name-mutation", lambda: capsule.verify(changed, AUTHORITY_KEY, CHECKER_KEY))
    changed = copy.deepcopy(issued)
    changed["contract"] = "other-contract"
    add("contract-mutation", lambda: capsule.verify(changed, AUTHORITY_KEY, CHECKER_KEY))
    changed = copy.deepcopy(issued)
    changed["sequence"] = True
    add("sequence-type-confusion", lambda: capsule.verify(changed, AUTHORITY_KEY, CHECKER_KEY))
    add("wrong-authority-key", lambda: capsule.verify(issued, WRONG_KEY, CHECKER_KEY))
    add("wrong-checker-key", lambda: capsule.verify(issued, AUTHORITY_KEY, WRONG_KEY))
    add(
        "stale-epoch",
        lambda: capsule.verify(issued, AUTHORITY_KEY, CHECKER_KEY, expected_epoch="policyB"),
    )
    add(
        "stale-sequence",
        lambda: capsule.verify(issued, AUTHORITY_KEY, CHECKER_KEY, minimum_sequence=8),
    )
    add(
        "wrong-shard",
        lambda: capsule.verify(issued, AUTHORITY_KEY, CHECKER_KEY, expected_shard="other"),
    )
    add(
        "per-shard-stale-sequence",
        lambda: capsule.compose(
            [issued],
            AUTHORITY_KEY,
            CHECKER_KEY,
            expected_epoch="policyA",
            minimum_sequences={"example": 8},
        ),
    )
    add(
        "duplicate-capsule-identity",
        lambda: capsule.compose(
            [issued, issued], AUTHORITY_KEY, CHECKER_KEY, expected_epoch="policyA"
        ),
    )
    revised = capsule.issue(
        policy,
        log,
        AUTHORITY_KEY,
        CHECKER_KEY,
        shard="example",
        epoch="policyA",
        sequence=8,
    )
    add(
        "duplicate-shard-revision",
        lambda: capsule.compose(
            [issued, revised], AUTHORITY_KEY, CHECKER_KEY, expected_epoch="policyA"
        ),
    )
    policy_changed = copy.deepcopy(policy)
    policy_changed["roots"][0]["intent"] += " changed"
    add(
        "bound-policy-substitution",
        lambda: capsule.verify_bound(policy_changed, log, issued, AUTHORITY_KEY, CHECKER_KEY),
    )
    log_changed = copy.deepcopy(log)
    log_changed["outputs"][0]["name"] = "changed.txt"
    add(
        "bound-ledger-substitution",
        lambda: capsule.verify_bound(policy, log_changed, issued, AUTHORITY_KEY, CHECKER_KEY),
    )

    with tempfile.TemporaryDirectory(prefix="containment-deployment-") as temp_name:
        temp = Path(temp_name)
        policy_file = temp / "policy.json"
        ledger_file = temp / "ledger.json"
        policy_file.write_text(json.dumps(policy))
        ledger_file.write_text(json.dumps(log))

        authenticated_path = temp / "authenticated.zip"
        stats = emitter.emit_authenticated(
            policy,
            log,
            issued,
            AUTHORITY_KEY,
            CHECKER_KEY,
            authenticated_path,
            expected_epoch="policyA",
            minimum_sequence=7,
            expected_shard="example",
        )
        assert valid_zip(authenticated_path, stats["members"])
        bad = copy.deepcopy(issued)
        bad["checker_tag"] = mutate_hex(bad["checker_tag"])
        refused_path = temp / "refused.zip"
        add(
            "authenticated-emission-tamper",
            lambda: emitter.emit_authenticated(
                policy, log, bad, AUTHORITY_KEY, CHECKER_KEY, refused_path
            ),
        )
        assert not refused_path.exists()

        # Concurrent create-if-absent publication: exactly one complete winner.
        race_path = temp / "race.zip"
        commands = [
            [sys.executable, '-S', str(ROOT / "src" / "emitter.py"), str(policy_file), str(ledger_file), str(race_path)]
            for _ in range(8)
        ]
        children = [
            subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for command in commands
        ]
        outcomes = [child.communicate(timeout=15) + (child.returncode,) for child in children]
        winners = sum(code == 0 for _out, _err, code in outcomes)
        assert winners == 1 and valid_zip(race_path, 2 * len(log["outputs"]))
        race_temporary_files = len(
            [item for item in temp.iterdir() if item.name.startswith(".race.zip.containment-")]
        )
        assert race_temporary_files == 0

        victim = temp / "victim.txt"
        victim.write_text("unchanged")
        symlink_path = temp / "symlink.zip"
        symlink_path.symlink_to(victim)
        add("destination-symlink", lambda: emitter.emit(policy, log, symlink_path))
        assert victim.read_text() == "unchanged" and symlink_path.is_symlink()

        existing = temp / "existing.zip"
        existing.write_bytes(b"sentinel")
        add("preexisting-destination", lambda: emitter.emit(policy, log, existing))
        assert existing.read_bytes() == b"sentinel"

        real_parent = temp / "real-parent"
        real_parent.mkdir()
        parent_link = temp / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        add("symlink-parent", lambda: emitter.emit(policy, log, parent_link / "output.zip"))
        assert not (real_parent / "output.zip").exists()

        crash_observations = []
        for stage, committed in (
            ("temp-created", False),
            ("zip-closed", False),
            ("file-synced", False),
            ("linked", True),
            ("directory-synced", True),
            ("temporary-removed", True),
        ):
            directory = temp / ("crash-" + stage)
            directory.mkdir()
            output = directory / "output.zip"
            command = [
                sys.executable, "-S",
                str(ROOT / "tests" / "emitter_worker.py"),
                str(policy_file),
                str(ledger_file),
                str(output),
                stage,
            ]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15)
            assert completed.returncode == 91
            if committed:
                assert output.exists() and valid_zip(output, 2 * len(log["outputs"]))
            else:
                assert not output.exists()
            temporary_files = len(
                {item.name for item in directory.iterdir() if item.name.endswith(".tmp")}
            )
            assert temporary_files == (0 if stage == "temporary-removed" else 1)
            crash_observations.append(
                {
                    "checkpoint": stage,
                    "destination_exists": output.exists(),
                    "expected_committed": committed,
                    "temporary_files": temporary_files,
                }
            )

    result = {
        "replay_call_boundaries": call_boundaries,
        "capsule_contract": capsule.CONTRACT,
        "valid_capsule_bound_and_verified": True,
        "tamper_or_context_cases_rejected": len(tamper_cases),
        "tamper_cases": tamper_cases,
        "race_processes": 8,
        "race_successful_publishers": winners,
        "race_result_complete": True,
        "race_temporary_files_remaining": race_temporary_files,
        "preexisting_destination_preserved": True,
        "destination_symlink_preserved_and_target_unchanged": True,
        "symlink_parent_refused": True,
        "process_death_checkpoints": crash_observations,
        "precommit_deaths_created_no_destination": all(
            not row["destination_exists"] for row in crash_observations if not row["expected_committed"]
        ),
        "postlink_deaths_left_complete_destination": all(
            row["destination_exists"] for row in crash_observations if row["expected_committed"]
        ),
        "power_loss_or_arbitrary_filesystem_durability_tested": False,
        "public_signature_or_nonrepudiation_claimed": False,
        "cpu_seconds": time.process_time() - cpu,
        "wall_seconds": time.perf_counter() - wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    (ROOT / "results" / "deployment.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
