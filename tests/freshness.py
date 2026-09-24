"""Persistent freshness, epoch rotation, race, tamper, and death checks."""
from __future__ import annotations

import copy
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import capsule
import checker
import freshness

AUTHORITY_A = bytes.fromhex("31" * 32)
CHECKER_A = bytes.fromhex("32" * 32)
AUTHORITY_B = bytes.fromhex("41" * 32)
CHECKER_B = bytes.fromhex("42" * 32)
STATE_KEY = bytes.fromhex("33" * 32)
WRONG_STATE_KEY = bytes.fromhex("34" * 32)


def rejected(fn):
    try:
        fn()
    except (freshness.FreshnessError, capsule.CapsuleError, OSError, ValueError):
        return True
    raise AssertionError("invalid freshness operation accepted")


def issue(policy, ledger, epoch, sequence):
    keys = {
        "policyA": (AUTHORITY_A, CHECKER_A),
        "policyB": (AUTHORITY_B, CHECKER_B),
    }
    authority, checker_key = keys[epoch]
    return capsule.issue(
        policy,
        ledger,
        authority,
        checker_key,
        shard="example",
        epoch=epoch,
        sequence=sequence,
    )


def write_initial(path, policy, ledger, sequence=7):
    return freshness.accept_bound(
        path,
        STATE_KEY,
        policy,
        ledger,
        issue(policy, ledger, "policyA", sequence),
        {"policyA": AUTHORITY_A},
        {"policyA": CHECKER_A},
    )


def main():
    cpu = time.process_time()
    wall = time.perf_counter()
    policy = checker.read_json(ROOT / "data" / "example-policy.json")
    ledger = checker.read_json(ROOT / "data" / "example-ledger.json")
    tamper_cases = []

    with tempfile.TemporaryDirectory(prefix="containment-freshness-") as temp_name:
        temp = Path(temp_name)
        policy_path = temp / "policy.json"
        ledger_path = temp / "ledger.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

        state_path = temp / "state.json"
        first = write_initial(state_path, policy, ledger)
        assert first["state"]["accepted_sequences"] == {"example": 7}
        reopened = freshness.read_state(state_path, STATE_KEY)
        assert reopened == first["state"]
        replay = issue(policy, ledger, "policyA", 7)
        assert rejected(
            lambda: freshness.accept_bound(
                state_path,
                STATE_KEY,
                policy,
                ledger,
                replay,
                {"policyA": AUTHORITY_A},
                {"policyA": CHECKER_A},
            )
        )
        tamper_cases.append("persistent-replay")

        next_capsule = issue(policy, ledger, "policyA", 8)
        second = freshness.accept_bound(
            state_path,
            STATE_KEY,
            policy,
            ledger,
            next_capsule,
            {"policyA": AUTHORITY_A},
            {"policyA": CHECKER_A},
        )
        assert second["state"]["accepted_sequences"] == {"example": 8}
        assert freshness.read_state(state_path, STATE_KEY)["accepted_sequences"] == {"example": 8}

        # Authenticated state rejects content changes, wrong state keys, and symlinks.
        original_raw = state_path.read_bytes()
        changed = bytearray(original_raw)
        changed[max(0, len(changed) // 2)] ^= 1
        state_path.write_bytes(changed)
        assert rejected(lambda: freshness.read_state(state_path, STATE_KEY))
        tamper_cases.append("state-content-mutation")
        state_path.write_bytes(original_raw)
        assert rejected(lambda: freshness.read_state(state_path, WRONG_STATE_KEY))
        tamper_cases.append("wrong-state-key")
        state_link = temp / "state-link.json"
        state_link.symlink_to(state_path)
        assert rejected(lambda: freshness.read_state(state_link, STATE_KEY))
        tamper_cases.append("state-symlink")

        # Explicit policy-epoch transition selects a new key pair. A downgrade or
        # an omitted key is rejected after the transition.
        rotated = issue(policy, ledger, "policyB", 1)
        assert rejected(
            lambda: freshness.accept_bound(
                state_path,
                STATE_KEY,
                policy,
                ledger,
                rotated,
                {"policyA": AUTHORITY_A, "policyB": AUTHORITY_B},
                {"policyA": CHECKER_A, "policyB": CHECKER_B},
            )
        )
        tamper_cases.append("unapproved-epoch-transition")
        rotation = freshness.accept_bound(
            state_path,
            STATE_KEY,
            policy,
            ledger,
            rotated,
            {"policyA": AUTHORITY_A, "policyB": AUTHORITY_B},
            {"policyA": CHECKER_A, "policyB": CHECKER_B},
            allowed_epoch_transition=("policyA", "policyB"),
        )
        assert rotation["state"]["epoch"] == "policyB"
        assert rotation["state"]["accepted_sequences"] == {"example": 1}
        assert rejected(
            lambda: freshness.accept_bound(
                state_path,
                STATE_KEY,
                policy,
                ledger,
                next_capsule,
                {"policyA": AUTHORITY_A, "policyB": AUTHORITY_B},
                {"policyA": CHECKER_A, "policyB": CHECKER_B},
            )
        )
        tamper_cases.append("epoch-downgrade")
        assert rejected(
            lambda: freshness.verify_with_keyring(
                rotated, {"policyA": AUTHORITY_A}, {"policyA": CHECKER_A}
            )
        )
        tamper_cases.append("missing-rotated-key")

        # Eight isolated processes race to accept the same next sequence. The
        # lock and strict sequence advance permit exactly one successful acceptor.
        race_dir = temp / "race"
        race_dir.mkdir()
        race_state = race_dir / "state.json"
        write_initial(race_state, policy, ledger)
        command = [
            sys.executable,
            str(ROOT / "tests" / "freshness_worker.py"),
            str(policy_path),
            str(ledger_path),
            str(race_state),
        ]
        children = [
            subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(8)
        ]
        outcomes = [child.communicate(timeout=15) + (child.returncode,) for child in children]
        winners = sum(code == 0 for _out, _err, code in outcomes)
        stale = sum(code == 3 for _out, _err, code in outcomes)
        assert winners == 1 and stale == 7
        assert freshness.read_state(race_state, STATE_KEY)["accepted_sequences"] == {"example": 8}

        # Process death before replace retains the old complete state; death
        # after replace exposes the new complete state. This is not a power-loss claim.
        death_observations = []
        for stage, expected_sequence in (
            ("temp-created", 7),
            ("file-synced", 7),
            ("replaced", 8),
            ("directory-synced", 8),
        ):
            directory = temp / ("death-" + stage)
            directory.mkdir()
            state = directory / "state.json"
            write_initial(state, policy, ledger)
            completed = subprocess.run(
                command[:2] + [str(policy_path), str(ledger_path), str(state), stage],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert completed.returncode == 92
            loaded = freshness.read_state(state, STATE_KEY)
            assert loaded["accepted_sequences"] == {"example": expected_sequence}
            temporary_files = len(
                [item for item in directory.iterdir() if item.name.endswith(".tmp")]
            )
            death_observations.append(
                {
                    "checkpoint": stage,
                    "accepted_sequence_after_restart": expected_sequence,
                    "temporary_files": temporary_files,
                }
            )

    result = {
        "contract": freshness.CONTRACT,
        "authenticated_state_reopened": True,
        "strict_replay_rejected_after_process_restart": True,
        "same_epoch_advance_persisted": True,
        "explicit_epoch_rotation_accepted": True,
        "old_epoch_downgrade_rejected": True,
        "retired_or_missing_epoch_key_rejected": True,
        "tamper_or_context_cases_rejected": len(tamper_cases),
        "tamper_cases": tamper_cases,
        "race_processes": 8,
        "race_successful_acceptors": winners,
        "race_stale_rejections": stale,
        "process_death_checkpoints": death_observations,
        "pre_replace_death_retained_prior_complete_state": all(
            row["accepted_sequence_after_restart"] == 7
            for row in death_observations
            if row["checkpoint"] in ("temp-created", "file-synced")
        ),
        "post_replace_death_exposed_new_complete_state": all(
            row["accepted_sequence_after_restart"] == 8
            for row in death_observations
            if row["checkpoint"] in ("replaced", "directory-synced")
        ),
        "whole_state_file_rollback_detected": False,
        "distributed_consensus_or_transparency_provided": False,
        "power_loss_or_network_filesystem_durability_tested": False,
        "cpu_seconds": time.process_time() - cpu,
        "wall_seconds": time.perf_counter() - wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    (ROOT / "results" / "freshness.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
