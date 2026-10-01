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


def json_boundaries():
    """Controlled parser cases with a valid fixture-key authenticated state.

    Duplicate/hidden-constant inputs keep the original canonical body and tag.
    They test syntax rejection, not MAC forgery or whole-state rollback.
    """
    body = {"contract": freshness.CONTRACT, "epoch": "policyA", "generation": 0,
            "accepted_sequences": {"example": 7}}
    valid = freshness.encode_state(body, STATE_KEY)
    positive = [valid, b" \n\t" + valid + b" ",
                json.dumps(json.loads(valid), indent=2).encode()]
    for raw in positive:
        if freshness.decode_state(raw, STATE_KEY) != body:
            raise RuntimeError("valid authenticated state changed")
    critical = {
        "duplicate-generation": valid.replace(b'"generation":0', b'"generation":9,"generation":0'),
        "hidden-NaN-generation": valid.replace(b'"generation":0', b'"generation":NaN,"generation":0'),
    }
    negatives = {**critical,
        "duplicate-generation-identical": valid.replace(b'"generation":0', b'"generation":0,"generation":0'),
        "escaped-duplicate-key": valid.replace(b'"generation":0', b'"generati\\u006fn":9,"generation":0'),
        "duplicate-shard": valid.replace(b'"example":7', b'"example":99,"example":7'),
        "hidden-Infinity": valid.replace(b'"generation":0', b'"generation":Infinity,"generation":0'),
        "hidden-negative-Infinity": valid.replace(b'"generation":0', b'"generation":-Infinity,"generation":0'),
        "boolean-generation": valid.replace(b'"generation":0', b'"generation":true'),
        "integer-length": valid.replace(b'"generation":0', b'"generation":12345678901234567890'),
        "invalid-UTF8": b'\xff',
        "lexical-depth": b'[' * 65 + b'0' + b']' * 65,
        "lexical-atoms": b'[' + b'0,' * freshness.MAX_JSON_ATOMS + b'0]',
        "byte-limit": b' ' * (freshness.MAX_STATE_BYTES + 1),
        "changed-body-valid-syntax": valid.replace(b'"generation":0', b'"generation":1'),
    }
    rejected_rows = []
    for name, raw in negatives.items():
        try:
            freshness.decode_state(raw, STATE_KEY)
        except freshness.FreshnessError as exc:
            message = str(exc)
            if name == "lexical-depth" and "depth" not in message:
                raise RuntimeError("depth case did not reject lexically")
            if name == "lexical-atoms" and "atom" not in message:
                raise RuntimeError("atom case did not reject lexically")
            if name == "hidden-NaN-generation" and "non-finite" not in message:
                raise RuntimeError("hidden constant did not reject before overwrite")
            rejected_rows.append({"case": name, "bytes": len(raw), "rejection": message})
        else:
            raise RuntimeError("malformed state accepted: " + name)
    policy = checker.read_json(ROOT / "data/example-policy.json")
    log = checker.read_json(ROOT / "data/example-ledger.json")
    candidate = issue(policy, log, "policyA", 8)
    unchanged = []
    with tempfile.TemporaryDirectory(prefix="freshness-json-boundary-") as directory:
        path = Path(directory) / "state.json"
        for name, raw in critical.items():
            path.write_bytes(raw)
            try:
                freshness.accept_bound(path, STATE_KEY, policy, log, candidate,
                                       {"policyA": AUTHORITY_A}, {"policyA": CHECKER_A})
            except freshness.FreshnessError:
                if path.read_bytes() != raw:
                    raise RuntimeError("rejected state was modified")
                unchanged.append(name)
            else:
                raise RuntimeError("malformed persisted state accepted: " + name)
    return {"status": "passed", "valid_controls": len(positive),
            "rejected_cases": rejected_rows, "rejected_count": len(rejected_rows),
            "persisted_state_rejections_unchanged": unchanged,
            "fixture_keys_only": True,
            "interpretation": "Malformed encodings of an unchanged canonical authenticated body are rejected. No HMAC bypass or state rollback is claimed."}


def main():
    cpu = time.process_time()
    wall = time.perf_counter()
    policy = checker.read_json(ROOT / "data" / "example-policy.json")
    ledger = checker.read_json(ROOT / "data" / "example-ledger.json")
    tamper_cases = []
    json_checks = json_boundaries()

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
            sys.executable, "-S",
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
                command[:3] + [str(policy_path), str(ledger_path), str(state), stage],
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
        "json_boundaries": json_checks,
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
    if sys.argv[1:] == ["--json-only"]:
        result = json_boundaries()
        (ROOT / "results/freshness-json.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
    else:
        main()
