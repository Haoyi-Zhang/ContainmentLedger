"""Isolated worker for local freshness races and process-death checkpoints."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import capsule
import checker
import freshness

AUTHORITY_A = bytes.fromhex("31" * 32)
CHECKER_A = bytes.fromhex("32" * 32)
STATE_KEY = bytes.fromhex("33" * 32)


def main():
    if len(sys.argv) not in (4, 5):
        raise SystemExit("usage: freshness_worker.py POLICY LEDGER STATE [KILL_STAGE]")
    policy = checker.read_json(Path(sys.argv[1]))
    ledger = checker.read_json(Path(sys.argv[2]))
    state = Path(sys.argv[3])
    kill_stage = sys.argv[4] if len(sys.argv) == 5 else None
    issued = capsule.issue(
        policy,
        ledger,
        AUTHORITY_A,
        CHECKER_A,
        shard="example",
        epoch="policyA",
        sequence=8,
    )

    def checkpoint(stage: str):
        if stage == kill_stage:
            os._exit(92)

    try:
        accepted = freshness.accept_bound(
            state,
            STATE_KEY,
            policy,
            ledger,
            issued,
            {"policyA": AUTHORITY_A},
            {"policyA": CHECKER_A},
            checkpoint=checkpoint,
        )
    except capsule.CapsuleError as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise SystemExit(3)
    print(json.dumps({"sequence": accepted["verified"]["sequence"]}))


if __name__ == "__main__":
    main()
