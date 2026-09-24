"""Test-only subprocess wrapper for process-death publication checkpoints."""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import checker
import emitter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("policy")
    parser.add_argument("ledger")
    parser.add_argument("destination")
    parser.add_argument("stage")
    args = parser.parse_args()

    def checkpoint(stage):
        if stage == args.stage:
            os._exit(91)

    emitter.emit(
        checker.read_json(args.policy),
        checker.read_json(args.ledger),
        args.destination,
        _checkpoint_callback=checkpoint,
    )


if __name__ == "__main__":
    main()
