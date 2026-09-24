"""Deterministic adapter from retained source files to exact line-slice ledgers.

It discovers naturally repeated canonical lines and constructs benign shard
pipelines using import -> extract -> rewrite -> collect.  Labels are synthetic
fixture facts; repeated text is observed in the retained public files.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import ledger


def selected_files(public_root: Path) -> list[Path]:
    files = sorted(path for path in public_root.rglob("*") if path.is_file())
    if not files:
        raise ValueError("no retained source files")
    return files


def duplicate_line_classes(public_root: Path, minimum_length: int = 8) -> dict[str, list[dict]]:
    if type(minimum_length) is not int or minimum_length < 1:
        raise ValueError("minimum line length")
    classes: dict[str, dict[str, dict]] = defaultdict(dict)
    for path in selected_files(public_root):
        relative = path.relative_to(public_root).as_posix()
        text = path.read_text(encoding="utf-8")
        cursor = 0
        for line_number, line_with_end in enumerate(text.splitlines(keepends=True), 1):
            line = line_with_end.rstrip("\r\n")
            stop = cursor + len(line)
            canonical = ledger.canonical(line)
            if len(canonical) >= minimum_length and canonical.strip() and relative not in classes[canonical]:
                classes[canonical][relative] = {
                    "file": relative,
                    "project": relative.split("/", 1)[0],
                    "line": line_number,
                    "start": cursor,
                    "stop": stop,
                    "text": line,
                }
            cursor += len(line_with_end)
        # splitlines omits a final empty record; all offsets above still refer to text code points.
    return {
        key: [items[name] for name in sorted(items)]
        for key, items in sorted(classes.items())
        if len(items) >= 2
    }


def build_line_shard(
    public_root: Path,
    occurrence: dict,
    *,
    labelled: bool,
    suffix: str,
) -> tuple[dict, dict]:
    relative = occurrence["file"]
    code = (public_root / relative).read_text(encoding="utf-8")
    start, stop = occurrence["start"], occurrence["stop"]
    line = code[start:stop]
    if line != occurrence["text"] or not line:
        raise ValueError("stale line coordinates")
    intent = "source:" + relative
    rewritten = line + "\n# containment-output-" + suffix
    policy = {
        "roots": [{"id": "source", "code": code, "intent": intent, "labels": 1 if labelled else 0}],
        "repairs": [],
    }
    log = {
        "units": [
            {"id": "imported", "op": "import", "source": "source", "code": code, "intent": intent},
            {
                "id": "slice",
                "op": "extract",
                "parent": "imported",
                "start": start,
                "stop": stop,
                "code": line,
                "intent": intent,
            },
            {
                "id": "rewritten",
                "op": "rewrite",
                "parent": "slice",
                "old": line,
                "new": rewritten,
                "code": rewritten,
                "intent": intent,
            },
        ],
        "bundles": [
            {"id": "collected", "op": "collect", "items": [{"name": "result.txt", "unit": "rewritten"}]},
            {"id": "archive", "op": "repack", "parent": "collected", "prefix": "corpus"},
        ],
        "final": "archive",
        "outputs": [
            {"name": "corpus/0.txt", "unit": "rewritten", "code": rewritten, "intent": intent}
        ],
        "claims": {},
    }
    ledger.annotate(policy, log)
    return policy, log
