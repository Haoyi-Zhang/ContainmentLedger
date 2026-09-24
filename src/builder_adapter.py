"""Bridge a retained BigCode decontamination function to containment ledgers.

The upstream exact-substring function is retained verbatim under ``upstream/``
and loaded as an ordinary module.  This adapter supplies deterministic static
records and translates the upstream include/exclude decision into a declared
content-scoped policy fact.  It does not execute corpus code or claim that the
small bridge reproduces BigCode's complete pipeline.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import ledger

UPSTREAM_COMMIT = "bebec929edd826f19b5fa3538f22d18d5b50da4b"
UPSTREAM_BLOB = "446313901df4de049a3cfc473152f438b542c799"
UPSTREAM_PATH = "decontamination/find_substrings.py"
HUMANEVAL_COMMIT = "6d43fb980f9fee3c892a914eda09951f772ad10d"
HUMANEVAL_BLOB = "06236282a45e10e92233e2b8f84cea10ae25be46"


def _artifact_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_upstream() -> ModuleType:
    """Load the dependency-free retained function excerpt by exact path."""
    source = _artifact_root() / "upstream" / "bigcode-dataset" / "find_substrings_excerpt.py"
    spec = importlib.util.spec_from_file_location("retained_bigcode_find_substrings", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load retained BigCode excerpt")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "find_substrings", None)):
        raise RuntimeError("retained BigCode function missing")
    return module


def read_bridge_policy() -> dict:
    path = _artifact_root() / "data" / "builder" / "bridge-policy.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not (
        type(value) is dict
        and set(value) == {"profile", "benchmarks", "notes"}
        and value["profile"] == "bigcode-exact-substring-bridge/v1"
        and type(value["benchmarks"]) is dict
    ):
        raise ValueError("bridge policy schema")
    for name, samples in value["benchmarks"].items():
        if not (
            type(name) is str
            and name
            and type(samples) is list
            and samples
            and all(type(sample) is str and sample for sample in samples)
        ):
            raise ValueError("bridge benchmark entry")
    return value


def scan(content: str, filter_out: dict[str, list[str]]) -> tuple[bool, str | None, str | None]:
    """Invoke the retained upstream exact-substring decision."""
    if type(content) is not str:
        raise TypeError("content")
    upstream = load_upstream()
    included, reason, matched = upstream.find_substrings(
        {"content": content}, filter_out, return_matched=True
    )
    if type(included) is not bool:
        raise RuntimeError("unexpected upstream result")
    return included, reason, matched


def select_natural_probe(text: str, minimum_length: int = 24) -> str:
    """Choose a deterministic nonblank source line suitable for a text probe."""
    if type(text) is not str or type(minimum_length) is not int or minimum_length < 8:
        raise ValueError("probe input")
    candidates = []
    for line in text.splitlines():
        stripped = line.strip()
        if (
            len(line) >= minimum_length
            and stripped
            and sum(ch.isalnum() for ch in line) >= 8
            and "\x00" not in line
        ):
            candidates.append(line)
    if not candidates:
        raise ValueError("no natural probe line")
    # Prefer a long, information-bearing line; lexical tie-breaking is stable.
    return sorted(set(candidates), key=lambda item: (-len(item), item))[0]


def mutate_probe(probe: str) -> str:
    """Change one interior ASCII alphanumeric so exact substring matching fails."""
    if type(probe) is not str or len(probe) < 2:
        raise ValueError("probe")
    chars = list(probe)
    positions = [index for index, char in enumerate(chars) if char.isascii() and char.isalnum()]
    if not positions:
        raise ValueError("probe has no mutable ASCII alphanumeric")
    index = positions[len(positions) // 2]
    replacement = "_" if chars[index] != "_" else "-"
    chars[index] = replacement
    changed = "".join(chars)
    if changed == probe or probe.lower() in changed.lower():
        raise ValueError("probe mutation did not remove match")
    return changed


def build_rewrite_ledger(
    code: str,
    *,
    probe: str,
    benchmark: str,
    source_id: str,
    member_name: str,
) -> tuple[dict, dict, dict]:
    """Run the upstream decision and build an exact import/rewrite/repack ledger."""
    filter_out = {benchmark: [probe]}
    included_before, reason, matched = scan(code, filter_out)
    if included_before or matched != probe:
        raise ValueError("probe does not classify root")
    changed_probe = mutate_probe(probe)
    rewritten = code.replace(probe, changed_probe)
    if rewritten == code:
        raise ValueError("rewrite did not change input")
    included_after, after_reason, after_match = scan(rewritten, filter_out)
    if not included_after or after_reason is not None or after_match is not None:
        raise ValueError("endpoint still matches upstream filter")
    intent = "builder-bridge:" + source_id
    policy = {
        "roots": [{"id": "source", "code": code, "intent": intent, "labels": ledger.B}],
        "repairs": [],
    }
    log = {
        "units": [
            {"id": "imported", "op": "import", "source": "source", "code": code, "intent": intent},
            {
                "id": "rewritten",
                "op": "rewrite",
                "parent": "imported",
                "old": probe,
                "new": changed_probe,
                "code": rewritten,
                "intent": intent,
            },
        ],
        "bundles": [
            {"id": "collected", "op": "collect", "items": [{"name": member_name, "unit": "rewritten"}]},
            {"id": "archive", "op": "repack", "parent": "collected", "prefix": "corpus"},
        ],
        "final": "archive",
        "outputs": [
            {"name": "corpus/0.txt", "unit": "rewritten", "code": rewritten, "intent": intent}
        ],
        "claims": {},
    }
    ledger.annotate(policy, log)
    observation = {
        "benchmark": benchmark,
        "source_id": source_id,
        "probe": probe,
        "mutated_probe": changed_probe,
        "root_included_by_upstream": included_before,
        "root_filter_reason": reason,
        "endpoint_included_by_upstream": included_after,
        "lineage_output_mask": log["claims"]["rewritten"],
    }
    return policy, log, observation


def build_clean_control(code: str, *, source_id: str, index: int) -> tuple[dict, dict, dict]:
    """Build a clean control whose absent probe passes both scanner and replay."""
    probe = f"__containment_absent_probe_{index:04d}__"
    while probe.lower() in code.lower():
        probe += "x"
    included, reason, matched = scan(code, {"absent_control": [probe]})
    if not included or reason is not None or matched is not None:
        raise ValueError("absent clean probe matched")
    intent = "builder-clean:" + source_id
    policy = {
        "roots": [{"id": "source", "code": code, "intent": intent, "labels": 0}],
        "repairs": [],
    }
    log = {
        "units": [
            {"id": "imported", "op": "import", "source": "source", "code": code, "intent": intent},
            {"id": "copied", "op": "copy", "parent": "imported", "code": code, "intent": intent},
        ],
        "bundles": [
            {"id": "collected", "op": "collect", "items": [{"name": "source.txt", "unit": "copied"}]},
            {"id": "archive", "op": "repack", "parent": "collected", "prefix": "corpus"},
        ],
        "final": "archive",
        "outputs": [{"name": "corpus/0.txt", "unit": "copied", "code": code, "intent": intent}],
        "claims": {},
    }
    ledger.annotate(policy, log)
    return policy, log, {
        "source_id": source_id,
        "probe": probe,
        "root_included_by_upstream": included,
        "endpoint_included_by_upstream": included,
        "lineage_output_mask": log["claims"]["copied"],
    }
