"""Authenticated containment-summary capsules (standard library only).

The profile computationally binds a checked local summary to canonical policy
and ledger bytes under HMAC authenticity and SHA-256 collision resistance.
It is a shared-key integrity profile, not a public signature,
transparency service, non-repudiation mechanism, or key-distribution system.
Freshness requires verifier-maintained epoch/sequence state.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy

import checker
import merge

CONTRACT = "containment-ledger/equality-only/hmac-sha256"
MAX_CANONICAL_BYTES = 64 * 1024 * 1024
MAX_SUMMARY_KEYS = 40000
MAX_SUMMARY_ARCS = 240000
MAX_OUTPUTS = 20000
MAX_KEY_BYTES = 128 * 1024 * 1024


class CapsuleError(ValueError):
    """The authenticated capsule or its deployment context is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CapsuleError(message)


def _identifier(value: object, where: str) -> str:
    _require(
        type(value) is str
        and 1 <= len(value) <= 160
        and all(ch.isalnum() or ch in "._-" for ch in value),
        where,
    )
    return value


def _key(value: object, where: str) -> bytes:
    _require(type(value) is bytes and 32 <= len(value) <= 4096, where)
    return value


def _hex_digest(value: object, where: str) -> str:
    _require(
        type(value) is str
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value),
        where,
    )
    return value


def canonical_bytes(value: object) -> bytes:
    """Return a single UTF-8 JSON encoding after rejecting non-JSON values."""

    def walk(node: object, depth: int = 0) -> None:
        _require(depth <= 64, "canonical depth")
        if node is None or type(node) in (str, int, bool):
            if type(node) is str:
                try:
                    node.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise CapsuleError("canonical Unicode") from exc
            return
        if type(node) is list:
            for item in node:
                walk(item, depth + 1)
            return
        if type(node) is dict:
            for key, item in node.items():
                _require(type(key) is str, "canonical object key")
                walk(key, depth + 1)
                walk(item, depth + 1)
            return
        raise CapsuleError("canonical JSON type")

    walk(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CapsuleError("canonical encoding") from exc
    _require(len(encoded) <= MAX_CANONICAL_BYTES, "canonical byte budget")
    return encoded


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _tag(key: bytes, domain: bytes, value: object) -> str:
    return hmac.new(key, domain + canonical_bytes(value), hashlib.sha256).hexdigest()


def validate_summary(summary: object) -> dict:
    """Strictly validate the equality-only summary before authentication/use."""
    _require(
        type(summary) is dict and set(summary) == {"components", "origin_labels"},
        "summary fields",
    )
    components = summary["components"]
    origin = summary["origin_labels"]
    _require(type(components) is list and len(components) == 2, "summary components")
    _require(
        type(origin) is list
        and len(origin) <= MAX_OUTPUTS
        and all(type(value) is int and value in (0, 2) for value in origin),
        "summary origin labels",
    )
    total_keys = total_arcs = key_bytes = 0
    checked = []
    for expected_bit, component in zip((1, 4), components):
        _require(
            type(component) is dict
            and set(component) == {"bit", "keys", "arcs", "seeds", "outputs"},
            "summary component fields",
        )
        _require(type(component["bit"]) is int and component["bit"] == expected_bit, "summary bit")
        keys = component["keys"]
        arcs = component["arcs"]
        seeds = component["seeds"]
        outputs = component["outputs"]
        _require(all(type(x) is list for x in (keys, arcs, seeds, outputs)), "summary lists")
        total_keys += len(keys)
        total_arcs += len(arcs)
        _require(total_keys <= MAX_SUMMARY_KEYS, "summary key budget")
        _require(total_arcs <= MAX_SUMMARY_ARCS, "summary arc budget")
        _require(len(outputs) == len(origin), "summary output cardinality")

        seen_keys = set()
        normalized_keys = []
        expected_width = 1 if expected_bit == 1 else 2
        for item in keys:
            _require(
                type(item) is list
                and len(item) == expected_width
                and all(type(part) is str for part in item),
                "summary key",
            )
            encoded_parts = []
            for part in item:
                try:
                    raw = part.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise CapsuleError("summary key Unicode") from exc
                _require(len(raw) <= 262144, "summary key part budget")
                key_bytes += len(raw)
                encoded_parts.append(part)
            key = tuple(encoded_parts)
            _require(key not in seen_keys, "duplicate summary key")
            seen_keys.add(key)
            normalized_keys.append(list(key))
        _require(key_bytes <= MAX_KEY_BYTES, "summary key byte budget")

        def local_index(value: object, where: str) -> int:
            _require(type(value) is int and 0 <= value < len(keys), where)
            return value

        normalized_arcs = []
        seen_arcs = set()
        for arc in arcs:
            _require(type(arc) is list and len(arc) == 2, "summary arc")
            edge = (local_index(arc[0], "summary arc index"), local_index(arc[1], "summary arc index"))
            _require(edge[0] != edge[1] and edge not in seen_arcs, "summary arc uniqueness")
            seen_arcs.add(edge)
            normalized_arcs.append(list(edge))
        _require(normalized_arcs == sorted(normalized_arcs), "summary arc order")

        normalized_seeds = [local_index(value, "summary seed") for value in seeds]
        _require(normalized_seeds == sorted(set(normalized_seeds)), "summary seed order")
        normalized_outputs = [local_index(value, "summary output") for value in outputs]
        checked.append(
            {
                "bit": expected_bit,
                "keys": normalized_keys,
                "arcs": normalized_arcs,
                "seeds": normalized_seeds,
                "outputs": normalized_outputs,
            }
        )
    return {"components": checked, "origin_labels": list(origin)}


def _policy_binding(contract: str, epoch: str, policy_digest: str) -> dict:
    return {"contract": contract, "epoch": epoch, "policy_digest": policy_digest}


def issue(
    policy: dict,
    ledger: dict,
    authority_key: bytes,
    checker_key: bytes,
    *,
    shard: str,
    epoch: str,
    sequence: int,
) -> dict:
    """Replay a shard and issue a shared-key authenticated composition capsule."""
    authority_key = _key(authority_key, "authority key")
    checker_key = _key(checker_key, "checker key")
    shard = _identifier(shard, "shard identifier")
    epoch = _identifier(epoch, "epoch identifier")
    _require(type(sequence) is int and 0 <= sequence < 2**63, "sequence")

    summary = validate_summary(checker.verify(policy, ledger, summary=True))
    output_names = [item["name"] for item in ledger["outputs"]]
    _require(
        len(output_names) == len(summary["origin_labels"])
        and len(output_names) == len(set(output_names))
        and all(type(name) is str and 0 < len(name) <= 512 for name in output_names),
        "capsule output names",
    )
    policy_digest = digest(policy)
    ledger_digest = digest(ledger)
    summary_digest = digest(summary)
    policy_tag = _tag(
        authority_key,
        b"containment-policy\x00",
        _policy_binding(CONTRACT, epoch, policy_digest),
    )
    body = {
        "contract": CONTRACT,
        "shard": shard,
        "epoch": epoch,
        "sequence": sequence,
        "policy_digest": policy_digest,
        "ledger_digest": ledger_digest,
        "summary_digest": summary_digest,
        "policy_tag": policy_tag,
        "output_names": output_names,
        "summary": summary,
    }
    body["checker_tag"] = _tag(checker_key, b"containment-checker\x00", body)
    return body


def verify(
    capsule: object,
    authority_key: bytes,
    checker_key: bytes,
    *,
    expected_epoch: str | None = None,
    minimum_sequence: int | None = None,
    expected_shard: str | None = None,
) -> dict:
    """Authenticate a capsule and enforce optional caller-held freshness state."""
    authority_key = _key(authority_key, "authority key")
    checker_key = _key(checker_key, "checker key")
    _require(
        type(capsule) is dict
        and set(capsule)
        == {
            "contract",
            "shard",
            "epoch",
            "sequence",
            "policy_digest",
            "ledger_digest",
            "summary_digest",
            "policy_tag",
            "output_names",
            "summary",
            "checker_tag",
        },
        "capsule fields",
    )
    contract = capsule["contract"]
    _require(type(contract) is str and contract == CONTRACT, "capsule contract")
    shard = _identifier(capsule["shard"], "capsule shard")
    epoch = _identifier(capsule["epoch"], "capsule epoch")
    sequence = capsule["sequence"]
    _require(type(sequence) is int and 0 <= sequence < 2**63, "capsule sequence")
    policy_digest = _hex_digest(capsule["policy_digest"], "policy digest")
    _hex_digest(capsule["ledger_digest"], "ledger digest")
    summary_digest = _hex_digest(capsule["summary_digest"], "summary digest")
    policy_tag = _hex_digest(capsule["policy_tag"], "policy tag")
    checker_tag = _hex_digest(capsule["checker_tag"], "checker tag")
    output_names = capsule["output_names"]
    _require(
        type(output_names) is list
        and len(output_names) <= MAX_OUTPUTS
        and len(output_names) == len(set(output_names))
        and all(type(name) is str and 0 < len(name) <= 512 for name in output_names),
        "capsule outputs",
    )
    summary = validate_summary(capsule["summary"])
    _require(len(output_names) == len(summary["origin_labels"]), "capsule output cardinality")
    _require(hmac.compare_digest(summary_digest, digest(summary)), "summary digest mismatch")
    expected_policy_tag = _tag(
        authority_key,
        b"containment-policy\x00",
        _policy_binding(contract, epoch, policy_digest),
    )
    _require(hmac.compare_digest(policy_tag, expected_policy_tag), "policy authentication")
    body = {key: deepcopy(value) for key, value in capsule.items() if key != "checker_tag"}
    expected_checker_tag = _tag(checker_key, b"containment-checker\x00", body)
    _require(hmac.compare_digest(checker_tag, expected_checker_tag), "checker authentication")
    if expected_epoch is not None:
        _require(epoch == _identifier(expected_epoch, "expected epoch"), "stale policy epoch")
    if minimum_sequence is not None:
        _require(type(minimum_sequence) is int and sequence >= minimum_sequence, "stale sequence")
    if expected_shard is not None:
        _require(shard == _identifier(expected_shard, "expected shard"), "unexpected shard")
    return {
        "contract": contract,
        "shard": shard,
        "epoch": epoch,
        "sequence": sequence,
        "policy_digest": policy_digest,
        "ledger_digest": capsule["ledger_digest"],
        "output_names": list(output_names),
        "summary": summary,
    }


def verify_bound(
    policy: dict,
    ledger: dict,
    capsule: object,
    authority_key: bytes,
    checker_key: bytes,
    **expectations: object,
) -> dict:
    """Authenticate and bind a capsule to locally supplied policy and ledger."""
    result = verify(capsule, authority_key, checker_key, **expectations)
    _require(hmac.compare_digest(result["policy_digest"], digest(policy)), "policy binding")
    _require(hmac.compare_digest(result["ledger_digest"], digest(ledger)), "ledger binding")
    local_summary = validate_summary(checker.verify(policy, ledger, summary=True))
    _require(local_summary == result["summary"], "summary replay binding")
    _require(result["output_names"] == [item["name"] for item in ledger["outputs"]], "output binding")
    return result


def compose(
    capsules: list,
    authority_key: bytes,
    checker_key: bytes,
    *,
    expected_epoch: str | None = None,
    minimum_sequences: dict[str, int] | None = None,
) -> list[dict]:
    """Authenticate all shard summaries before equality-only composition."""
    _require(type(capsules) is list and capsules, "capsule list")
    _require(len(capsules) <= 20000, "capsule count")
    checked = []
    seen = set()
    seen_shards = set()
    for item in capsules:
        shard = item.get("shard") if type(item) is dict else None
        minimum = None if minimum_sequences is None else minimum_sequences.get(shard, 0)
        verified = verify(
            item,
            authority_key,
            checker_key,
            expected_epoch=expected_epoch,
            minimum_sequence=minimum,
        )
        identity = (verified["shard"], verified["epoch"], verified["sequence"])
        _require(identity not in seen, "duplicate capsule identity")
        _require(verified["shard"] not in seen_shards, "duplicate shard capsule")
        seen.add(identity)
        seen_shards.add(verified["shard"])
        checked.append(verified)
    masks = merge.compose([item["summary"] for item in checked])
    return [
        {
            "shard": item["shard"],
            "epoch": item["epoch"],
            "sequence": item["sequence"],
            "outputs": [
                {"name": name, "mask": mask}
                for name, mask in zip(item["output_names"], shard_masks)
            ],
        }
        for item, shard_masks in zip(checked, masks)
    ]
