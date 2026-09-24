"""Authenticated, process-persistent freshness state for capsule verification.

The store provides fail-closed local replay rejection across process restarts,
serialized updates, explicit epoch transitions, and atomic whole-file updates on
the evaluated POSIX profile.  It does not resist rollback of the entire state
file by a privileged adversary, provide distributed consensus, or establish
power-loss durability.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Callable

import capsule

CONTRACT = "containment-ledger/local-freshness/hmac-sha256/v1"
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_SHARDS = 20000
Checkpoint = Callable[[str], None]


class FreshnessError(capsule.CapsuleError):
    """The local freshness state or transition is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FreshnessError(message)


def _state_key(value: object) -> bytes:
    _require(type(value) is bytes and 32 <= len(value) <= 4096, "freshness state key")
    return value


def _identifier(value: object, where: str) -> str:
    _require(
        type(value) is str
        and 1 <= len(value) <= 160
        and all(ch.isalnum() or ch in "._-" for ch in value),
        where,
    )
    return value


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FreshnessError("freshness state encoding") from exc
    _require(len(raw) <= MAX_STATE_BYTES, "freshness state byte budget")
    return raw


def _tag(key: bytes, body: dict) -> str:
    return hmac.new(key, b"containment-freshness\x00" + _canonical(body), hashlib.sha256).hexdigest()


def _validate_body(body: object) -> dict:
    _require(
        type(body) is dict
        and set(body) == {"contract", "epoch", "generation", "accepted_sequences"},
        "freshness body fields",
    )
    _require(body["contract"] == CONTRACT, "freshness contract")
    epoch = _identifier(body["epoch"], "freshness epoch")
    generation = body["generation"]
    _require(type(generation) is int and 0 <= generation < 2**63, "freshness generation")
    sequences = body["accepted_sequences"]
    _require(type(sequences) is dict and len(sequences) <= MAX_SHARDS, "freshness sequences")
    checked = {}
    for shard, sequence in sequences.items():
        shard = _identifier(shard, "freshness shard")
        _require(type(sequence) is int and 0 <= sequence < 2**63, "freshness sequence")
        checked[shard] = sequence
    _require(list(sequences) == sorted(sequences), "freshness shard order")
    return {
        "contract": CONTRACT,
        "epoch": epoch,
        "generation": generation,
        "accepted_sequences": checked,
    }


def encode_state(body: dict, state_key: bytes) -> bytes:
    key = _state_key(state_key)
    checked = _validate_body(body)
    record = {"body": checked, "tag": _tag(key, checked)}
    return _canonical(record) + b"\n"


def decode_state(raw: bytes, state_key: bytes) -> dict:
    key = _state_key(state_key)
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES, "freshness state size")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise FreshnessError("freshness state JSON") from exc
    _require(type(record) is dict and set(record) == {"body", "tag"}, "freshness record fields")
    body = _validate_body(record["body"])
    tag = record["tag"]
    _require(
        type(tag) is str
        and len(tag) == 64
        and all(ch in "0123456789abcdef" for ch in tag),
        "freshness tag",
    )
    _require(hmac.compare_digest(tag, _tag(key, body)), "freshness authentication")
    return body


def _open_parent(path: Path) -> tuple[int, str]:
    path = Path(path)
    _require(path.name not in ("", ".", ".."), "freshness filename")
    _require(path.parent != path, "freshness parent")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(path.parent, flags)
    except OSError as exc:
        raise FreshnessError("freshness parent open") from exc
    return directory_fd, path.name


def _read_at(directory_fd: int, name: str, state_key: bytes, *, missing_ok: bool) -> dict | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise FreshnessError("freshness state missing")
    except OSError as exc:
        raise FreshnessError("freshness state open") from exc
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode), "freshness state regular file")
        chunks = []
        remaining = MAX_STATE_BYTES + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        _require(len(raw) <= MAX_STATE_BYTES, "freshness state byte budget")
        return decode_state(raw, state_key)
    finally:
        os.close(fd)


def read_state(path: str | os.PathLike[str], state_key: bytes) -> dict:
    directory_fd, name = _open_parent(Path(path))
    try:
        state = _read_at(directory_fd, name, state_key, missing_ok=False)
        assert state is not None
        return state
    finally:
        os.close(directory_fd)


def _write_atomic(
    directory_fd: int,
    name: str,
    raw: bytes,
    checkpoint: Checkpoint | None,
) -> None:
    temp_name = f".{name}.freshness-{os.getpid()}-{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
    try:
        if checkpoint:
            checkpoint("temp-created")
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
        if checkpoint:
            checkpoint("file-synced")
    finally:
        os.close(fd)
    try:
        os.replace(temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        if checkpoint:
            checkpoint("replaced")
        os.fsync(directory_fd)
        if checkpoint:
            checkpoint("directory-synced")
    except BaseException:
        # Before replace, this removes the private incomplete candidate. After
        # replace, temp_name no longer exists and the complete state remains.
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _select_keys(
    untrusted_capsule: object,
    authority_keys: dict[str, bytes],
    checker_keys: dict[str, bytes],
) -> tuple[str, bytes, bytes]:
    _require(type(untrusted_capsule) is dict, "capsule object for key selection")
    epoch = _identifier(untrusted_capsule.get("epoch"), "capsule epoch for key selection")
    _require(type(authority_keys) is dict and type(checker_keys) is dict, "freshness keyrings")
    _require(epoch in authority_keys and epoch in checker_keys, "untrusted or retired epoch key")
    return epoch, capsule._key(authority_keys[epoch], "authority key"), capsule._key(
        checker_keys[epoch], "checker key"
    )


def verify_with_keyring(
    untrusted_capsule: object,
    authority_keys: dict[str, bytes],
    checker_keys: dict[str, bytes],
    **expectations: object,
) -> dict:
    """Select epoch-scoped keys, then perform ordinary capsule verification."""
    epoch, authority_key, checker_key = _select_keys(untrusted_capsule, authority_keys, checker_keys)
    supplied_epoch = expectations.pop("expected_epoch", epoch)
    _require(supplied_epoch == epoch, "keyring epoch expectation")
    return capsule.verify(
        untrusted_capsule,
        authority_key,
        checker_key,
        expected_epoch=epoch,
        **expectations,
    )


def accept_bound(
    path: str | os.PathLike[str],
    state_key: bytes,
    policy: dict,
    ledger_record: dict,
    untrusted_capsule: object,
    authority_keys: dict[str, bytes],
    checker_keys: dict[str, bytes],
    *,
    allowed_epoch_transition: tuple[str, str] | None = None,
    checkpoint: Checkpoint | None = None,
) -> dict:
    """Verify a bound capsule and durably advance local replay state.

    State advances before a caller publishes an output. A later publication
    failure can therefore consume a sequence number (fail closed) but cannot
    permit replay of an already accepted capsule.
    """
    state_key = _state_key(state_key)
    epoch, authority_key, checker_key = _select_keys(
        untrusted_capsule, authority_keys, checker_keys
    )
    directory_fd, name = _open_parent(Path(path))
    lock_name = "." + name + ".lock"
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        os.close(directory_fd)
        raise FreshnessError("freshness lock open") from exc
    try:
        info = os.fstat(lock_fd)
        _require(stat.S_ISREG(info.st_mode), "freshness lock regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        prior = _read_at(directory_fd, name, state_key, missing_ok=True)
        if prior is None:
            generation = 0
            accepted = {}
        elif prior["epoch"] == epoch:
            generation = prior["generation"] + 1
            accepted = dict(prior["accepted_sequences"])
        else:
            _require(
                allowed_epoch_transition == (prior["epoch"], epoch),
                "unauthorized freshness epoch transition",
            )
            generation = prior["generation"] + 1
            accepted = {}

        shard = _identifier(
            untrusted_capsule.get("shard") if type(untrusted_capsule) is dict else None,
            "freshness capsule shard",
        )
        previous = accepted.get(shard, -1)
        verified = capsule.verify_bound(
            policy,
            ledger_record,
            untrusted_capsule,
            authority_key,
            checker_key,
            expected_epoch=epoch,
            minimum_sequence=previous + 1,
            expected_shard=shard,
        )
        sequence = verified["sequence"]
        _require(sequence > previous, "freshness replay")
        accepted[shard] = sequence
        body = {
            "contract": CONTRACT,
            "epoch": epoch,
            "generation": generation,
            "accepted_sequences": {key: accepted[key] for key in sorted(accepted)},
        }
        _write_atomic(directory_fd, name, encode_state(body, state_key), checkpoint)
        return {"verified": verified, "state": body, "previous_sequence": previous}
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
        os.close(directory_fd)
