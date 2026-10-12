"""Reconstruct and atomically publish a clean ZIP; never execute corpus code.

Validation finishes before any destination entry is created.  Publication uses a
same-directory temporary file, fsync, and an atomic hard-link create, so process
failure before commit leaves no destination and concurrent writers cannot
replace an existing destination.  This is not a proof of power-loss durability
on every file system; directory trust and storage semantics remain assumptions.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import zipfile

import checker


class PublishError(OSError):
    pass


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _file_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _checkpoint(callback, stage: str) -> None:
    if callback is not None:
        callback(stage)


def _publish(exports: list[dict], destination: Path, checkpoint=None) -> dict:
    destination = Path(destination)
    basename = destination.name
    if not basename or basename in (".", "..") or "/" in basename or "\\" in basename:
        raise PublishError("invalid destination basename")
    parent = destination.parent if str(destination.parent) else Path(".")
    # POSIX retains its opened-directory/no-follow protocol. Windows supports
    # only an owned, stable directory: pathname/reparse races are not covered.
    windows = os.name == "nt"
    if windows:
        parent = parent.resolve(strict=True)
        original_info = destination.parent.lstat()
        if getattr(original_info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PublishError("reparse publication parent")
        if not parent.is_dir():
            raise PublishError("publication parent is not a directory")
        dirfd = None
    else:
        dirfd = os.open(parent, _directory_flags())
    relative = {} if windows else {"dir_fd": dirfd}
    temp_name = "." + basename[:120] + ".containment-" + secrets.token_hex(12) + ".tmp"
    if windows:
        temp_name = str(parent / temp_name)
        basename = str(parent / basename)
    temp_created = linked = False
    try:
        fd = os.open(temp_name, _file_flags() | getattr(os, "O_BINARY", 0), 0o600, **relative)
        temp_created = True
        with os.fdopen(fd, "w+b", closefd=True) as stream:
            _checkpoint(checkpoint, "temp-created")
            with zipfile.ZipFile(stream, "w") as archive:
                for item in exports:
                    for prefix, field in (("code/", "code"), ("intent/", "intent")):
                        info = zipfile.ZipInfo(prefix + item["name"], date_time=(2000, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = 0o100644 << 16
                        archive.writestr(info, item[field].encode("utf-8"))
            stream.flush()
            if not windows:
                os.fchmod(stream.fileno(), 0o644)
            _checkpoint(checkpoint, "zip-closed")
            os.fsync(stream.fileno())
            _checkpoint(checkpoint, "file-synced")
        # link(2) is an atomic create-if-absent commit in the already-opened directory.
        link_options = {} if windows else {"src_dir_fd": dirfd, "dst_dir_fd": dirfd}
        os.link(
            temp_name,
            basename,
            follow_symlinks=False,
            **link_options,
        )
        linked = True
        _checkpoint(checkpoint, "linked")
        if not windows:
            os.fsync(dirfd)
        _checkpoint(checkpoint, "directory-synced")
        os.unlink(temp_name, **relative)
        temp_created = False
        if not windows:
            os.fsync(dirfd)
        _checkpoint(checkpoint, "temporary-removed")
        info = os.stat(basename, follow_symlinks=False, **relative)
        return {"units": len(exports), "members": 2 * len(exports), "bytes": info.st_size}
    except BaseException:
        # A linked destination is already a complete, fsynced archive.  Never
        # remove it after commit merely because later cleanup/reporting failed.
        if temp_created:
            try:
                os.unlink(temp_name, **relative)
            except OSError:
                pass
        raise
    finally:
        if dirfd is not None:
            os.close(dirfd)


def emit(policy, log, destination, *, _checkpoint_callback=None):
    """Local sealed-snapshot primitive, not an equality-composed release gate."""
    exports = checker.verify(policy, log, exports=True)
    return _publish(exports, Path(destination), _checkpoint_callback)


def emit_authenticated(
    policy,
    log,
    capsule_record,
    authority_key,
    checker_key,
    destination,
    *,
    expected_epoch=None,
    minimum_sequence=None,
    expected_shard=None,
    release_manifest=None,
    composition_inputs=None,
    _checkpoint_callback=None,
):
    # Authenticated publication requires complete owned admission. Local replay
    # alone is insufficient when a release context includes other shards.
    import capsule
    import consumer

    consumer.require(release_manifest is not None and type(composition_inputs) is list,
                     "complete release admission required")
    gate = consumer.Consumer(release_manifest, authority_key, checker_key)

    capsule.verify_bound(
        policy,
        log,
        capsule_record,
        authority_key,
        checker_key,
        expected_epoch=expected_epoch,
        minimum_sequence=minimum_sequence,
        expected_shard=expected_shard,
    )
    consumer.require(capsule_record["epoch"] == release_manifest["epoch"], "release epoch binding")
    for item in composition_inputs:
        consumer.require(type(item) is dict and set(item) == {"policy", "ledger", "capsule"},
                         "release input fields")
        gate.admit(item["policy"], item["ledger"], item["capsule"])
    shard = capsule_record["shard"]
    gate.seal()
    consumer.require(shard in gate._admitted and
                     gate._admitted[shard][2] == capsule_record, "release target binding")
    return gate.publish(shard, destination, _checkpoint_callback=_checkpoint_callback)


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("policy")
    ap.add_argument("ledger")
    ap.add_argument("destination")
    args = ap.parse_args()
    try:
        print(
            json.dumps(
                emit(
                    checker.read_json(args.policy),
                    checker.read_json(args.ledger),
                    args.destination,
                ),
                sort_keys=True,
            )
        )
    except (checker.Rejected, OSError) as exc:
        ap.exit(2, str(exc) + "\n")
