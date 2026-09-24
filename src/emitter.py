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
    dirfd = os.open(parent, _directory_flags())
    temp_name = "." + basename[:120] + ".containment-" + secrets.token_hex(12) + ".tmp"
    temp_created = linked = False
    try:
        fd = os.open(temp_name, _file_flags(), 0o600, dir_fd=dirfd)
        temp_created = True
        _checkpoint(checkpoint, "temp-created")
        with os.fdopen(fd, "w+b", closefd=True) as stream:
            with zipfile.ZipFile(stream, "w") as archive:
                for item in exports:
                    for prefix, field in (("code/", "code"), ("intent/", "intent")):
                        info = zipfile.ZipInfo(prefix + item["name"], date_time=(2000, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = 0o100644 << 16
                        archive.writestr(info, item[field].encode("utf-8"))
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            _checkpoint(checkpoint, "zip-closed")
            os.fsync(stream.fileno())
            _checkpoint(checkpoint, "file-synced")
        # link(2) is an atomic create-if-absent commit in the already-opened directory.
        os.link(
            temp_name,
            basename,
            src_dir_fd=dirfd,
            dst_dir_fd=dirfd,
            follow_symlinks=False,
        )
        linked = True
        _checkpoint(checkpoint, "linked")
        os.fsync(dirfd)
        _checkpoint(checkpoint, "directory-synced")
        os.unlink(temp_name, dir_fd=dirfd)
        temp_created = False
        os.fsync(dirfd)
        _checkpoint(checkpoint, "temporary-removed")
        stat = os.stat(basename, dir_fd=dirfd, follow_symlinks=False)
        return {"units": len(exports), "members": 2 * len(exports), "bytes": stat.st_size}
    except BaseException:
        # A linked destination is already a complete, fsynced archive.  Never
        # remove it after commit merely because later cleanup/reporting failed.
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=dirfd)
            except OSError:
                pass
        raise
    finally:
        os.close(dirfd)


def emit(policy, log, destination, *, _checkpoint_callback=None):
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
    _checkpoint_callback=None,
):
    # Imported lazily so the plain emitter remains a small standalone checker path.
    import capsule

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
    return emit(policy, log, destination, _checkpoint_callback=_checkpoint_callback)


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
