"""File-based publication for a complete, trusted equality-only release.

The controller supplies the manifest independently of the submitted records.
No membership is inferred, no local-only fallback is offered, and no key is
loaded or defaulted here. Freshness advancement remains a separate operation.
"""
import checker
import consumer


def admit_release(manifest, inputs, authority_key, checker_key):
    """Bind and replay every pinned member, then seal its complete context."""
    gate = consumer.Consumer(manifest, authority_key, checker_key)
    consumer.require(type(inputs) is list and len(inputs) <= 20000,
                     "release input list")
    for item in inputs:
        consumer.require(type(item) is dict and set(item) == {"policy", "ledger", "capsule"},
                         "release input fields")
        gate.admit(item["policy"], item["ledger"], item["capsule"])
    gate.seal()
    return gate


def publish_files(manifest_path, inputs_path, shard, destination,
                  authority_key, checker_key):
    """Read bounded JSON and publish the selected shard only after composition.

    The manifest file must come from the trusted release controller, not from
    an untrusted producer allowed to choose a smaller context. inputs_path is
    a JSON list of policy/ledger/capsule records. Both files use the existing
    byte/depth/atom and duplicate-key/non-finite-value rejecting reader.
    Keys are explicitly supplied bytes; this API neither retrieves credentials
    nor advances persistent sequence state. Successful return reports archive
    costs, not power-loss durability or safety of the emitted text.
    """
    manifest = checker.read_json(manifest_path)
    inputs = checker.read_json(inputs_path)
    gate = admit_release(manifest, inputs, authority_key, checker_key)
    return gate.publish(shard, destination)
