"""Owned release gate for a frozen, trusted equality-only context.

The manifest is a trusted input, not inferred from submitted capsules. It pins
every member and revision. Admission replays each local ledger; sealing composes
the entire admitted set. No code/intent text is released before the selected
shard's composed masks are zero. This does not discover omitted world history,
persist freshness state, or give an untrusted caller authority to shrink context.
"""
from copy import deepcopy
import hmac

import capsule
import checker


class AdmissionError(capsule.CapsuleError):
    pass


def require(condition, message):
    if not condition:
        raise AdmissionError(message)


class Consumer:
    def __init__(self, manifest, authority_key, checker_key):
        require(type(manifest) is dict and set(manifest) == {"epoch", "members"},
                "release manifest fields")
        self._epoch = capsule._identifier(manifest["epoch"], "release epoch")
        members = manifest["members"]
        require(type(members) is list and 0 < len(members) <= 20000,
                "release member count")
        self._expected = {}
        for member in members:
            require(type(member) is dict and set(member) == {"shard", "sequence", "capsule_digest"},
                    "release member fields")
            shard = capsule._identifier(member["shard"], "release shard")
            require(shard not in self._expected, "duplicate release shard")
            sequence = member["sequence"]
            require(type(sequence) is int and 0 <= sequence < 2**63, "release sequence")
            capsule._hex_digest(member["capsule_digest"], "release capsule digest")
            self._expected[shard] = deepcopy(member)
        self._authority_key = capsule._key(authority_key, "authority key")
        self._checker_key = capsule._key(checker_key, "checker key")
        self._admitted = {}
        self._admitted_bytes = 0
        self._sealed = None

    def admit(self, policy, log, record):
        require(self._sealed is None, "release context already sealed")
        require(type(record) is dict, "release capsule object")
        shard = record.get("shard")
        require(type(shard) is str and shard in self._expected, "unexpected release member")
        require(shard not in self._admitted, "duplicate release admission")
        # Own the exact records checked; later caller mutation cannot alter them.
        policy, log, record = deepcopy((policy, log, record))
        added_bytes = sum(len(capsule.canonical_bytes(value)) for value in (policy, log, record))
        require(self._admitted_bytes + added_bytes <= 67108864, "release input byte budget")
        member = self._expected[shard]
        require(hmac.compare_digest(capsule.digest(record), member["capsule_digest"]),
                "release revision binding")
        bound = capsule.verify_bound(
            policy, log, record, self._authority_key, self._checker_key,
            expected_epoch=self._epoch, expected_shard=shard,
            minimum_sequence=member["sequence"],
        )
        require(bound["sequence"] == member["sequence"], "release exact sequence")
        # Keep the existing aggregate summary guards active across admissions.
        all_summaries = [value[2]["summary"] for value in self._admitted.values()]
        totals = all_summaries + [bound["summary"]]
        require(sum(len(sm["origin_labels"]) for sm in totals) <= 20000,
                "release output budget")
        require(sum(len(c["keys"]) for sm in totals for c in sm["components"]) <= 40000,
                "release key budget")
        require(sum(len(c["arcs"]) for sm in totals for c in sm["components"]) <= 240000,
                "release arc budget")
        require(sum(len(part.encode("utf-8")) for sm in totals for c in sm["components"]
                    for key in c["keys"] for part in key) <= 134217728,
                "release key text budget")
        self._admitted[shard] = (policy, log, record)
        self._admitted_bytes += added_bytes

    def _compose(self, records):
        return capsule.compose(
            records, self._authority_key, self._checker_key,
            expected_epoch=self._epoch,
            minimum_sequences={shard: member["sequence"]
                               for shard, member in self._expected.items()},
        )

    def seal(self):
        require(set(self._admitted) == set(self._expected), "incomplete release context")
        if self._sealed is None:
            records = [self._admitted[shard][2] for shard in self._expected]
            self._sealed = self._compose(records)
        return deepcopy(self._sealed)

    def consume(self, shard):
        """Return freshly reconstructed text only after complete composition."""
        decisions = self.seal()
        require(type(shard) is str and shard in self._expected, "unknown release target")
        decision = next(item for item in decisions if item["shard"] == shard)
        require(not any(item["mask"] for item in decision["outputs"]), "composed blocked export")
        policy, log, record = self._admitted[shard]
        exports = checker.verify(policy, log, exports=True)
        require([item["name"] for item in exports] == record["output_names"],
                "release output order")
        require(record["output_names"] == [item["name"] for item in decision["outputs"]],
                "composed output order")
        return exports

    def publish(self, shard, destination, *, _checkpoint_callback=None):
        # There is no caller-supplied verdict or context at this final boundary.
        exports = self.consume(shard)
        import emitter
        return emitter._publish(exports, destination, _checkpoint_callback)
