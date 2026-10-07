"""Owned finite summaries, raw-record oracle and API boundaries; no publication."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import capsule
import checker
import fixtures
import ledger
import merge

AUTHORITY = b"A" * 32  # Public test fixtures, never operational credentials.
CHECKER_KEY = b"C" * 32


def scan_canonical(text):
    """Literal line scan; deliberately calls neither replay normalizer."""
    result = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\r":
            result.append("\n")
            index += 2 if index + 1 < len(text) and text[index + 1] == "\n" else 1
        else:
            result.append(char)
            index += 1
    lines = "".join(result).split("\n")
    return "\n".join(line.rstrip(" \t") for line in lines)


def literal_oracle(policy, log):
    """Raw owned records plus all-pairs Boolean closure, not replay helpers.

    This is a finite accepted-record reference, not another hardened ingress
    validator. It reconstructs every owned transformation and bundle before
    calculating labels and a sufficient ordered quotient.
    """
    names = []
    values = []
    seeds = []
    direct = []
    roots = {}
    units = {}
    authorities = {item["id"]: item for item in policy["repairs"]}
    for root in policy["roots"]:
        roots[root["id"]] = len(names)
        names.append("r:" + root["id"])
        values.append((root["code"], root["intent"]))
        seeds.append(root["labels"])
    for unit in log["units"]:
        op = unit["op"]
        parent = roots[unit["source"]] if op == "import" else units[unit["parent"]]
        code, intent = values[parent]
        mask = 7
        if op == "normalize":
            code = scan_canonical(code)
        elif op == "extract":
            code = code[unit["start"]:unit["stop"]]
        elif op == "rewrite":
            code = code.replace(unit["old"], unit["new"])
        elif op == "repair":
            authority = authorities[unit["authority"]]
            assert (code, intent) == (authority["code"], authority["before"])
            intent = authority["after"]
            mask = 3
        else:
            assert op in ("import", "copy")
        assert (code, intent) == (unit["code"], unit["intent"])
        child = len(names)
        units[unit["id"]] = child
        names.append("u:" + unit["id"])
        values.append((code, intent))
        seeds.append(0)
        direct.append((parent, child, mask))
    canonical = [scan_canonical(code) for code, _ in values]
    collections = {}
    for bundle in log["bundles"]:
        op = bundle["op"]
        if op == "collect":
            output = [(item["name"], units[item["unit"]]) for item in bundle["items"]]
        elif op == "mix":
            output = [(str(k) + "/" + name, unit)
                      for k, parent in enumerate(bundle["parents"])
                      for name, unit in collections[parent]]
        else:
            previous = collections[bundle["parent"]]
            if op == "repack":
                output = [(bundle["prefix"] + "/" + str(k) + ".txt", unit)
                          for k, (_, unit) in enumerate(previous)]
            elif op == "filter":
                output = [previous[k] for k in bundle["indices"]]
            else:
                assert op == "dedup"
                output = []
                seen = []  # Scan-based independent pair membership.
                for name, unit in previous:
                    key = (canonical[unit], values[unit][1])
                    if key not in seen:
                        seen.append(key)
                        output.append((name, unit))
        collections[bundle["id"]] = output
    outputs = collections[log["final"]]
    exports = [{"name": name, "unit": names[unit][2:],
                "code": values[unit][0], "intent": values[unit][1]}
               for name, unit in outputs]
    assert log["outputs"] == exports
    labels = [0] * len(names)
    components = []
    edge_count = len(direct)
    for bit in (1, 2, 4):
        count = len(names)
        reachable = [[left == right for right in range(count)] for left in range(count)]
        for left, right, mask in direct:
            if mask & bit:
                reachable[left][right] = True
        if bit != 2:
            for left in range(count):
                for right in range(count):
                    equal = canonical[left] == canonical[right]
                    if bit == 4:
                        equal = equal and values[left][1] == values[right][1]
                    if equal:
                        reachable[left][right] = True
        for via in range(count):
            for left in range(count):
                for right in range(count):
                    reachable[left][right] = reachable[left][right] or (
                        reachable[left][via] and reachable[via][right])
        for right in range(count):
            if any(seeds[left] & bit and reachable[left][right] for left in range(count)):
                labels[right] |= bit
        if bit != 2:
            keys = []
            owners = []
            for index, (_, intent) in enumerate(values):
                key = [canonical[index]] if bit == 1 else [canonical[index], intent]
                if key not in keys:
                    keys.append(key)
                owners.append(keys.index(key))
            projected = sorted({(owners[left], owners[right])
                                for left, right, mask in direct
                                if mask & bit and owners[left] != owners[right]})
            components.append({"bit": bit, "keys": keys,
                               "arcs": [list(edge) for edge in projected],
                               "seeds": sorted({owners[v] for v in range(count) if seeds[v] & bit}),
                               "outputs": [owners[v] for _, v in outputs]})
            edge_count += 2 * (count - len(keys))
    claims = {name: labels[v] for name, v in units.items()}
    return {
        "result": {"status": "valid", "retained": len(outputs),
                   "blocked": sum(labels[v] != 0 for _, v in outputs),
                   "nodes": len(names), "edges": edge_count, "labels": claims},
        "summary": {"components": components,
                    "origin_labels": [labels[v] & 2 for _, v in outputs]},
        "details": {"values": dict(zip(names, values)), "initial": dict(zip(names, seeds)),
                    "direct": [(names[a], names[b], mask) for a, b, mask in direct],
                    "outputs": [names[v] for _, v in outputs]},
        "exports": exports,
    }


def owned_cases():
    for code in ("alpha\r\nbeta \t\rending \t", "λ 中\t\né e\u0301\u00a0 \t"):
        for scenario in fixtures.SCENARIOS:
            policy, log, expected = fixtures.case(code, scenario)
            oracle = literal_oracle(policy, log)
            assert bool(oracle["result"]["blocked"]) == expected
            log["claims"] = oracle["result"]["labels"]
            yield scenario + ":" + repr(code), policy, log
    empty = {"units": [], "bundles": [{"id": "empty", "op": "collect", "items": []}],
             "final": "empty", "outputs": [], "claims": {}}
    yield "wholly-empty", {"roots": [], "repairs": []}, deepcopy(empty)
    for mask in range(8):
        yield "unused:" + str(mask), {
            "roots": [{"id": "unused", "code": "owned \t\r\n", "intent": "", "labels": mask}],
            "repairs": []}, deepcopy(empty)


def context_cases():
    for scenario in ("C15", "C20", "C09", "C12"):
        for mask in range(8):
            policy, log, _ = fixtures.case("context \t\r\nλ", scenario)
            log["claims"] = literal_oracle(policy, log)["result"]["labels"]
            # The admitted root may seed a non-exported intermediate, an exact
            # after-pair, or an unused registry alias. Repeated outputs retain
            # their own order and count.
            value = log["units"][1] if scenario == "C15" else log["units"][-1]
            other_policy = {"roots": [{"id": "probe", "code": value["code"],
                                       "intent": value["intent"], "labels": mask}], "repairs": []}
            other_log = {
                "units": [{"id": "q", "op": "import", "source": "probe",
                           "code": value["code"], "intent": value["intent"]}],
                "bundles": [{"id": "out", "op": "collect",
                             "items": [{"name": "a.txt", "unit": "q"},
                                       {"name": "b.txt", "unit": "q"}]}],
                "final": "out",
                "outputs": [{"name": name, "unit": "q", "code": value["code"],
                             "intent": value["intent"]} for name in ("a.txt", "b.txt")],
                "claims": {}}
            other_log["claims"] = literal_oracle(other_policy, other_log)["result"]["labels"]
            yield scenario + ":" + str(mask), [(policy, log), (other_policy, other_log)]


def outcomes(implementation, policy, log):
    """Complete public API outcomes/errors, suitable for separate-module comparison."""
    result = {}
    for name, options in (
            ("default", {}), ("summary", {"summary": True}), ("details", {"details": True}),
            ("exports", {"exports": True}), ("unchecked", {"summary": True, "assert_claims": False}),
            ("details-first", {"summary": True, "exports": True, "details": True}),
            ("exports-first", {"summary": True, "exports": True})):
        try:
            result[name] = ("return", implementation.verify(policy, log, **options))
        except implementation.Rejected as error:
            result[name] = ("rejected", str(error))
    groups = {unit["id"]: "action" for unit in log["units"] if unit["op"] != "import"}
    result["audit"] = implementation.audit_graph(policy, log, groups)
    return result


class SummaryReuseRegression(unittest.TestCase):
    def test_complete_named_fixture_oracles(self):
        cases = list(owned_cases())
        self.assertEqual(len(cases), 49)
        for name, policy, log in cases:
            with self.subTest(case=name):
                protected = deepcopy((policy, log))
                expected = literal_oracle(policy, log)
                self.assertEqual(checker.verify(policy, log), expected["result"])
                self.assertEqual(checker.verify(policy, log, summary=True), expected["summary"])
                self.assertEqual(checker.verify(policy, log, details=True), expected["details"])
                self.assertEqual(merge.summarize(policy, log), expected["summary"])
                self.assertEqual(ledger.validate(policy, log), expected["result"])
                if expected["result"]["blocked"]:
                    with self.assertRaisesRegex(checker.Rejected, "^blocked export$"):
                        checker.verify(policy, log, exports=True)
                else:
                    self.assertEqual(checker.verify(policy, log, exports=True), expected["exports"])
                self.assertEqual((policy, log), protected)

    def test_ordered_composition_against_joined_literal_oracle(self):
        cases = list(context_cases())
        self.assertEqual(len(cases), 32)
        for name, pairs in cases:
            with self.subTest(case=name):
                protected = deepcopy(pairs)
                policy, log = merge.combine_logs(pairs)
                expected = literal_oracle(policy, log)
                log["claims"] = expected["result"]["labels"]
                summaries = [checker.verify(p, l, summary=True) for p, l in pairs]
                masks = merge.compose(summaries)
                flat = [mask for shard in masks for mask in shard]
                self.assertEqual(flat, [expected["result"]["labels"][item["unit"]]
                                        for item in log["outputs"]])
                self.assertEqual(checker.verify(policy, log), expected["result"])
                self.assertEqual(checker.verify(policy, log, summary=True), expected["summary"])
                self.assertEqual(pairs, protected)

    def test_capsule_records_and_role_boundaries(self):
        for name, policy, log in owned_cases():
            with self.subTest(case=name):
                with patch.object(capsule.checker, "verify", wraps=checker.verify) as replay:
                    issued = capsule.issue(policy, log, AUTHORITY, CHECKER_KEY,
                                           shard="local", epoch="epoch", sequence=3)
                    self.assertEqual(replay.call_count, 1)
                    self.assertEqual(issued["summary"], literal_oracle(policy, log)["summary"])
                    verified = capsule.verify(issued, AUTHORITY, CHECKER_KEY,
                                              expected_epoch="epoch", minimum_sequence=3,
                                              expected_shard="local")
                    self.assertEqual(replay.call_count, 1)
                    bound = capsule.verify_bound(policy, log, issued, AUTHORITY, CHECKER_KEY)
                    self.assertEqual(replay.call_count, 2)
                    self.assertEqual(verified, bound)
                with self.assertRaisesRegex(capsule.CapsuleError, "^stale sequence$"):
                    capsule.verify(issued, AUTHORITY, CHECKER_KEY, minimum_sequence=4)
                wrong = deepcopy(issued)
                wrong["summary"]["origin_labels"].append(0)
                with self.assertRaises(capsule.CapsuleError):
                    capsule.verify(wrong, AUTHORITY, CHECKER_KEY)
        for _, pairs in context_cases():
            capsules = [capsule.issue(p, l, AUTHORITY, CHECKER_KEY, shard="s" + str(k),
                                      epoch="epoch", sequence=0) for k, (p, l) in enumerate(pairs)]
            with patch.object(capsule.checker, "verify", wraps=checker.verify) as replay:
                composed = capsule.compose(capsules, AUTHORITY, CHECKER_KEY, expected_epoch="epoch")
                self.assertEqual(replay.call_count, 0)
            policy, log = merge.combine_logs(pairs)
            expected = literal_oracle(policy, log)["result"]["labels"]
            self.assertEqual([item["mask"] for shard in composed for item in shard["outputs"]],
                             [expected[item["unit"]] for item in log["outputs"]])
            with self.assertRaisesRegex(capsule.CapsuleError, "^duplicate capsule identity$"):
                capsule.compose([capsules[0], capsules[0]], AUTHORITY, CHECKER_KEY)

    def test_no_extra_normalization_passes_or_cross_call_cache(self):
        for _, policy, log in owned_cases():
            with patch.object(checker, "norm", wraps=checker.norm) as calls:
                checker.verify(policy, log)
                ordinary = calls.call_count
            with patch.object(checker, "norm", wraps=checker.norm) as calls:
                checker.verify(policy, log, summary=True)
                self.assertEqual(calls.call_count, ordinary)
        policy, log, _ = fixtures.case("changing", "C11")
        log["claims"] = literal_oracle(policy, log)["result"]["labels"]
        first = checker.verify(policy, log, summary=True)
        policy["roots"].append({"id": "later", "code": "unused changed", "intent": "", "labels": 4})
        second = checker.verify(policy, log, summary=True)
        self.assertNotEqual(first, second)
        self.assertEqual(second, literal_oracle(policy, log)["summary"])

    def test_option_precedence_and_owned_rejections(self):
        for _, policy, log in owned_cases():
            expected = literal_oracle(policy, log)
            self.assertEqual(checker.verify(policy, log, summary=True, exports=True, details=True),
                             expected["details"])
            if expected["result"]["blocked"]:
                with self.assertRaisesRegex(checker.Rejected, "^blocked export$"):
                    checker.verify(policy, log, summary=True, exports=True)
            else:
                self.assertEqual(checker.verify(policy, log, summary=True, exports=True),
                                 expected["exports"])
        policy, log, _ = fixtures.case("boundary", "C05")
        log["claims"] = literal_oracle(policy, log)["result"]["labels"]
        for label, mutate, error in (
                ("boolean-index", lambda p, l: l["units"][-1].update(start=True), "bounded integer"),
                ("boolean-label", lambda p, l: p["roots"][0].update(labels=True), "bounded integer"),
                ("false-claim", lambda p, l: l["claims"].update(initial=0), "incorrect label claim"),
                ("output-order", lambda p, l: l["outputs"].clear(), "export mismatch"),
                ("schema", lambda p, l: p.update(extra=0), "record fields"),
                ("text-cap", lambda p, l: p["roots"][0].update(code="x" * 262145), "bounded text"),
                ("node-cap", lambda p, l: p.update(roots=p["roots"] * 20001), "node bound")):
            p, l = deepcopy((policy, log))
            mutate(p, l)
            with self.subTest(case=label):
                for options in ({}, {"summary": True}, {"details": True}, {"exports": True}):
                    with self.assertRaisesRegex(checker.Rejected, "^" + error + "$"):
                        checker.verify(p, l, **options)

    def test_literal_canonicalizer_boundaries(self):
        texts = ("", " \t", "\r\n\r", "λ 中\r\né e\u0301\u00a0 \t", "quote='a \t'\r\n")
        for text in texts:
            self.assertEqual(checker.norm(text), scan_canonical(text))
            self.assertEqual(ledger.canonical(text), scan_canonical(text))


if __name__ == "__main__":
    unittest.main()
