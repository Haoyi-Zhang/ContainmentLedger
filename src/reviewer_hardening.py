#!/usr/bin/env python3
"""Reviewer-facing robustness experiments for the containment-ledger artifact.

This module is intentionally standard-library only.  It adds three forms of
*bounded* evidence without changing the production contract:

1. an independently structured quotient-graph oracle and exhaustive small-model
   comparison against iterative closure;
2. a mutation campaign and metamorphic properties that measure whether the
   finite suite rejects plausible implementation mistakes; and
3. a transform-family bridge that calls the vendored upstream BigCode exact
   substring predicate while varying the textual rewrite used to evade an
   endpoint-only scan.

The output is evidence about the frozen model and retained inputs.  It is not a
proof about arbitrary implementations, a prevalence estimate, or a production
performance claim.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import statistics
import sys
import time
from typing import Callable, Iterable, Iterator, Mapping, Sequence

import builder_adapter
import checker
import ledger

SCHEMA = "pcl-reviewer-hardening/v1"
SEED = 20260920


def _partitions(n: int) -> Iterator[tuple[tuple[int, ...], ...]]:
    """Yield canonical set partitions of range(n)."""
    blocks: list[list[int]] = []

    def rec(i: int) -> Iterator[tuple[tuple[int, ...], ...]]:
        if i == n:
            yield tuple(tuple(b) for b in blocks)
            return
        for b in blocks:
            b.append(i)
            yield from rec(i + 1)
            b.pop()
        blocks.append([i])
        yield from rec(i + 1)
        blocks.pop()

    yield from rec(0)


def iterative_closure(
    n: int,
    edges: Sequence[tuple[int, int]],
    partition: Sequence[Sequence[int]],
    roots: Iterable[int],
) -> frozenset[int]:
    """Least fixed point using explicit rule iteration."""
    tainted = set(roots)
    changed = True
    while changed:
        changed = False
        for block in partition:
            if tainted.intersection(block):
                before = len(tainted)
                tainted.update(block)
                changed |= len(tainted) != before
        for source, target in edges:
            if source in tainted and target not in tainted:
                tainted.add(target)
                changed = True
    if any(x < 0 or x >= n for x in tainted):
        raise AssertionError("closure escaped node universe")
    return frozenset(tainted)


def quotient_oracle(
    n: int,
    edges: Sequence[tuple[int, int]],
    partition: Sequence[Sequence[int]],
    roots: Iterable[int],
) -> frozenset[int]:
    """Independent oracle: quotient equality classes, then graph reachability."""
    cls_of = [-1] * n
    blocks = [tuple(block) for block in partition]
    for class_id, block in enumerate(blocks):
        for node in block:
            if cls_of[node] != -1:
                raise ValueError("partition overlap")
            cls_of[node] = class_id
    if any(x == -1 for x in cls_of):
        raise ValueError("partition does not cover universe")
    adjacency = [set() for _ in blocks]
    for source, target in edges:
        adjacency[cls_of[source]].add(cls_of[target])
    reached = {cls_of[r] for r in roots}
    stack = list(reached)
    while stack:
        source = stack.pop()
        for target in adjacency[source]:
            if target not in reached:
                reached.add(target)
                stack.append(target)
    return frozenset(
        node for class_id in reached for node in blocks[class_id]
    )


def _dag_edges(n: int, mask: int) -> tuple[tuple[int, int], ...]:
    candidates = [(i, j) for i in range(n) for j in range(i + 1, n)]
    return tuple(edge for bit, edge in enumerate(candidates) if mask & (1 << bit))


def _renamed(
    n: int,
    edges: Sequence[tuple[int, int]],
    partition: Sequence[Sequence[int]],
    roots: Iterable[int],
    permutation: Sequence[int],
) -> tuple[tuple[tuple[int, int], ...], tuple[tuple[int, ...], ...], tuple[int, ...]]:
    return (
        tuple((permutation[a], permutation[b]) for a, b in edges),
        tuple(tuple(permutation[x] for x in block) for block in partition),
        tuple(permutation[x] for x in roots),
    )


def exact_small_model() -> dict[str, object]:
    n = 4
    partitions = tuple(_partitions(n))
    edge_masks = 1 << (n * (n - 1) // 2)
    cases = 0
    disagreements = 0
    monotonicity_checks = 0
    renaming_checks = 0
    decomposition_checks = 0
    rng = random.Random(SEED)

    for edge_mask in range(edge_masks):
        edges = _dag_edges(n, edge_mask)
        for partition in partitions:
            for roots_mask in range(1, 1 << n):
                roots = tuple(i for i in range(n) if roots_mask & (1 << i))
                left = iterative_closure(n, edges, partition, roots)
                right = quotient_oracle(n, edges, partition, roots)
                cases += 1
                if left != right:
                    disagreements += 1

                # Adding one root or one directed fact may not remove taint.
                for node in range(n):
                    extended = iterative_closure(n, edges, partition, (*roots, node))
                    if not left.issubset(extended):
                        raise AssertionError("root monotonicity violated")
                    monotonicity_checks += 1

                # A deterministic permutation checks alpha-renaming invariance.
                permutation = list(range(n))
                rng.shuffle(permutation)
                e2, p2, r2 = _renamed(n, edges, partition, roots, permutation)
                renamed = iterative_closure(n, e2, p2, r2)
                expected = frozenset(permutation[x] for x in left)
                if renamed != expected:
                    raise AssertionError("renaming invariance violated")
                renaming_checks += 1

                # Disjoint-union decomposition with a two-node clean component.
                p3 = tuple(tuple(block) for block in partition) + ((n,), (n + 1,))
                e3 = tuple(edges) + ((n, n + 1),)
                combined = iterative_closure(n + 2, e3, p3, roots)
                if combined.intersection({n, n + 1}):
                    raise AssertionError("disjoint component became tainted")
                if combined.intersection(range(n)) != left:
                    raise AssertionError("disjoint-union projection changed")
                decomposition_checks += 1

    return {
        "nodes": n,
        "partitions": len(partitions),
        "edge_masks": edge_masks,
        "root_masks": (1 << n) - 1,
        "cases": cases,
        "oracle_disagreements": disagreements,
        "root_monotonicity_checks": monotonicity_checks,
        "renaming_checks": renaming_checks,
        "decomposition_checks": decomposition_checks,
    }


def _directed_only(n: int, edges: Sequence[tuple[int, int]], roots: Iterable[int]) -> frozenset[int]:
    reached = set(roots)
    changed = True
    while changed:
        changed = False
        for a, b in edges:
            if a in reached and b not in reached:
                reached.add(b)
                changed = True
    return frozenset(reached)


def _mutant_no_alias(n: int, e, p, r):
    return _directed_only(n, e, r)


def _mutant_reverse_edges(n: int, e, p, r):
    return iterative_closure(n, tuple((b, a) for a, b in e), p, r)


def _mutant_single_pass(n: int, e, p, r):
    reached = set(r)
    for block in p:
        if reached.intersection(block):
            reached.update(block)
    for a, b in reversed(tuple(e)):
        if a in reached:
            reached.add(b)
    return frozenset(reached)


def _mutant_root_alias_only(n: int, e, p, r):
    reached = set(r)
    for block in p:
        if reached.intersection(block):
            reached.update(block)
    return _directed_only(n, e, reached)


def _mutant_undirected_edges(n: int, e, p, r):
    return iterative_closure(n, tuple(e) + tuple((b, a) for a, b in e), p, r)


def _mutant_drop_intermediate(n: int, e, p, r):
    roots = set(r)
    direct = {b for a, b in e if a in roots}
    return iterative_closure(n, (), p, roots | direct)


def _mutant_half_graph(n: int, e, p, r):
    midpoint = n // 2
    kept = tuple((a, b) for a, b in e if (a < midpoint) == (b < midpoint))
    return iterative_closure(n, kept, p, r)


def _mutant_ignore_late_alias(n: int, e, p, r):
    singleton = tuple((i,) for i in range(n))
    return iterative_closure(n, e, singleton, r)


def _mutant_all_alias(n: int, e, p, r):
    return iterative_closure(n, e, (tuple(range(n)),), r)


def _mutant_ignore_second_root(n: int, e, p, r):
    roots = tuple(r)
    return iterative_closure(n, e, p, roots[:1])


def _mutant_edge_intersection(n: int, e, p, r):
    # Models a composition bug that retains only duplicated facts.
    counts: dict[tuple[int, int], int] = {}
    for edge in e:
        counts[edge] = counts.get(edge, 0) + 1
    kept = tuple(edge for edge, count in counts.items() if count > 1)
    return iterative_closure(n, kept, p, r)


def _mutant_authorized_repair_by_deletion(n: int, e, p, r):
    # Unsoundly treats the highest numbered tainted node as a repair cut.
    correct = set(iterative_closure(n, e, p, r))
    if correct:
        correct.remove(max(correct))
    return frozenset(correct)


MUTANTS: Mapping[str, Callable[..., frozenset[int]]] = {
    "drop_alias_relation": _mutant_no_alias,
    "reverse_transform_edges": _mutant_reverse_edges,
    "single_pass_instead_of_fixed_point": _mutant_single_pass,
    "expand_aliases_only_at_roots": _mutant_root_alias_only,
    "treat_transform_edges_as_undirected": _mutant_undirected_edges,
    "drop_non_endpoint_intermediates": _mutant_drop_intermediate,
    "drop_cross_partition_edges": _mutant_half_graph,
    "cache_before_late_alias": _mutant_ignore_late_alias,
    "collapse_all_identities": _mutant_all_alias,
    "keep_only_first_composed_root": _mutant_ignore_second_root,
    "intersect_instead_of_union_edges": _mutant_edge_intersection,
    "diagnosis_as_implicit_repair": _mutant_authorized_repair_by_deletion,
}


def mutation_campaign() -> dict[str, object]:
    rng = random.Random(SEED ^ 0x5A17)
    witnesses: list[tuple[int, tuple[tuple[int, int], ...], tuple[tuple[int, ...], ...], tuple[int, ...]]] = []

    # Structured witnesses cover long chains, late aliases, cross halves, and
    # multiple roots.  Random witnesses prevent a hand-picked-only suite.
    witnesses.extend([
        (4, ((0, 1), (1, 2), (2, 3)), ((0,), (1,), (2,), (3,)), (0,)),
        (4, ((0, 1), (2, 3)), ((0,), (1, 2), (3,)), (0,)),
        (4, ((0, 2), (2, 3)), ((0, 1), (2,), (3,)), (1,)),
        (4, ((0, 1), (1, 3)), ((0,), (1, 2), (3,)), (0, 2)),
        (4, ((0, 3),), ((0,), (1,), (2,), (3,)), (0, 2)),
        # Duplicate one edge so edge-intersection mutant sometimes retains one
        # and can be distinguished from the empty-graph special case.
        (4, ((0, 1), (0, 1), (1, 2)), ((0,), (1,), (2,), (3,)), (0,)),
    ])
    partitions = list(_partitions(5))
    candidates = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    for _ in range(2000):
        edges = tuple(edge for edge in candidates if rng.random() < 0.28)
        rng.shuffle(candidates)
        roots = tuple(i for i in range(5) if rng.random() < 0.25) or (rng.randrange(5),)
        witnesses.append((5, edges, rng.choice(partitions), roots))

    mutant_results: dict[str, dict[str, object]] = {}
    for name, mutant in MUTANTS.items():
        killed = 0
        first_witness = None
        for index, (n, edges, partition, roots) in enumerate(witnesses):
            expected = iterative_closure(n, edges, partition, roots)
            observed = mutant(n, edges, partition, roots)
            if observed != expected:
                killed += 1
                if first_witness is None:
                    first_witness = {
                        "index": index,
                        "n": n,
                        "edges": [list(x) for x in edges],
                        "partition": [list(x) for x in partition],
                        "roots": list(roots),
                        "expected": sorted(expected),
                        "observed": sorted(observed),
                    }
        if killed == 0:
            raise AssertionError(f"surviving mutant: {name}")
        mutant_results[name] = {
            "killed_cases": killed,
            "first_witness": first_witness,
        }
    return {
        "witness_cases": len(witnesses),
        "mutants": mutant_results,
        "mutants_total": len(mutant_results),
        "mutants_killed": sum(1 for item in mutant_results.values() if item["killed_cases"]),
    }


def _extract_find_substrings(artifact_root: Path) -> tuple[Callable[..., object], Path, str]:
    """Reuse the fixed-path module loader, including the upstream helper.

    Only the retained dependency-free excerpt is imported. No source search,
    isolated function compilation, or corpus-code execution is permitted.
    """
    expected = artifact_root.resolve() / "upstream" / "bigcode-dataset" / "find_substrings_excerpt.py"
    module = builder_adapter.load_upstream()
    actual = Path(module.__file__).resolve()
    if actual != expected or not callable(getattr(module, "benchmark_name_to_filter_reason", None)):
        raise RuntimeError("unexpected or incomplete retained upstream module")
    return module.find_substrings, actual, hashlib.sha256(actual.read_bytes()).hexdigest()


def _scanner_includes(result: object) -> bool:
    if isinstance(result, tuple):
        return bool(result[0])
    return bool(result)


def _candidate_lines(artifact_root: Path) -> list[tuple[str, str]]:
    """Read only the exact selected public text files, never implementation code."""
    selection = json.loads((artifact_root / "data" / "selection.json").read_text(encoding="utf-8"))
    rows: list[tuple[str, str]] = []
    public_root = artifact_root / "data" / "public"
    for record in sorted(selection["files"], key=lambda item: item["file"]):
        relative = Path(record["file"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe selected source path")
        path = public_root / relative
        text = path.read_bytes().decode("utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if 18 <= len(stripped) <= 120 and re.search(r"[A-Za-z_][A-Za-z0-9_]{4,}", stripped):
                if not stripped.startswith(("//", "#", "/*", "*", "=cut")):
                    rows.append((f"{path.relative_to(artifact_root)}:{line_no}", stripped))
    seen: set[str] = set()
    unique = []
    for origin, line in rows:
        if line not in seen:
            seen.add(line)
            unique.append((origin, line))
    return unique


def _space_double(s: str) -> str | None:
    match = re.search(r"(?<=\S) (?=\S)", s)
    return s[: match.start()] + "  " + s[match.end() :] if match else None


def _line_split(s: str) -> str | None:
    match = re.search(r"(?<=\S) (?=\S)", s)
    return s[: match.start()] + "\n    " + s[match.end() :] if match else None


def _identifier_underscore(s: str) -> str | None:
    match = max(re.finditer(r"[A-Za-z_][A-Za-z0-9_]{5,}", s), key=lambda m: len(m.group()), default=None)
    if match is None:
        return None
    token = match.group()
    cut = max(1, len(token) // 2)
    replacement = token[:cut] + "_" + token[cut:]
    if replacement == token:
        return None
    return s[: match.start()] + replacement + s[match.end() :]


def _punctuation_spacing(s: str) -> str | None:
    for token, replacement in (("(", "( "), (",", " ,"), ("=", " = "), (":", " :")):
        if token in s:
            out = s.replace(token, replacement, 1)
            if out != s:
                return out
    return None


def _comment_insertion(s: str) -> str | None:
    match = re.search(r"[A-Za-z_][A-Za-z0-9_]{3,}", s)
    if match is None:
        return None
    return s[: match.end()] + "/*lineage*/" + s[match.end() :]


TRANSFORMS: Mapping[str, Callable[[str], str | None]] = {
    "whitespace_expansion": _space_double,
    "line_reflow": _line_split,
    "identifier_substitution": _identifier_underscore,
    "punctuation_spacing": _punctuation_spacing,
    "comment_insertion": _comment_insertion,
}


def transform_bridge(artifact_root: Path) -> dict[str, object]:
    scanner, scanner_path, scanner_digest = _extract_find_substrings(artifact_root)
    candidates = _candidate_lines(artifact_root)
    if len(candidates) < 12:
        raise AssertionError(f"too few retained-source candidates: {len(candidates)}")

    cases: list[dict[str, object]] = []
    per_family: dict[str, int] = {name: 0 for name in TRANSFORMS}
    original_rejections = 0
    endpoint_passes = 0
    lineage_blocks = 0
    clean_control_passes = 0

    # Cap each family so the matrix is broad but bounded and easy to inspect.
    for family, transform in TRANSFORMS.items():
        for origin, root in candidates:
            if per_family[family] >= 24:
                break
            rewritten = transform(root)
            if rewritten is None or rewritten == root or root.lower() in rewritten.lower():
                continue
            policy = {f"root_{family}_{per_family[family]}": [root]}
            original_result = scanner({"content": root}, policy, return_matched=True)
            endpoint_result = scanner({"content": rewritten}, policy, return_matched=True)
            clean_probe = "PCL_CLEAN_PROBE_" + hashlib.sha256(root.encode()).hexdigest()[:16]
            clean_result = scanner({"content": rewritten}, {"clean": [clean_probe]}, return_matched=True)
            original_rejected = not _scanner_includes(original_result)
            endpoint_passed = _scanner_includes(endpoint_result)
            clean_passed = _scanner_includes(clean_result)
            # Exercise the actual fixed text algebra, not just a two-node oracle.
            local_policy = {"roots": [{"id": "source", "code": root,
                "intent": "static-line", "labels": ledger.B}], "repairs": []}
            local_log = {
                "units": [
                    {"id": "imported", "op": "import", "source": "source",
                     "code": root, "intent": "static-line"},
                    {"id": "rewritten", "op": "rewrite", "parent": "imported",
                     "old": root, "new": rewritten, "code": rewritten, "intent": "static-line"}],
                "bundles": [{"id": "collected", "op": "collect",
                    "items": [{"name": "line.txt", "unit": "rewritten"}]}],
                "final": "collected", "outputs": [{"name": "line.txt", "unit": "rewritten",
                    "code": rewritten, "intent": "static-line"}], "claims": {}}
            ledger.annotate(local_policy, local_log)
            lineage_blocked = (ledger.validate(local_policy, local_log)["blocked"] == 1
                               and checker.verify(local_policy, local_log)["blocked"] == 1)
            if not (original_rejected and endpoint_passed and clean_passed and lineage_blocked):
                raise AssertionError(f"transform bridge invariant failed: {family} {origin}")
            original_rejections += 1
            endpoint_passes += 1
            clean_control_passes += 1
            lineage_blocks += 1
            per_family[family] += 1
            cases.append({
                "family": family,
                "origin": origin,
                "root_sha256": hashlib.sha256(root.encode()).hexdigest(),
                "rewritten_sha256": hashlib.sha256(rewritten.encode()).hexdigest(),
                "root_length": len(root),
                "rewritten_length": len(rewritten),
                "original_rejected": original_rejected,
                "endpoint_scan_passed": endpoint_passed,
                "lineage_blocked": lineage_blocked,
                "clean_control_passed": clean_passed,
            })

    if min(per_family.values()) < 12:
        raise AssertionError(f"insufficient family coverage: {per_family}")
    return {
        "upstream_function_path": str(scanner_path.relative_to(artifact_root)),
        "upstream_excerpt_sha256": scanner_digest,
        "retained_candidate_lines": len(candidates),
        "candidate_source": "data/selection.json -> data/public (24 retained files)",
        "lineage_check": "ledger.validate and checker.verify on each literal rewrite",
        "transform_families": list(TRANSFORMS),
        "cases": len(cases),
        "cases_by_family": per_family,
        "original_scan_rejections": original_rejections,
        "rewritten_endpoint_scan_passes": endpoint_passes,
        "lineage_blocks": lineage_blocks,
        "clean_control_passes": clean_control_passes,
        "case_records": cases,
        "claim_boundary": (
            "Generated labels and exact textual rewrites, without semantic-equivalence claims. Function-level evidence on retained static source text; no source file is executed, "
            "and the matrix does not reproduce the complete upstream distributed builder."
        ),
    }


def _quantile(values: Sequence[float], q: float) -> float:
    if not values:
        raise ValueError("empty quantile")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - position) + ordered[hi] * (position - lo)


def _bootstrap_median_ci(values: Sequence[float], seed: int, rounds: int = 1200) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(values)
    medians = []
    for _ in range(rounds):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    return _quantile(medians, 0.025), _quantile(medians, 0.975)


def _theil_sen(xs: Sequence[float], ys: Sequence[float]) -> float:
    slopes = []
    for i in range(len(xs)):
        for j in range(i + 1, len(xs)):
            if xs[j] != xs[i]:
                slopes.append((ys[j] - ys[i]) / (xs[j] - xs[i]))
    return statistics.median(slopes)


def _shape(size: int, name: str):
    if name == "chain":
        edges = tuple((i, i + 1) for i in range(size - 1))
        partition = tuple((i,) for i in range(size))
        roots = (0,)
    elif name == "alias_copy":
        edges = tuple((i, i + 1) for i in range(0, size - 1, 2))
        blocks = []
        i = 0
        while i < size:
            if i + 1 < size:
                blocks.append((i, i + 1))
            else:
                blocks.append((i,))
            i += 2
        partition = tuple(blocks)
        roots = (0,)
    elif name == "many_roots":
        edges = tuple((i, i + 1) for i in range(size - 1))
        partition = tuple((i,) for i in range(size))
        roots = tuple(range(0, size, max(1, size // 32)))
    else:
        raise ValueError(name)
    return edges, partition, roots


def scaling_study() -> dict[str, object]:
    sizes = (64, 128, 256, 512, 1024, 2048, 4096, 8192)
    shapes = ("chain", "alias_copy", "many_roots")
    repetitions = 11
    warmups = 2
    result: dict[str, object] = {
        "sizes": list(sizes),
        "shapes": list(shapes),
        "repetitions": repetitions,
        "warmups": warmups,
        "timing_clock": "time.perf_counter_ns",
        "records": [],
        "summaries": {},
    }
    records: list[dict[str, object]] = result["records"]  # type: ignore[assignment]
    summaries: dict[str, object] = result["summaries"]  # type: ignore[assignment]

    for shape_index, shape in enumerate(shapes):
        medians = []
        for size in sizes:
            edges, partition, roots = _shape(size, shape)
            loops = max(1, 131072 // size)
            for _ in range(warmups):
                for _ in range(loops):
                    quotient_oracle(size, edges, partition, roots)
            samples = []
            for repetition in range(repetitions):
                started = time.perf_counter_ns()
                last = None
                for _ in range(loops):
                    last = quotient_oracle(size, edges, partition, roots)
                elapsed = time.perf_counter_ns() - started
                if not last:
                    raise AssertionError("benchmark closure unexpectedly empty")
                per_call = elapsed / loops
                samples.append(per_call)
                records.append({
                    "shape": shape,
                    "size": size,
                    "repetition": repetition,
                    "loops": loops,
                    "elapsed_ns": elapsed,
                    "per_call_ns": per_call,
                    "tainted_nodes": len(last),
                })
            median = statistics.median(samples)
            medians.append(median)
            low, high = _bootstrap_median_ci(samples, SEED + shape_index * 10000 + size)
            summaries[f"{shape}:{size}"] = {
                "median_ns": median,
                "q1_ns": _quantile(samples, 0.25),
                "q3_ns": _quantile(samples, 0.75),
                "mad_ns": statistics.median(abs(x - median) for x in samples),
                "bootstrap_median_95pct_ns": [low, high],
                "min_ns": min(samples),
                "max_ns": max(samples),
            }
        slope = _theil_sen(
            [math.log2(x) for x in sizes[-6:]],
            [math.log2(y) for y in medians[-6:]],
        )
        summaries[f"{shape}:loglog_slope"] = {
            "theil_sen_slope_largest_six_sizes": slope,
            "interpretation_boundary": (
                "An implementation-level trend under this host and harness, not an asymptotic proof "
                "or a cross-system performance comparison."
            ),
        }

    cpu_model = None
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    result["environment"] = {
        "python": sys.version,
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_model": cpu_model,
        "logical_cpus": os.cpu_count(),
        "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
    }
    result["claim_boundary"] = (
        "Medians, dispersion, and raw repetitions characterize this deterministic microbenchmark only; "
        "they are not production throughput or latency measurements."
    )
    return result


def run(artifact_root: Path) -> dict[str, object]:
    started = time.perf_counter()
    small = exact_small_model()
    mutation = mutation_campaign()
    bridge = transform_bridge(artifact_root)
    scaling = scaling_study()
    if small["oracle_disagreements"] != 0:
        raise AssertionError("small-model oracle disagreement")
    if mutation["mutants_killed"] != mutation["mutants_total"]:
        raise AssertionError("mutation campaign did not kill every listed mutant")
    return {
        "schema": SCHEMA,
        "seed": SEED,
        "status": "passed",
        "small_model": small,
        "mutation_campaign": mutation,
        "transform_bridge": bridge,
        "scaling": scaling,
        "elapsed_seconds": time.perf_counter() - started,
        "limitations": [
            "The exhaustive domain has four nodes and directed acyclic transformation facts; larger random cases are mutation witnesses, not exhaustive coverage.",
            "Mutants are a documented set of plausible mistakes, not every possible implementation defect.",
            "The transform bridge calls one upstream predicate and does not reproduce the complete distributed dataset builder.",
            "Microbenchmark timing is host-specific and does not establish a general complexity theorem.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    artifact_root = args.artifact_root.resolve()
    output = args.output or artifact_root / "results" / "reviewer-hardening.json"
    report = run(artifact_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "small_model_cases": report["small_model"]["cases"],
        "mutants_killed": report["mutation_campaign"]["mutants_killed"],
        "transform_cases": report["transform_bridge"]["cases"],
        "scaling_records": len(report["scaling"]["records"]),
        "output": str(output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
