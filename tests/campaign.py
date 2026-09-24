"""Frozen benign multi-project corpus campaign. Source text is never imported or executed."""
import copy
import csv
import itertools
import json
import resource
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import checker  # noqa: E402
import fixtures  # noqa: E402
import ledger  # noqa: E402
import merge  # noqa: E402

BITS = (1, 2, 4)


def failure_pair(policy, log):
    observed = []
    for fn, err in ((ledger.validate, ledger.Invalid), (checker.verify, checker.Rejected)):
        try:
            fn(policy, log)
        except err:
            observed.append(True)
        else:
            observed.append(False)
    assert all(observed), observed


def _keys(summary, scope):
    return [tuple(key) for key in summary['components'][scope]['keys']]


def compose_seed_to_output(summaries):
    """Ablation: join equal keys but retain no local reachability arcs."""
    results = [list(summary['origin_labels']) for summary in summaries]
    for scope, bit in enumerate((1, 4)):
        seeded = set()
        local_keys = []
        for summary in summaries:
            keys = _keys(summary, scope)
            local_keys.append(keys)
            component = summary['components'][scope]
            seeded.update(keys[index] for index in component['seeds'])
        for shard, summary in enumerate(summaries):
            component = summary['components'][scope]
            for output, index in enumerate(component['outputs']):
                if local_keys[shard][index] in seeded:
                    results[shard][output] |= bit
    return results


def compose_output_alias(summaries, local_masks):
    """Ablation: cache local output labels and join only equal output endpoints."""
    results = [list(mask) for mask in local_masks]
    for scope, bit in enumerate((1, 4)):
        tagged = set()
        local_keys = []
        for shard, summary in enumerate(summaries):
            keys = _keys(summary, scope)
            local_keys.append(keys)
            component = summary['components'][scope]
            for output, index in enumerate(component['outputs']):
                if local_masks[shard][output] & bit:
                    tagged.add(keys[index])
        for shard, summary in enumerate(summaries):
            component = summary['components'][scope]
            for output, index in enumerate(component['outputs']):
                if local_keys[shard][index] in tagged:
                    results[shard][output] |= bit
    return results


def flatten(parts):
    return [value for part in parts for value in part]


def evaluate_prediction(totals, prediction, truth):
    assert len(prediction) == len(truth)
    totals['outputs'] += len(truth)
    exact = True
    for predicted, expected in zip(prediction, truth):
        totals['exact_outputs'] += predicted == expected
        totals['false_clean_outputs'] += expected != 0 and predicted == 0
        totals['false_block_outputs'] += expected == 0 and predicted != 0
        for bit in BITS:
            totals['missed_scope_bits'] += bool(expected & bit) and not bool(predicted & bit)
            totals['extra_scope_bits'] += bool(predicted & bit) and not bool(expected & bit)
        exact &= predicted == expected
    totals['contexts'] += 1
    totals['exact_contexts'] += exact


def run():
    cpu = time.process_time()
    wall = time.perf_counter()
    rows = []
    mutations = []
    confusion = {}
    project_records = defaultdict(dict)
    public_root = ROOT / 'data' / 'public'
    files = fixtures.public_files(ROOT)

    for shard, source in enumerate(files):
        relative = source.relative_to(public_root).as_posix()
        project = relative.split('/', 1)[0]
        code = source.read_text(encoding='utf-8')
        for scenario, (description, _) in fixtures.SCENARIOS.items():
            policy, log, expected = fixtures.case(code, scenario)
            answer = ledger.annotate(policy, log)
            second = checker.verify(policy, log)
            assert bool(answer['blocked']) == expected, (relative, scenario, answer)
            assert second['labels'] == answer['labels']
            decisions = fixtures.flawed_decisions(policy, log)
            decisions['scoped-replay'] = bool(answer['blocked'])
            for method, prediction in decisions.items():
                matrix = confusion.setdefault(method, {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0})
                matrix['tp' if expected and prediction else 'fn' if expected else 'fp' if prediction else 'tn'] += 1
            rows.append({
                'project': project,
                'shard': relative,
                'case': scenario,
                'description': description,
                'expected_blocked': int(expected),
                'nodes': answer['nodes'],
                'edges': answer['edges'],
                'outputs': answer['retained'],
                **{key: int(value) for key, value in decisions.items()},
            })
            producer_summary = merge.summarize(policy, log)
            checker_summary = checker.verify(policy, log, summary=True)
            assert producer_summary == checker_summary
            mask = [answer['labels'][output['unit']] for output in log['outputs']]
            assert merge.compose([producer_summary]) == [mask]
            if scenario not in project_records[project]:
                project_records[project][scenario] = {
                    'policy': policy,
                    'log': log,
                    'summary': producer_summary,
                    'mask': mask,
                    'source': relative,
                }

        # Twelve independent structural/claim mutations per source file.
        policy, log, _ = fixtures.case(code, 'C09')
        ledger.annotate(policy, log)
        edits = []

        def add(kind, edit):
            edited_policy = copy.deepcopy(policy)
            edited_log = copy.deepcopy(log)
            edit(edited_policy, edited_log)
            edits.append((kind, edited_policy, edited_log))

        add('unregistered-source', lambda p, l: l['units'][0].update(source='missing'))
        add('nonpreceding-parent', lambda p, l: l['units'][-1].update(parent=l['units'][-1]['id']))
        add('unknown-authority', lambda p, l: l['units'][-1].update(authority='missing'))
        add('authority-input-binding', lambda p, l: p['repairs'][0].update(before='wrong'))
        add('counterfeit-unit-bytes', lambda p, l: l['units'][-1].update(code='not the replay'))
        add('counterfeit-export', lambda p, l: l['outputs'][0].update(code='not the output'))
        add('missing-export', lambda p, l: l['outputs'].clear())
        add('extra-export', lambda p, l: l['outputs'].append(dict(l['outputs'][0])))
        add('duplicate-unit', lambda p, l: l['units'].append(dict(l['units'][0])))
        add('extra-record-field', lambda p, l: l['units'][0].update(extra=True))
        add('false-label', lambda p, l: l['claims'].update(repaired=7))
        add('unsafe-member', lambda p, l: l['bundles'][0]['items'][0].update(name='../outside'))
        for kind, edited_policy, edited_log in edits:
            failure_pair(edited_policy, edited_log)
            mutations.append({'project': project, 'shard': relative, 'mutation': kind, 'both_reject': True})

    scenario_order = list(fixtures.SCENARIOS)
    assert all(list(records) == scenario_order for records in project_records.values())
    composition = []
    baseline_totals = {
        name: Counter()
        for name in ('cached-local-decisions', 'seed-to-output-equality', 'output-endpoint-alias', 'context-complete-summary')
    }

    def check_context(kind, project_names, records, family_names):
        pairs = [(record['policy'], record['log']) for record in records]
        policy, log = merge.combine_logs(pairs)
        answer = ledger.annotate(policy, log)
        checker.verify(policy, log)
        summaries = [record['summary'] for record in records]
        local_masks = [record['mask'] for record in records]
        full_parts = merge.compose(summaries)
        full = flatten(full_parts)
        expected = [answer['labels'][output['unit']] for output in log['outputs']]
        assert full == expected, (kind, project_names, family_names, full, expected)
        local = flatten(local_masks)
        seed_only = flatten(compose_seed_to_output(summaries))
        endpoint = flatten(compose_output_alias(summaries, local_masks))
        predictions = {
            'cached-local-decisions': local,
            'seed-to-output-equality': seed_only,
            'output-endpoint-alias': endpoint,
            'context-complete-summary': full,
        }
        for name, prediction in predictions.items():
            evaluate_prediction(baseline_totals[name], prediction, expected)
        newly_blocked = sum(before == 0 and after != 0 for before, after in zip(local, full))
        composition.append({
            'kind': kind,
            'projects': list(project_names),
            'families': list(family_names),
            'outputs': len(full),
            'newly_blocked': newly_blocked,
            'cached_local_false_clean': sum(t != 0 and p == 0 for p, t in zip(local, expected)),
            'seed_to_output_false_clean': sum(t != 0 and p == 0 for p, t in zip(seed_only, expected)),
            'output_endpoint_false_clean': sum(t != 0 and p == 0 for p, t in zip(endpoint, expected)),
            'equal_to_full_replay': True,
        })

    # Equality-rich ordered family pairs and one all-family union per project.
    for project in sorted(project_records):
        records = project_records[project]
        selections = list(itertools.product(scenario_order, repeat=2)) + [tuple(scenario_order)]
        for selection in selections:
            chosen = [records[name] for name in selection]
            check_context('within-project', [project], chosen, selection)

    # Heterogeneous contexts: each family across all projects, a global union,
    # and directed common-header label/clean pairs across distinct projects.
    projects = sorted(project_records)
    for scenario in scenario_order:
        check_context(
            'same-family-across-projects',
            projects,
            [project_records[project][scenario] for project in projects],
            [scenario] * len(projects),
        )
    all_records = [project_records[project][scenario] for project in projects for scenario in scenario_order]
    check_context(
        'all-projects-all-families',
        projects,
        all_records,
        [scenario for _project in projects for scenario in scenario_order],
    )
    for labelled_project, clean_project in itertools.permutations(projects, 2):
        check_context(
            'cross-project-common-header',
            [labelled_project, clean_project],
            [project_records[labelled_project]['C21'], project_records[clean_project]['C22']],
            ['C21', 'C22'],
        )

    with (ROOT / 'results' / 'corpus-cases.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (ROOT / 'results' / 'mutations.json').write_text(json.dumps(mutations, indent=2) + '\n')
    (ROOT / 'results' / 'composition.json').write_text(json.dumps(composition, indent=2) + '\n')

    baseline_report = {}
    for name, counts in baseline_totals.items():
        data = dict(counts)
        outputs = data['outputs']
        contexts = data['contexts']
        data['exact_output_rate'] = data['exact_outputs'] / outputs if outputs else 1.0
        data['exact_context_rate'] = data['exact_contexts'] / contexts if contexts else 1.0
        baseline_report[name] = data
    (ROOT / 'results' / 'composition-baselines.json').write_text(json.dumps(baseline_report, indent=2) + '\n')

    files_per_project = Counter(path.relative_to(public_root).parts[0] for path in files)
    source_bytes = sum(path.stat().st_size for path in files)
    source_lines = sum(path.read_text(encoding='utf-8').count('\n') + 1 for path in files)
    metrics = {
        'source_projects': len(files_per_project),
        'files_per_project': dict(sorted(files_per_project.items())),
        'source_files': len(files),
        'source_bytes': source_bytes,
        'source_lines': source_lines,
        'families': len(fixtures.SCENARIOS),
        'valid_cases': len(rows),
        'positive_cases': sum(row['expected_blocked'] for row in rows),
        'negative_cases': sum(1 - row['expected_blocked'] for row in rows),
        'structural_mutations': len(mutations),
        'composition_contexts': len(composition),
        'heterogeneous_composition_contexts': sum(row['kind'] != 'within-project' for row in composition),
        'contexts_invalidating_a_local_clean_decision': sum(row['newly_blocked'] > 0 for row in composition),
        'newly_blocked_output_decisions': sum(row['newly_blocked'] for row in composition),
        'confusion': confusion,
        'composition_baselines': baseline_report,
        'cpu_seconds': time.process_time() - cpu,
        'wall_seconds': time.perf_counter() - wall,
        'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    (ROOT / 'results' / 'campaign.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    run()
