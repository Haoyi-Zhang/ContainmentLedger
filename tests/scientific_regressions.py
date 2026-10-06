"""Small portable regressions for empty diagnostics and the delivered inventory.

No source text is executed and no filesystem publication/locking is emulated.
Output is separate from the retained Linux/POSIX measurements.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import checker
import cutcheck
import cuts
import diagnose
import ledger
import package_audit


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run():
    began = time.perf_counter()
    cpu = time.process_time()
    records = []
    empty = {'units': [], 'bundles': [{'id': 'empty', 'op': 'collect', 'items': []}],
             'final': 'empty', 'outputs': [], 'claims': {}}
    policies = [{'roots': [], 'repairs': []}] + [
        {'roots': [{'id': 'unused', 'code': 'own finite value', 'intent': 'task',
                    'labels': mask}], 'repairs': []} for mask in range(8)]
    for number, policy in enumerate(policies):
        require(ledger.validate(policy, empty)['blocked'] == 0, 'empty producer replay')
        require(checker.verify(policy, empty)['blocked'] == 0, 'empty checker replay')
        graph = diagnose.graph(policy, empty, {})
        independent = checker.audit_graph(policy, empty, {})
        require(graph == independent and graph['n'] >= 1, 'empty diagnostic graph agreement')
        certificate = cuts.minimize(graph)
        require(certificate['status'] == 'cut' and certificate['cut'] == [], 'empty separator')
        require(cutcheck.verify(independent, certificate)['kind'] == 'inclusion-minimal',
                'empty diagnostic certificate')
        wrapped_graph, wrapped_certificate = diagnose.diagnose(policy, empty, {})
        require(wrapped_graph == graph and wrapped_certificate == certificate, 'diagnose adapter')
        records.append({'case': number, 'roots': len(policy['roots']), 'vertices': graph['n'],
                        'source_states': len(graph['sources']), 'targets': 0, 'cut_size': 0})
    inventory = {'package_shape': package_audit.package_shape_audit(),
                 'source_safety': package_audit.source_audit(),
                 'public_inputs': package_audit.public_input_audit(),
                 'retained_upstream': package_audit.retained_upstream_audit(),
                 'evidence_tables': package_audit.evidence_table_audit(),
                 'emitter_source': package_audit.emitter_publication_audit()}
    return {'status': 'passed', 'diagnostic_cases': len(records), 'records': records,
            'inventory': inventory, 'cpu_seconds': time.process_time() - cpu,
            'wall_seconds': time.perf_counter() - began,
            'scope': 'Owned empty-ledger inputs and static retained-input/source checks; '
                     'no POSIX publication, persistent freshness, or performance rerun.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = run()
    if args.output is not None:
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
