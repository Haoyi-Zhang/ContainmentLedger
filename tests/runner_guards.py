#!/usr/bin/env python3
"""Small benign supervisor regressions; expected failures remain recorded."""
from __future__ import annotations
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import reproduce


def probe(mode):
    if mode == 'normal':
        begin = time.process_time()
        count = 0
        while time.process_time() - begin < 0.02:
            count += 1
        print(json.dumps({'count': count, 'address_space_limit': resource.getrlimit(resource.RLIMIT_AS)[0],
                          'cpu_affinity_count': len(os.sched_getaffinity(0))}), flush=True)
    elif mode == 'fail':
        print('intentional nonzero worker exit', file=sys.stderr, flush=True)
        return 7
    elif mode == 'allocate':
        try:
            value = bytearray(128 * 1024**2)
        except MemoryError:
            print(json.dumps({'allocation_refused': True}), flush=True)
            return 0
        print(json.dumps({'allocation_refused': False, 'bytes': len(value)}), flush=True)
        return 8
    elif mode == 'group-memory':
        value = bytearray(32 * 1024**2)
        print(len(value), flush=True)
        time.sleep(10)
    elif mode in ('timeout', 'orphan'):
        child = subprocess.Popen([sys.executable, '-S', str(Path(__file__)), '--probe', 'sleep'])
        print(json.dumps({'descendant_pid': child.pid}), flush=True)
        if mode == 'orphan':
            return 0
        time.sleep(10)
    elif mode == 'interrupt':
        time.sleep(0.05)
        os.kill(os.getppid(), signal.SIGTERM)
        time.sleep(10)
    elif mode == 'sleep':
        time.sleep(10)
    else:
        raise ValueError(mode)
    return 0


def main():
    records = []
    specification = (
        ('normal', 2.0, 128, 128, None),
        ('fail', 2.0, 128, 128, 'nonzero_exit'),
        ('timeout', 0.35, 128, 128, 'wall_timeout'),
        ('allocate', 2.0, 64, 128, None),
        ('group-memory', 2.0, 128, 24, 'sampled_aggregate_rss_limit'),
        ('orphan', 2.0, 128, 128, 'unwaited_descendants_after_worker_exit'),
        ('interrupt', 2.0, 128, 128, 'interrupted:'),
    )
    for name, wall, address_mib, group_mib, expected_reason in specification:
        row = reproduce.supervise(['tests/runner_guards.py', '--probe', name],
            wall_limit=wall, memory_bytes=address_mib * 1024**2,
            aggregate_bytes=group_mib * 1024**2, cpu_seconds=5)
        if row['remaining_descendants']:
            raise RuntimeError(f'unclean descendants: {name}: {row}')
        if expected_reason is None:
            if row['status'] != 'passed':
                raise RuntimeError(f'control failed: {name}: {row}')
        elif row['status'] != 'failed' or not row['termination_reason'].startswith(expected_reason):
            raise RuntimeError(f'wrong guard outcome: {name}: {row}')
        if name == 'allocate' and not json.loads(row['stdout'])['allocation_refused']:
            raise RuntimeError('RLIMIT_AS not enforced')
        if name == 'normal':
            values = json.loads(row['stdout'])
            if values['address_space_limit'] != 128 * 1024**2 or values['cpu_affinity_count'] > 4:
                raise RuntimeError('child limits not inherited')
        if name in ('timeout', 'orphan'):
            pid = json.loads(row['stdout'])['descendant_pid']
            if Path('/proc') .joinpath(str(pid)).exists():
                raise RuntimeError('descendant survived cleanup')
            if not any(item['pid'] == pid for item in row['reaped_processes']):
                raise RuntimeError('orphan descendant was not reaped/accounted')
        if not (row['whole_child_cpu_seconds'] > 0 and row['wall_seconds'] > 0 and row['peak_child_rss_kib'] > 0):
            raise RuntimeError('missing real resource observations')
        records.append({'case': name, 'expected_worker_status': 'passed' if expected_reason is None else 'failed',
                        'actual': row})
    report = {'status': 'passed', 'cases': records,
              'scope': 'Benign bounded worker probes only. Per-process address-space limits are hard; aggregate RSS is sampled. Linux subreaping covers adopted descendants; no universal hostile-process or kernel-failure guarantee.'}
    reproduce.write_json(ROOT / 'results/runner-guards.json', report)
    print(json.dumps({'status': 'passed', 'cases': len(records),
                      'expected_worker_failures': sum(item['expected_worker_status'] == 'failed' for item in records)}))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--probe':
        raise SystemExit(probe(sys.argv[2]))
    main()
