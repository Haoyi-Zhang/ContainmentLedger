#!/usr/bin/env python3
"""Supervised sequential offline reproduction on Linux/POSIX; no corpus execution."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / 'results'
MEMORY_BYTES = 3 * 1024**3
PART_LIMITS = {'hardening': 170.0, 'checks': 90.0,
               'scaling-chain-distinct': 60.0, 'scaling-alias-copy': 60.0,
               'scaling-many-roots': 60.0}
PARTS = list(PART_LIMITS)
PART_OUTPUTS = {
    'hardening': ['upstream-regression.json', 'freshness-json.json', 'runner-guards.json',
                  'package-audit.json', 'reviewer-hardening.json', 'scientific-regressions.json'],
    'checks': ['pilot.json', 'campaign.json', 'mutations.json', 'composition.json',
               'composition-baselines.json', 'corpus-cases.csv', 'finite-closure.json',
               'finite-cuts.json', 'context.json', 'natural-duplicates.json',
               'builder-bridge.json', 'deployment.json', 'freshness.json',
               'boundaries.json', 'diagnoses.json'],
}
for _shape in ('chain-distinct', 'alias-copy', 'many-roots'):
    PART_OUTPUTS['scaling-' + _shape] = ['scaling-' + _shape + '.json', 'scaling-' + _shape + '.csv']


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    # Results are not a security authority. Atomic replacement avoids partial
    # success records if a coordinator is interrupted during a report write.
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')
    os.replace(temporary, path)


def execution_identity():
    """Bind observations to current source and exact consumed local inputs.

    This is measurement provenance in run records, not a software release or
    a signature/attestation. Mutable result files are deliberately excluded.
    """
    sources = [ROOT / 'reproduce.py', *sorted((ROOT / 'src').glob('*.py')),
               *sorted((ROOT / 'tests').glob('*.py'))]
    inputs = []
    for directory in ('data', 'upstream', 'licenses', 'proofs'):
        inputs.extend(p for p in (ROOT / directory).rglob('*') if p.is_file())
    inputs.extend(ROOT / name for name in ('claim_evidence_ledger.csv', 'external_resources.csv',
                                         'reviewer-evidence-ledger.csv'))
    source_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(sources)}
    input_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(inputs)}
    encoded = json.dumps({'sources': source_hashes, 'inputs': input_hashes},
                         sort_keys=True, separators=(',', ':')).encode()
    return {'sha256': hashlib.sha256(encoded).hexdigest(), 'python_sources': len(sources),
            'source_sha256': source_hashes, 'input_sha256': input_hashes}


def configure_supervisor():
    """Reap orphaned descendants as well as the initially launched worker."""
    _require(sys.platform.startswith('linux') and Path('/proc/self/stat').exists(),
             'This measured supervisor requires Linux/POSIX with procfs.')
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'cannot enable descendant reaping')
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, allowed[:4])


def process_table():
    result = {}
    page_kib = os.sysconf('SC_PAGE_SIZE') // 1024
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / 'stat').read_text()
            fields = raw[raw.rindex(')') + 2:].split()
            result[int(entry.name)] = {'parent': int(fields[1]), 'group': int(fields[2]),
                'state': fields[0], 'start': int(fields[19]),
                'rss_kib': max(0, int(fields[21])) * page_kib}
        except (OSError, ValueError, IndexError):
            continue  # A process may exit between listing and reading stat.
    return result


def _owned_processes(root_pid, tracked, table):
    owned = {pid for pid, start in tracked.items()
             if pid in table and table[pid]['start'] == start}
    if root_pid in table:
        owned.add(root_pid)
    # The supervisor launches one command at a time. Immediate adopted children
    # after worker death therefore belong to that command too, even if their
    # ancestry disappeared between samples or they created another session.
    owned.update(pid for pid, data in table.items() if data['parent'] == os.getpid())
    while True:
        larger = owned | {pid for pid, data in table.items() if data['parent'] in owned}
        if larger == owned:
            break
        owned = larger
    for pid in owned:
        tracked[pid] = table[pid]['start']
    return owned


def supervise(arguments, *, wall_limit, memory_bytes=MEMORY_BYTES,
              aggregate_bytes=MEMORY_BYTES, cpu_seconds=160, output_limit=65536):
    """Bound, measure, and clean up one worker and its descendants.

    RLIMIT_AS is per process. Aggregate RSS is sampled every 10 ms (not a
    proof of the instantaneous maximum). wait4 accounts for waited descendant
    CPU; adopted unwaited descendants are reaped separately exactly once.
    """
    configure_supervisor()
    started = time.perf_counter()
    command = [sys.executable, '-S', *arguments]
    tracked = {}
    reaped = []
    cleanup_pids = set()
    peak_group = 0
    reason = None
    root_exit = None
    cleanup_deadline = None
    proc = None

    def limits():
        hard = resource.getrlimit(resource.RLIMIT_AS)[1]
        ceiling = memory_bytes if hard == resource.RLIM_INFINITY else min(memory_bytes, hard)
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
        hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)[1]
        cap = cpu_seconds if hard_cpu == resource.RLIM_INFINITY else min(cpu_seconds, hard_cpu)
        resource.setrlimit(resource.RLIMIT_CPU, (cap, cap))

    old_handlers = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt('received signal ' + str(signum))
    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, interrupted)

    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(command, cwd=ROOT, stdout=out, stderr=err,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'},
                start_new_session=True, preexec_fn=limits)
            while True:
                try:
                    table = process_table()
                    owned = _owned_processes(proc.pid, tracked, table)
                    rss = sum(table[pid]['rss_kib'] for pid in owned)
                    peak_group = max(peak_group, rss)
                    while True:
                        try:
                            pid, status, usage = os.wait4(-1, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if not pid:
                            break
                        exit_code = os.waitstatus_to_exitcode(status)
                        reaped.append({'pid': pid, 'exit_code': exit_code,
                                       'cpu_seconds': usage.ru_utime + usage.ru_stime,
                                       'peak_rss_kib': usage.ru_maxrss})
                        if pid == proc.pid:
                            root_exit = exit_code
                            proc.returncode = exit_code
                    now = time.perf_counter()
                    if root_exit is not None:
                        table = process_table()
                        owned = _owned_processes(proc.pid, tracked, table)
                        if not owned:
                            break
                        if reason is None and any(table[pid]['state'] != 'Z' for pid in owned):
                            reason = 'unwaited_descendants_after_worker_exit'
                    if reason is None and now - started >= wall_limit:
                        reason = 'wall_timeout'
                    if reason is None and rss * 1024 > aggregate_bytes:
                        reason = 'sampled_aggregate_rss_limit'
                    if reason is None and max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > output_limit:
                        reason = 'output_volume_limit'
                except KeyboardInterrupt as exc:
                    reason = 'interrupted: ' + str(exc)
                    table = process_table()
                    owned = _owned_processes(proc.pid, tracked, table)
                    now = time.perf_counter()
                if reason is not None:
                    if cleanup_deadline is None:
                        cleanup_deadline = now + 3.0
                    groups = {table[pid]['group'] for pid in owned}
                    for group in groups:
                        if group != os.getpgrp():
                            try:
                                os.killpg(group, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    for pid in owned:
                        cleanup_pids.add(pid)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if now >= cleanup_deadline:
                        break
                try:
                    time.sleep(0.01)
                except KeyboardInterrupt as exc:
                    reason = 'interrupted: ' + str(exc)
        except (Exception, KeyboardInterrupt) as exc:
            reason = 'launch_or_supervisor_error: ' + type(exc).__name__ + ': ' + str(exc)
            if proc is not None:
                # Keep error cleanup bounded too; never wait indefinitely on
                # just the root while leaving its descendants behind.
                cleanup_end = time.perf_counter() + 3.0
                while time.perf_counter() < cleanup_end:
                    table = process_table()
                    owned = _owned_processes(proc.pid, tracked, table)
                    for pid in owned:
                        cleanup_pids.add(pid)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    while True:
                        try:
                            pid, status, usage = os.wait4(-1, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if not pid:
                            break
                        code = os.waitstatus_to_exitcode(status)
                        reaped.append({'pid': pid, 'exit_code': code,
                            'cpu_seconds': usage.ru_utime + usage.ru_stime,
                            'peak_rss_kib': usage.ru_maxrss})
                        if pid == proc.pid:
                            root_exit = code
                            proc.returncode = code
                    if root_exit is not None and not _owned_processes(proc.pid, tracked, process_table()):
                        break
                    time.sleep(0.01)
        finally:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
        table = process_table()
        remaining = [] if proc is None else sorted(_owned_processes(proc.pid, tracked, table))
        if remaining:
            reason = (reason or '') + '; descendant_cleanup_incomplete'
        out.seek(0); err.seek(0)
        stdout = out.read(output_limit + 1).decode('utf-8', errors='replace')
        stderr = err.read(output_limit + 1).decode('utf-8', errors='replace')
    if root_exit and reason is None:
        reason = 'nonzero_exit'
    return {'command': ['python', '-S', *arguments], 'status': 'passed' if root_exit == 0 and reason is None else 'failed',
            'exit_code': root_exit, 'termination_reason': reason,
            'wall_seconds': time.perf_counter() - started,
            'whole_child_cpu_seconds': sum(item['cpu_seconds'] for item in reaped),
            'peak_child_rss_kib': max((item['peak_rss_kib'] for item in reaped), default=0),
            'sampled_peak_group_rss_kib': peak_group,
            'reaped_processes': reaped, 'cleanup_pids': sorted(cleanup_pids),
            'remaining_descendants': remaining,
            'limits': {'wall_seconds': wall_limit, 'address_space_bytes_per_process': memory_bytes,
                       'sampled_group_rss_bytes': aggregate_bytes, 'cpu_seconds_per_process': cpu_seconds,
                       'rss_sample_interval_seconds': 0.01, 'cleanup_seconds': 3},
            'stdout': stdout, 'stderr': stderr}


def validate_hardening():
    def get(name):
        return json.loads((RESULTS / name).read_text())
    smoke = get('upstream-regression.json')
    state = get('freshness-json.json')
    guards = get('runner-guards.json')
    audit = get('package-audit.json')
    hardening = get('reviewer-hardening.json')
    regression = get('scientific-regressions.json')
    _require(regression['status'] == 'passed' and regression['diagnostic_cases'] == 9,
             'empty diagnostic and inventory regressions')
    _require(smoke['status'] == 'passed' and smoke['query_count'] == 8, 'upstream smoke')
    _require(state['status'] == 'passed' and state['valid_controls'] == 3 and state['rejected_count'] == 14, 'state syntax')
    _require(len(state['persisted_state_rejections_unchanged']) == 2, 'persisted malformed states')
    _require(guards['status'] == 'passed' and len(guards['cases']) == 7, 'supervisor guards')
    _require(audit['status'] == 'passed' and audit['source_safety']['python_files_ast_parsed'] == execution_identity()['python_sources'], 'current source audit')
    _require(hardening['status'] == 'passed' and hardening['schema'] == 'pcl-reviewer-hardening/v1', 'hardening report')
    _require(hardening['small_model']['cases'] == 14400 and hardening['small_model']['oracle_disagreements'] == 0, 'small-model oracle')
    _require(hardening['mutation_campaign']['mutants_killed'] == hardening['mutation_campaign']['mutants_total'] == 12, 'mutants')
    bridge = hardening['transform_bridge']
    _require(bridge['cases'] >= 60 and min(bridge['cases_by_family'].values()) >= 12, 'transform coverage')
    _require(bridge['cases'] == bridge['lineage_blocks'] == bridge['rewritten_endpoint_scan_passes'] == bridge['clean_control_passes'], 'transform outcomes')
    _require(all(row['origin'].startswith('data/public/') for row in bridge['case_records']), 'retained public text origin')
    _require(len(hardening['scaling']['records']) == 264, 'supplementary microbenchmark repetitions')
    return {'status': 'passed', 'reports': PART_OUTPUTS['hardening']}


def check_results(include_scaling):

    def get(name):
        return json.loads((RESULTS / name).read_text())
    c = get('campaign.json')
    f = get('finite-closure.json')
    g = get('finite-cuts.json')
    x = get('context.json')
    b = get('boundaries.json')
    n = get('natural-duplicates.json')
    d = get('deployment.json')
    r = get('builder-bridge.json')
    q = get('freshness.json')
    a = get('package-audit.json')
    _require((c['source_projects'], c['source_files'], c['families'], c['valid_cases'], c['positive_cases'], c['negative_cases']) == (6, 24, 20, 480, 336, 144), "(c['source_projects'], c['source_files'], c['families'], c['valid_cases'], c['positive_cases'], c['negative_cases']) == (6, 24, 20, 480, 336, 144)")
    _require(c['source_bytes'] == 268614 and c['source_lines'] == 8191, 'physical input accounting')
    _require(c['structural_mutations'] == 288, "c['structural_mutations'] == 288")
    _require(c['composition_contexts'] == 2457 and c['heterogeneous_composition_contexts'] == 51, "c['composition_contexts'] == 2457 and c['heterogeneous_composition_contexts'] == 51")
    _require(c['contexts_invalidating_a_local_clean_decision'] == 793 and c['newly_blocked_output_decisions'] == 846, "c['contexts_invalidating_a_local_clean_decision'] == 793 and c['newly_blocked_output_decisions'] == 846")
    _require(c['composition_baselines']['context-complete-summary']['exact_outputs'] == 4962, "c['composition_baselines']['context-complete-summary']['exact_outputs'] == 4962")
    _require(c['composition_baselines']['context-complete-summary']['false_clean_outputs'] == 0, "c['composition_baselines']['context-complete-summary']['false_clean_outputs'] == 0")
    _require(c['composition_baselines']['cached-local-decisions']['false_clean_outputs'] == 846, "c['composition_baselines']['cached-local-decisions']['false_clean_outputs'] == 846")
    _require(c['composition_baselines']['seed-to-output-equality']['false_clean_outputs'] == 1626, "c['composition_baselines']['seed-to-output-equality']['false_clean_outputs'] == 1626")
    _require(c['composition_baselines']['output-endpoint-alias']['false_clean_outputs'] == 492, "c['composition_baselines']['output-endpoint-alias']['false_clean_outputs'] == 492")
    _require(f['cases'] == 327680 and f['disagreements'] == 0, "f['cases'] == 327680 and f['disagreements'] == 0")
    _require((g['graphs'], g['cut_certificates'], g['infeasible_certificates']) == (15625, 11456, 4169), "(g['graphs'], g['cut_certificates'], g['infeasible_certificates']) == (15625, 11456, 4169)")
    _require(g['mutations_rejected'] == 2059 and g['greedy_gaps'] == 52, "g['mutations_rejected'] == 2059 and g['greedy_gaps'] == 52")
    _require((b['clean_archives_emitted_and_read_back'], b['blocked_archives_not_created']) == (144, 336), "(b['clean_archives_emitted_and_read_back'], b['blocked_archives_not_created']) == (144, 336)")
    _require((b['inclusion_minimal_diagnoses'], b['uncuttable_diagnoses']) == (288, 192), "(b['inclusion_minimal_diagnoses'], b['uncuttable_diagnoses']) == (288, 192)")
    _require(len(b['boundary_checks']) == 20 and b['false_clean_claims_rejected_and_diagnosable'] == 336, "len(b['boundary_checks']) == 20 and b['false_clean_claims_rejected_and_diagnosable'] == 336")
    _require(x['merged_graph_seed_contexts'] == 262144 and x['disagreements'] == 0, "x['merged_graph_seed_contexts'] == 262144 and x['disagreements'] == 0")
    _require(x['actual_rewrite_pipeline_probe_contexts'] == 64, "x['actual_rewrite_pipeline_probe_contexts'] == 64")
    _require((n['duplicate_line_classes'], n['cross_project_duplicate_classes'], n['pair_contexts']) == (127, 6, 216), "(n['duplicate_line_classes'], n['cross_project_duplicate_classes'], n['pair_contexts']) == (127, 6, 216)")
    _require(n['cross_project_pair_contexts'] == 13, "n['cross_project_pair_contexts'] == 13")
    _require(n['complete_summary_equal_to_joined_replay'] == 216, "n['complete_summary_equal_to_joined_replay'] == 216")
    _require(n['authenticated_capsule_compositions_equal_to_joined_replay'] == 216, "n['authenticated_capsule_compositions_equal_to_joined_replay'] == 216")
    _require(n['endpoint_only_false_clean_outputs'] == 216 and n['capsules_issued_and_verified'] == 432, "n['endpoint_only_false_clean_outputs'] == 216 and n['capsules_issued_and_verified'] == 432")
    _require(d['tamper_or_context_cases_rejected'] == 23, "d['tamper_or_context_cases_rejected'] == 23")
    _require((r['source_projects'], r['retained_source_files']) == (6, 24), "(r['source_projects'], r['retained_source_files']) == (6, 24)")
    _require(r['matched_roots_total'] == 25, "r['matched_roots_total'] == 25")
    _require(r['rewritten_endpoints_passing_same_upstream_scanner'] == 25, "r['rewritten_endpoints_passing_same_upstream_scanner'] == 25")
    _require(r['rewritten_endpoints_blocked_by_lineage'] == 25, "r['rewritten_endpoints_blocked_by_lineage'] == 25")
    _require(r['final_state_false_clean_if_used_alone'] == 25, "r['final_state_false_clean_if_used_alone'] == 25")
    _require(r['clean_controls'] == 24 and r['clean_controls_accepted_by_scanner_and_ledger'] == 24, "r['clean_controls'] == 24 and r['clean_controls_accepted_by_scanner_and_ledger'] == 24")
    _require(r['independent_upstream_oracle_cases'] == 4 and r['independent_upstream_oracle_disagreements'] == 0, "r['independent_upstream_oracle_cases'] == 4 and r['independent_upstream_oracle_disagreements'] == 0")
    _require(q['strict_replay_rejected_after_process_restart'], "q['strict_replay_rejected_after_process_restart']")
    _require(q['explicit_epoch_rotation_accepted'] and q['old_epoch_downgrade_rejected'], "q['explicit_epoch_rotation_accepted'] and q['old_epoch_downgrade_rejected']")
    _require(q['race_processes'] == 8 and q['race_successful_acceptors'] == 1 and (q['race_stale_rejections'] == 7), "q['race_processes'] == 8 and q['race_successful_acceptors'] == 1 and (q['race_stale_rejections'] == 7)")
    _require(q['pre_replace_death_retained_prior_complete_state'], "q['pre_replace_death_retained_prior_complete_state']")
    _require(q['post_replace_death_exposed_new_complete_state'], "q['post_replace_death_exposed_new_complete_state']")
    _require(not q['whole_state_file_rollback_detected'], "not q['whole_state_file_rollback_detected']")
    _require(d['race_processes'] == 8 and d['race_successful_publishers'] == 1, "d['race_processes'] == 8 and d['race_successful_publishers'] == 1")
    _require(d['race_temporary_files_remaining'] == 0, "d['race_temporary_files_remaining'] == 0")
    _require(d['precommit_deaths_created_no_destination'] and d['postlink_deaths_left_complete_destination'], "d['precommit_deaths_created_no_destination'] and d['postlink_deaths_left_complete_destination']")
    _require(not d['power_loss_or_arbitrary_filesystem_durability_tested'], "not d['power_loss_or_arbitrary_filesystem_durability_tested']")
    _require(x['two_by_two_bipartite_relations_distinguished'] == 16, "x['two_by_two_bipartite_relations_distinguished'] == 16")
    _require(a['status'] == 'passed', "a['status'] == 'passed'")
    _require(a['public_inputs']['selection_files'] == 24 and a['public_inputs']['selection_projects'] == 6, "a['public_inputs']['selection_files'] == 24 and a['public_inputs']['selection_projects'] == 6")
    _require((a['public_inputs']['selection_bytes'], a['public_inputs']['selection_physical_lines']) == (268614, 8191), "(a['public_inputs']['selection_bytes'], a['public_inputs']['selection_physical_lines']) == (268614, 8191)")
    _require(a['source_safety']['forbidden_network_imports'] == 0, "a['source_safety']['forbidden_network_imports'] == 0")
    _require(a['source_safety']['forbidden_dynamic_execution_calls'] == 0, "a['source_safety']['forbidden_dynamic_execution_calls'] == 0")
    _require(a['source_safety']['producer_checker_cross_imports'] == 0, "a['source_safety']['producer_checker_cross_imports'] == 0")
    _require(a['retained_upstream']['retained_bigcode_functions_ast_matched'] == 2, "a['retained_upstream']['retained_bigcode_functions_ast_matched'] == 2")
    _require(a['retained_upstream']['humaneval_example_exact_record_matched'], "a['retained_upstream']['humaneval_example_exact_record_matched']")
    _require(a['evidence_tables']['scholarly_or_standard_resource_rows'] == 85, "a['evidence_tables']['scholarly_or_standard_resource_rows'] == 85")
    if include_scaling:
        for shape in ('chain-distinct', 'alias-copy', 'many-roots'):
            s = get('scaling-' + shape + '.json')
            _require(len(s['measurements']) == 12, "len(s['measurements']) == 12")
            _require({r['nodes'] for r in s['measurements']} == {512, 2048, 8192, 20000}, "{r['nodes'] for r in s['measurements']} == {512, 2048, 8192, 20000}")
            _require(all((r['exit_code'] == 0 for r in s['observations'])), "all((r['exit_code'] == 0 for r in s['observations']))")
    _require(q['json_boundaries']['rejected_count'] == 14, 'authenticated state syntax cases')
    _require(d['replay_call_boundaries']['local_checker_calls'] == {'issue': 1, 'verify': 0, 'compose': 0, 'verify_bound': 1, 'accept_bound': 1}, 'replay role boundary')
    return {'context_checks': 'passed', 'generated_result_files': ['campaign.json', 'composition-baselines.json', 'finite-closure.json', 'finite-cuts.json', 'context.json', 'natural-duplicates.json', 'builder-bridge.json', 'deployment.json', 'freshness.json', 'boundaries.json', 'package-audit.json'], 'scaling_included': include_scaling}

def _cpu_self():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def execute_part(part):
    began = time.perf_counter()
    cpu_began = _cpu_self()
    records = []
    dest = RESULTS / ('reproduction-' + part + '.json')
    identity = execution_identity()
    outcome = {'status': 'running', 'part': part, 'execution_identity': identity,
               'worker_count': 1, 'commands': records, 'result_sha256': {}}
    write_json(dest, outcome)  # Invalidate any old success before launching work.
    def run(arguments):
        remaining = PART_LIMITS[part] - (time.perf_counter() - began)
        _require(remaining > 3, 'part wall budget exhausted before command')
        row = supervise(arguments, wall_limit=min(remaining - 3, 160 if part == 'hardening' else 55))
        records.append(row)
        print(json.dumps({key: row[key] for key in ('command', 'status', 'exit_code', 'wall_seconds')}), flush=True)
        _require(row['status'] == 'passed', 'command failed: ' + ' '.join(arguments) + ': ' + str(row['termination_reason']))
        return row
    try:
        if part == 'hardening':
            for command in (['tests/builder_bridge.py', '--smoke'], ['tests/freshness.py', '--json-only'],
                            ['tests/runner_guards.py'], ['tests/package_audit.py'],
                            ['tests/scientific_regressions.py', '--output', 'results/scientific-regressions.json'],
                            ['tests/reviewer_hardening.py']):
                run(command)
            outcome['checks'] = validate_hardening()
        elif part == 'checks':
            for command in (
                ['tests/pilot.py'], ['tests/campaign.py'], ['tests/finite.py', 'closure'],
                ['tests/finite.py', 'cuts'], ['tests/context.py'], ['tests/natural.py'],
                ['tests/builder_bridge.py'], ['tests/deployment.py'], ['tests/freshness.py'], ['tests/boundaries.py'],
                ['src/ledger.py', 'data/example-policy.json', 'data/example-ledger.json'],
                ['src/checker.py', 'data/example-policy.json', 'data/example-ledger.json']):
                run(command)
            with tempfile.TemporaryDirectory(prefix='containment-emission-') as temporary:
                output = str(Path(temporary) / 'checked.zip')
                row = run(['src/emitter.py', 'data/example-policy.json', 'data/example-ledger.json', output])
                row['command'][-1] = '<temporary-output>/checked.zip'
                with zipfile.ZipFile(output) as archive:
                    _require(len(archive.namelist()) == 2, 'emitted example member count')
                    for name in archive.namelist():
                        archive.read(name).decode('utf-8')
            outcome['checks'] = check_results(False)
        else:
            shape = part.removeprefix('scaling-')
            run(['tests/scaling.py', '--shape', shape])
            raw = json.loads((RESULTS / ('scaling-' + shape + '.json')).read_text())
            _require(len(raw['measurements']) == 12 and all(row['exit_code'] == 0 for row in raw['observations']), 'scaling output')
        _require(identity == execution_identity(), 'source/input changed during part')
        outcome['result_sha256'] = {name: hashlib.sha256((RESULTS / name).read_bytes()).hexdigest()
                                    for name in PART_OUTPUTS[part]}
        outcome['status'] = 'passed-part'
    except (Exception, KeyboardInterrupt) as exc:
        outcome['status'] = 'failed'
        outcome['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        outcome['wall_seconds'] = time.perf_counter() - began
        outcome['whole_child_cpu_seconds'] = sum(row['whole_child_cpu_seconds'] for row in records)
        outcome['coordinator_cpu_seconds'] = _cpu_self() - cpu_began
        outcome['total_cpu_seconds'] = outcome['whole_child_cpu_seconds'] + outcome['coordinator_cpu_seconds']
        outcome['coordinator_peak_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        outcome['peak_child_rss_kib'] = max((row['peak_child_rss_kib'] for row in records), default=0)
        outcome['sampled_peak_group_rss_kib'] = max((row['sampled_peak_group_rss_kib'] for row in records), default=0)
        outcome['part_wall_limit_seconds'] = PART_LIMITS[part]
        write_json(dest, outcome)
    print(json.dumps({k: outcome[k] for k in ('status', 'part', 'wall_seconds', 'total_cpu_seconds', 'peak_child_rss_kib')}), flush=True)
    _require(outcome['status'] == 'passed-part', outcome.get('error', 'part failed'))


def verify_saved():
    began = time.perf_counter()
    cpu_began = _cpu_self()
    identity = execution_identity()
    result = {'status': 'failed', 'execution_identity': identity}
    try:
        parts = []
        for name in PARTS:
            part = json.loads((RESULTS / ('reproduction-' + name + '.json')).read_text())
            _require(part['status'] == 'passed-part' and part['part'] == name, 'missing/failed current part: ' + name)
            _require(part['execution_identity'] == identity, 'source/input identity mismatch: ' + name)
            _require(all(row['status'] == 'passed' and not row['remaining_descendants'] for row in part['commands']), 'failed/unclean command: ' + name)
            _require(set(part['result_sha256']) == set(PART_OUTPUTS[name]), 'result inventory: ' + name)
            for filename, expected_digest in part['result_sha256'].items():
                _require(hashlib.sha256((RESULTS / filename).read_bytes()).hexdigest() == expected_digest,
                         'result changed or missing: ' + filename)
            parts.append(part)
        hardening = validate_hardening()
        checks = check_results(True)
        result = {'status': 'passed', 'execution_identity': identity, 'parts': parts,
            'checks': checks, 'hardening': hardening, 'worker_count': 1,
            'whole_child_cpu_seconds': sum(p['whole_child_cpu_seconds'] for p in parts),
            'coordinator_cpu_seconds': sum(p['coordinator_cpu_seconds'] for p in parts),
            'sum_part_wall_seconds': sum(p['wall_seconds'] for p in parts),
            'peak_child_rss_kib': max(p['peak_child_rss_kib'] for p in parts),
            'sampled_peak_group_rss_kib': max(p['sampled_peak_group_rss_kib'] for p in parts),
            'accounting_scope': 'Five saved sequential supervised parts, including mandatory small regressions, guard tests, all additional hardening microbenchmark warmups/repetitions, original checks, all three primary scaling shapes, coordinators and waited/adopted descendants; plus this saved-result verification. Excludes earlier development, document build, and archive packaging.',
            'verification_scope': 'Validates current source/input identity, saved command status, output digests and scientific invariants; does not rerun experiments.'}
    except (Exception, KeyboardInterrupt) as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    result['verification_cpu_seconds'] = _cpu_self() - cpu_began
    result['verification_wall_seconds'] = time.perf_counter() - began
    if result['status'] == 'passed':
        result['total_cpu_seconds'] = result['whole_child_cpu_seconds'] + result['coordinator_cpu_seconds'] + result['verification_cpu_seconds']
        result['accounted_wall_seconds'] = result['sum_part_wall_seconds'] + result['verification_wall_seconds']
    write_json(RESULTS / 'reproduction.json', result)
    _require(result['status'] == 'passed', result.get('error', 'verification failed'))
    print(json.dumps({k: result[k] for k in ('status', 'total_cpu_seconds', 'accounted_wall_seconds', 'peak_child_rss_kib')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--checks', action='store_true')
    choice.add_argument('--scale', choices=('chain-distinct', 'alias-copy', 'many-roots'))
    choice.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    RESULTS.mkdir(exist_ok=True)
    configure_supervisor()
    if args.verify:
        verify_saved()
    elif args.checks:
        # Nothing scientific runs before part accounting starts.
        execute_part('hardening')
        execute_part('checks')
    else:
        execute_part('scaling-' + args.scale)

if __name__ == '__main__':
    main()
