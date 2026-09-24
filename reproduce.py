#!/usr/bin/env python3
"""Sequential, offline reproduction. Corpus text is never executed or imported."""
import argparse
import json
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


def child_limits():
    """A per-process virtual-memory ceiling supplements measured RSS."""
    ceiling = 3 * 1024**3
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY:
        ceiling = min(ceiling, hard)
    resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 125))


def run(arguments, records, started):
    remaining = 35 - (time.perf_counter() - started)
    if remaining <= 0:
        raise RuntimeError('overall 35-second part ceiling reached')
    command = [sys.executable, *arguments]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    begin = time.perf_counter()
    # A private process group contains the scaling coordinator and its child.
    # Killing only the coordinator on timeout could leave that child running.
    proc = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
        start_new_session=True, preexec_fn=child_limits)
    interrupted = None
    try:
        stdout, stderr = proc.communicate(timeout=min(30, remaining))
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        interrupted = exc
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
    completed = subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    entry = {
        'command': ['python', *arguments], 'exit_code': completed.returncode,
        'wall_seconds': time.perf_counter() - begin,
        'whole_child_cpu_seconds': after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
        'cumulative_peak_child_rss_kib': after.ru_maxrss,
        'stdout': completed.stdout, 'stderr': completed.stderr,
    }
    if interrupted is not None:
        entry['termination_reason'] = type(interrupted).__name__
    records.append(entry)
    if interrupted is not None:
        raise interrupted
    if len(completed.stdout) > 65536 or len(completed.stderr) > 65536:
        raise RuntimeError('unexpected reproduction output volume')
    if completed.returncode:
        raise RuntimeError('command failed: ' + ' '.join(arguments))
    print(json.dumps({k: entry[k] for k in ('command','exit_code','wall_seconds')}), flush=True)
    return completed


def check_results(include_scaling):
    def get(name):
        return json.loads((RESULTS / name).read_text())
    # Exact, scientifically meaningful invariants; timing fields are not pinned.
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
    assert (c['source_projects'], c['source_files'], c['families'], c['valid_cases'], c['positive_cases'], c['negative_cases']) == (6,24,20,480,336,144)
    assert c['structural_mutations'] == 288
    assert c['composition_contexts'] == 2457 and c['heterogeneous_composition_contexts'] == 51
    assert c['contexts_invalidating_a_local_clean_decision'] == 793 and c['newly_blocked_output_decisions'] == 846
    assert c['composition_baselines']['context-complete-summary']['exact_outputs'] == 4962
    assert c['composition_baselines']['context-complete-summary']['false_clean_outputs'] == 0
    assert c['composition_baselines']['cached-local-decisions']['false_clean_outputs'] == 846
    assert c['composition_baselines']['seed-to-output-equality']['false_clean_outputs'] == 1626
    assert c['composition_baselines']['output-endpoint-alias']['false_clean_outputs'] == 492
    assert f['cases'] == 327680 and f['disagreements'] == 0
    assert (g['graphs'],g['cut_certificates'],g['infeasible_certificates']) == (15625,11456,4169)
    assert g['mutations_rejected'] == 2059 and g['greedy_gaps'] == 52
    assert (b['clean_archives_emitted_and_read_back'], b['blocked_archives_not_created']) == (144,336)
    assert (b['inclusion_minimal_diagnoses'],b['uncuttable_diagnoses']) == (288,192)
    assert len(b['boundary_checks']) == 20 and b['false_clean_claims_rejected_and_diagnosable'] == 336
    assert x['merged_graph_seed_contexts'] == 262144 and x['disagreements'] == 0
    assert x['actual_rewrite_pipeline_probe_contexts'] == 64
    assert (n['duplicate_line_classes'], n['cross_project_duplicate_classes'], n['pair_contexts']) == (127,6,216)
    assert n['cross_project_pair_contexts'] == 13
    assert n['complete_summary_equal_to_joined_replay'] == 216
    assert n['authenticated_capsule_compositions_equal_to_joined_replay'] == 216
    assert n['endpoint_only_false_clean_outputs'] == 216 and n['capsules_issued_and_verified'] == 432
    assert d['tamper_or_context_cases_rejected'] == 23
    assert (r['source_projects'], r['retained_source_files']) == (6, 24)
    assert r['matched_roots_total'] == 25
    assert r['rewritten_endpoints_passing_same_upstream_scanner'] == 25
    assert r['rewritten_endpoints_blocked_by_lineage'] == 25
    assert r['final_state_false_clean_if_used_alone'] == 25
    assert r['clean_controls'] == 24 and r['clean_controls_accepted_by_scanner_and_ledger'] == 24
    assert r['independent_upstream_oracle_cases'] == 4 and r['independent_upstream_oracle_disagreements'] == 0
    assert q['strict_replay_rejected_after_process_restart']
    assert q['explicit_epoch_rotation_accepted'] and q['old_epoch_downgrade_rejected']
    assert q['race_processes'] == 8 and q['race_successful_acceptors'] == 1 and q['race_stale_rejections'] == 7
    assert q['pre_replace_death_retained_prior_complete_state']
    assert q['post_replace_death_exposed_new_complete_state']
    assert not q['whole_state_file_rollback_detected']
    assert d['race_processes'] == 8 and d['race_successful_publishers'] == 1
    assert d['race_temporary_files_remaining'] == 0
    assert d['precommit_deaths_created_no_destination'] and d['postlink_deaths_left_complete_destination']
    assert not d['power_loss_or_arbitrary_filesystem_durability_tested']
    assert x['two_by_two_bipartite_relations_distinguished'] == 16
    assert a['status'] == 'passed'
    assert a['public_inputs']['selection_files'] == 24 and a['public_inputs']['selection_projects'] == 6
    assert (a['public_inputs']['selection_bytes'], a['public_inputs']['selection_logical_lines']) == (268614, 8215)
    assert a['source_safety']['forbidden_network_imports'] == 0
    assert a['source_safety']['forbidden_dynamic_execution_calls'] == 0
    assert a['source_safety']['producer_checker_cross_imports'] == 0
    assert a['retained_upstream']['retained_bigcode_functions_ast_matched'] == 2
    assert a['retained_upstream']['humaneval_example_exact_record_matched']
    assert a['evidence_tables']['scholarly_or_standard_resource_rows'] == 85
    if include_scaling:
        for shape in ('chain-distinct','alias-copy','many-roots'):
            s = get('scaling-' + shape + '.json')
            assert len(s['measurements']) == 12
            assert {r['nodes'] for r in s['measurements']} == {512,2048,8192,20000}
            assert all(r['exit_code'] == 0 for r in s['observations'])
    return {'context_checks': 'passed', 'generated_result_files': [
        'campaign.json','composition-baselines.json','finite-closure.json','finite-cuts.json','context.json','natural-duplicates.json','builder-bridge.json','deployment.json','freshness.json','boundaries.json','package-audit.json'],
        'scaling_included': include_scaling}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--checks', action='store_true')
    choice.add_argument('--scale', choices=('chain-distinct','alias-copy','many-roots'))
    choice.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    RESULTS.mkdir(exist_ok=True)
    if args.verify:
        # This collates current saved runs; it does not itself execute their tests.
        checks=check_results(True)
        names=['checks','scaling-chain-distinct','scaling-alias-copy','scaling-many-roots']
        parts=[json.loads((RESULTS/('reproduction-'+n+'.json')).read_text()) for n in names]
        assert all(p['status']=='passed-part' and p['part']==n for p,n in zip(parts,names))
        report={'status':'passed','parts':parts,'checks':checks,'worker_count':1,
                'whole_child_cpu_seconds':sum(p['whole_child_cpu_seconds'] for p in parts),
                'sum_part_wall_seconds':sum(p['wall_seconds'] for p in parts),
                'peak_child_rss_kib':max(p['peak_child_rss_kib'] for p in parts),
                'accounting_scope':'Four saved sequential parts and waited descendants; not earlier exploration.',
                'verification_scope':'Checks saved part reports and current scientific invariants; does not rerun tests.'}
        (RESULTS/'reproduction.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:report[k] for k in ('status','whole_child_cpu_seconds','sum_part_wall_seconds','peak_child_rss_kib')}))
        return
    began=time.perf_counter();records=[]
    part='checks' if args.checks else 'scaling-'+args.scale
    dest=RESULTS/('reproduction-'+part+'.json')
    try:
        if args.checks:
            for arguments in (
                ['tests/pilot.py'], ['tests/campaign.py'], ['tests/finite.py','closure'],
                ['tests/finite.py','cuts'], ['tests/context.py'], ['tests/natural.py'],
                ['tests/builder_bridge.py'], ['tests/deployment.py'], ['tests/freshness.py'], ['tests/boundaries.py'],
                ['tests/package_audit.py'],
                ['src/ledger.py','data/example-policy.json','data/example-ledger.json'],
                ['src/checker.py','data/example-policy.json','data/example-ledger.json']):
                run(arguments,records,began)
            with tempfile.TemporaryDirectory(prefix='containment-emission-') as temp:
                output=str(Path(temp)/'checked.zip')
                run(['src/emitter.py','data/example-policy.json','data/example-ledger.json',output],records,began)
                records[-1]['command'][-1]='<temporary-output>/checked.zip'
                with zipfile.ZipFile(output) as archive:
                    assert len(archive.namelist())==2
                    for name in archive.namelist():archive.read(name).decode('utf-8')
            check_results(False)
        else:
            run(['tests/scaling.py','--shape',args.scale],records,began)
            raw=json.loads((RESULTS/('scaling-'+args.scale+'.json')).read_text())
            assert len(raw['measurements'])==12 and all(r['exit_code']==0 for r in raw['observations'])
        outcome={'status':'passed-part','part':part,'worker_count':1,'commands':records,
                 'wall_seconds':time.perf_counter()-began,
                 'whole_child_cpu_seconds':sum(x['whole_child_cpu_seconds'] for x in records),
                 'coordinator_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                 'peak_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
        dest.write_text(json.dumps(outcome,indent=2)+'\n')
        print(json.dumps({k:outcome[k] for k in ('status','part','wall_seconds','whole_child_cpu_seconds','peak_child_rss_kib')}))
    except (Exception,KeyboardInterrupt) as exc:
        dest.write_text(json.dumps({'status':'failed','part':part,'commands':records,
                                   'error':type(exc).__name__+': '+str(exc)},indent=2)+'\n')
        raise




def _run_reviewer_hardening_gate() -> None:
    """Run additive reviewer-facing checks as part of the public check command."""
    import os as _os
    import subprocess as _subprocess
    import sys as _sys
    from pathlib import Path as _Path
    _root = _Path(__file__).resolve().parent
    _subprocess.run(
        [_sys.executable, str(_root / "tests" / "reviewer_hardening.py")],
        cwd=_root,
        check=True,
        env={**_os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"},
    )

if __name__=='__main__':
    if "--checks" in sys.argv:
        _run_reviewer_hardening_gate()
    main()
