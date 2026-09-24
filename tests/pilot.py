"""One-worker discriminating pilot, with negative controls and an exact oracle."""
import sys,time,resource,json,copy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
import ledger,checker,fixtures,cuts,cutcheck

def main():
    cpu=time.process_time(); wall=time.perf_counter(); records=[]
    for file in fixtures.public_files(ROOT)[:2]:
        code=file.read_text(encoding='utf-8')
        for scenario in ('C07','C08','C09','C15'):
            policy,log,expected=fixtures.case(code,scenario)
            answer=ledger.annotate(policy,log); independent=checker.verify(policy,log)
            assert bool(answer['blocked'])==expected and independent['blocked']==answer['blocked']
            records.append({'file':file.name,'scenario':scenario,'expected_blocked':expected,'blocked':answer['blocked']})
    policy,log,_=fixtures.case(code,'C09'); ledger.annotate(policy,log)
    invalid=copy.deepcopy(log); invalid['units'][-1]['authority']='unapproved'
    rejected=[]
    for fn,error in ((ledger.validate,ledger.Invalid),(checker.verify,checker.Rejected)):
        try: fn(policy,invalid)
        except error: rejected.append(True)
        else: raise AssertionError('unapproved repair accepted')
    graph={'n':5,'sources':[0],'targets':[4], 'edges':[[0,i,'a'] for i in (1,2,3)]+[[i,4,'z'+str(i)] for i in (1,2,3)]}
    cert=cuts.minimize(graph); exact=cuts.exact_minimum(graph)
    assert len(cert['cut'])==3 and exact==['a']; cutcheck.verify(graph,cert)
    output={'stage':'pre-lock-pilot','workers':1,'records':records,'unauthorized_repair_rejected_by_both':all(rejected),
            'greedy_size':len(cert['cut']),'exact_minimum_size':len(exact),
            'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.perf_counter()-wall,
            'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'interpretation':'Finite checks only. No corpus code executed; no model, poisoning attack, or production workload.'}
    (ROOT/'results'/'pilot.json').write_text(json.dumps(output,indent=2)+'\n')
    (ROOT/'data'/'example-policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    (ROOT/'data'/'example-ledger.json').write_text(json.dumps(log,indent=2)+'\n')
    print(json.dumps(output,indent=2))
if __name__=='__main__':main()
