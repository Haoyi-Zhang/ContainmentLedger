"""Benign emission, diagnosis, parser and representation boundary checks."""
import sys,json,time,resource,tempfile,zipfile,copy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import ledger,checker,fixtures,emitter,diagnose,cuts,cutcheck

def main():
    cpu=time.process_time();wall=time.perf_counter();emitted=blocked=certified=infeasible=false_clean=0;checks=[];diagnoses=[]
    with tempfile.TemporaryDirectory(prefix='scoped-replay-') as temp:
        output=Path(temp)/'emitted.zip'
        for f in fixtures.public_files(ROOT):
            code=f.read_text(encoding='utf-8')
            for scenario in fixtures.SCENARIOS:
                p,l,expected=fixtures.case(code,scenario);ledger.annotate(p,l)
                if expected:
                    try:emitter.emit(p,l,output)
                    except checker.Rejected:blocked+=1
                    else:raise AssertionError('blocked output emitted')
                    assert not output.exists()
                else:
                    stats=emitter.emit(p,l,output)
                    with zipfile.ZipFile(output) as z:
                        assert len(z.namelist())==2*len(l['outputs'])
                        for item in l['outputs']:
                            for prefix,field in (('code/','code'),('intent/','intent')):
                                assert z.read(prefix+item['name'])==item[field].encode('utf-8')
                    try:emitter.emit(p,l,output)
                    except FileExistsError:pass
                    else:raise AssertionError('existing file overwritten')
                    output.unlink();emitted+=1
                groups={u['id']:u['op'] for u in l['units'] if u['op']!='import'}
                graph,cert=diagnose.diagnose(p,l,groups)
                independent=checker.audit_graph(p,l,groups)
                assert independent==graph
                verdict=cutcheck.verify(independent,cert)
                if expected:
                    forged=copy.deepcopy(l);forged['claims']={k:0 for k in forged['claims']}
                    for fn,error in ((ledger.validate,ledger.Invalid),(checker.verify,checker.Rejected)):
                        try:fn(p,forged)
                        except error:pass
                        else:raise AssertionError('false-clean claims accepted')
                    assert checker.audit_graph(p,forged,groups)==graph
                    false_clean+=1
                minimum=cuts.exact_minimum(graph)
                if cert['status']=='infeasible': assert minimum is None;infeasible+=1
                else:certified+=1;assert len(cert['cut'])>=len(minimum)
                diagnoses.append({'shard':f.name,'case':scenario,'kind':cert['status'],
                                  'cut_size':len(cert['cut']) if cert['status']=='cut' else None,
                                  'minimum_size':len(minimum) if minimum is not None else None})
        malformed=['{"roots":[],"roots":[],"repairs":[]}','{"x":NaN}','['*70+'0'+']'*70,'9'*5000]
        for text in malformed:
            fp=Path(temp)/'malformed.json';fp.write_text(text)
            for reader,error in ((ledger.load,ledger.Invalid),(checker.read_json,checker.Rejected)):
                try:reader(fp)
                except error:checks.append('malformed JSON rejected')
                else:raise AssertionError('malformed JSON accepted')
    for fn,error in ((ledger.member,ledger.Invalid),(checker.path,checker.Rejected)):
        try:fn('bad\ud800.txt')
        except error:checks.append('member Unicode scalar checked')
        else:raise AssertionError('invalid member Unicode accepted')
    # All supported text operations, empty input, Unicode offsets, and fixed limits.
    empty={'units':[],'bundles':[{'id':'empty','op':'collect','items':[]}],'final':'empty','outputs':[],'claims':{}}
    assert ledger.validate({'roots':[],'repairs':[]},empty)['blocked']==0
    assert checker.verify({'roots':[],'repairs':[]},empty)['blocked']==0;checks.append('empty ledger')
    for raw in ('',' \t'*50000,'a\r\nb\rc \t\n','\u03bb\r\n\u4e2d \t'):
        assert ledger.canonical(raw)==checker.norm(raw);checks.append('normalizer boundary')
    p,l,_=fixtures.case('x','C05');l['units'][-1]['start']=True
    for verify,error in ((ledger.validate,ledger.Invalid),(checker.verify,checker.Rejected)):
        try:verify(p,l)
        except error:checks.append('Boolean index rejected')
        else:raise AssertionError('Boolean index accepted')
    p,l,_=fixtures.case('x','C11');u=copy.deepcopy(l['units'][-1]);u['id']='copied';u['op']='copy';u['parent']=l['units'][-1]['id'];u.pop('old');u.pop('new');l['units'].append(u)
    l['bundles'][0]['items'][0]['unit']='copied';l['outputs'][0]['unit']='copied'
    ledger.annotate(p,l);checker.verify(p,l);checks.append('copy replay')
    large='x'*262144
    pp={'roots':[{'id':'r','code':large,'intent':'','labels':0}],'repairs':[]}
    ll={'units':[{'id':'u','op':'import','source':'r','code':large,'intent':''}],
        'bundles':[{'id':'f','op':'collect','items':[{'name':str(k)+'.txt','unit':'u'} for k in range(300)]}],
        'final':'f','outputs':[{'name':str(k)+'.txt','unit':'u','code':large,'intent':''} for k in range(300)],'claims':{'u':0}}
    for fn,error in ((ledger.validate,ledger.Invalid),(checker.verify,checker.Rejected)):
        try:fn(pp,ll)
        except error:checks.append('expanded export budget enforced')
        else:raise AssertionError('oversized expanded output accepted')
    # The same observable recipe cannot attest two different physical histories.
    p={'roots':[{'id':'marked','code':'alpha','intent':'','labels':1},
                {'id':'clear','code':'beta','intent':'','labels':0}],'repairs':[]}
    l={'units':[{'id':'u','op':'import','source':'clear','code':'beta','intent':''}],
       'bundles':[{'id':'f','op':'collect','items':[{'name':'unit.txt','unit':'u'}]}],
       'final':'f','outputs':[{'name':'unit.txt','unit':'u','code':'beta','intent':''}],'claims':{'u':0}}
    assert checker.verify(p,l)['blocked']==0
    observational={'trusted_policy':p,'reported_ledger':l,
                   'declared_reconstruction':'Import clear (beta).',
                   'unobserved_history_alternative':'Replace alpha by beta before reporting the same clear import.',
                   'verifier_decision':'Accepts the declared clean reconstruction, not the unobserved history.'}
    (ROOT/'data'/'observational-counterexample.json').write_text(json.dumps(observational,indent=2)+'\n')
    (ROOT/'results'/'diagnoses.json').write_text(json.dumps(diagnoses,indent=2)+'\n')
    result={'clean_archives_emitted_and_read_back':emitted,'blocked_archives_not_created':blocked,
            'inclusion_minimal_diagnoses':certified,'uncuttable_diagnoses':infeasible,'boundary_checks':checks,
            'false_clean_claims_rejected_and_diagnosable':false_clean,'observable_history_boundary_demonstrated':True,'cpu_seconds':time.process_time()-cpu,
            'wall_seconds':time.perf_counter()-wall,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    (ROOT/'results'/'boundaries.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
