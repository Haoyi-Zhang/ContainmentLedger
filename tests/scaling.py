"""Fresh-process, deterministic stress shapes; no imported or executed corpus text.

Use --shape NAME to run twelve observations, or --all for all 36. Each child
is sequential and has a 30-second wall timeout. Raw results are overwritten
per shape; no measurement is a deployed workload or statistical population.
"""
import argparse,csv,json,os,resource,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SIZES=(512,2048,8192,20000)
SHAPES=('chain-distinct','alias-copy','many-roots')

def fixture(shape,n):
    p={'roots':[],'repairs':[]}; u=[]
    if shape in ('chain-distinct','alias-copy'):
        p['roots']=[{'id':'r','code':'value00000','intent':'task','labels':7}]
        u=[{'id':'u0','op':'import','source':'r','code':'value00000','intent':'task'}]
        for k in range(1,n-1):
            if shape=='chain-distinct':
                u.append({'id':'u'+str(k),'op':'rewrite','parent':'u'+str(k-1),
                          'old':'value'+str(k-1).zfill(5),'new':'value'+str(k).zfill(5),
                          'code':'value'+str(k).zfill(5),'intent':'task'})
            else:
                u.append({'id':'u'+str(k),'op':'copy','parent':'u0',
                          'code':'value00000','intent':'task'})
        selected=u[-1:] if shape=='chain-distinct' else u
    elif shape=='many-roots':
        for k in range(n//2):
            body='class'+str(k%128).zfill(3); intent='task'+str(k%31)
            p['roots'].append({'id':'r'+str(k),'code':body,'intent':intent,'labels':7 if k%97==0 else 0})
            u.append({'id':'u'+str(k),'op':'import','source':'r'+str(k),'code':body,'intent':intent})
        selected=u
    else: raise ValueError('unknown shape')
    l={'units':u,'bundles':[{'id':'f','op':'collect','items':[{'name':str(k)+'.txt','unit':x['id']} for k,x in enumerate(selected)]}],
       'final':'f','outputs':[{'name':str(k)+'.txt','unit':x['id'],'code':x['code'],'intent':x['intent']} for k,x in enumerate(selected)],
       'claims':{x['id']:0 for x in u}}
    return p,l

def child(shape,n,rep):
    sys.path.insert(0,str(ROOT/'src'))
    import ledger,checker,merge
    start_cpu=time.process_time();start=time.perf_counter()
    p,l=fixture(shape,n); generated=time.perf_counter()
    a=ledger.annotate(p,l);produced=time.perf_counter()
    b=checker.verify(p,l);checked=time.perf_counter()
    assert a['labels']==b['labels'] and a['nodes']==n
    sm=merge.summarize(p,l);summarized=time.perf_counter()
    independent=checker.verify(p,l,summary=True);ind_summarized=time.perf_counter()
    assert sm==independent
    composed=merge.compose([independent]);merged=time.perf_counter()
    assert composed==[[a['labels'][x['unit']] for x in l['outputs']]]
    raw_p=json.dumps(p,separators=(',',':')).encode();raw_l=json.dumps(l,separators=(',',':')).encode()
    raw_s=json.dumps(sm,separators=(',',':')).encode()
    with tempfile.TemporaryDirectory(prefix='scope-size-') as d:
        pp=Path(d)/'policy.json';ll=Path(d)/'ledger.json';pp.write_bytes(raw_p);ll.write_bytes(raw_l)
        parse_start=time.perf_counter()
        p1,l1=ledger.load(pp),ledger.load(ll);p2,l2=checker.read_json(pp),checker.read_json(ll)
        parsed=time.perf_counter()
        assert p1==p2==p and l1==l2==l
    return {'shape':shape,'nodes':n,'repeat':rep,'edges':a['edges'],'outputs':a['retained'],'blocked':a['blocked'],
            'input_bytes':len(raw_p)+len(raw_l),'summary_bytes':len(raw_s),
            'generation_seconds':generated-start,'producer_seconds':produced-generated,
            'checker_seconds':checked-produced,'producer_summary_seconds':summarized-checked,
            'checker_summary_seconds':ind_summarized-summarized,'compose_seconds':merged-ind_summarized,
            'both_json_readers_seconds':parsed-parse_start,'body_cpu_seconds':time.process_time()-start_cpu,
            'body_wall_seconds':time.perf_counter()-start,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}

def run(shape):
    rows=[]; records=[]
    for n in SIZES:
        for rep in range(1,4):
            cmd=[sys.executable,'-S',str(Path(__file__).resolve()),'--child',shape,str(n),str(rep)]
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
            before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.perf_counter()
            done=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=30,check=False)
            after=resource.getrusage(resource.RUSAGE_CHILDREN)
            if done.returncode: raise RuntimeError('size child failed: '+done.stderr[:4096])
            row=json.loads(done.stdout);rows.append(row)
            records.append({'shape':shape,'nodes':n,'repeat':rep,'exit_code':done.returncode,
                            'whole_child_cpu_seconds':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                            'whole_child_wall_seconds':time.perf_counter()-start,'stderr':done.stderr,
                            'peak_child_rss_kib':row['peak_rss_kib']})
    dest=ROOT/'results';dest.mkdir(exist_ok=True)
    with (dest/('scaling-'+shape+'.csv')).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (dest/('scaling-'+shape+'.json')).write_text(json.dumps({'observations':records,'measurements':rows},indent=2)+'\n')
    print(json.dumps({'shape':shape,'runs':len(rows),'whole_child_cpu_seconds':sum(r['whole_child_cpu_seconds'] for r in records),
                     'max_body_wall_seconds':max(r['body_wall_seconds'] for r in rows),'max_rss_kib':max(r['peak_rss_kib'] for r in rows)}))

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--child',nargs=3);ap.add_argument('--shape',choices=SHAPES);ap.add_argument('--all',action='store_true');args=ap.parse_args()
    if args.child: print(json.dumps(child(args.child[0],int(args.child[1]),int(args.child[2]))))
    elif args.all:
        for name in SHAPES:run(name)
    elif args.shape:run(args.shape)
    else:ap.error('choose --shape or --all')
