"""Exhaustive small closure and grouped-cut oracles, in bounded separate modes."""
import sys,time,resource,json,itertools,copy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import ledger,cuts,cutcheck

def oracle(n,seeds,edges):
    # Floyd-Warshall over each bit, not a worklist, and no producer helper calls.
    labels=[0]*n
    for bit in (1,2,4):
        r=[[i==j for j in range(n)] for i in range(n)]
        for a,b,m,_ in edges:
            if m&bit:r[a][b]=True
        for k in range(n):
            for i in range(n):
                if r[i][k]:
                    for j in range(n):r[i][j]=r[i][j] or r[k][j]
        for j in range(n):
            if any(seeds[i]&bit and r[i][j] for i in range(n)):labels[j]|=bit
    return labels

def closure_cases():
    rows=[];n=3;positions=[(0,1),(0,2),(1,2)]
    for first in range(8):
        cpu=time.process_time();count=0
        for other in itertools.product(range(8),repeat=2):
            masks=(first,)+other
            edges=[(a,b,m,None) for (a,b),m in zip(positions,masks) if m]
            for seed in itertools.product(range(8),repeat=3):
                actual=ledger.closure(range(n),dict(enumerate(seed)),edges)
                assert list(actual.values())==oracle(n,seed,edges),(masks,seed)
                count+=1
        rows.append({'family':'three-node-all-mask-DAG','first_edge_mask':first,'cases':count,'cpu_seconds':time.process_time()-cpu})
    n=4;positions=[(a,b) for a in range(n) for b in range(n) if a!=b]
    for prefix in range(16):
        cpu=time.process_time();count=0
        for suffix in range(256):
            encoding=(prefix<<8)|suffix
            edges=[(a,b,1,None) for k,(a,b) in enumerate(positions) if encoding>>k&1]
            for seedmask in range(16):
                seeds=[int(bool(seedmask>>k&1)) for k in range(n)]
                actual=ledger.closure(range(n),dict(enumerate(seeds)),edges)
                assert list(actual.values())==oracle(n,seeds,edges),(encoding,seedmask)
                count+=1
        rows.append({'family':'four-node-all-directed-B-graphs','edge_prefix':prefix,'cases':count,'cpu_seconds':time.process_time()-cpu})
    return {'batches':rows,'cases':sum(x['cases'] for x in rows),'disagreements':0,
            'encoding':'3-node forward DAG: 3 edges x masks 0..7 and 3 seeds x labels 0..7. 4-node directed no-self-edge graphs: 12 Boolean B edges and 4 Boolean B seeds. No claim of exhaustive larger or all mixed-label cyclic graphs.'}

def boolean_oracle_cut(g,cut):
    # Fixed-point closure, not generator BFS or witness verifier.
    reached=set(g['sources'])
    while True:
        old=set(reached)
        for a,b,action in g['edges']:
            if a in reached and (action is None or action not in cut):reached.add(b)
        if old==reached:return not reached.intersection(g['targets'])

def cut_cases():
    positions=[(0,1),(0,2),(0,3),(1,2),(1,3),(2,3)]
    choices=['absent',None,'a','b','c'];rows=[];valid=0;infeasible=0;mutants=0;gaps=0
    for code,setting in enumerate(itertools.product(choices,repeat=len(positions))):
        g={'n':4,'sources':[0],'targets':[3], 'edges':[[a,b,c] for (a,b),c in zip(positions,setting) if c!='absent']}
        actions=sorted({e[2] for e in g['edges'] if e[2] is not None})
        all_cuts=[set(c) for n in range(len(actions)+1) for c in itertools.combinations(actions,n) if boolean_oracle_cut(g,set(c))]
        cert=cuts.minimize(g);cutcheck.verify(g,cert)
        if not all_cuts:
            assert cert['status']=='infeasible';infeasible+=1
        else:
            C=set(cert['cut']);assert C in all_cuts and all(C-{a} not in all_cuts for a in C)
            minimum=min(map(len,all_cuts));exact=cuts.exact_minimum(g)
            assert len(exact)==minimum;valid+=1;gaps+=len(C)>minimum
            if code%11==0:
                wrong=copy.deepcopy(cert);wrong['reachable']=[]
                try:cutcheck.verify(g,wrong)
                except cutcheck.BadCertificate:mutants+=1
                else:raise AssertionError('bad reachable set accepted')
                if C:
                    wrong=copy.deepcopy(cert);wrong['necessity'][sorted(C)[0]]['source']=3
                    try:cutcheck.verify(g,wrong)
                    except cutcheck.BadCertificate:mutants+=1
                    else:raise AssertionError('bad necessity accepted')
        if code%625==624:rows.append({'through_encoding':code,'valid_cuts':valid,'infeasible':infeasible,'greedy_larger_than_minimum':gaps,'rejected_mutations':mutants})
    # Unbounded greedy gap family and a zero-length uncuttable source-target path.
    gap_family=[]
    for width in (1,2,3,4,8,16):
        g={'n':width+2,'sources':[0],'targets':[width+1],
           'edges':[[0,k,'a'] for k in range(1,width+1)]+[[k,width+1,'z'+str(k)] for k in range(1,width+1)]}
        cert=cuts.minimize(g);cutcheck.verify(g,cert);exact=cuts.exact_minimum(g)
        assert len(cert['cut'])==width and len(exact)==1
        gap_family.append({'paths':width,'greedy_size':len(cert['cut']),'minimum_size':1})
    g={'n':1,'sources':[0],'targets':[0],'edges':[]};c=cuts.minimize(g);assert c['status']=='infeasible';cutcheck.verify(g,c)
    return {'graphs':5**6,'cut_certificates':valid,'infeasible_certificates':infeasible,'mutations_rejected':mutants,
            'greedy_gaps':gaps,'batches':rows,'gap_family':gap_family,'zero_length_infeasibility_checked':True,
            'encoding':'All 5^6 four-node DAGs: each edge absent, uncuttable, or group a/b/c. All action subsets enumerated by a separate Boolean oracle.'}

def main(which):
    cpu=time.process_time();wall=time.perf_counter()
    result=closure_cases() if which=='closure' else cut_cases()
    result.update(cpu_seconds=time.process_time()-cpu,wall_seconds=time.perf_counter()-wall,
                  peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    (ROOT/'results'/('finite-'+which+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('batches',)},indent=2))
if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=('closure','cuts'));args=ap.parse_args();main(args.mode)
