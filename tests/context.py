"""Exact three-key test of the contextual-information argument.

This is a finite check, not a mechanized proof. It tests one B-scoped graph:
64 directed graphs x 8 seed sets x 64 contextual graphs x 8 added seed sets.
The contextual signature is initial reachability plus the relation restricted
to initially unlabelled keys. All three keys may be observed as output ports.
"""
import itertools,json,resource,time,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PAIRS=[(a,b) for a in range(3) for b in range(3) if a!=b]

def adjacency(mask):
    rows=[0,0,0]
    for k,(a,b) in enumerate(PAIRS):
        if mask&(1<<k):rows[a]|=1<<b
    return rows

def propagate(rows,seed):
    pending=seed;seen=seed
    while pending:
        bit=pending&-pending;pending-=bit;a=bit.bit_length()-1
        fresh=rows[a]&~seen;seen|=fresh;pending|=fresh
    return seen

def floyd(rows):
    r=[[bool(a==b or rows[a]&(1<<b)) for b in range(3)] for a in range(3)]
    for k in range(3):
        for i in range(3):
            for j in range(3):r[i][j]=r[i][j] or (r[i][k] and r[k][j])
    return r

def main():
    cpu=time.process_time();wall=time.perf_counter();worlds=[];groups={};contexts=0
    for g in range(64):
        edges=adjacency(g);rel=floyd(edges)
        for s in range(8):
            c=sum((1<<j) for j in range(3) if any(s&(1<<i) and rel[i][j] for i in range(3)))
            restricted=[sum(1<<j for j in range(3) if not(c&(1<<j)) and rel[i][j]) if not(c&(1<<i)) else 0 for i in range(3)]
            signature=(c,*restricted)
            # The finite single-probe interface already distinguishes unequal
            # signatures; no probe needs to execute any corpus content.
            probes=(propagate(edges,s),)+tuple(propagate(edges,s|(1<<i)) for i in range(3))
            for q in range(64):
                ctx=adjacency(q)
                whole=[edges[i]|ctx[i] for i in range(3)]
                compressed=[restricted[i]|ctx[i] for i in range(3)]
                for extra in range(8):
                    assert propagate(whole,s|extra)==propagate(compressed,c|extra)
                    contexts+=1
            if probes in groups:assert groups[probes]==signature
            else:groups[probes]=signature
            worlds.append((signature,probes))
    by_signature={}
    for sig,probes in worlds:
        if sig in by_signature:assert by_signature[sig]==probes
        else:by_signature[sig]=probes
    # Realize each two-by-two relation using the actual literal-rewrite algebra.
    # Local outputs are empty, so a status-only cache observes the same clean
    # decision in every world. A separate context seeds x_i and exports y_j.
    sys.path.insert(0,str(ROOT/'src'))
    import ledger,checker,merge
    vectors=set(); pipeline_contexts=0
    for relation in range(16):
        policy={'roots':[{'id':k,'code':k,'intent':'task','labels':0}
                         for k in ('x0','x1','y0','y1')],'repairs':[]}
        units=[{'id':'i'+str(i),'op':'import','source':'x'+str(i),
                'code':'x'+str(i),'intent':'task'} for i in range(2)]
        for i in range(2):
            for j in range(2):
                if relation&(1<<(2*i+j)):
                    units.append({'id':'w'+str(i)+str(j),'op':'rewrite','parent':'i'+str(i),
                                  'old':'x'+str(i),'new':'y'+str(j),
                                  'code':'y'+str(j),'intent':'task'})
        log={'units':units,'bundles':[{'id':'out','op':'collect','items':[]}],
             'final':'out','outputs':[],'claims':{}}
        ledger.annotate(policy,log); checker.verify(policy,log)
        local_summary=checker.verify(policy,log,summary=True)
        assert local_summary==merge.summarize(policy,log)
        observed=[]
        for i in range(2):
            for j in range(2):
                context_policy={'roots':[{'id':'seed','code':'x'+str(i),'intent':'task','labels':1},
                                         {'id':'query','code':'y'+str(j),'intent':'task','labels':0}],
                                'repairs':[]}
                context_log={'units':[{'id':'q','op':'import','source':'query',
                                       'code':'y'+str(j),'intent':'task'}],
                             'bundles':[{'id':'out','op':'collect','items':[{'name':'query.txt','unit':'q'}]}],
                             'final':'out','outputs':[{'name':'query.txt','unit':'q',
                                                      'code':'y'+str(j),'intent':'task'}],'claims':{}}
                ledger.annotate(context_policy,context_log)
                context_summary=checker.verify(context_policy,context_log,summary=True)
                joined_policy,joined_log=merge.combine_logs([(policy,log),(context_policy,context_log)])
                produced=ledger.annotate(joined_policy,joined_log)
                checked=checker.verify(joined_policy,joined_log)
                expected=1 if relation&(1<<(2*i+j)) else 0
                assert produced['labels']==checked['labels']
                assert checked['labels']['s1-q']==expected
                assert merge.compose([local_summary,context_summary])==[[],[expected]]
                observed.append(bool(expected)); pipeline_contexts+=1
        vectors.add(tuple(observed))
    assert len(vectors)==16
    result={'keys':3,'local_graph_seed_worlds':len(worlds),'merged_graph_seed_contexts':contexts,
            'distinct_context_signatures':len(by_signature),'single_probes_distinguish_every_signature':True,
            'two_by_two_bipartite_relations_distinguished':len(vectors),
            'actual_rewrite_pipeline_probe_contexts':pipeline_contexts,'disagreements':0,
            'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.perf_counter()-wall,
            'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    (ROOT/'results'/'context.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
