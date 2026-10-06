"""Build a diagnostic graph from replayed records and explicit audit groups.

Equality and registered imports are uncuttable. Removing a group is a diagnostic
counterfactual, not authorization to delete history or emit the same code.
"""
import ledger,cuts

def graph(policy,log,groups):
    data,seeds,edges,units,outputs=ledger.replay(policy,log)
    if type(groups) is not dict: raise ledger.Invalid('audit group map')
    eligible={r['id'] for r in log['units'] if r['op']!='import'}
    ledger.require(set(groups)<=eligible,'audit group record')
    for g in groups.values(): ledger.name(g,'audit group')
    ledger.require(len(set(groups.values()))<=64,'audit group limit')
    names=sorted(data); number={v:3*i for i,v in enumerate(names)}; encoded=[]
    for a,b,mask,kind in edges:
        if kind is not None: continue
        group=groups.get(b[2:])
        for offset,bit in enumerate((1,2,4)):
            if mask&bit: encoded.append([number[a]+offset,number[b]+offset,group])
    for bit,offset in ((1,0),(4,2)):
        classes={}
        for v,(code,intent) in data.items():
            key=(ledger.canonical(code),) if bit==1 else (ledger.canonical(code),intent)
            classes.setdefault(key,[]).append(v)
        for values in classes.values():
            hub=min(values)
            for v in values:
                if v!=hub:
                    encoded.append([number[hub]+offset,number[v]+offset,None])
                    encoded.append([number[v]+offset,number[hub]+offset,None])
    encoded.sort(key=lambda e:(e[0],e[1],'' if e[2] is None else e[2]))
    # The generic cut format has a nonempty vertex universe. Represent an
    # empty replay by one isolated, nonterminal vertex in both adapters.
    return {'n':max(1,3*len(names)),'edges':encoded,
            'sources':[number[v]+k for v in names for k,bit in enumerate((1,2,4)) if seeds[v]&bit],
            'targets':sorted({number[v]+k for v in outputs for k in range(3)})}

def diagnose(policy,log,groups):
    g=graph(policy,log,groups)
    return g,cuts.minimize(g)
