"""Witness-only certificate checker; no imports from the separator generator."""
class BadCertificate(ValueError): pass

def expect(x, message):
    if not x: raise BadCertificate(message)

def verify(g,cert):
    expect(type(g) is dict and set(g)=={'n','edges','sources','targets'},'graph fields')
    n=g['n']; expect(type(n) is int and 1<=n<=60000,'vertex bound')
    es=g['edges']; expect(type(es) is list and len(es)<=360000,'edge bound')
    actions=set()
    for e in es:
        expect(type(e) is list and len(e)==3,'edge record'); a,b,c=e
        expect(type(a) is int and type(b) is int and 0<=a<n and 0<=b<n,'edge endpoints')
        expect(c is None or (type(c) is str and 1<=len(c)<=160),'edge action')
        if c is not None: actions.add(c)
    for key in ('sources','targets'):
        expect(type(g[key]) is list and all(type(v) is int and 0<=v<n for v in g[key]),'terminal list')
        expect(len(g[key])==len(set(g[key])),'terminal duplicates')
    starts=set(g['sources']); finishes=set(g['targets'])
    base=n+len(es)+len(starts)+len(finishes)
    expect(base<=500000,'graph obligation budget')
    expect(type(cert) is dict,'certificate record')
    def path_ok(witness, removed):
        expect(type(witness) is dict and set(witness)=={'source','edges'},'path fields')
        v=witness['source']; expect(type(v) is int and v in starts,'path source')
        sequence=witness['edges']; expect(type(sequence) is list and len(sequence)<=n,'bounded path')
        for k in sequence:
            expect(type(k) is int and 0<=k<len(es),'edge index')
            a,b,action=es[k]; expect(a==v,'path continuity')
            expect(action is None or action not in removed,'path crosses removed action'); v=b
        expect(v in finishes,'path destination')
    if cert.get('status')=='infeasible':
        expect(set(cert)=={'status','path'},'infeasible fields'); path_ok(cert['path'],actions)
        expect(base+len(cert['path']['edges'])<=500000,'path obligation budget')
        return {'valid':True,'kind':'infeasible'}
    expect(cert.get('status')=='cut' and set(cert)=={'status','cut','reachable','necessity'},'cut fields')
    cutlist=cert['cut']; expect(type(cutlist) is list and all(type(x) is str for x in cutlist),'cut list')
    cut=set(cutlist); expect(len(cut)==len(cutlist) and cut<=actions,'cut action domain')
    zlist=cert['reachable']; expect(type(zlist) is list and all(type(v) is int and 0<=v<n for v in zlist),'reachable list')
    z=set(zlist); expect(len(z)==len(zlist) and starts<=z and not z&finishes,'reachability separator')
    for a,b,action in es:
        if action is None or action not in cut:
            expect(a not in z or b in z,'reachable set not closed')
    necessity=cert['necessity']; expect(type(necessity) is dict and set(necessity)==cut,'necessity domain')
    count=n+len(es)+len(starts)+len(finishes)
    for action,witness in necessity.items():
        path_ok(witness,cut-{action});count+=len(witness['edges'])
        expect(count<=500000,'certificate obligation budget')
    return {'valid':True,'kind':'inclusion-minimal','size':len(cut)}
