"""Diagnostic grouped-edge separators; deletion is not code sanitization.

Graph fields: n, edges ([from,to,action-or-None]), sources, targets.
The caller must supply the trusted graph; certificates do not authenticate it.
"""
from collections import deque
from itertools import combinations

class CutError(ValueError): pass

def assert_ok(value, message):
    if not value: raise CutError(message)

def valid_graph(g):
    assert_ok(type(g) is dict and set(g)=={'n','edges','sources','targets'},'graph schema')
    n=g['n']; assert_ok(type(n) is int and 1<=n<=60000,'n')
    assert_ok(type(g['edges']) is list and len(g['edges'])<=360000,'edges')
    for e in g['edges']:
        assert_ok(type(e) is list and len(e)==3,'edge')
        a,b,c=e
        assert_ok(type(a) is int and type(b) is int and 0<=a<n and 0<=b<n,'endpoint')
        assert_ok(c is None or (type(c) is str and 1<=len(c)<=160),'action')
    for k in ('sources','targets'):
        assert_ok(type(g[k]) is list,'terminals')
        assert_ok(all(type(x) is int and 0<=x<n for x in g[k]),'terminal')
        assert_ok(len(set(g[k]))==len(g[k]),'duplicate terminal')
    return sorted({e[2] for e in g['edges'] if e[2] is not None})

def search(g, cut):
    adj=[[] for _ in range(g['n'])]
    for k,(a,b,c) in enumerate(g['edges']):
        if c is None or c not in cut: adj[a].append((b,k))
    predecessor={x:None for x in g['sources']}; q=deque(g['sources']); target=set(g['targets']); hit=None
    while q:
        a=q.popleft()
        if a in target: hit=a; break
        for b,k in adj[a]:
            if b not in predecessor: predecessor[b]=(a,k); q.append(b)
    if hit is None: return set(predecessor),None
    sequence=[]; p=hit
    while predecessor[p] is not None:
        p,k=predecessor[p]; sequence.append(k)
    return set(predecessor),{'source':p,'edges':sequence[::-1]}

def minimize(g):
    actions=valid_graph(g)
    assert_ok(len(actions)<=64,'greedy action budget')
    assert_ok(g['n']+len(g['edges'])+len(g['sources'])+len(g['targets'])<=500000,'graph obligation budget')
    cut=set(actions)
    _,path=search(g,cut)
    if path is not None:
        assert_ok(g['n']+len(g['edges'])+len(g['sources'])+len(g['targets'])+len(path['edges'])<=500000,'infeasible witness budget')
        return {'status':'infeasible','path':path}
    for a in actions:
        trial=cut-{a}
        if search(g,trial)[1] is None: cut=trial
    reached,_=search(g,cut)
    necessity={a:search(g,cut-{a})[1] for a in sorted(cut)}
    obligations=g['n']+len(g['edges'])+len(g['sources'])+len(g['targets'])+sum(len(w['edges']) for w in necessity.values())
    assert_ok(obligations<=500000,'certificate obligation budget')
    return {'status':'cut','cut':sorted(cut),'reachable':sorted(reached),'necessity':necessity}

def exact_minimum(g, limit=18):
    actions=valid_graph(g)
    assert_ok(len(actions)<=limit,'exact enumeration action limit')
    for size in range(len(actions)+1):
        for candidate in combinations(actions,size):
            if search(g,set(candidate))[1] is None: return list(candidate)
    return None
