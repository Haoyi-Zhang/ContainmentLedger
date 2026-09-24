"""Composition of locally validated scope summaries.

Summaries are trusted *outputs* of local replay. This module does not authenticate
remote summaries. Equality of full canonical text keys is used, not a hash.
"""
from collections import deque

class MergeError(ValueError): pass

def summarize(policy, log):
    import ledger
    data,seeds,edges,units,outputs=ledger.replay(policy,log)
    labels=ledger.closure(data,seeds,edges)
    ledger.require(all(log['claims'][u]==labels[v] for u,v in units.items()),'summary label claims')
    components=[]
    for bit in (1,4):
        keys=[]; ids={}; node_key={}
        for v,(code,intent) in data.items():
            key=(ledger.canonical(code),) if bit==1 else (ledger.canonical(code),intent)
            if key not in ids: ids[key]=len(keys); keys.append(list(key))
            node_key[v]=ids[key]
        arcs=sorted({(node_key[a],node_key[b]) for a,b,mask,_ in edges if mask&bit and node_key[a]!=node_key[b]})
        components.append({'bit':bit,'keys':keys,'arcs':[list(e) for e in arcs],
                           'seeds':sorted({node_key[v] for v in data if seeds[v]&bit}),
                           'outputs':[node_key[v] for v in outputs]})
    return {'components':components,'origin_labels':[labels[v]&2 for v in outputs]}

def compose(summaries):
    """Return per-shard retained-output masks after equality-only shard mixing."""
    if type(summaries) is not list: raise MergeError('summary list')
    results=[]; output_total=0; key_total=0; arc_total=0; key_bytes=0
    for sm in summaries:
        if type(sm) is not dict or set(sm)!={'components','origin_labels'}: raise MergeError('summary fields')
        origin=sm['origin_labels']
        if type(origin) is not list or any(type(x) is not int or x not in (0,2) for x in origin): raise MergeError('origin labels')
        if type(sm['components']) is not list or len(sm['components'])!=2: raise MergeError('scope components')
        results.append(list(origin)); output_total+=len(origin)
        if output_total>20000: raise MergeError('output limit')
    for scope,bit in enumerate((1,4)):
        vertices={}; adjacency=[]; roots=set(); out_indices=[]
        for sm in summaries:
            c=sm['components'][scope]
            if type(c) is not dict or set(c)!={'bit','keys','arcs','seeds','outputs'} or type(c['bit']) is not int or c['bit']!=bit: raise MergeError('component')
            for k in ('keys','arcs','seeds','outputs'):
                if type(c[k]) is not list: raise MergeError('component list')
            key_total+=len(c['keys']); arc_total+=len(c['arcs'])
            if key_total>40000 or arc_total>240000: raise MergeError('summary graph limit')
            if len(c['outputs'])!=len(sm['origin_labels']): raise MergeError('output cardinality')
            local=[]; seen=set()
            for key in c['keys']:
                if type(key) is not list or len(key)!=(1 if bit==1 else 2) or any(type(z) is not str for z in key): raise MergeError('key')
                key=tuple(key)
                key_bytes+=sum(len(z.encode('utf-8')) for z in key)
                if key_bytes>134217728: raise MergeError('summary text budget')
                if key in seen: raise MergeError('duplicate local key')
                seen.add(key)
                if key not in vertices: vertices[key]=len(adjacency); adjacency.append([])
                local.append(vertices[key])
            def local_index(v):
                if type(v) is not int or not 0<=v<len(local): raise MergeError('local index')
                return local[v]
            for e in c['arcs']:
                if type(e) is not list or len(e)!=2: raise MergeError('summary arc')
                a,b=(local_index(v) for v in e); adjacency[a].append(b)
            for v in c['seeds']: roots.add(local_index(v))
            out_indices.append([local_index(v) for v in c['outputs']])
        reached=set(roots); q=deque(roots)
        while q:
            a=q.popleft()
            for b in adjacency[a]:
                if b not in reached: reached.add(b); q.append(b)
        for shard,indices in enumerate(out_indices):
            for i,v in enumerate(indices):
                if v in reached: results[shard][i]|=bit
    return results

def combine_logs(pairs):
    """Exact test adapter: namespace inputs, concatenate exports, retain all roots."""
    policy={'roots':[],'repairs':[]}; log={'units':[],'bundles':[],'final':'combined','outputs':[],'claims':{}}
    finals=[]
    for k,(p,l) in enumerate(pairs):
        prefix='s'+str(k)+'-'
        for r in p['roots']: policy['roots'].append({**r,'id':prefix+r['id']})
        for a in p['repairs']: policy['repairs'].append({**a,'id':prefix+a['id']})
        for u in l['units']:
            v=dict(u); v['id']=prefix+u['id']
            for field in ('source','parent','authority'):
                if field in v: v[field]=prefix+v[field]
            log['units'].append(v)
        for b in l['bundles']:
            c=dict(b); c['id']=prefix+b['id']
            if 'parent' in c: c['parent']=prefix+c['parent']
            if 'parents' in c: c['parents']=[prefix+x for x in c['parents']]
            if 'items' in c: c['items']=[{'name':x['name'],'unit':prefix+x['unit']} for x in c['items']]
            log['bundles'].append(c)
        finals.append(prefix+l['final'])
        for o in l['outputs']: log['outputs'].append({**o,'name':str(k)+'/'+o['name'],'unit':prefix+o['unit']})
    log['bundles'].append({'id':'combined','op':'mix','parents':finals})
    return policy,log
