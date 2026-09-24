"""Bounded producer for replay-scoped label containment. Standard library only.

B=1: content-scoped; O=2: declared-origin scoped; M=4: pair-scoped obligation.
This is a finite declared-lineage checker, not execution capture or poisoning detection.
"""
from collections import deque
import json
from pathlib import Path

B, O, M = 1, 2, 4
ALL = B | O | M
MAX_NODES, MAX_EDGES = 20000, 120000
MAX_PAYLOAD, MAX_TEXT, MAX_RECORDS = 64 * 1024 * 1024, 256 * 1024, 20000

class Invalid(ValueError):
    """A structural/replay obligation failed; no flow-cut claim is made."""

def require(test, message):
    if not test:
        raise Invalid(message)

def exact(record, keys, where):
    require(isinstance(record, dict) and set(record) == set(keys), 'schema: '+where)

def integer(value, low, high, where):
    require(type(value) is int and low <= value <= high, 'integer: '+where)
    return value

def text(value, where):
    require(type(value) is str, 'text: '+where)
    try: encoded=value.encode('utf-8')
    except UnicodeEncodeError as exc: raise Invalid('invalid Unicode scalar: '+where) from exc
    require(len(encoded) <= MAX_TEXT, 'text size: '+where)
    return value

def name(value, where):
    require(type(value) is str and 0 < len(value) <= 160, 'name: '+where)
    require(all(c.isalnum() or c in '._-' for c in value), 'name alphabet: '+where)
    return value

def member(value):
    require(type(value) is str and len(value) <= 512 and '\x00' not in value and '\\' not in value, 'member name')
    try: value.encode('utf-8')
    except UnicodeEncodeError as exc: raise Invalid('invalid member Unicode') from exc
    require(all(p not in ('', '.', '..') for p in value.split('/')), 'member path')
    return value

def canonical(code):
    """Declared textual equality, not a semantics-preserving compiler claim."""
    return '\n'.join(part.rstrip(' \t') for part in code.replace('\r\n','\n').replace('\r','\n').split('\n'))

def load(path):
    p=Path(path)
    with p.open('rb') as stream: raw=stream.read(MAX_PAYLOAD+1)
    require(len(raw)<=MAX_PAYLOAD,'input byte limit')
    depth=atoms=0; quoted=escaped=literal=False
    for char in raw:
        if quoted:
            if escaped: escaped=False
            elif char==92: escaped=True
            elif char==34: quoted=False
        elif char==34:
            quoted=True; literal=False; atoms+=1
        elif char in (123,91):
            depth+=1; atoms+=1; literal=False
            require(depth<=64,'JSON depth limit')
        elif char in (125,93): depth-=1; literal=False
        elif char in (32,9,10,13,44,58): literal=False
        elif not literal: atoms+=1; literal=True
        require(atoms<=1000000,'JSON atom limit')
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result, 'duplicate JSON key')
            result[key]=value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('non-finite JSON')))
    except (UnicodeError, ValueError) as exc:
        raise Invalid('JSON decoding') from exc

def replay(policy, ledger):
    """Validate and replay every unit and bundle, returning a finite flow graph."""
    exact(policy, ('roots','repairs'), 'policy')
    exact(ledger, ('units','bundles','final','outputs','claims'), 'ledger')
    require(isinstance(policy['roots'],list) and isinstance(policy['repairs'],list), 'policy lists')
    require(isinstance(ledger['units'],list) and isinstance(ledger['bundles'],list), 'ledger lists')
    require(len(policy['roots'])+len(ledger['units']) <= MAX_NODES, 'node limit')
    require(len(ledger['bundles']) <= MAX_RECORDS and len(policy['repairs']) <= MAX_RECORDS,'record limit')
    values, seeds, edges, roots, units, repairs = {}, {}, [], {}, {}, {}
    total=0
    for r in policy['roots']:
        exact(r, ('id','code','intent','labels'), 'root')
        rid=name(r['id'],'root id')
        require(rid not in roots,'duplicate root')
        code,intent=text(r['code'],'root code'),text(r['intent'],'root intent')
        total+=len(code.encode())+len(intent.encode())
        v='r:'+rid
        roots[rid]=v; values[v]=(code,intent)
        seeds[v]=integer(r['labels'],0,ALL,'root labels')
    for r in policy['repairs']:
        exact(r, ('id','code','before','after'), 'repair authority')
        rid=name(r['id'],'repair id'); require(rid not in repairs,'duplicate authority')
        repairs[rid]=tuple(text(r[k],'repair '+k) for k in ('code','before','after'))
        total+=sum(len(x.encode()) for x in repairs[rid])
    require(total<=MAX_PAYLOAD, 'aggregate policy payload')
    for rec in ledger['units']:
        require(isinstance(rec,dict),'unit object')
        uid=name(rec.get('id'),'unit id'); op=rec.get('op')
        require(uid not in units,'duplicate unit')
        fields={'import':('source',),'copy':('parent',),'extract':('parent','start','stop'),
                'normalize':('parent',),'rewrite':('parent','old','new'),'repair':('parent','authority')}
        require(type(op) is str and op in fields,'operation')
        exact(rec,('id','op','code','intent')+fields[op], 'unit '+uid)
        code,intent=text(rec['code'],'unit code'),text(rec['intent'],'unit intent')
        total+=len(code.encode())+len(intent.encode())
        require(total<=MAX_PAYLOAD,'aggregate replay payload')
        mask=ALL
        if op=='import':
            sid=name(rec['source'],'source'); require(sid in roots,'unregistered source')
            parent=roots[sid]; expected=values[parent]
        else:
            pid=name(rec['parent'],'parent'); require(pid in units,'parent must precede child')
            parent=units[pid]; pc,pi=values[parent]
            if op=='copy': expected=(pc,pi)
            elif op=='normalize': expected=(canonical(pc),pi)
            elif op=='extract':
                start=integer(rec['start'],0,len(pc),'start')
                stop=integer(rec['stop'],start,len(pc),'stop')
                expected=(pc[start:stop],pi)
            elif op=='rewrite':
                old,new=text(rec['old'],'old'),text(rec['new'],'new')
                require(bool(old),'empty rewrite pattern')
                projected=len(pc.encode())+pc.count(old)*(len(new.encode())-len(old.encode()))
                require(projected<=MAX_TEXT,'rewrite expansion')
                expected=(pc.replace(old,new),pi)
            else:
                aid=name(rec['authority'],'authority'); require(aid in repairs,'unknown repair authority')
                ac,before,after=repairs[aid]
                require(pc==ac and pi==before,'repair binding')
                expected=(pc,after); mask=B|O
        require((code,intent)==expected,'replay mismatch: '+uid)
        v='u:'+uid; units[uid]=v; values[v]=(code,intent); seeds[v]=0
        edges.append((parent,v,mask,None))
    # Root registry is deliberately not pruned to the roots reported by the producer.
    normalized={v:canonical(code) for v,(code,_) in values.items()}
    byte_size={v:len(code.encode())+len(intent.encode()) for v,(code,intent) in values.items()}
    first={}
    for v,(code,_) in values.items():
        key=normalized[v]
        if key in first:
            edges.extend(((first[key],v,B,'alias-B'),(v,first[key],B,'alias-B')))
        else: first[key]=v
    first_pair={}
    for v,(code,intent) in values.items():
        key=(normalized[v],intent)
        if key in first_pair:
            edges.extend(((first_pair[key],v,M,'alias-M'),(v,first_pair[key],M,'alias-M')))
        else: first_pair[key]=v
    require(len(edges)<=MAX_EDGES,'edge limit')
    bundles={}
    total_members=0
    for rec in ledger['bundles']:
        require(isinstance(rec,dict),'bundle object')
        bid=name(rec.get('id'),'bundle id'); op=rec.get('op')
        require(bid not in bundles,'duplicate bundle')
        fields={'collect':('items',),'repack':('parent','prefix'),'filter':('parent','indices'),
                'mix':('parents',),'dedup':('parent',)}
        require(type(op) is str and op in fields,'bundle operation')
        exact(rec,('id','op')+fields[op],'bundle '+bid)
        if op=='collect':
            require(isinstance(rec['items'],list) and len(rec['items'])<=MAX_NODES,'collect list')
            out=[]
            for item in rec['items']:
                exact(item,('name','unit'),'bundle item')
                uid=name(item['unit'],'item unit'); require(uid in units,'unknown item unit')
                out.append((member(item['name']),uid))
        elif op=='mix':
            require(isinstance(rec['parents'],list) and len(rec['parents'])<=MAX_RECORDS,'mix parents')
            parents=[]
            for p in rec['parents']:
                p=name(p,'mix parent'); require(p in bundles,'unknown mix parent'); parents.append(p)
            require(sum(len(bundles[p]) for p in parents)<=MAX_NODES,'mix expansion')
            out=[(str(i)+'/'+nm,u) for i,p in enumerate(parents) for nm,u in bundles[p]]
        else:
            p=name(rec['parent'],'bundle parent'); require(p in bundles,'unknown bundle parent')
            prior=bundles[p]
            if op=='repack':
                prefix=name(rec['prefix'],'prefix')
                out=[(prefix+'/'+str(i)+'.txt',u) for i,(_,u) in enumerate(prior)]
            elif op=='filter':
                ix=rec['indices']; require(isinstance(ix,list),'filter indices')
                for i in ix: integer(i,0,len(prior)-1,'filter index')
                require(ix==sorted(set(ix)),'ordered distinct indices')
                out=[prior[i] for i in ix]
            else:
                seen=set(); out=[]
                for nm,u in prior:
                    c,it=values[units[u]]; key=(normalized[units[u]],it)
                    if key not in seen:
                        seen.add(key); out.append((nm,u))
        require(len(out)<=MAX_NODES and len({nm for nm,_ in out})==len(out),'bundle names/size')
        for nm,_ in out: member(nm)
        total_members+=len(out)
        require(total_members<=500000,'bundle obligations limit')
        bundles[bid]=out
    final=name(ledger['final'],'final bundle'); require(final in bundles,'unknown final bundle')
    require(isinstance(ledger['outputs'],list),'outputs list')
    require(sum(byte_size[units[u]] for _,u in bundles[final])<=MAX_PAYLOAD,'expanded export payload')
    expected=[{'name':nm,'unit':u,'code':values[units[u]][0],'intent':values[units[u]][1]} for nm,u in bundles[final]]
    require(ledger['outputs']==expected,'exact export mismatch')
    require(isinstance(ledger['claims'],dict) and set(ledger['claims'])==set(units),'claim domain')
    for v,label in ledger['claims'].items(): integer(label,0,ALL,'claim '+v)
    return values,seeds,edges,units,[units[u] for _,u in bundles[final]]

def closure(vertices,seeds,edges):
    adjacency={v:[] for v in vertices}
    for a,b,mask,_ in edges: adjacency[a].append((b,mask))
    labels={v:seeds.get(v,0) for v in vertices}
    queue=deque(v for v in vertices if labels[v]); pending=set(queue)
    while queue:
        a=queue.popleft(); pending.remove(a)
        for b,mask in adjacency[a]:
            new=labels[b] | (labels[a]&mask)
            if new!=labels[b]:
                labels[b]=new
                if b not in pending: queue.append(b); pending.add(b)
    return labels

def annotate(policy,ledger):
    """Fill exact labels after replay; existing claims are not trusted."""
    ledger['claims']={r['id']:0 for r in ledger['units']}
    values,seeds,edges,units,outputs=replay(policy,ledger)
    labels=closure(values,seeds,edges)
    ledger['claims']={u:labels[v] for u,v in units.items()}
    return {'retained':len(outputs),'blocked':sum(bool(labels[v]) for v in outputs),
            'nodes':len(values),'edges':len(edges),'labels':ledger['claims']}

def validate(policy,ledger):
    values,seeds,edges,units,outputs=replay(policy,ledger)
    labels=closure(values,seeds,edges)
    require(all(ledger['claims'][u]==labels[v] for u,v in units.items()),'label claim mismatch')
    return {'status':'valid','retained':len(outputs),'blocked':sum(bool(labels[v]) for v in outputs),
            'nodes':len(values),'edges':len(edges),'labels':ledger['claims']}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy'); parser.add_argument('ledger')
    args=parser.parse_args()
    try: print(json.dumps(validate(load(args.policy),load(args.ledger)),sort_keys=True))
    except (Invalid,OSError) as exc: parser.exit(2,str(exc)+'\n')
