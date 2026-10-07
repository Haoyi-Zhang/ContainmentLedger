"""Separate replay and bit-reachability validator; imports no producer module.

Separation means distinct code paths, not independent authorship, capture, or a
machine-checked proof. Both implementations share the Python runtime and format.
"""
import json
from pathlib import Path

class Rejected(ValueError):
    pass

def check(condition, message):
    if not condition: raise Rejected(message)

def shape(x, fields):
    check(type(x) is dict and frozenset(x)==frozenset(fields.split()),'record fields')

def s(x):
    check(type(x) is str,'text type')
    try: encoded=x.encode('utf-8')
    except UnicodeEncodeError as exc: raise Rejected('invalid Unicode scalar') from exc
    check(len(encoded)<=262144,'bounded text')
    return x

def ident(x):
    check(type(x) is str and 1<=len(x)<=160 and all(c.isalnum() or c in '._-' for c in x),'identifier')
    return x

def index(x, low, high):
    check(type(x) is int and low<=x<=high,'bounded integer')
    return x

def path(x):
    check(type(x) is str and len(x)<=512 and '\x00' not in x and '\\' not in x,'member path')
    try: x.encode('utf-8')
    except UnicodeEncodeError as exc: raise Rejected('invalid member Unicode') from exc
    check(not any(p in ('','..','.') for p in x.split('/')),'member traversal')
    return x

def norm(x):
    # Deliberately implemented here rather than imported from ledger.canonical.
    lines=x.replace('\r\n','\n').replace('\r','\n').split('\n')
    for n in range(len(lines)):
        end=len(lines[n])
        while end and lines[n][end-1] in ' \t': end-=1
        lines[n]=lines[n][:end]
    return '\n'.join(lines)

def read_json(filename):
    p=Path(filename)
    with p.open('rb') as handle: document=handle.read(67108865)
    check(len(document)<=67108864,'input bytes')
    nesting=objects=0; in_string=False; slash=False; primitive=False
    for ch in document:
        if in_string:
            if slash: slash=False
            elif ch==92: slash=True
            elif ch==34: in_string=False
            continue
        if ch==34: in_string=True; objects+=1; primitive=False
        elif ch==91 or ch==123:
            nesting+=1; objects+=1; primitive=False; check(nesting<=64,'nesting budget')
        elif ch==93 or ch==125: nesting-=1; primitive=False
        elif ch in b' \t\r\n,:': primitive=False
        elif not primitive: primitive=True; objects+=1
        check(objects<=1000000,'syntax budget')
    def collect(items):
        obj={}
        for k,v in items:
            check(k not in obj,'repeated JSON key'); obj[k]=v
        return obj
    def constant(x): raise Rejected('non-finite JSON')
    try: return json.loads(document.decode('utf-8'), object_pairs_hook=collect,parse_constant=constant)
    except (UnicodeError,ValueError) as e: raise Rejected('malformed JSON') from e

def verify(policy,log,summary=False,exports=False,details=False,assert_claims=True):
    shape(policy,'roots repairs'); shape(log,'units bundles final outputs claims')
    for obj,key in ((policy,'roots'),(policy,'repairs'),(log,'units'),(log,'bundles')):
        check(type(obj[key]) is list,'list required')
    check(len(policy['roots'])+len(log['units'])<=20000,'node bound')
    check(len(policy['repairs'])<=20000 and len(log['bundles'])<=20000,'record bound')
    data={}; initial={}; arcs=[]; rootnames={}; nodenames={}; auth={}; bytes_used=0
    for r in policy['roots']:
        shape(r,'id code intent labels'); n=ident(r['id'])
        check(n not in rootnames,'repeated root')
        v=('root',n); rootnames[n]=v; data[v]=(s(r['code']),s(r['intent']))
        initial[v]=index(r['labels'],0,7)
        bytes_used+=sum(len(z.encode()) for z in data[v])
    for a in policy['repairs']:
        shape(a,'id code before after'); n=ident(a['id']); check(n not in auth,'repeated authority')
        auth[n]=(s(a['code']),s(a['before']),s(a['after']))
        bytes_used+=sum(len(z.encode()) for z in auth[n])
    check(bytes_used<=67108864,'policy size')
    for u in log['units']:
        check(type(u) is dict,'unit record'); n=ident(u.get('id')); check(n not in nodenames,'repeated unit')
        op=u.get('op'); check(type(op) is str,'operation name')
        base='id op code intent '
        if op=='import':
            shape(u,base+'source'); source=ident(u['source']); check(source in rootnames,'root absent')
            p=rootnames[source]; result=data[p]; mask=7
        else:
            schema={'copy':'parent','normalize':'parent','extract':'parent start stop',
                    'rewrite':'parent old new','repair':'parent authority'}
            check(op in schema,'unknown operation'); shape(u,base+schema[op])
            parent=ident(u['parent']); check(parent in nodenames,'nonpreceding parent')
            p=nodenames[parent]; c,i=data[p]; mask=7
            if op=='copy': result=(c,i)
            elif op=='normalize': result=(norm(c),i)
            elif op=='extract':
                lo=index(u['start'],0,len(c)); hi=index(u['stop'],lo,len(c)); result=(c[lo:hi],i)
            elif op=='rewrite':
                old,new=s(u['old']),s(u['new']); check(old!='','empty rewrite')
                count=c.count(old)
                check(len(c.encode())+count*(len(new.encode())-len(old.encode()))<=262144,'rewrite bound')
                result=(c.replace(old,new),i)
            else:
                aid=ident(u['authority']); check(aid in auth,'missing authority')
                ac,ai,ao=auth[aid]; check(c==ac and i==ai,'authority mismatch')
                result=(c,ao); mask=3
        reported=(s(u['code']),s(u['intent'])); check(reported==result,'replay failed')
        bytes_used+=sum(len(z.encode()) for z in reported); check(bytes_used<=67108864,'payload bound')
        v=('unit',n); nodenames[n]=v; data[v]=result; initial[v]=0; arcs.append((p,v,mask))
    normal={v:norm(c) for v,(c,_) in data.items()}
    sizes={v:len(c.encode())+len(i.encode()) for v,(c,i) in data.items()}
    classes={}
    for v,(c,_) in data.items(): classes.setdefault(normal[v],[]).append(v)
    # A different star center makes agreement independent of producer edge order.
    for group in classes.values():
        hub=group[-1]
        for v in group[:-1]: arcs.append((v,hub,1)); arcs.append((hub,v,1))
    pair_classes={}
    for v,(c,i) in data.items(): pair_classes.setdefault((normal[v],i),[]).append(v)
    for group in pair_classes.values():
        hub=group[-1]
        for v in group[:-1]: arcs.append((v,hub,4)); arcs.append((hub,v,4))
    check(len(arcs)<=120000,'arc bound')
    collections={}; member_count=0
    for rec in log['bundles']:
        check(type(rec) is dict,'bundle record'); n=ident(rec.get('id')); check(n not in collections,'repeated bundle')
        op=rec.get('op'); check(type(op) is str,'bundle operation')
        if op=='collect':
            shape(rec,'id op items'); check(type(rec['items']) is list and len(rec['items'])<=20000,'items')
            output=[]
            for item in rec['items']:
                shape(item,'name unit'); u=ident(item['unit']); check(u in nodenames,'unseen item')
                output.append((path(item['name']),u))
        elif op=='mix':
            shape(rec,'id op parents'); check(type(rec['parents']) is list and len(rec['parents'])<=20000,'parents')
            ps=[]
            for p in rec['parents']:
                p=ident(p); check(p in collections,'mix input'); ps.append(p)
            check(sum(len(collections[p]) for p in ps)<=20000,'mix size')
            output=[]
            for k,p in enumerate(ps): output.extend((str(k)+'/'+nm,u) for nm,u in collections[p])
        else:
            fields={'repack':'id op parent prefix','filter':'id op parent indices','dedup':'id op parent'}
            check(op in fields,'collection operation'); shape(rec,fields[op])
            p=ident(rec['parent']); check(p in collections,'collection input'); previous=collections[p]
            if op=='repack':
                pre=ident(rec['prefix']); output=[(pre+'/'+str(k)+'.txt',u) for k,(_,u) in enumerate(previous)]
            elif op=='filter':
                picks=rec['indices']; check(type(picks) is list,'index list')
                last=-1; output=[]
                for k in picks:
                    index(k,0,len(previous)-1); check(k>last,'index order'); last=k; output.append(previous[k])
            else:
                keys=set(); output=[]
                for nm,u in previous:
                    c,i=data[nodenames[u]]; key=(normal[nodenames[u]],i)
                    if key not in keys: keys.add(key); output.append((nm,u))
        check(len(output)<=20000 and len({p for p,_ in output})==len(output),'bundle cardinality')
        for p,_ in output: path(p)
        member_count+=len(output); check(member_count<=500000,'member obligations')
        collections[n]=output
    final=ident(log['final']); check(final in collections,'final reference')
    check(sum(sizes[nodenames[u]] for _,u in collections[final])<=67108864,'expanded export budget')
    expected=[]
    for nm,u in collections[final]:
        c,i=data[nodenames[u]]; expected.append({'name':nm,'unit':u,'code':c,'intent':i})
    check(type(log['outputs']) is list and log['outputs']==expected,'export mismatch')
    # Three separate reachability traversals, not the producer's bitset worklist.
    calculated={v:0 for v in data}
    for bit in (1,2,4):
        successors={v:[] for v in data}
        for a,b,m in arcs:
            if m&bit: successors[a].append(b)
        reached={v for v,m in initial.items() if m&bit}; stack=list(reached)
        while stack:
            current=stack.pop()
            for nxt in successors[current]:
                if nxt not in reached: reached.add(nxt); stack.append(nxt)
        for v in reached: calculated[v]+=bit
    claims=log['claims']; check(type(claims) is dict and set(claims)==set(nodenames),'claim identifiers')
    for u,v in nodenames.items():
        claimed=index(claims[u],0,7)
        if assert_claims: check(claimed==calculated[v],'incorrect label claim')
    output_nodes=[nodenames[u] for _,u in collections[final]]
    if details:
        def named(v): return ('r:' if v[0]=='root' else 'u:')+v[1]
        return {'values':{named(v):data[v] for v in data},
                'initial':{named(v):initial[v] for v in data},
                'direct':[(named(a),named(b),m) for a,b,m in arcs[:len(log['units'])]],
                'outputs':[named(v) for v in output_nodes]}
    if exports:
        check(not any(calculated[v] for v in output_nodes),'blocked export')
        # Expected was rebuilt from replayed values, not copied from log outputs.
        return expected
    if summary:
        projected=[]
        for bit in (1,4):
            by_value={}; owner={}
            for vertex,(body,task) in data.items():
                value=(normal[vertex],) if bit==1 else (normal[vertex],task)
                by_value.setdefault(value,len(by_value)); owner[vertex]=by_value[value]
            rows=set()
            for left,right,mask in arcs:
                if mask&bit and owner[left]!=owner[right]: rows.add((owner[left],owner[right]))
            projected.append({'bit':bit,'keys':[list(k) for k in by_value],
                              'arcs':[list(k) for k in sorted(rows)],
                              'seeds':sorted({owner[v] for v in data if initial[v]&bit}),
                              'outputs':[owner[v] for v in output_nodes]})
        return {'components':projected,'origin_labels':[calculated[v]&2 for v in output_nodes]}
    return {'status':'valid','retained':len(output_nodes),'blocked':sum(calculated[v]!=0 for v in output_nodes),
            'nodes':len(data),'edges':len(arcs),'labels':{u:calculated[v] for u,v in nodenames.items()}}

if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('policy'); ap.add_argument('ledger'); args=ap.parse_args()
    try: print(json.dumps(verify(read_json(args.policy),read_json(args.ledger)),sort_keys=True))
    except (Rejected,OSError) as exc: ap.exit(2,str(exc)+'\n')


def audit_graph(policy,log,groups):
    """Separately reconstruct the canonical state graph after separate replay.

    The producer's graph or group memberships are never accepted as evidence.
    Group selection itself is a trusted audit configuration, not remediation.
    """
    details=verify(policy,log,details=True,assert_claims=False)
    values=details['values']; initial=details['initial']; direct=details['direct']
    check(type(groups) is dict,'group dictionary')
    allowed={r['id'] for r in log['units'] if r['op']!='import'}
    check(set(groups).issubset(allowed),'group record domain')
    for value in groups.values():ident(value)
    check(len(set(groups.values()))<=64,'group count')
    ordered=sorted(values); slot={v:i for i,v in enumerate(ordered)}
    triples=[]
    for origin,destination,mask in direct:
        action=groups.get(destination[2:])
        for k in range(3):
            if mask&(1<<k):triples.append([slot[origin]*3+k,slot[destination]*3+k,action])
    for offset in (0,2):
        buckets={}
        for name in ordered:
            body,task=values[name]
            key=norm(body) if offset==0 else (norm(body),task)
            buckets.setdefault(key,[]).append(name)
        for bucket in buckets.values():
            first=bucket[0]
            for other in bucket[1:]:
                left,right=slot[first]*3+offset,slot[other]*3+offset
                triples.extend([[left,right,None],[right,left,None]])
    triples.sort(key=lambda x:(x[0],x[1],x[2] or ''))
    return {'n':max(1,3*len(ordered)),'edges':triples,
            'sources':sorted(slot[v]*3+k for v in ordered for k in range(3) if initial[v]&(1<<k)),
            'targets':sorted({slot[v]*3+k for v in details['outputs'] for k in range(3)})}
