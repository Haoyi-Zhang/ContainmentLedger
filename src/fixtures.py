"""Benign, deterministic static-text fixtures. Corpus code is never executed."""
import copy
from pathlib import Path
import ledger

SCENARIOS={
 'C01':('direct content label',True),
 'C02':('member rename',True),
 'C03':('normalization',True),
 'C04':('literal rewrite',True),
 'C05':('substring extraction',True),
 'C06':('unreported registered content alias',True),
 'C07':('alias before rewrite',True),
 'C08':('origin label on an alternative occurrence',False),
 'C09':('authorized pair repair',False),
 'C10':('unrepaired pair obligation',True),
 'C11':('clean transform control',False),
 'C12':('mix filter and deduplication',True),
 'C15':('label admitted at an intermediate value',True),
 'C16':('origin-scoped lineage',True),
 'C17':('empty retained bundle',False),
 'C18':('pair label on an alternative occurrence',True),
 'C19':('repair returns to a registered rejected pair',True),
 'C20':('different intent does not inherit pair label',False),
 'C21':('labelled common-header extraction',True),
 'C22':('clean common-header extraction',False),
}

def case(code,which):
    """Return a trusted policy, a replayable log and a hand-specified decision."""
    assert which in SCENARIOS
    # This prefix guarantees a deterministic nonempty literal rewrite witness.
    code='# FIXTURE UNIT\n'+code[:2048]
    baseline=ledger.canonical(code)
    sourcecode=code+' \t' if which=='C03' else code
    labels=1
    if which in ('C06','C07','C08','C11','C12','C15','C18','C19','C20','C22'): labels=0
    if which in ('C09','C10'): labels=4
    if which=='C16': labels=2
    policy={'roots':[{'id':'primary','code':sourcecode,'intent':'before','labels':labels}], 'repairs':[]}
    log={'units':[],'bundles':[],'final':'final','outputs':[],'claims':{}}
    def add(uid,op,pc,pi='before',**extra):
        log['units'].append({'id':uid,'op':op,'code':pc,'intent':pi,**extra})
        return uid
    u=add('initial','import',sourcecode,source='primary'); current=sourcecode
    if which in ('C06','C07','C08','C12'):
        policy['roots'].append({'id':'alternative','code':sourcecode,'intent':'before','labels':2 if which=='C08' else 1})
    if which in ('C18','C19','C20'):
        policy['roots'].append({'id':'pair-label','code':sourcecode,'intent':'before' if which=='C18' else 'reviewed','labels':4})
    if which=='C19':
        policy['repairs']=[{'id':'return-review','code':current,'before':'before','after':'reviewed'}]
        u=add('repair-return','repair',current,pi='reviewed',parent=u,authority='return-review')
    if which=='C03':
        current=ledger.canonical(current); u=add('normalized','normalize',current,parent=u)
    if which in ('C04','C07','C11','C15','C16'):
        old='# FIXTURE UNIT'; new='# REPACKAGED UNIT'
        current=current.replace(old,new); u=add('rewritten','rewrite',current,parent=u,old=old,new=new)
    if which=='C05':
        start,stop=16,len(current)-3
        current=current[start:stop]; u=add('extracted','extract',current,parent=u,start=start,stop=stop)
    if which in ('C21','C22'):
        start,stop=0,len('# FIXTURE UNIT\n')
        current=current[start:stop]; u=add('common-header','extract',current,parent=u,start=start,stop=stop)
    if which=='C09':
        policy['repairs']=[{'id':'pair-review','code':current,'before':'before','after':'approved'}]
        u=add('repaired','repair',current,pi='approved',parent=u,authority='pair-review')
    if which=='C15':
        policy['roots'].append({'id':'intermediate-label','code':current,'intent':'other','labels':1})
        current=current.replace('# REPACKAGED UNIT','# FINAL UNIT')
        u=add('last','rewrite',current,parent=u,old='# REPACKAGED UNIT',new='# FINAL UNIT')
    items=[{'name':'source.txt','unit':u}]
    log['bundles'].append({'id':'collected','op':'collect','items':items})
    if which=='C12':
        extra=add('duplicate','import',sourcecode,source='alternative')
        log['bundles'].append({'id':'second','op':'collect','items':[{'name':'copy.txt','unit':extra}]})
        log['bundles'].append({'id':'mixed','op':'mix','parents':['collected','second']})
        log['bundles'].append({'id':'distinct','op':'dedup','parent':'mixed'})
        log['bundles'].append({'id':'final','op':'filter','parent':'distinct','indices':[0]})
        final_names=['0/source.txt']
    elif which=='C17':
        log['bundles'].append({'id':'final','op':'filter','parent':'collected','indices':[]})
        final_names=[]
    elif which=='C01':
        log['bundles'].append({'id':'final','op':'filter','parent':'collected','indices':[0]})
        final_names=['source.txt']
    else:
        log['bundles'].append({'id':'final','op':'repack','parent':'collected','prefix':'package'})
        final_names=['package/0.txt']
    last=next(r for r in log['units'] if r['id']==u)
    log['outputs']=[{'name':nm,'unit':u,'code':last['code'],'intent':last['intent']} for nm in final_names]
    return policy,log,SCENARIOS[which][1]

def public_files(base):
    return sorted(p for p in (Path(base)/'data'/'public').rglob('*') if p.is_file())

def flawed_decisions(policy,log):
    """Explicit, intentionally weaker policy baselines, not upstream tools."""
    values,seeds,edges,units,outs=ledger.replay(policy,log)
    direct=[e for e in edges if e[3] is None] # Equality edges are marked by their scope.
    forward=ledger.closure(values,seeds,direct)
    wide=[(a,b,7 if c is not None else mask,c) for a,b,mask,c in edges]
    over=ledger.closure(values,seeds,wide)
    no_repair=ledger.closure(values,seeds,[(a,b,7 if mask==3 else mask,c) for a,b,mask,c in edges])
    keys={ledger.canonical(r['code']) for r in policy['roots'] if r['labels']&1}
    # Same-information baseline: fixed-point relaxation, no byte-replay advantage assumed.
    generic=dict(seeds); changed=True
    while changed:
        changed=False
        for a,b,mask,_ in edges:
            new=generic[b]|(generic[a]&mask)
            if new!=generic[b]: generic[b]=new; changed=True
    final_alias={}
    for bit in (1,4):
        tagged=set()
        for v,(c,i) in values.items():
            if forward[v]&bit: tagged.add((ledger.canonical(c),) if bit==1 else (ledger.canonical(c),i))
        for v in outs:
            c,i=values[v]; key=(ledger.canonical(c),) if bit==1 else (ledger.canonical(c),i)
            final_alias[v]=final_alias.get(v,forward[v]) | (bit if key in tagged else 0)
    primary=policy['roots'][0]['labels']
    return {
      'path-only':bool(primary and any(x['name']=='source.txt' for x in log['outputs'])),
      'final-marker':any('[[REVIEW_LABEL]]' in x['code'] for x in log['outputs']),
      'canonical-content':any(ledger.canonical(x['code']) in keys for x in log['outputs']),
      'declared-lineage':any(forward[v] for v in outs),
      'all-label-alias':any(over[v] for v in outs),
      'no-authorized-repair':any(no_repair[v] for v in outs),
      'lineage-plus-final-alias':any(final_alias[v] for v in outs),
      'same-information-fixed-point':any(generic[v] for v in outs),
    }
