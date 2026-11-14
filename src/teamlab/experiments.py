"""Comparable collaboration measurements; replay and live are kept separate."""
import json
import hashlib
import platform
import statistics
import time
from pathlib import Path

from .analytics import digest
from .controller import Controller
from .fixture import generate, read_records
from .grader import reference
from .review import all_events


def summarize(events, elapsed):
    claims = [e for e in events if e['kind']=='task.claimed']
    usage=[]
    for event in events:
        if event['kind']=='inference.completed':
            usage.extend(u for u in event['detail'].get('usage',[]) if u)
    monitor_usage=[e['detail'].get('usage',{}) for e in events if e['kind']=='monitor.completed']
    monitor_times=sorted(e['detail']['elapsed_seconds'] for e in events if e['kind']=='monitor.completed')
    created={e['detail']['id']:e['created'] for e in events if e['kind']=='task.created'}
    waits=[e['created']-created[e['detail']['id']] for e in claims if e['detail']['id'] in created]
    roots=[e for e in events if e['kind']=='task.created' and e['detail']['parent'] is None]
    finish=next((e['created'] for e in reversed(events) if e['kind']=='run.completed'),None)
    return {'elapsed_seconds': elapsed, 'claims': len(claims),
        'repeated_claims':len(claims)-len({e['detail']['id'] for e in claims}),
        'completed_tasks':sum(e['kind']=='task.done' for e in events),
        'input_tokens':sum(u.get('input_tokens',0) for u in usage+monitor_usage),
        'output_tokens':sum(u.get('output_tokens',0) for u in usage+monitor_usage),
        'usage_records':len(usage)+len(monitor_usage), 'monitor_requests':sum(e['kind']=='inference.requested' and e['detail']['purpose']=='security-monitor' for e in events),
        'event_count':len(events), 'created_to_claim_seconds':waits,
        'root_span_seconds':finish-roots[0]['created'] if roots and finish else None,
        'monitor_latency_p95_seconds':monitor_times[min(len(monitor_times)-1,int(.95*len(monitor_times)))] if monitor_times else None}


def benchmark(root, output, rows=1000, seeds=5, counts=(1,2,4,8), mode='sdk-replay', monitors=None, budget=None):
    if not 1<=seeds<=10 or mode not in ('sdk-replay','live') or not counts or len(set(counts))!=len(counts) or any(not 1<=w<=8 for w in counts):
        raise ValueError('bounded seeds, distinct 1..8 worker counts and explicit replay/live mode required')
    if mode=='live' and budget is None:
        raise ValueError('live scaling requires a shared experiment spend budget')
    if mode=='live':
        # This benchmark client stays in-process. `run` and `evaluate-security` can use --control-plane.
        from openai import OpenAI
        from .security import LunaMonitor,RuleMonitor
        client=OpenAI(timeout=45,max_retries=0,http_client=budget.client())
        monitors=[RuleMonitor(),LunaMonitor(client),LunaMonitor(client,contextual=True)]
    from .collaborative import CollaborativeTeam
    measurements=[]
    for seed in range(seeds):
        source=Path(root)/f'input-{seed}.csv';generate(source,rows,seed,injection=True)
        records,input_hash=read_records(source)
        started=time.perf_counter();expected=reference(records);elapsed=time.perf_counter()-started
        measurements.append({'seed':seed,'workers':0,'mode':'reference-sql','input_hash':input_hash,'elapsed_seconds':elapsed,'correct':True,'model_calls':0,'input_tokens':0,'output_tokens':0})
        for workers in counts:
            c=Controller(Path(root)/f'{mode}-{seed}-{workers}',source,workers,mode,monitors=monitors,spend_budget=budget,model_call_limit=500)
            started=time.perf_counter();out=CollaborativeTeam(c,replay=mode=='sdk-replay').run();elapsed=time.perf_counter()-started
            candidate=json.loads((out/'candidate.json').read_text());run=c.store.run(c.run_id)
            measurements.append({'seed':seed,'workers':workers,'mode':mode,'input_hash':input_hash,'run_id':c.run_id,
                'correct':candidate==expected and run['state']=='COMPLETED','model_calls':run['model_calls'],
                **summarize(all_events(c.store,c.run_id),elapsed)})
    summary=[]
    for workers in (0,*counts):
        entries=[m for m in measurements if m['workers']==workers];times=[m['elapsed_seconds'] for m in entries]
        summary.append({'workers':workers,'runs':len(entries),'mode':entries[0]['mode'],'median_seconds':statistics.median(times),
            'min_seconds':min(times),'max_seconds':max(times),'all_correct':all(m['correct'] for m in entries)})
    result={'implementation_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob('*.py'))},
        'python_version': platform.python_version(), 'platform': platform.system(), 'workflow':'collaborative','mode':mode,'summary':summary,'measurements':measurements,'spend_reservations':budget.report() if budget else None,
        'limitations':['Replay measures orchestration only, not model intelligence or live inference.',
            'Trusted baseline calculations; no artifact execution or microVM performance.',
            'Tiny analytics workload does not establish useful parallel speedup.',
            'Spend reservations use operator-supplied prices; they are not measured invoice cost.']}
    Path(output).parent.mkdir(parents=True,exist_ok=True);Path(output).write_text(json.dumps(result,indent=2)+'\n')
    return result
