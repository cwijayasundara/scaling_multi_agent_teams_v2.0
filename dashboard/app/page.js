'use client';
import {useEffect, useRef, useState} from 'react';
import ActivityAnimator from './components/ActivityAnimator';
import AlertHealth from './components/AlertHealth';
import {workModel} from '../lib/work.mjs';

const time = n => new Date(n*1000).toLocaleTimeString();
async function api(path, signal) { const r=await fetch('/api/teamlab/'+path,{cache:'no-store',signal}); const d=await r.json(); if(!r.ok) throw Error(d.error || `Server returned ${r.status}`); return d; }
function summary(value) {try {const v=JSON.parse(value); return Array.isArray(v)?v.map(x=>x.text||'').join('\n'):value;}catch{return value}}
const role = a => a==='coordinator'?'Coordinator':a==='verifier'?'Verifier':`Analyst ${+a.split('-')[1]+1}`;
const initials = a => a==='coordinator'?'CO':a==='verifier'?'VE':'A'+(+a.split('-')[1]+1);
const tone = s => {const v=String(s||'').toUpperCase(); return ['COMPLETED','DONE','PASSED','VERIFIED','READY'].includes(v)?'ok':['RUNNING','CLAIMED','ACTIVE','PLAYBACK'].includes(v)?'live':['PAUSED','PENDING','OPEN'].includes(v)?'warn':['STOPPED','FAILED','DENIED','ERROR'].includes(v)?'bad':'neutral'};
const Status = ({value}) => <span className={'status status-'+tone(value)}><i/>{String(value||'').toLowerCase()}</span>;
const Avatar = ({agent}) => <span className={'avatar avatar-'+(agent==='coordinator'?'co':agent==='verifier'?'ve':'an')}>{initials(agent)}</span>;
const Logo = () => <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><rect x="2" y="2" width="20" height="20" rx="6" fill="var(--accent)"/><path d="M7 8h10M12 8v9" stroke="var(--accent-ink)" strokeWidth="2.4" strokeLinecap="round"/></svg>;

export default function Dashboard(){
 const [runs,setRuns]=useState([]),[id,setId]=useState(''),[data,setData]=useState(null),[error,setError]=useState(''),[panel,setPanel]=useState(null),[review,setReview]=useState(null),[reviewError,setReviewError]=useState(''),[cursor,setCursor]=useState(null),[playing,setPlaying]=useState(false),[filter,setFilter]=useState('all'),[speed,setSpeed]=useState(4);
 const dialog=useRef(null);
 useEffect(()=>{const ac=new AbortController(); async function load(){try{const d=await api('runs',ac.signal); setRuns(d.runs);setId(x=>x||d.runs[0]?.id||'');setError('')}catch(e){if(!ac.signal.aborted)setError(e.message)}}load();const t=setInterval(load,5000);return()=>{ac.abort();clearInterval(t)}},[]);
 useEffect(()=>{setData(null);setCursor(null);setPanel(null);setReview(null);setPlaying(false);if(!id)return;const ac=new AbortController();async function load(){try{setData(await api(`runs/${id}/snapshot`,ac.signal));setError('')}catch(e){if(!ac.signal.aborted)setError(e.message)}}load();const t=setInterval(load,1500);return()=>{ac.abort();clearInterval(t)}},[id]);
 useEffect(()=>{if(!playing)return;const t=setInterval(()=>setCursor(x=>{const next=(x??0)+1;if(next>= (data?.events.length||0)){setPlaying(false);return data?.events.length||0}return next}),1000/speed);return()=>clearInterval(t)},[playing,data?.events.length,speed]);
 useEffect(()=>{if(panel)dialog.current?.showModal();else dialog.current?.close()},[panel]);
 async function openReview(){setPanel({type:'offline',title:'Evidence review'});setReviewError('');setReview(null);try{setReview(await api(`runs/${id}/review`))}catch(e){setReviewError(e.message)}}
 const events=data?.events||[], visible=cursor===null?events:events.slice(0,cursor), run=data?.run;
 const actors=['coordinator',...Array.from({length:run?.workers||0},(_,i)=>`worker-${i}`),'verifier'];
 const work=workModel(visible,actors);
 const decisions=visible.filter(e=>['action.authorized','action.denied'].includes(e.kind));
 const denied=decisions.filter(e=>e.kind==='action.denied').length;
 const shown=visible.filter(e=>filter==='all'||e.agent_id===filter);
 const latest=visible.at(-1);
 const live=cursor===null&&run?.state==='RUNNING';
 const authored=data&&data.execution?.code_execution!=='trusted-baseline';
 const playbackControls=<div className="playback"><button className="btn btn-icon" aria-label={playing?'Pause':'Play'} onClick={()=>{if(cursor===null||cursor>=events.length)setCursor(0);setPlaying(!playing)}}>{playing?'❚❚':'▶'}</button><input aria-label="Playback position" type="range" min="0" max={events.length} value={cursor??events.length} onChange={e=>{setPlaying(false);setCursor(+e.target.value)}}/><span className="mono">{cursor??events.length} / {events.length}</span><select aria-label="Playback speed" value={speed} onChange={e=>setSpeed(+e.target.value)}>{[1,4,12].map(n=><option key={n} value={n}>{n}×</option>)}</select><button className="btn" onClick={()=>{setCursor(null);setPlaying(false)}}>{cursor===null?'Live':'Jump to latest'}</button></div>;

 return <>
 <header className="topbar"><div className="topbar-inner">
  <a className="brand" href="/"><Logo/><b>TeamLab</b><span>Mission control</span></a>
  <div className="topbar-right">
   <label className="run-picker"><span>Run</span><select value={id} onChange={e=>setId(e.target.value)}><option value="" disabled>Select a run</option>{runs.map(r=><option key={r.id} value={r.id}>{r.id.slice(0,10)} · {r.state.toLowerCase()} · {r.mode}</option>)}</select></label>
   <span className={'conn '+(error?'conn-bad':'conn-ok')}><i/>{error?'Disconnected':'Connected'}</span>
  </div>
 </div></header>

 <main>
 {error&&<div role="alert" className="error">{error}</div>}
 {!runs.length&&!error&&<div className="empty-state"><Logo/><h2>No runs yet</h2><p>Start an agent run against the same run folder as this dashboard.</p><code>make authored BUDGET=1 INPUT_PRICE=0.10 OUTPUT_PRICE=0.50</code></div>}

 {data&&<>
 <section className="page-head">
  <div>
   <p className="crumb">Runs <span>/</span> {run.id.slice(0,10)}</p>
   <h1>Run {run.id.slice(0,10)} <Status value={run.state}/></h1>
   <p className="meta"><span>{run.mode}</span><span>{actors.length} agents</span><span>{events.length} events</span>{latest&&<span>Last activity {time(latest.created)}</span>}</p>
  </div>
  <div className="head-actions">
   <button className="btn" onClick={()=>setPanel({type:'realtime',title:'Activity monitor'})}>Expand monitor</button>
   <button className="btn btn-primary" onClick={openReview}>Evidence review</button>
  </div>
 </section>

 <div className={'boundary '+(authored?'boundary-vm':'')}>
  <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/></svg>
  <b>{authored?'Authored code runs in OpenShell microVMs':'Trusted calculations only'}</b>
  <span>{data.execution?.description||'No per-agent containers or microVMs.'}</span>
 </div>

 <section className="stats">
  <article><span>Status</span><strong><Status value={run.state}/></strong><small>{run.mode} mode</small></article>
  <article><span>Team</span><strong>{actors.length}</strong><small>1 coordinator · {run.workers} analyst{run.workers===1?'':'s'} · 1 verifier</small></article>
  <article><span>Tool dispatches</span><strong>{run.calls}</strong><small>{decisions.length} safety decisions{denied?` · ${denied} denied`:''}</small></article>
  <article><span>Model requests</span><strong>{run.model_calls}</strong><small>Including security monitors</small></article>
 </section>

 <AlertHealth key={id} runId={id}/>

 <section className="section-title"><h2>Agents</h2><span>Select an agent to inspect its recorded activity</span></section>
 <section className="agents">{actors.map(a=>{const es=visible.filter(e=>e.agent_id===a), last=es.at(-1), task=work.dynamic?work.nodes.filter(t=>t.actor===a).at(-1):data.tasks.find(t=>t.owner===a);return <button className="agent" key={a} onClick={()=>setPanel({type:'agent',agent:a,title:role(a)})}>
  <div className="agent-top"><Avatar agent={a}/><div><h3>{role(a)}</h3><p className="mono">{a}</p></div><Status value={cursor!==null?'PLAYBACK':task?.state||run.state}/></div>
  <p className="agent-task">{task?(work.dynamic?task.label:`Shard ${task.shard}`):'No assigned task'}</p>
  <div className="last mono">{last?.detail.action||last?.kind||'No activity yet'}</div>
  <footer><span>{es.length} events</span><span>{last?time(last.created):'—'}</span></footer>
 </button>})}</section>

 <ActivityAnimator key={id} events={visible} actors={actors} runId={id} controls={playbackControls} live={live} playing={playing} onAgent={a=>setPanel({type:'agent',agent:a,title:role(a)})} onEvent={e=>setPanel({type:'event',title:`Event #${e.seq}`,event:e})}/>

 <section className="card timeline">
  <div className="section-title"><div><h2>Timeline</h2><p className="hint">{cursor===null?'Refreshes every 1.5 s':'Showing playback position; counters above show current totals'}</p></div><select aria-label="Filter timeline by agent" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All agents</option>{actors.map(a=><option key={a} value={a}>{role(a)}</option>)}</select></div>
  <div className="event-head"><span>Time</span><span>Agent</span><span>Event</span><span>Detail</span></div>
  <div className="event-list">{shown.length===0?<p className="empty">No events at this position.</p>:shown.slice().reverse().map(e=><button className="event" key={e.seq} onClick={()=>setPanel({type:'event',title:`Event #${e.seq}`,event:e})}><time className="mono">{time(e.created)}</time><b>{e.agent_id}</b><span className={'kind '+(e.kind.includes('denied')||e.kind.includes('blocked')?'kind-bad':e.kind.includes('authorized')?'kind-ok':'')}>{e.kind}</span><code>{e.detail.action||e.detail.purpose||''}</code></button>)}</div>
 </section>
 </>}

 <dialog className={panel?.type==='realtime'?'animator-dialog':''} ref={dialog} onCancel={()=>setPanel(null)} onClick={e=>{if(e.target===dialog.current)setPanel(null)}}>
  <div className="modal-head"><div><p className="crumb">Recorded evidence</p><h2>{panel?.title}</h2></div><button className="btn btn-icon" autoFocus aria-label="Close details" onClick={()=>setPanel(null)}>✕</button></div>
  {panel?.type==='agent'&&<>{data?.summaries[panel.agent]&&cursor===null&&<article className="finding"><h3>Final summary</h3><p className="prose">{summary(data.summaries[panel.agent])}</p></article>}{visible.filter(e=>e.agent_id===panel.agent).map(e=><Evidence key={e.seq} e={e}/>)}</>}
  {panel?.type==='realtime'&&<><ActivityAnimator events={visible} actors={actors} runId={id} controls={playbackControls} live={live} playing={playing} compact onAgent={a=>setPanel({type:'agent',agent:a,title:role(a)})} onEvent={e=>setPanel({type:'event',title:`Event #${e.seq}`,event:e})}/><h3>Safety decisions</h3><p className="hint">Recorded before tool dispatch. A monitor failure pauses the team; serious violations stop it.</p>{decisions.map(e=><Evidence key={e.seq} e={e}/>)}</>}
  {panel?.type==='event'&&<Evidence e={panel.event}/>}
  {panel?.type==='offline'&&<>{reviewError?<p role="alert" className="error">{reviewError}</p>:!review?<p className="hint">Checking saved evidence…</p>:<><p className="boundary">{review.limitation}</p>{review.checks.map(c=><article className="finding" key={c.name}><div className="finding-head"><h3>{c.name}</h3><Status value={c.status}/></div><p>{c.detail}</p></article>)}<h3>Behavioral review</h3>{review.behavior?<article className="finding"><p>{review.behavior.events_reviewed}/{review.behavior.event_count} evidence IDs reviewed · {review.behavior.complete_coverage?'Complete recorded coverage':'Coverage gaps'}</p><p>{review.behavior.limitation}</p>{review.behavior.findings.map((f,i)=><p key={i}><b>{f.severity} · {f.category}</b> — {f.summary} · Evidence: {f.evidence.join(', ')}</p>)}{!review.behavior.findings.length&&<p>No findings returned; this does not establish absence of unsafe behavior.</p>}</article>:<p className="hint">No live behavioral review has been recorded for this run.</p>}<h3>Recorded safety findings</h3>{review.findings.length?review.findings.map(e=><Evidence key={e.seq} e={e}/>):<p className="hint">No denial or stopped/paused/failed events recorded. This does not establish the absence of unsafe behavior.</p>}</>}</>}
 </dialog>
 <footer className="page-footer"><span>TeamLab · local operator console</span><span>Read-only</span></footer>
 </main>
 </>
}
function Evidence({e}){return <article className="finding"><p className="finding-meta mono">#{e.seq} · {time(e.created)} · {e.agent_id}</p><h3>{e.detail.action||e.kind}</h3><pre>{JSON.stringify(e.detail,null,2)}</pre></article>}
