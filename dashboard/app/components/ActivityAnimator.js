'use client';
import {useEffect,useMemo,useRef,useState} from 'react';
import {activity,resources} from '../../lib/activity.mjs';
import WorkViews from './WorkViews';
const colors={read:'#4ade80',write:'#f87171',message:'#a78bfa',handoff:'#a78bfa',check:'#fbbf24',blocked:'#ef4444'};
export default function ActivityAnimator({events,actors,runId,live,playing,onAgent,onEvent,controls,compact=false}){
 const model=useMemo(()=>activity(events,actors),[events,actors]);
 const [pulses,setPulses]=useState([]),[selected,setSelected]=useState('all'),[view,setView]=useState('communication');
 const previous=useRef({runId:null,seq:0});
 const latest=events.at(-1)?.seq||0;
 useEffect(()=>{
  const old=previous.current;
  previous.current={runId,seq:latest};
  if(old.runId!==runId||latest<old.seq){setPulses([]);return}
  if(!(live||playing)||latest===old.seq)return;
  const incoming=model.flows.filter(f=>f.seq>old.seq);
  setPulses(p=>[...p,...incoming.map(f=>({...f,expires:Date.now()+1300}))]);
 },[latest,runId,live,playing,model]);
 useEffect(()=>{const t=setInterval(()=>setPulses(p=>p.filter(f=>f.expires>Date.now())),250);return()=>clearInterval(t)},[]);
 const width=Math.max(1100,actors.length*140), spacing=width/(actors.length+1);
 const points=Object.fromEntries(actors.map((a,i)=>[a,{x:spacing*(i+1),y:82,actor:true}]));
 resources.forEach((r,i)=>points[r.id]={x:width/(resources.length+1)*(i+1),y:265});
 const relevant=f=>selected==='all'||f.from===selected||f.to===selected;
 const recent=model.flows.filter(relevant).slice(-18);
 function path(f){const s=points[f.from],t=points[f.to];if(!s||!t)return '';
  if(s.actor&&t.actor)return `M ${s.x} 60 Q ${(s.x+t.x)/2} -20 ${t.x} 60`;
  if(s.actor)return `M ${s.x} 104 C ${s.x} 175 ${t.x} 175 ${t.x} 244`;
  return `M ${s.x} 286 C ${s.x} 350 ${t.x} 350 ${t.x} 424`;
 }
 function inspectAgent(a){setSelected(a);onAgent(a)}
 return <section className={'activity-animator '+(compact?'expanded-animator':'')} aria-label="Animated real-time agent activity">
 <div className="animator-heading"><div><p className="eyebrow">REAL-TIME MONITOR / ACTIVITY ANIMATOR</p><h2>Activity</h2></div><span className={'status status-'+(playing?'warn':live?'live':'neutral')}><i/>{playing?'Replaying':live?'Live':'Recorded'}</span></div>
 <p className="muted">How agents read and write shared resources, hand off work and pass safety checks.</p>
 <nav className="view-tabs" aria-label="Activity visualization">{[['communication','Communication'],['tree','Task dependencies'],['allocation','Work map']].map(([key,label])=><button key={key} aria-pressed={view===key} onClick={()=>setView(key)}>{label}</button>)}</nav>
 <div className="animator-controls"><div className="flow-legend">{[['read','Reads / results'],['write','Writes'],['message','Messages / handoffs'],['check','Safety checks']].map(([k,v])=><span key={k}><i style={{background:colors[k]}}/>{v}</span>)}</div><select aria-label="Focus activity map on agent" value={selected} onChange={e=>setSelected(e.target.value)}><option value="all">Whole team</option>{actors.map(a=><option key={a}>{a}</option>)}</select></div>
 <div className="flow-counters"><span><b>{model.counts.read}</b> reads / results</span><span><b>{model.counts.write}</b> writes</span><span><b>{model.counts.message}</b> messages / handoffs</span><span>{events.length} events at this position</span></div>
 {controls}
 {view==='communication'?<><div className="map-scroll"><svg className="activity-map" viewBox={`0 -30 ${width} 520`} role="img" aria-label="Agents at the top send writes to shared resources in the middle. Reads return to agents below. Purple arcs show handoffs and messages.">
 <text x="16" y="16" className="map-caption">SEND</text><text x="16" y="204" className="map-caption">SHARED RESOURCES</text><text x="16" y="399" className="map-caption">RECEIVE</text>
 {recent.map(f=><path key={f.id} d={path(f)} fill="none" stroke={colors[f.type]} strokeWidth="1.5" opacity=".25"/>)}
 {pulses.filter(relevant).map(f=><g key={f.id}><path d={path(f)} fill="none" stroke={colors[f.type]} strokeWidth="2.5" className="flow-flash"/><circle r="5" fill={colors[f.type]} className="flow-particle"><animateMotion dur="1.1s" path={path(f)} repeatCount="1" fill="freeze"/></circle></g>)}
 {actors.map(a=>{const p=points[a],state=model.states[a],active=pulses.some(f=>f.from===a||f.to===a);return [82,446].map((y,i)=><g key={a+i} className={`map-agent ${active?'map-active':''}`} role="button" tabIndex="0" aria-label={`Inspect ${a}: ${state.label}`} onClick={()=>inspectAgent(a)} onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inspectAgent(a)}}}><title>{a}: {state.label}. {state.detail}</title><rect x={p.x-62} y={y-22} width="124" height="44" rx="10"/><circle cx={p.x-48} cy={y} r="3"/><text x={p.x+3} y={y+4} textAnchor="middle">{a}</text>{i===0&&<text className="map-status" x={p.x} y={y+41} textAnchor="middle">{state.label.length>24?state.label.slice(0,22)+'…':state.label}</text>}</g>)})}
 {resources.map(r=>{const p=points[r.id];return <g key={r.id} className="map-resource"><rect x={p.x-57} y="244" width="114" height="42" rx="10"/><text x={p.x} y="269" textAnchor="middle">{r.label}</text></g>})}
 </svg></div>
 <p className="map-explainer">Top and bottom rows show the same agents. Click an agent or operation for evidence. Motion occurs only when new events arrive or playback advances; idle agents generate no traffic.</p></>:<WorkViews view={view} events={events} actors={actors} onAgent={onAgent} onEvent={onEvent}/>}
 <div className="activity-bottom"><div><h3>Latest activity per agent</h3><div className="agent-status-list">{actors.map(a=><button key={a} onClick={()=>onAgent(a)}><b>{a}</b><span>{model.states[a].label}</span><small>{model.states[a].detail}</small></button>)}</div></div><div><h3>Recent transfers</h3><div className="transfer-list">{recent.length===0?<p className="muted">No recorded transfers at this position.</p>:recent.slice().reverse().slice(0,8).map(f=><button key={f.id} onClick={()=>onEvent(f.event)}><span style={{color:colors[f.type]}}>{f.from} → {f.to}</span><b>{f.label}</b><small>#{f.seq} · {f.type==='handoff'?'Authorization recorded':f.type==='message'?'Runtime dispatch recorded':f.type==='check'?'Monitor request recorded':'Recorded operation'}</small></button>)}</div></div></div>
 </section>
}
