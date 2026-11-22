'use client';
import {useEffect, useState} from 'react';
import {healthModel,parseMetrics} from '../../lib/metrics.mjs';

async function api(path, signal) { const r=await fetch('/api/teamlab/'+path,{cache:'no-store',signal}); const d=await r.json(); if(!r.ok) throw Error(d.error || `Server returned ${r.status}`); return d; }

export default function AlertHealth({runId}){
 const [m,setM]=useState(null),[error,setError]=useState('');
 useEffect(()=>{setM(null);setError('');if(!runId)return;const ac=new AbortController();
  async function load(){try{setM(parseMetrics(await api(`runs/${runId}/metrics`,ac.signal)));setError('')}catch(e){if(!ac.signal.aborted)setError(e.message)}}
  load();const t=setInterval(load,5000);return()=>{ac.abort();clearInterval(t)}},[runId]);
 const h=m&&healthModel(m);
 return <section className="card alert-health">
  <div className="section-title"><div><h2>Alert health</h2><p className="hint">Triage and acknowledgement coverage; refreshes every 5 s</p></div></div>
  {error&&<p role="alert" className="error">Alert metrics unavailable: {error}</p>}
  {h&&(h.empty?<p className="empty">No alerts</p>:<div className="stats">{h.tiles.map(t=><article key={t.id}><span>{t.label}</span><strong><span className={'status status-'+t.tone}><i/>{t.value}</span></strong></article>)}</div>)}
  {m?.dwell_measured_from&&<p className="hint">Dwell measured from {m.dwell_measured_from}.</p>}
 </section>;
}
