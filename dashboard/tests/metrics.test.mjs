import {test} from 'node:test';
import assert from 'node:assert/strict';
import {formatDuration,formatCoverage,healthModel,parseMetrics} from '../lib/metrics.mjs';
const base={alerts:4,triage_coverage:1,human_coverage:0.75,dwell_p50_s:720,open_alerts:0,slo_breaches:0};
const tone=(m,id)=>healthModel(m).tiles.find(t=>t.id===id).tone;
test('formatDuration',()=>{
 assert.equal(formatDuration(null),'—');
 assert.equal(formatDuration(45),'45 s');
 assert.equal(formatDuration(720),'12 min');
 assert.equal(formatDuration(11520),'3.2 h');
});
test('formatCoverage',()=>{assert.equal(formatCoverage(null),'—');assert.equal(formatCoverage(0.75),'75%')});
test('healthModel is empty with zero alerts',()=>{
 const h=healthModel({...base,alerts:0,triage_coverage:null,human_coverage:null,dwell_p50_s:null});
 assert.equal(h.empty,true);
});
test('healthModel tiles and tones',()=>{
 const h=healthModel(base);
 assert.deepEqual(h.tiles.map(t=>t.id),['alerts','triage_coverage','human_coverage','dwell_p50','open_alerts','slo_breaches']);
 assert.equal(h.empty,false);
 assert.equal(h.tiles.find(t=>t.id==='human_coverage').value,'75%');
 assert.equal(tone(base,'open_alerts'),'ok');
 assert.equal(tone({...base,open_alerts:2},'open_alerts'),'warn');
 assert.equal(tone({...base,open_alerts:2,slo_breaches:1},'slo_breaches'),'bad');
});
test('parseMetrics accepts the unwrapped route payload and rejects anything else',()=>{
 const payload={run_id:'a'.repeat(24),alerts:2,triaged:2,acknowledged:1,triage_coverage:1,human_coverage:0.5,dwell_p50_s:30,open_alerts:1,slo_breaches:0,dwell_measured_from:'alert detection',items:[]};
 assert.equal(parseMetrics(payload),payload);
 assert.equal(healthModel(parseMetrics(payload)).empty,false);
 assert.throws(()=>parseMetrics({}),/unexpected metrics response/);
 assert.throws(()=>parseMetrics({alert_metrics:payload}),/unexpected metrics response/);
});
