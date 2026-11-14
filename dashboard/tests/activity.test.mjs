import {test} from 'node:test';
import assert from 'node:assert/strict';
import {activity} from '../lib/activity.mjs';
const actors=['coordinator','worker-0','worker-1','verifier'];
function event(seq,kind,agent,detail){return {seq,kind,agent_id:agent,detail,created:seq}}
function operation(seq,agent,action,args={}){return [event(seq,'action.authorized',agent,{operation_id:String(seq),action,arguments_summary:args}),event(seq+1,'action.committed',agent,{operation_id:String(seq),action})]}
test('maps committed writes and reads to shared resources, not fictitious peer messages',()=>{
 const result=activity([...operation(1,'worker-0','claim_task'),...operation(3,'worker-0','inspect_shard'),...operation(5,'worker-0','submit_result')],actors);
 assert.deepEqual(result.flows.map(f=>[f.from,f.to,f.type]),[['worker-0','tasks','write'],['input','worker-0','read'],['worker-0','results','write']]);
 assert.deepEqual(result.counts,{read:1,write:2,message:0});
});
test('does not animate an authorized action as committed and routes delegation to exact shard',()=>{
 const pair=operation(1,'coordinator','delegate',{shard:1});
 assert.equal(activity(pair.slice(0,1),actors).flows.length,0);
 assert.equal(activity(pair,actors).flows[0].to,'worker-1');
 assert.equal(activity(operation(3,'coordinator','delegate'),actors).flows.length,0);
});
test('reconstructs parallel in-flight work at the selected history position',()=>{
 const events=[event(1,'inference.requested','worker-0',{purpose:'agent'}),event(2,'inference.requested','worker-1',{purpose:'security-monitor'})];
 const r=activity(events,actors);
 assert.equal(r.states['worker-0'].label,'Model request in flight');
 assert.equal(r.states['worker-1'].label,'Safety check pending');
 assert.equal(r.states.verifier.label,'Awaiting activity');
 assert.equal(r.flows[0].to,'monitor');
 const ended=activity([...events,event(3,'run.paused','controller',{})],actors);
 assert.equal(ended.states['worker-0'].label,'Run paused');
});
test('uses actual dispatch content and keeps denied actions away from resource writes',()=>{
 const r=activity([event(1,'message.sent','coordinator',{to:'worker-0',content:'Analyze shard 0.'}),event(2,'action.denied','worker-0',{action:'post_note'})],actors);
 assert.equal(r.flows[0].label,'Analyze shard 0.');
 assert.equal(r.flows[1].type,'blocked');
 assert.equal(r.counts.write,0);
});
