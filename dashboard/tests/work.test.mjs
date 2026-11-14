import {test} from 'node:test';
import assert from 'node:assert/strict';
import {workModel} from '../lib/work.mjs';
const actors=['coordinator','worker-0','worker-1','verifier'];
const ev=(seq,kind,agent_id,detail)=>({seq,kind,agent_id,detail});
function op(seq,agent,action,args={}){return [ev(seq,'action.authorized',agent,{operation_id:String(seq),action,arguments_summary:args}),ev(seq+1,'action.committed',agent,{operation_id:String(seq),action})]}
test('declared dependencies stay pending until their committed event is visible',()=>{
 const empty=workModel([],actors);
 assert.equal(empty.total,10);assert.equal(empty.completed,0);
 const e=op(1,'worker-0','claim_task');
 assert.equal(workModel(e.slice(0,1),actors).completed,0);
 const done=workModel(e,actors);
 assert.equal(done.completed,1);
 assert.equal(done.positions['worker-0'].stage,'claimed');
 assert.equal(done.positions['worker-1'].stage,'waiting');
 assert.equal(done.nodes.find(n=>n.id==='report').done,false);
});
test('replay reconstructs individual allocation and preserves stopped work positions',()=>{
 const e=[...op(1,'worker-0','inspect_shard'),...op(3,'worker-1','calculate_shard'),ev(5,'run.paused','operator',{})];
 const model=workModel(e,actors);
 assert.equal(model.positions['worker-0'].stage,'inspecting');
 assert.equal(model.positions['worker-1'].stage,'calculating');
 assert.equal(model.ended,'paused');
 assert.equal(workModel(e.slice(0,2),actors).positions['worker-1'].stage,'waiting');
});
test('actual return messages mark agents returned, not tasks independently verified',()=>{
 const r=workModel([ev(1,'message.sent','worker-0',{channel:'graph-return',to:'coordinator',content:'Submitted.'})],actors);
 assert.equal(r.positions['worker-0'].stage,'finished');
 assert.equal(r.nodes.find(n=>n.id==='verification').done,false);
});
test('publication and verification are separate observed operations',()=>{
 const r=workModel(op(1,'verifier','verify_candidates'),actors);
 assert.equal(r.nodes.find(n=>n.id==='verification').done,true);
 assert.equal(r.nodes.find(n=>n.id==='report').done,false);
 const end=workModel([...op(1,'verifier','verify_candidates'),...op(3,'coordinator','publish')],actors);
 assert.equal(end.nodes.find(n=>n.id==='report').done,true);
});
test('agent-created task tree follows claims and recorded completion at playback position',()=>{
 const events=[ev(1,'task.created','coordinator',{id:'root',parent:null,title:'Report',state:'READY',creator:'coordinator',origin:'sdk-replay',dependencies:[]}),
 ev(2,'task.created','worker-0',{id:'child',parent:'root',title:'Calculate',state:'READY',creator:'worker-0',origin:'sdk-replay',dependencies:[]}),
 ev(3,'task.split','worker-0',{task_id:'root',children:['child']}),
 ev(4,'task.claimed','worker-1',{id:'child',owner:'worker-1',state:'LEASED'}),
 ev(5,'task.done','coordinator',{task_id:'child'})];
 const early=workModel(events.slice(0,4),actors),late=workModel(events,actors);
 assert.equal(early.dynamic,true);assert.deepEqual(early.edges,[['root','child']]);
 assert.equal(early.nodes.find(n=>n.id==='child').actor,'worker-1');assert.equal(early.completed,0);
 assert.equal(late.completed,1);assert.equal(late.nodes.find(n=>n.id==='child').ring,1);
 assert.equal(late.nodes.find(n=>n.id==='child').origin,'sdk-replay');
});
