// A declared analytics workflow, reconstructed only from the selected events.
// This is not an agent-generated task tree or evidence of dynamic staffing.
export const workStages=[
 {id:'waiting',label:'Awaiting work'}, {id:'coordinating',label:'Coordination'},
 {id:'claimed',label:'Shard claimed'}, {id:'inspecting',label:'Shard inspected'},
 {id:'calculating',label:'Calculation'}, {id:'submitted',label:'Submitted / waiting'},
 {id:'verifying',label:'Verification'}, {id:'finished',label:'Returned / finished'},
];
const locations={record_plan:'coordinating',delegate:'coordinating',get_progress:'coordinating',post_note:null,claim_task:'claimed',inspect_shard:'inspecting',calculate_shard:'calculating',submit_result:'submitted',request_verification:'verifying',verify_candidates:'verifying',publish:'finished',create_task:'coordinating',split_task:'coordinating',list_tasks:null,claim_work:'claimed',inspect_work:'inspecting',calculate_work:'calculating',run_artifact:'calculating',write_artifact:'calculating',submit_task:'submitted',verify_task:'verifying',verify_artifact:'verifying',publish_work:'finished'};
export function workModel(events,actors){
 const positions=Object.fromEntries(actors.map(a=>[a,{stage:'waiting',event:null,detail:'No work observed'}]));
 const commits=new Map(),authorized=new Map(),tasks=new Map();let ended=null;
 for(const e of events){const d=e.detail||{};
  if(e.kind==='task.created')tasks.set(d.id,{...d,event:e});
  if(e.kind==='task.claimed'){
   tasks.set(d.id,{...tasks.get(d.id),...d,event:e});
   if(positions[e.agent_id])positions[e.agent_id]={stage:'claimed',event:e,detail:`Claimed task ${d.id}`};
  }
  if(['task.split','task.submitted','task.verified','task.done','task.blocked'].includes(e.kind)){
   const t=tasks.get(d.task_id);
   if(t){t.state={'task.split':'WAITING','task.submitted':'SUBMITTED','task.verified':d.verdict?.passed?'VERIFIED':'FAILED','task.done':'DONE','task.blocked':'BLOCKED'}[e.kind];t.event=e;}
   if(positions[e.agent_id]&&e.kind==='task.submitted')positions[e.agent_id]={stage:'submitted',event:e,detail:`Submitted task ${d.task_id}`};
  }
  if(e.kind==='action.authorized')authorized.set(d.operation_id,e);
  if(e.kind==='action.committed'){
   const request=authorized.get(d.operation_id);
   commits.set(`${e.agent_id}:${d.action}`,{event:e,request});
   if(positions[e.agent_id]&&locations[d.action])positions[e.agent_id]={stage:locations[d.action],event:request||e,detail:`${d.action} committed`};
   if(d.action==='delegate'){
    const worker=`worker-${request?.detail.arguments_summary?.shard}`;
    if(positions[worker])positions[worker]={stage:'waiting',event:request,detail:'Delegation authorized; awaiting recorded worker activity'};
   }
  }
  if(e.kind==='agent.completed'&&positions[e.agent_id])positions[e.agent_id]={stage:'finished',event:e,detail:'Agent graph returned'};
  if(e.kind==='message.sent'&&d.channel==='graph-return'&&positions[e.agent_id])positions[e.agent_id]={stage:'finished',event:e,detail:'Result returned to coordinator'};
  if(['run.completed','run.paused','run.stopped','run.failed'].includes(e.kind))ended=e.kind.slice(4);
 }
 if(tasks.size){
  const levels=new Map();
  function depth(t){if(levels.has(t.id))return levels.get(t.id);const n=t.parent&&tasks.has(t.parent)?depth(tasks.get(t.parent))+1:0;levels.set(t.id,n);return n;}
  const byRing=new Map();
  const nodes=[...tasks.values()].map(t=>{const ring=depth(t),index=byRing.get(ring)||0;byRing.set(ring,index+1);return {id:t.id,label:t.title,actor:t.owner||t.creator,ring,index,state:t.state,done:t.state==='DONE',event:t.event,committed:t.event,origin:t.origin,dependencies:t.dependencies};});
  for(const n of nodes)n.ringCount=byRing.get(n.ring);
  const edges=[...tasks.values()].filter(t=>t.parent&&tasks.has(t.parent)).map(t=>[t.parent,t.id]);
  const dependencyEdges=[...tasks.values()].flatMap(t=>(t.dependencies||[]).filter(d=>tasks.has(d)).map(d=>[d,t.id]));
  return {dynamic:true,nodes,edges,dependencyEdges,positions,ended,workers:actors.filter(a=>a.startsWith('worker-')),completed:nodes.filter(n=>n.done).length,total:nodes.length};
 }
 const nodes=[{id:'report',label:'Verified report',actor:'coordinator',action:'publish',ring:0},
 {id:'verification',label:'Independent check',actor:'verifier',action:'verify_candidates',ring:1}];
 const workers=actors.filter(a=>a.startsWith('worker-'));
 for(const [index,actor] of workers.entries())for(const [ring,action,label] of [[2,'submit_result','Submit'],[3,'calculate_shard','Calculate'],[4,'inspect_shard','Inspect'],[5,'claim_task','Claim']]){
  nodes.push({id:`${actor}:${action}`,actor,action,label:`Shard ${actor.slice(7)} · ${label}`,ring,index});
 }
 for(const n of nodes){const record=commits.get(`${n.actor}:${n.action}`);n.done=!!record;n.event=record?.request||record?.event||null;n.committed=record?.event||null;}
 const edges=[['report','verification']];
 for(const a of workers)edges.push(['verification',`${a}:submit_result`],[`${a}:submit_result`,`${a}:calculate_shard`],[`${a}:calculate_shard`,`${a}:inspect_shard`],[`${a}:inspect_shard`,`${a}:claim_task`]);
 return {nodes,edges,positions,ended,workers,completed:nodes.filter(n=>n.done).length,total:nodes.length};
}
