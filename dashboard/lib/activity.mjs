// Only committed operations become data flows. Authorization is not execution.
export const resources = [
 {id:'notes',label:'Plans & notes'}, {id:'tasks',label:'Task leases'},
 {id:'input',label:'Input shards'}, {id:'calculation',label:'Trusted calculator'},
 {id:'results',label:'Result receipts'}, {id:'grader',label:'Reference grader'},
 {id:'report',label:'Verified report'}, {id:'monitor',label:'Safety gateway'},
];
const routes = {
 create_task:['tasks','write','Create task'],split_task:['tasks','write','Split task'],
 list_tasks:['tasks','read','Read task board'],claim_work:['tasks','write','Claim ready task'],
 read_notes:['notes','read','Read peer notes'],inspect_work:['input','read','Inspect task input'],
 calculate_work:['calculation','read','Trusted baseline calculation'],write_artifact:['results','write','Author source'],
 run_artifact:['results','read','Execute isolated artifact'],submit_task:['results','write','Submit task'],
 verify_task:['grader','read','Verify task'],verify_artifact:['grader','read','Reproduce authored calculation'],
 integrate_task:['results','write','Integrate verified task'],integrate_artifact:['results','write','Merge verified source'],
 publish_work:['report','write','Publish completed task tree'],
 record_plan:['notes','write','Record plan'],post_note:['notes','write','Post note'],
 claim_task:['tasks','write','Claim assigned shard'],inspect_shard:['input','read','Inspect shard sample'],
 calculate_shard:['calculation','read','Calculate shard with trusted tool'],submit_result:['results','write','Submit calculation receipt'],
 get_progress:['tasks','read','Read team progress'],verify_candidates:['grader','read','Verify candidate against reference'],
 publish:['report','write','Publish verified report'],
};
export function activity(events, actors) {
 const states=Object.fromEntries(actors.map(a=>[a,{label:'Awaiting activity',detail:'No event observed yet',seq:null}]));
 const flows=[], authorized=new Map(); let terminal=null;
 for(const e of events){
  const d=e.detail||{}, a=e.agent_id;
  if(e.kind==='action.authorized')authorized.set(d.operation_id,e);
  if(e.kind.startsWith('run.')&&e.kind!=='run.started') terminal=e.kind.slice(4);
  if(states[a]){
   if(e.kind==='inference.requested')states[a]={label:d.purpose==='security-monitor'?'Safety check pending':'Model request in flight',detail:d.purpose==='security-monitor'?'Waiting for external monitor verdict':'Waiting for model response; private reasoning is not exposed',seq:e.seq};
   if(e.kind==='inference.completed')states[a]={label:'Model response received',detail:'Next tool or final response may follow',seq:e.seq};
   if(e.kind==='action.authorized')states[a]={label:'Action authorized',detail:d.action,seq:e.seq};
   if(e.kind==='action.denied')states[a]={label:'Action denied',detail:d.action||'Safety finding',seq:e.seq};
   if(e.kind==='message.sent')states[a]={label:d.channel==='graph-return'?'Agent finished · result returned':'Message sent',detail:`To ${d.to}: ${d.content}`,seq:e.seq};
   if(e.kind==='agent.completed')states[a]={label:'Agent finished',detail:d.summary||'Agent graph returned',seq:e.seq};
  }
  if(e.kind==='inference.requested'&&d.purpose==='security-monitor')flows.push({id:`${e.seq}-check`,seq:e.seq,from:a,to:'monitor',type:'check',label:'Request safety decision',event:e});
  if(e.kind==='action.denied')flows.push({id:`${e.seq}-deny`,seq:e.seq,from:'monitor',to:a,type:'blocked',label:'Action blocked',event:e});
  if(e.kind==='message.sent'&&actors.includes(d.to)) flows.push({id:`${e.seq}-message`,seq:e.seq,from:a,to:d.to,type:'message',label:d.content,event:e});
  if(e.kind!=='action.committed')continue;
  const request=authorized.get(d.operation_id), args=request?.detail.arguments_summary||{};
  const route=routes[d.action];
  if(route){
   const [resource,type,label]=route;
   flows.push({id:`${e.seq}-tool`,seq:e.seq,from:type==='read'?resource:a,to:type==='read'?a:resource,type,label,event:request||e,committed:e});
   if(states[a]) states[a]={label:label+' · committed',detail:args.text|| (args.fence!==undefined?`Lease fence ${args.fence}`:d.action),seq:e.seq};
  }
  // Older runs do not contain explicit dispatch messages. Show only the observed
  // delegation request, never a fabricated response or conversation transcript.
  if(d.action==='delegate'&&Number.isInteger(args.shard)&&actors.includes(`worker-${args.shard}`)){
   flows.push({id:`${e.seq}-delegate`,seq:e.seq,from:a,to:`worker-${args.shard}`,type:'handoff',label:`Authorized delegation · shard ${args.shard}`,event:request||e});
   if(states[a])states[a]={label:'Delegation authorized',detail:`Shard ${args.shard} → worker-${args.shard}`,seq:e.seq};
  }
  if(d.action==='request_verification'){
   flows.push({id:`${e.seq}-verify`,seq:e.seq,from:a,to:'verifier',type:'handoff',label:'Verification delegation authorized',event:request||e});
   if(states[a])states[a]={label:'Verification requested',detail:'Delegated to independent verifier',seq:e.seq};
  }
 }
 if(terminal)for(const state of Object.values(states)){state.lastLabel=state.label;state.label=`Run ${terminal}`;state.detail=`Last observed: ${state.lastLabel}. ${state.detail}`}
 return {states,flows,counts:{read:flows.filter(f=>f.type==='read').length,write:flows.filter(f=>f.type==='write').length,message:flows.filter(f=>f.type==='message'||f.type==='handoff').length}};
}
// Spans are trace structure; they are not agent activity.
export function agentEvents(events, agent) {
 return events.filter(e=>e.agent_id===agent&&!e.kind.startsWith('span.'));
}
