export const formatDuration = s => s==null?'—':s<60?`${Math.round(s)} s`:s<3600?`${Math.round(s/60)} min`:`${(s/3600).toFixed(1)} h`;
export const formatCoverage = v => v==null?'—':`${Math.round(v*100)}%`;
export function parseMetrics(json){
 if(!json||typeof json.alerts!=='number')throw Error('unexpected metrics response');
 return json;
}
export function healthModel(m){
 const tone=m.slo_breaches>0?'bad':m.open_alerts>0?'warn':'ok';
 const t=(id,label,value)=>({id,label,value,tone});
 return {empty:m.alerts===0,tiles:[
  t('alerts','Alerts',String(m.alerts)),
  t('triage_coverage','Triage coverage',formatCoverage(m.triage_coverage)),
  t('human_coverage','Human coverage',formatCoverage(m.human_coverage)),
  t('dwell_p50','Median dwell',formatDuration(m.dwell_p50_s)),
  t('open_alerts','Open alerts',String(m.open_alerts)),
  t('slo_breaches','SLO breaches',String(m.slo_breaches))]};
}
