import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const code=await readFile(new URL('../app/api/teamlab/[...path]/route.js',import.meta.url),'utf8');
const {GET}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
const params={params:Promise.resolve({path:['runs']})};
function request(headers={}) {return new Request('http://127.0.0.1:3000/api/teamlab/runs',{headers:{host:'127.0.0.1:3000',...headers}})}
test('rejects foreign hosts and origins before fetching',async()=>{
 assert.equal((await GET(request({host:'evil.example:3000'}),params)).status,403);
 assert.equal((await GET(request({origin:'http://evil.example'}),params)).status,403);
 assert.equal((await GET(request({'sec-fetch-site':'cross-site'}),params)).status,403);
});
test('requires a server credential and allows only monitoring routes',async()=>{
 delete process.env.TEAMLAB_MONITOR_TOKEN;
 assert.equal((await GET(request(),params)).status,503);
 assert.equal((await GET(request(),{params:Promise.resolve({path:['runs','../secret','snapshot']})})).status,404);
});
test('keeps token upstream and forwards errors safely',async()=>{
 process.env.TEAMLAB_MONITOR_TOKEN='test-token-'.repeat(4);
 const saved=global.fetch;
 try {
 global.fetch=async(url,options)=>{assert.equal(options.headers.Authorization,'Bearer '+process.env.TEAMLAB_MONITOR_TOKEN);assert.equal(String(url),'http://127.0.0.1:8765/runs');return Response.json({runs:[]})};
 const result=await GET(request(),params);assert.equal(result.status,200);assert.deepEqual(await result.json(),{runs:[]});
 global.fetch=async()=>{throw Error('internal credential data')};
 const failure=await GET(request(),params);assert.equal(failure.status,502);assert.ok(!(await failure.text()).includes('internal credential'));
 }finally{global.fetch=saved;delete process.env.TEAMLAB_MONITOR_TOKEN}
});
