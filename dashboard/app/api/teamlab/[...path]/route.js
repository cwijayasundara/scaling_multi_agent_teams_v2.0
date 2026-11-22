export const dynamic = 'force-dynamic';
export async function GET(request, {params}) {
  // Browser callers never receive the upstream credential. Bind Next to loopback.
  const host = request.headers.get('host') || '';
  if (!/^(localhost|127\.0\.0\.1):\d+$/.test(host)) return new Response('Local access only', {status:403});
  const origin = request.headers.get('origin');
  if (origin && origin !== new URL(request.url).origin) return new Response('Origin rejected', {status:403});
  if (request.headers.get('sec-fetch-site') === 'cross-site') return new Response('Cross-site access rejected', {status:403});
  const {path} = await params;
  if (!(path.length === 1 && ['runs','metrics'].includes(path[0])) && !(path.length === 3 && path[0] === 'runs' && /^[a-f0-9]{24}$/.test(path[1]) && ['snapshot','review','events','metrics','triage','trace'].includes(path[2]))) return new Response('Not found',{status:404});
  const token = process.env.TEAMLAB_MONITOR_TOKEN;
  if (!token || token.length < 32) return Response.json({error:'Set TEAMLAB_MONITOR_TOKEN on the Next.js server (at least 32 characters).'}, {status:503});
  try {
    const base = process.env.TEAMLAB_API_URL || 'http://127.0.0.1:8765';
    const url = new URL('/'+path.join('/'), base);
    if(path[2] === 'events') url.search = new URL(request.url).search;
    const result = await fetch(url, {headers:{Authorization:`Bearer ${token}`},cache:'no-store',signal:AbortSignal.timeout(30000)});
    return new Response(result.body, {status:result.status,headers:{'Content-Type':result.headers.get('Content-Type') || 'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
  } catch {return Response.json({error:'Python monitoring server is unreachable. Start teamlab serve with the same token.'},{status:502})}
}
