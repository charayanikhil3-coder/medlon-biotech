// Cloudflare Pages middleware. Protects ALL /admin/api/* endpoints.
// /admin/ is a public login shell only; no customer records are delivered in HTML.
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const unauthorized = () => new Response(JSON.stringify({error:'Unauthorized admin request.'}), {
  status:401, headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}
});
const forbidden = () => new Response(JSON.stringify({error:'Not authorized for Medlon Admin.'}), {
  status:403, headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}
});
function decode64url(s) {
  if (!/^[\w-]+$/.test(s)) throw Error('Invalid base64url');
  const base64=s.replace(/-/g,'+').replace(/_/g,'/');
  const bin=atob(base64+'='.repeat((4-base64.length%4)%4));
  return Uint8Array.from(bin, c=>c.charCodeAt(0));
}
function json64(s){ return JSON.parse(new TextDecoder().decode(decode64url(s))); }
async function verify(request, env) {
  const project=String(env.FIREBASE_PROJECT_ID||'').trim();
  const admin=String(env.ADMIN_UID||'').trim();
  if (!project || !admin) return {status:503};
  const bearer=request.headers.get('authorization')||'';
  if (!/^Bearer\s+[^\s]+$/.test(bearer) || bearer.length > 12000) return {status:401};
  const jwt=bearer.slice(7).trim(), parts=jwt.split('.');
  if (parts.length!==3) return {status:401};
  let header, claims;
  try {header=json64(parts[0]);claims=json64(parts[1]);}catch{return {status:401};}
  const now=Math.floor(Date.now()/1000);
  if (header.alg!=='RS256'||typeof header.kid!=='string'||!header.kid||
      claims.aud!==project||claims.iss!==`https://securetoken.google.com/${project}`||
      typeof claims.sub!=='string'||!claims.sub||claims.sub.length>128||
      typeof claims.iat!=='number'||typeof claims.exp!=='number'||
      typeof claims.auth_time!=='number'||claims.iat>now+60||
      claims.auth_time>now+60||claims.exp<=now||claims.exp-claims.iat>3700) return {status:401};
  let data;
  try {
    const resp=await fetch(JWKS_URL,{cf:{cacheEverything:true,cacheTtl:1800}});
    if(!resp.ok) return {status:503};
    data=await resp.json();
  }catch{return {status:503};}
  const key=Array.isArray(data.keys)?data.keys.find(k=>k.kid===header.kid&&k.kty==='RSA'):null;
  if (!key) return {status:401};
  try {
    const cryptoKey=await crypto.subtle.importKey('jwk',key,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
    const ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',cryptoKey,decode64url(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1]));
    if (!ok) return {status:401};
  }catch{return {status:401};}
  if(claims.sub!==admin)return {status:403};
  return {status:200};
}
export async function onRequest(context) {
  const path=new URL(context.request.url).pathname;
  if(!(path==='/admin/api'||path.startsWith('/admin/api/')))return context.next();
  const result=await verify(context.request,context.env);
  if(result.status===503)return new Response(JSON.stringify({error:'Authentication temporarily unavailable or not configured.'}),{status:503,headers:{'content-type':'application/json','cache-control':'no-store'}});
  if(result.status===401)return unauthorized();
  if(result.status===403)return forbidden();
  const response=await context.next();
  const h=new Headers(response.headers);h.set('Cache-Control','private, no-store');h.set('X-Content-Type-Options','nosniff');
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers:h});
}
