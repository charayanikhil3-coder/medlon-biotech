const reply=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const statuses=['New','Reviewing','Quoted','Approved','Packed','Dispatched','Completed','Cancelled'];
export async function onRequestPatch({request,env,params}){
  if(!env.ORDERS_DB)return reply({error:'Database not connected.'},503);
  const origin=request.headers.get('origin');if(!origin||origin!==new URL(request.url).origin)return reply({error:'Invalid origin.'},403);
  if(!/application\/json/i.test(request.headers.get('content-type')||''))return reply({error:'JSON required.'},415);
  let body;try{body=await request.json()}catch{return reply({error:'Invalid JSON.'},400)}
  if(!body||!statuses.includes(body.status))return reply({error:'Invalid status.'},400);
  try{
    const result=await env.ORDERS_DB.prepare("UPDATE enquiries SET status=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? RETURNING id,status,updated_at").bind(body.status,params.id).first();
    if(!result)return reply({error:'Order not found.'},404);
    return reply({ok:true,order:result});
  }catch(e){console.error(e);return reply({error:'Could not update status.'},503)}
}
