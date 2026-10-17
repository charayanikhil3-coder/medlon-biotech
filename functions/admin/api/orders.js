const reply=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
export async function onRequestGet({env}){
  if(!env.ORDERS_DB) return reply({error:'Orders database has not been connected.'},503);
  try {
    const result=await env.ORDERS_DB.prepare('SELECT id,buyer_type,name,phone,city,product,quantity,message,status,source,created_at,updated_at FROM enquiries ORDER BY created_at DESC LIMIT 1000').all();
    return reply({orders:result.results||[]});
  }catch(e){console.error(e);return reply({error:'Could not load orders.'},503)}
}
