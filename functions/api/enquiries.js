// Public product enquiry intake. Creates REAL entries in D1; never charges a customer.
const json=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const clean=(v,max)=>typeof v==='string'?v.trim().slice(0,max):'';
export async function onRequestPost({request,env}) {
  if(!env.ORDERS_DB||!env.RATE_SALT) return json({error:'Order intake is not configured yet.'},503);
  const origin=request.headers.get('Origin');
  if(origin && origin!==new URL(request.url).origin) return json({error:'Origin not permitted.'},403);
  if(!/application\/json/i.test(request.headers.get('content-type')||'')) return json({error:'JSON required.'},415);
  if(Number(request.headers.get('content-length')||0)>12000) return json({error:'Request too large.'},413);
  let form;
  try{form=await request.json();}catch{return json({error:'Invalid data.'},400)}
  if(!form||typeof form!=='object'||Array.isArray(form)) return json({error:'Invalid data.'},400);
  // Honeypot input must remain empty. Quietly fail closed for spam submissions.
  if(clean(form.website,100)) return json({error:'Unable to submit this enquiry.'},400);
  const enquiry_type=clean(form.enquiry_type,20);
  if(!['product','general'].includes(enquiry_type)) return json({error:'Invalid enquiry type.'},400);
  const buyer_type=clean(form.buyer_type,20),name=clean(form.name,80),phone=clean(form.phone,30).replace(/[\s()\-]/g,''),city=clean(form.city,80),product=clean(form.product,120),message=clean(form.message,1000),quantity=Number(form.quantity);
  if(!['Retail','Wholesale'].includes(buyer_type)||name.length<2||!/^[+]?[0-9]{10,15}$/.test(phone)||product.length<2||message.length<5||!Number.isInteger(quantity)||quantity<1||quantity>9999||form.consent!==true) return json({error:'Please fill in buyer type, name, valid phone, product, quantity, message and consent.'},400);
  // Best-effort modest abuse control using salted digest of requesting IP, never raw IP.
  const ip=request.headers.get('cf-connecting-ip')||'unknown';
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(env.RATE_SALT+':'+ip));
  const fingerprint=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,'0')).join('');
  const slot=Math.floor(Date.now()/600000);
  try {
    const limit=await env.ORDERS_DB.prepare('INSERT INTO request_limits (identity_hash,slot,hits) VALUES (?, ?, 1) ON CONFLICT(identity_hash,slot) DO UPDATE SET hits=hits+1 RETURNING hits').bind(fingerprint,slot).first();
    if(limit && limit.hits>5) return json({error:'Too many requests. Try again later.'},429);
    const id='MB-'+crypto.randomUUID().slice(0,8).toUpperCase();
    await env.ORDERS_DB.prepare('INSERT INTO enquiries (id,buyer_type,name,phone,city,product,quantity,message,source) VALUES (?,?,?,?,?,?,?,?,?)').bind(id,buyer_type,name,phone,city,product,quantity,message,enquiry_type==='general'?'General Enquiry':'Product Enquiry').run();
    // Manual fulfilment only, subject to licence/prescription verification when required.
    return json({ok:true,id,status:'New'},201);
  } catch(e){console.error('D1 enquiry intake failed',e);return json({error:'Could not save your enquiry. Please try again.'},503)}
}
