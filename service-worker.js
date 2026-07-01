/**
 * DDD notify Worker — email (Resend) + Web Push (VAPID + aes128gcm).
 *
 * Routes:
 *   OPTIONS                          → CORS preflight
 *   GET  /test?secret=&email=&msg=   → send a test push (browser-friendly)
 *   POST {type:'push', secret, ...}  → send push to an audience
 *   POST {...resend email payload}   → forward to Resend (unchanged behaviour)
 *
 * Required secrets/vars:
 *   RESEND_KEY              (existing)
 *   VAPID_PRIVATE_KEY      (secret)  — base64url 32-byte key
 *   SUPABASE_SERVICE_ROLE (secret)  — Supabase service-role key (reads subscriptions)
 *   PUSH_SECRET           (secret)  — authorises push sends
 */

const VAPID_PUBLIC = 'BDSnFr-jWF6HWIQQxfKEOt2CY5gzsQscheKR1sDrFHhi4goguAtJKeRQhCOhRbms12951kDEsP88zwqtdXQEq44';
const VAPID_SUBJECT = 'mailto:victorhuni@gmail.com';
const SUPABASE_URL = 'https://bqznmupkqsxxlyiiqrys.supabase.co';
// Public anon key (safe to embed) — used only to validate a user's session token at /auth/v1/user
const ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJxem5tdXBrcXN4eGx5aWlxcnlzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzExMjUwNDEsImV4cCI6MjA4NjcwMTA0MX0.gtltfQ6YjsyqzHZLhtZbAF2XR6D-_plUr7HRJUXg0DY';
// Who may broadcast. Edit this list to add/remove admins (must match their app login email).
const ADMIN_EMAILS = ['victorhuni@gmail.com', 'victor@newleaders.co.za'];
const CORS = { 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Methods':'POST, GET', 'Access-Control-Allow-Headers':'Content-Type' };
const Cr = globalThis.crypto;

// ── small byte helpers ───────────────────────────────────────────────────────
function b64urlToBytes(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); const pad='='.repeat((4-s.length%4)%4); const bin=atob(s+pad); const a=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i); return a; }
function bytesToB64url(b){ b=new Uint8Array(b); let s=''; for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function concat(...arrs){ let n=0; for(const a of arrs)n+=a.length; const o=new Uint8Array(n); let p=0; for(const a of arrs){o.set(a,p);p+=a.length;} return o; }
function utf8(s){ return new TextEncoder().encode(s); }

async function hkdf(salt, ikm, info, len){
  const k=await Cr.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await Cr.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt,info}, k, len*8));
}
async function importVapidKey(privB64){
  const pub=b64urlToBytes(VAPID_PUBLIC), d=b64urlToBytes(privB64);
  const jwk={kty:'EC',crv:'P-256',ext:true,x:bytesToB64url(pub.slice(1,33)),y:bytesToB64url(pub.slice(33,65)),d:bytesToB64url(d)};
  return Cr.subtle.importKey('jwk', jwk, {name:'ECDSA',namedCurve:'P-256'}, false, ['sign']);
}
async function buildJWT(endpoint, privKey){
  const aud=new URL(endpoint).origin;
  const head=bytesToB64url(utf8(JSON.stringify({typ:'JWT',alg:'ES256'})));
  const pay=bytesToB64url(utf8(JSON.stringify({aud, exp:Math.floor(Date.now()/1000)+12*3600, sub:VAPID_SUBJECT})));
  const sig=await Cr.subtle.sign({name:'ECDSA',hash:'SHA-256'}, privKey, utf8(head+'.'+pay));
  return head+'.'+pay+'.'+bytesToB64url(new Uint8Array(sig));
}
async function encryptPayload(p256dhB64, authB64, payloadBytes){
  const uaPub=b64urlToBytes(p256dhB64), authSecret=b64urlToBytes(authB64);
  const salt=Cr.getRandomValues(new Uint8Array(16));
  const as=await Cr.subtle.generateKey({name:'ECDH',namedCurve:'P-256'}, true, ['deriveBits']);
  const asPub=new Uint8Array(await Cr.subtle.exportKey('raw', as.publicKey));
  const uaKey=await Cr.subtle.importKey('raw', uaPub, {name:'ECDH',namedCurve:'P-256'}, false, []);
  const ecdh=new Uint8Array(await Cr.subtle.deriveBits({name:'ECDH',public:uaKey}, as.privateKey, 256));
  const ikm=await hkdf(authSecret, ecdh, concat(utf8('WebPush: info'), new Uint8Array([0]), uaPub, asPub), 32);
  const cek=await hkdf(salt, ikm, utf8('Content-Encoding: aes128gcm\0'), 16);
  const nonce=await hkdf(salt, ikm, utf8('Content-Encoding: nonce\0'), 12);
  const aesKey=await Cr.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct=new Uint8Array(await Cr.subtle.encrypt({name:'AES-GCM',iv:nonce,tagLength:128}, aesKey, concat(payloadBytes, new Uint8Array([0x02]))));
  const rs=new Uint8Array(4); new DataView(rs.buffer).setUint32(0,4096);
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}

async function fetchSubs(env, to){
  let q=`${SUPABASE_URL}/rest/v1/push_subscriptions?select=endpoint,p256dh,auth,email`;
  if (to && to!=='all') {
    if (Array.isArray(to)) q+=`&email=in.(${to.map(encodeURIComponent).join(',')})`;
    else q+=`&email=eq.${encodeURIComponent(to)}`;
  }
  const r=await fetch(q, {headers:{apikey:env.SUPABASE_SERVICE_ROLE, Authorization:'Bearer '+env.SUPABASE_SERVICE_ROLE}});
  if(!r.ok) throw new Error('subs fetch '+r.status);
  return r.json();
}
async function deleteSub(env, endpoint){
  try{ await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, {method:'DELETE', headers:{apikey:env.SUPABASE_SERVICE_ROLE, Authorization:'Bearer '+env.SUPABASE_SERVICE_ROLE}}); }catch(e){}
}

// Validate a user's Supabase session token → returns lowercased email, or null
async function validateUser(token){
  if(!token) return null;
  try{
    const r=await fetch(`${SUPABASE_URL}/auth/v1/user`, {headers:{apikey:ANON_KEY, Authorization:'Bearer '+token}});
    if(!r.ok) return null;
    const u=await r.json();
    return (u && u.email) ? String(u.email).toLowerCase() : null;
  }catch(e){ return null; }
}
// Turn an audience descriptor into a `to` value for sendPush ('all' | [emails])
async function resolveAudience(env, audience){
  if(!audience || audience.kind==='everyone') return 'all';
  if(audience.kind==='person'){ const e=String(audience.value||'').trim().toLowerCase(); return e?[e]:[]; }
  if(audience.kind==='people'){ const arr=Array.isArray(audience.value)?audience.value:[]; const out=[]; const seen={}; for(const v of arr){ const e=String(v||'').trim().toLowerCase(); if(e&&!seen[e]){seen[e]=true;out.push(e);} } return out; }
  const col = audience.kind==='province' ? 'province' : audience.kind==='district' ? 'district' : null;
  if(!col || !audience.value) return [];
  const q=`${SUPABASE_URL}/rest/v1/officials?select=email&${col}=eq.${encodeURIComponent(audience.value)}`;
  const r=await fetch(q, {headers:{apikey:env.SUPABASE_SERVICE_ROLE, Authorization:'Bearer '+env.SUPABASE_SERVICE_ROLE}});
  if(!r.ok) throw new Error('officials fetch '+r.status);
  const rows=await r.json();
  return rows.map(x=>x.email).filter(Boolean);
}

async function sendPush(env, {to, title, body, url}){
  const privKey=await importVapidKey(env.VAPID_PRIVATE_KEY);
  const subs=await fetchSubs(env, to);
  const payload=utf8(JSON.stringify({title:title||'DDD Tracker', body:body||'', url:url||'https://ddd-interventions.github.io/ddd-tracker/'}));
  const jwtByOrigin={};
  let sent=0, failed=0, removed=0;
  for(const s of subs){
    try{
      const origin=new URL(s.endpoint).origin;
      if(!jwtByOrigin[origin]) jwtByOrigin[origin]=await buildJWT(s.endpoint, privKey);
      const enc=await encryptPayload(s.p256dh, s.auth, payload);
      const res=await fetch(s.endpoint, {method:'POST', headers:{
        'Authorization':'vapid t='+jwtByOrigin[origin]+', k='+VAPID_PUBLIC,
        'Content-Encoding':'aes128gcm', 'Content-Type':'application/octet-stream', 'TTL':'86400', 'Urgency':'high'
      }, body:enc});
      if(res.status===201||res.status===200){ sent++; }
      else if(res.status===404||res.status===410){ await deleteSub(env, s.endpoint); removed++; }
      else { failed++; }
    }catch(e){ failed++; }
  }
  return {total:subs.length, sent, failed, removed};
}

export default {
  async fetch(request, env){
    const url=new URL(request.url);
    if(request.method==='OPTIONS') return new Response(null, {headers:CORS});

    // Browser-friendly test hook
    if(request.method==='GET' && url.pathname==='/test'){
      if(url.searchParams.get('secret')!==env.PUSH_SECRET) return new Response('forbidden', {status:403, headers:CORS});
      const out=await sendPush(env, {
        to: url.searchParams.get('email') || 'all',
        title: url.searchParams.get('title') || 'DDD Tracker',
        body: url.searchParams.get('msg') || 'Tap to log in and update your circuit.',
        url: 'https://ddd-interventions.github.io/ddd-tracker/'
      });
      return new Response(JSON.stringify(out), {headers:{'Content-Type':'application/json', ...CORS}});
    }

    if(request.method!=='POST') return new Response('method not allowed', {status:405, headers:CORS});
    const body=await request.json();

    // Push send (authorised by shared secret — server-to-server / test use)
    if(body && body.type==='push'){
      if(body.secret!==env.PUSH_SECRET) return new Response(JSON.stringify({error:'forbidden'}), {status:403, headers:{'Content-Type':'application/json', ...CORS}});
      const out=await sendPush(env, {to:body.to||'all', title:body.title, body:body.body, url:body.url});
      return new Response(JSON.stringify(out), {headers:{'Content-Type':'application/json', ...CORS}});
    }

    // Broadcast (authorised by the caller's Supabase session token + admin allowlist)
    if(body && body.type==='broadcast'){
      const email=await validateUser(body.token);
      if(!email || ADMIN_EMAILS.map(e=>e.toLowerCase()).indexOf(email)===-1){
        return new Response(JSON.stringify({error:'not_authorised'}), {status:403, headers:{'Content-Type':'application/json', ...CORS}});
      }
      let to;
      try{ to=await resolveAudience(env, body.audience); }
      catch(e){ return new Response(JSON.stringify({error:'audience_failed'}), {status:500, headers:{'Content-Type':'application/json', ...CORS}}); }
      if(Array.isArray(to) && to.length===0){
        return new Response(JSON.stringify({total:0,sent:0,failed:0,removed:0,note:'no recipients matched'}), {headers:{'Content-Type':'application/json', ...CORS}});
      }
      const out=await sendPush(env, {to, title:body.title, body:body.body, url:body.url});
      return new Response(JSON.stringify(out), {headers:{'Content-Type':'application/json', ...CORS}});
    }

    // Email path — unchanged
    const res=await fetch('https://api.resend.com/emails', {
      method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+env.RESEND_KEY}, body:JSON.stringify(body)
    });
    const data=await res.json();
    return new Response(JSON.stringify(data), {headers:{'Content-Type':'application/json', ...CORS}});
  }
};
