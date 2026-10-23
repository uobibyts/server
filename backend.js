/* VAULT-OS static backend (GitHub Pages edition)
   Replaces app.py: every /api/* call is answered inside the browser.
   Files -> IndexedDB, settings/alerts/logins -> localStorage. Data is per-browser/per-device. */
(()=>{
window.__VB=1;
const KV='vaultos_state',of=window.fetch.bind(window),now=()=>Date.now()/1000;
// ---------- file store (IndexedDB) ----------
const idb=new Promise((res,rej)=>{const r=indexedDB.open('vaultos',2);r.onupgradeneeded=()=>{const d=r.result;if(!d.objectStoreNames.contains('f'))d.createObjectStore('f',{keyPath:'p'});if(!d.objectStoreNames.contains('k'))d.createObjectStore('k',{keyPath:'id'})};r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)});
const tx=(m,fn,st='f')=>idb.then(d=>new Promise((res,rej)=>{const t=d.transaction(st,m);const q=fn(t.objectStore(st));t.oncomplete=()=>res(q&&q.result);t.onerror=()=>rej(t.error)}));
const fget=p=>tx('readonly',s=>s.get(p)),fput=o=>tx('readwrite',s=>s.put(o)),fdel=p=>tx('readwrite',s=>s.delete(p)),fall=()=>tx('readonly',s=>s.getAll()),kget=()=>tx('readonly',s=>s.get('key'),'k'),kput=o=>tx('readwrite',s=>s.put(o),'k'),kdel=()=>tx('readwrite',s=>s.delete('key'),'k');
const norm=p=>{const a=String(p||'').replace(/\\/g,'/').split('/').filter(x=>x&&x!=='.');if(a.includes('..'))throw{error:'bad path'};return a.join('/')};
const par=p=>p.split('/').slice(0,-1).join('/'),base=p=>p.split('/').pop();
async function mkdirs(p){while(p){if(!await fget(p))await fput({p,dir:true,size:0,m:now()});p=par(p)}}
// ---------- state (localStorage) ----------
const D0={user:null,pw:null,salt:null,alerts:[],logins:[],monitors:[],block:[],locs:{},fail:[],seeded:0,nid:1,hits:0,first:now(),myip:'',geo:'',lastchk:0,bm:[],del:{},rev:0};
let S;try{S={...D0,...JSON.parse(localStorage[KV]||'{}')}}catch(e){S={...D0}}
const persist=()=>{try{localStorage[KV]=JSON.stringify(S)}catch(e){}};
const alertL=(level,msg)=>{S.alerts.unshift({id:S.nid++,ts:now(),level,msg});S.alerts=S.alerts.slice(0,200);persist();if(level==='crit'&&'Notification' in window&&Notification.permission==='granted'){try{new Notification('VAULT-OS',{body:msg})}catch(e){}}};
if(!S.seeded){for(const [k,t] of [['page','https://uobitechnology.github.io'],['page','https://aboutubaidurrehman.github.io'],['page','https://uobibyts.github.io'],['site','https://www.instagram.com/ubaid_uhiha'],['site','https://www.instagram.com/uobi.byts'],['site','https://www.instagram.com/uobi.technology'],['site','https://www.instagram.com/couch_casting_director'],['site','https://www.instagram.com/byts_boiie']])S.monitors.push({id:S.nid++,kind:k,target:t,state:'',hash:''});S.seeded=1}
S.hits++;persist();
const sess=()=>{try{const s=JSON.parse(localStorage.vsess||'null');return s&&s.exp>Date.now()?s.user:null}catch(e){return null}};
const myip=async()=>{try{const d=await(await of('https://ipwho.is/')).json();if(d.success){S.myip=d.ip;S.geo=`${d.city}, ${d.region}, ${d.country} | ${(d.connection||{}).isp||''}`;persist()}}catch(e){}};myip();
// ---------- password hashing ----------
const enc=new TextEncoder(),b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))),unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hpw=async(p,salt)=>b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:300000},await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']),256));
// ---------- threat scanner (same heuristics as app.py) ----------
const BR=['paypal','google','facebook','instagram','whatsapp','apple','microsoft','amazon','netflix','binance','jazzcash','easypaisa','telegram','tiktok'];
const KW=['verify','urgent','suspend','password','otp','login','secure','update','confirm','gift','winner','prize','claim','free','blocked','kyc','limit','immediately','expire'];
const SH=['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cutt.ly','rb.gy','shorturl.at'];
const TL=['.xyz','.top','.tk','.ml','.gq','.cf','.click','.work','.zip','.mov','.loan','.icu'];
const imit=(h,b)=>h.includes(b)&&!(h===b+'.com'||h.endsWith('.'+b+'.com'));
function scan(text){const bl=new Set(S.block),res=[],hosts=new Set(),notes=[];let total=0;
for(const u of new Set(text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi)||[])){let sc=0,why=[],pu,h='';try{pu=new URL(u.includes('://')?u:'http://'+u);h=pu.hostname.toLowerCase()}catch(e){}
if(!h)continue;hosts.add(h);
if(bl.has(h)||[...bl].some(b=>h.endsWith('.'+b))){sc+=10;why.push('in your blocklist')}
if(/^[\d.]+$/.test(h)){sc+=3;why.push('raw IP address')}
if(h.includes('xn--')){sc+=3;why.push('punycode lookalike domain')}
if(pu.username||pu.password){sc+=3;why.push('@ trick in URL')}
if(SH.includes(h)){sc+=2;why.push('link shortener hides destination')}
if(TL.some(t=>h.endsWith(t))){sc+=2;why.push('high-abuse TLD')}
if(h.split('.').length-1>=4){sc+=1;why.push('too many subdomains')}
if(h.split('-').length-1>=2){sc+=1;why.push('many hyphens')}
if(pu.protocol==='http:'){sc+=1;why.push('no HTTPS')}
for(const b of BR)if(imit(h,b)){sc+=4;why.push(`imitates "${b}"`);break}
if(KW.filter(k=>u.toLowerCase().includes(k)).length>=2){sc+=1;why.push('bait words in URL')}
res.push({url:u,score:sc,why});total=Math.max(total,sc)}
for(const m of text.matchAll(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g)){const e=m[1].toLowerCase();for(const b of BR)if(imit(e,b)){total=Math.max(total,4);res.push({url:'email domain '+e,score:4,why:[`imitates "${b}"`]})}}
const kw=KW.filter(k=>text.toLowerCase().includes(k));if(kw.length>=3){total+=2;notes.push('urgency/bait language: '+kw.slice(0,6).join(', '))}
for(const n of text.match(/\+?\d[\d\s-]{8,}\d/g)||[])if(bl.has(n.replace(/\D/g,''))||bl.has(n.trim())){total+=10;notes.push('number in blocklist: '+n.trim())}
const v=total>=5?'DANGEROUS':total>=3?'SUSPICIOUS':'LOW RISK';
if(v==='DANGEROUS'){for(const h of hosts)if(!S.block.includes(h))S.block.push(h);alertL('crit','Threat blocked: '+([...hosts].slice(0,3).join(', ')||'message')+` (score ${total})`)}
return{verdict:v,score:total,urls:res,notes}}
// ---------- monitors (browser can only test reachability, not page content) ----------
async function checkAll(){S.lastchk=now();persist();
for(const m of S.monitors){let st;if(m.kind==='port')st='N/A';else if(!/^https?:\/\//.test(m.target))st='BAD URL';else{try{await of(m.target,{mode:'no-cors',cache:'no-store',signal:AbortSignal.timeout(10000)});st='UP'}catch(e){st='DOWN'}}
if(m.state&&st!==m.state&&m.state!=='N/A')alertL(st==='UP'?'warn':'crit',`${m.kind.toUpperCase()} ${m.target}: ${m.state} -> ${st}`);m.state=st}persist()}
// ---------- code runner (JS in sandboxed iframe, Python via Pyodide) ----------
const runJS=code=>new Promise(res=>{const f=document.createElement('iframe');f.sandbox='allow-scripts';f.style.display='none';let out='';
const fin=()=>{clearTimeout(t);removeEventListener('message',h);f.remove();res(out.slice(-8000)||'(no output)')};
const h=e=>{if(e.source!==f.contentWindow||!e.data)return;if(e.data.vo!==undefined)out+=e.data.vo;if(e.data.vdone)fin()};
const t=setTimeout(()=>{out+='\nTIMEOUT (15s)';fin()},15000);addEventListener('message',h);
f.srcdoc='<script>const P=s=>parent.postMessage({vo:s},"*");console.log=console.info=console.warn=console.error=(...a)=>P(a.map(x=>typeof x==="object"?JSON.stringify(x):String(x)).join(" ")+"\\n");addEventListener("error",e=>P("Error: "+e.message+"\\n"));try{(0,eval)('+JSON.stringify(code).replace(/</g,'\\u003c')+')}catch(e){P("Error: "+e+"\\n")}setTimeout(()=>parent.postMessage({vdone:1},"*"),400)<\/script>';
document.body.appendChild(f)});
let PY;const pyLoad=()=>PY||(PY=new Promise((res,rej)=>{const s=document.createElement('script');s.src='https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.js';s.onload=()=>loadPyodide().then(res,rej);s.onerror=()=>{PY=null;rej(new Error('Pyodide could not load (internet needed)'))};document.head.appendChild(s)}));
const runPy=async code=>{let out='';try{const py=await pyLoad();py.setStdout({batched:s=>out+=s+'\n'});py.setStderr({batched:s=>out+=s+'\n'});await py.loadPackagesFromImports(code);await py.runPythonAsync(code)}catch(e){out+=String(e.message||e)}return out.slice(-8000)||'(no output)'};
// ---------- raw file URLs (blob:) ----------
const MIME={html:'text/html',htm:'text/html',css:'text/css',js:'text/javascript',json:'application/json',txt:'text/plain',md:'text/plain',svg:'image/svg+xml',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',pdf:'application/pdf',mp3:'audio/mpeg',wav:'audio/wav',ogg:'audio/ogg',mp4:'video/mp4',webm:'video/webm'};
const toBlob=r=>{const t=MIME[base(r.p).split('.').pop().toLowerCase()]||'application/octet-stream';return r.data instanceof Blob?(r.data.type?r.data:new Blob([r.data],{type:t})):new Blob([r.data],{type:t})};
window.rawURL=async p=>{const r=await fget(norm(p));if(!r||r.dir)throw{error:'not found'};return URL.createObjectURL(toBlob(r))};
new MutationObserver(()=>document.querySelectorAll('[data-raw]').forEach(async e=>{const p=e.dataset.raw;e.removeAttribute('data-raw');try{e.src=await rawURL(p)}catch(x){}})).observe(document.documentElement,{childList:true,subtree:true});
const dirty=()=>{persist()};
const MUT=new Set(['/api/save','/api/mkdir','/api/delete','/api/upload','/api/block','/api/unblock','/api/mon_add','/api/mon_del','/api/clear_alerts','/api/bm','/api/setup','/api/login','/api/scan']);
// ---------- API router ----------
const out=(o,st=200)=>new Response(JSON.stringify(o),{status:st,headers:{'Content-Type':'application/json'}});
async function route(url,o){const r=await route0(url,o);if((o.method||'GET')==='POST'&&r.status<300&&MUT.has(new URL(url,location.origin).pathname))dirty();return r}
async function route0(url,o){const u=new URL(url,location.origin),p=u.pathname,q=Object.fromEntries(u.searchParams),post=(o.method||'GET')==='POST';let d={};
if(post&&o.body&&p!=='/api/upload'){try{d=JSON.parse(o.body)}catch(e){}}
try{
if(p==='/api/me')return out({user:sess(),setup:!S.user});
if(p==='/api/setup'&&post){if(S.user)return out({error:'already set up'},403);if((d.pw||'').length<10||!d.user)return out({error:'Password min 10 chars'},400);const sa=crypto.getRandomValues(new Uint8Array(16));S.salt=b64(sa);S.pw=await hpw(d.pw,sa);S.user=String(d.user).slice(0,40);persist();alertL('info','Commander account created');return out({ok:1})}
if(p==='/api/login'&&post){S.fail=S.fail.filter(t=>t>now()-600);if(S.fail.length>=5)return out({error:'Locked out 10 min'},429);
const ok=!!S.user&&d.user===S.user&&await hpw(d.pw||'',unb64(S.salt))===S.pw;const dev=String(d.device||'').slice(0,64),ua=navigator.userAgent.slice(0,200),ip=S.myip||'this device';
if(!ok){S.fail.push(now());S.logins.unshift({id:S.nid++,ts:now(),user:String(d.user||'').slice(0,40),ip,ua,device:dev,ok:0,new:0});persist();alertL('warn',`FAILED LOGIN user=${String(d.user||'').slice(0,40)}`);return out({error:'Access denied'},401)}
const nw=S.logins.some(l=>l.ok&&l.device===dev)?0:1,id=S.nid++;S.logins.unshift({id,ts:now(),user:d.user,ip,ua,device:dev,ok:1,new:nw,geo:S.geo});S.logins=S.logins.slice(0,100);
localStorage.vsess=JSON.stringify({user:d.user,exp:Date.now()+28800000});persist();alertL(nw?'crit':'info',(nw?'UNKNOWN DEVICE LOGIN':'Login')+` user=${d.user}`);
myip().then(()=>{const l=S.logins.find(x=>x.id===id);if(l){l.ip=S.myip||l.ip;l.geo=S.geo;persist()}});return out({ok:1,login_id:id,new:nw})}
const me=sess();if(!me)return out({error:'auth'},401);
switch(p){
case'/api/logout':localStorage.removeItem('vsess');kdel().catch(()=>{});delete S.locs[me];persist();return out({ok:1});
case'/api/loc':{const la=+d.lat,lo=+d.lng;if(!(la>=-90&&la<=90&&lo>=-180&&lo<=180))throw{error:'bad coords'};const nw=!S.locs[me];S.locs[me]={lat:la,lon:lo,acc:+d.acc||0,spd:d.spd==null?null:+d.spd,ts:now()};persist();if(nw)alertL('info','TRACKER: '+me+' started location sharing');return out({ok:1})}
case'/api/locstop':delete S.locs[me];persist();return out({ok:1});
case'/api/locs':for(const k in S.locs)if(S.locs[k].ts<now()-86400)delete S.locs[k];persist();return out({now:now(),list:Object.keys(S.locs).sort().map(k=>({name:k,...S.locs[k]}))});
case'/api/geo':{const l=S.logins.find(x=>x.id===+d.id&&x.user===me);if(l){l.lat=+d.lat;l.lon=+d.lon;l.acc=+d.acc||0;persist()}return out({ok:1})}
case'/api/state':if(now()-S.lastchk>60)checkAll();return out({alerts:S.alerts.slice(0,60),logins:S.logins.slice(0,40),monitors:S.monitors,block:S.block});
case'/api/files':{const dir=norm(q.path),all=await fall();return out(all.filter(r=>par(r.p)===dir).sort((a,b)=>(!!b.dir-!!a.dir)||a.p.toLowerCase().localeCompare(b.p.toLowerCase())).map(r=>({name:base(r.p),dir:!!r.dir,size:r.dir?0:(r.size??0)})))}
case'/api/music':return out((await fall()).filter(r=>!r.dir&&/\.mp3$/i.test(r.p)).map(r=>r.p).sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase())));
case'/api/file':{const r=await fget(norm(q.path));if(!r||r.dir)throw{error:'not found'};if(typeof r.data==='string')return out({content:r.data});if(r.data.size>2097152)return out({binary:true});try{return out({content:new TextDecoder('utf-8',{fatal:true}).decode(await r.data.arrayBuffer())})}catch(e){return out({binary:true})}}
case'/api/save':{const f=norm(d.path);if(!f)throw{error:'bad path'};await mkdirs(par(f));await fput({p:f,data:String(d.content??''),size:new Blob([String(d.content??'')]).size,m:now()});alertL('info','Saved '+f);return out({ok:1})}
case'/api/mkdir':await mkdirs(norm(d.path));return out({ok:1});
case'/api/delete':{const f=norm(d.path);if(!f)throw{error:'no'};S.del=S.del||{};for(const r of await fall())if(r.p===f||r.p.startsWith(f+'/')){await fdel(r.p);S.del[r.p]=now()}persist();alertL('warn','Deleted '+f);return out({ok:1})}
case'/api/upload':{const dir=norm(q.path),f=(dir?dir+'/':'')+base(norm(q.name));await mkdirs(dir);await fput({p:f,data:o.body,size:o.body.size,m:now()});alertL('info','Uploaded '+q.name);return out({ok:1})}
case'/api/run':{const f=norm(d.path),r=await fget(f);if(!r||r.dir)throw{error:'not found'};alertL('info','Run '+f);const code=typeof r.data==='string'?r.data:await r.data.text(),x=f.split('.').pop().toLowerCase();
return out({out:x==='js'?await runJS(code):x==='py'?await runPy(code):['c','cpp','cc'].includes(x)?'C/C++ cannot be compiled on GitHub Pages (no server). Use Python or JavaScript.':'No runner for this file type'})}
case'/api/scan':return out(scan(String(d.text||'').slice(0,50000)));
case'/api/block':{const i=String(d.item||'').trim().toLowerCase();if(i&&!S.block.includes(i))S.block.push(i);persist();return out({ok:1})}
case'/api/unblock':S.block=S.block.filter(x=>x!==d.item);persist();return out({ok:1});
case'/api/mon_add':if(!['site','page','port'].includes(d.kind))throw{error:'kind'};S.monitors.push({id:S.nid++,kind:d.kind,target:String(d.target).trim(),state:'',hash:''});S.lastchk=0;persist();return out({ok:1});
case'/api/mon_del':S.monitors=S.monitors.filter(m=>m.id!==+d.id);persist();return out({ok:1});
case'/api/visitors':return out([{ip:S.myip||'this device',first:S.first,last:now(),hits:S.hits,ua:navigator.userAgent.slice(0,160),paths:'/ (this browser only)',flags:'',geo:S.geo||'location pending',lat:null,lon:null,status:'known'}]);
case'/api/ipblock':case'/api/ipunblock':case'/api/ipallow':return out({ok:1});
case'/api/summary':{const bad=S.monitors.filter(m=>!['UP','LIMITED','','N/A'].includes(m.state)).map(m=>m.target),crit=S.alerts.filter(a=>a.level==='crit').length;
return out({ai:false,summary:[`Static (GitHub Pages) mode - only this browser's visits are tracked.`,`Alerts: ${S.alerts.length} (${crit} critical) | Blocklist: ${S.block.length}`,'Down/problem: '+(bad.length?bad.join(', '):'none')+` | Monitors: ${S.monitors.length}`,bad.length||crit?'Action: review the critical alerts and down monitors.':'Everything looks fine.'].join('\n')})}
case'/api/bm':if(Array.isArray(d.list))S.bm=d.list.slice(0,200);persist();return out({list:S.bm||[]});
case'/api/clear_alerts':S.alerts=[];persist();return out({ok:1});
}
return out({error:'not found'},404)}
catch(e){return out({error:(e&&e.error)||String(e&&e.message||e)},400)}}
window.fetch=(u,o={})=>{const s=typeof u==='string'?u:(u&&u.url)||'';return s.startsWith('/api/')?route(s,o):of(u,o)};
})();
