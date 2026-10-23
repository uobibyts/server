/* VAULT-OS extras: built-in browser */
(()=>{
window.__VE=1;
const g=id=>document.getElementById(id),E=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
document.querySelector('main').insertAdjacentHTML('beforeend',`
<section class="tab" id="t-brw"><div class="hud"><h2>Built-in Browser</h2>
<div class="row"><button id="bb">◀</button><button id="bf">▶</button><button id="br">⟳</button><input id="bu" placeholder="Search or enter URL"><select id="bmo"><option value="proxy">Proxy</option><option value="reader">Reader</option><option value="direct">Direct</option></select><button id="bg">Go</button><button id="bs">★</button><button id="bo">↗</button></div>
<div id="bk" class="row"></div>
<iframe id="bfr" sandbox="allow-scripts allow-forms" style="height:68vh"></iframe>
<small class="m" id="bh">Proxy: works for most sites (via a public CORS proxy, so it sees the URLs you open; do not log in to anything here). Reader: text only. Direct: private, but many sites refuse to be embedded - use ↗ then.</small></div></section>
`);
// ---- browser ----
const B={h:[],i:-1};let BM=[];const fr=g('bfr');
const nrm=v=>{v=v.trim();if(!v)return null;if(/^https?:\/\//i.test(v))return{u:v};if(!/\s/.test(v)&&/^[\w-]+(\.[\w-]+)+(:\d+)?([\/?#].*)?$/.test(v))return{u:'https://'+v};return{u:'https://html.duckduckgo.com/html/?q='+encodeURIComponent(v),force:'proxy'}};
const HOOK='<script>document.addEventListener("click",e=>{const a=e.target.closest&&e.target.closest("a[href]");if(!a)return;e.preventDefault();if(/^https?:/.test(a.href))parent.postMessage({vnav:a.href},"*")},true);document.addEventListener("submit",e=>{const f=e.target;if((f.method||"get").toLowerCase()!=="get")return;e.preventDefault();const u=new URL(f.action||location.href);new FormData(f).forEach((v,k)=>u.searchParams.set(k,v));parent.postMessage({vnav:u.href},"*")},true)<\/script>';
const getTxt=async(u,proxies)=>{let err;for(const p of proxies){try{const r=await fetch(p+(p.includes('?')?encodeURIComponent(u):u),{signal:AbortSignal.timeout(20000)});if(r.ok)return await r.text();err='HTTP '+r.status}catch(e){err=e.message}}throw new Error(err||'failed')};
const st=m=>{g('bh').textContent=m};
async function go(v,push=true,mode){const n=typeof v==='string'?nrm(v):v;if(!n)return;let u=n.u;try{const x=new URL(u);if(/duckduckgo\.com$/.test(x.hostname)&&x.pathname.startsWith('/l/')&&x.searchParams.get('uddg'))u=x.searchParams.get('uddg')}catch(e){return}
mode=n.force||mode||g('bmo').value;g('bu').value=u;if(push){B.h=B.h.slice(0,B.i+1);B.h.push({u,mode});B.i++}
try{
if(mode==='direct'){fr.setAttribute('sandbox','allow-scripts allow-forms allow-same-origin allow-popups');fr.removeAttribute('srcdoc');fr.src=u;st('Direct: if the frame stays blank this site blocks embedding - use Proxy/Reader or ↗.');return}
fr.setAttribute('sandbox','allow-scripts allow-forms');st('Loading...');let h;
if(mode==='reader'){const t=await getTxt(u,['https://r.jina.ai/']);h='<base href="'+E(u)+'"><body style="font:14px/1.6 sans-serif;max-width:820px;margin:auto;padding:12px;white-space:pre-wrap;word-break:break-word">'+E(t).replace(/\[([^\]]*)\]\((https?:[^)\s]+)\)/g,'<a href="$2">$1</a>')+HOOK}
else{const t=await getTxt(u,['https://api.allorigins.win/raw?url=','https://corsproxy.io/?url=']);const hd=/<head[^>]*>/i;h=hd.test(t)?t.replace(hd,m=>m+'<base href="'+E(u)+'">'+HOOK):'<base href="'+E(u)+'">'+HOOK+t}
fr.removeAttribute('src');fr.srcdoc=h;st(mode+': '+u)}catch(e){st('Could not load ('+e.message+'). Try another mode or ↗.')}}
addEventListener('message',e=>{if(e.source===fr.contentWindow&&e.data&&e.data.vnav)go(e.data.vnav)});
const hist=d=>{const j=B.i+d;if(j<0||j>=B.h.length)return;B.i=j;g('bmo').value=B.h[j].mode==='direct'?'direct':B.h[j].mode;go({u:B.h[j].u},false,B.h[j].mode)};
g('bb').onclick=()=>hist(-1);g('bf').onclick=()=>hist(1);g('br').onclick=()=>B.h[B.i]&&go({u:B.h[B.i].u},false,B.h[B.i].mode);
g('bg').onclick=()=>go(g('bu').value);g('bu').onkeydown=e=>{if(e.key==='Enter')go(g('bu').value)};
g('bo').onclick=()=>{const u=B.h[B.i]?B.h[B.i].u:nrm(g('bu').value)?.u;if(u)window.open(u,'_blank','noopener')};
const bmR=()=>{g('bk').innerHTML=BM.map((b,i)=>`<span><button data-bi="${i}">${E(b.t)}</button><button class="d" data-bx="${i}">×</button></span>`).join('')||'<small class="m">No bookmarks - press ★</small>'};
const bmS=async()=>{await api('/api/bm',{list:BM});bmR()};
g('bs').onclick=()=>{const u=B.h[B.i]&&B.h[B.i].u;if(!u||BM.some(b=>b.u===u))return;let t=u;try{t=new URL(u).hostname}catch(e){}BM.push({u,t});bmS()};
g('bk').onclick=e=>{const i=e.target.dataset.bi,x=e.target.dataset.bx;if(i!==undefined)go(BM[i].u);if(x!==undefined){BM.splice(+x,1);bmS()}};
g('nav').addEventListener('click',e=>{const t=e.target.dataset.t;if(t==='brw'){api('/api/bm',{}).then(r=>{BM=r.list;bmR()}).catch(()=>{});if(!B.h.length)g('bu').focus()}});
// ---- login: forgot password -> reset vault ----
g('lb').insertAdjacentHTML('afterend','<button id="lrst" style="width:100%;margin-top:6px">Forgot password? Reset vault</button><small style="display:block;margin-top:6px;opacity:.5">build: no-sync v2</small>');
g('lrst').onclick=()=>{if(!confirm('Ye is browser ka poora vault (files, alerts, account) delete kar dega. Aage badhein?'))return;try{localStorage.removeItem('vaultos_state');localStorage.removeItem('vsess')}catch(e){}try{indexedDB.deleteDatabase('vaultos')}catch(e){}setTimeout(()=>location.reload(),500)};
})();
