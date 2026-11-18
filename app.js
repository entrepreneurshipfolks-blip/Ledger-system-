/* ============================================================================
   Institutional Ledger System — single-device, multi-role edition (v4)
   One HTML shell + one CSS file + this JS file. No server: all data lives in
   this browser's localStorage. Roles: Admin (manages schools/bursars/
   inspectors, inspects data read-only), Bursar (full day-to-day control of
   their one school), Inspector/Headmaster (read-only view of one school).
   ========================================================================= */
(function(){
"use strict";

/* ---------------------------------------------------------------- storage */
var LS_KEY = 'ils_v4';
var DATA = null;

function blank(){
  return {
    admin: { pinHash: null, salt: null, name: 'Admin', phone:'', email:'' },
    bursars: [], // {id,name,name_norm,sc,email,phone,pinHash,salt,active}
    inspectors: [], // {id,name,name_norm,sc,pinHash,salt,active}
    staff: [], // {id,sc,name,role,salary,allowance,active,created}
    activities: [], // {id,sc,title,fees:{cls:amt},active,created} — e.g. seminar/field study, paid alongside (not part of) school fees
    actPayments: [], // {id,sc,actId,sid,amount,date,ts,by,voided}
    schools: [],
    students: [], payments: [], charges: [], notes: [], log: [],
    ledger: [], // {id,sc,tid,type:'expense'|'income',title,amount,date,by,ts,voided}
    photos: {},
    settings: { colors:{}, look:{}, lastBackup:null, style:'ocean', rates:{UGX:1} },
    security: { attempts:{} },
    session: null, // {role:'admin'|'bursar'|'inspector', id, sc}
    remember: null // same shape as session, used for "remember this device"
  };
}
function load(){
  try{ var raw = localStorage.getItem(LS_KEY); DATA = raw ? JSON.parse(raw) : blank(); }catch(e){ DATA = blank(); }
  if(!DATA || typeof DATA!=='object') DATA = blank();
  ['schools','students','payments','charges','notes','log','bursars','inspectors','ledger','staff','activities','actPayments'].forEach(function(k){ if(!Array.isArray(DATA[k])) DATA[k]=[]; });
  if(!DATA.photos) DATA.photos={};
  if(!DATA.settings) DATA.settings={colors:{},look:{},lastBackup:null,style:'ocean',rates:{UGX:1},countryCode:'256'};
  if(!DATA.settings.rates) DATA.settings.rates={UGX:1};
  if(!DATA.settings.countryCode) DATA.settings.countryCode='256';
  if(!DATA.security) DATA.security={attempts:{}};
  if(!DATA.admin) DATA.admin={pinHash:null,salt:null,name:'Admin',phone:'',email:''};
  if(DATA.admin.phone===undefined) DATA.admin.phone='';
  if(DATA.admin.email===undefined) DATA.admin.email='';
  if(DATA.session===undefined) DATA.session=null;
  if(DATA.remember===undefined) DATA.remember=null;
}
/* names must be unique system-wide so a typed name maps to exactly one account */
function nameExists(name,excludeId){
  var n=norm(name);
  if(n===norm(DATA.admin.name) && excludeId!=='admin') return true;
  if(DATA.bursars.some(function(b){return b.id!==excludeId && norm(b.name)===n;})) return true;
  if(DATA.inspectors.some(function(b){return b.id!==excludeId && norm(b.name)===n;})) return true;
  return false;
}
function findAccount(name){
  var n=norm(name); if(!n) return null;
  if(n===norm(DATA.admin.name)) return {role:'admin',obj:DATA.admin};
  var b=DATA.bursars.filter(function(x){return x.active!==false && norm(x.name)===n;})[0];
  if(b) return {role:'bursar',obj:b};
  var i=DATA.inspectors.filter(function(x){return x.active!==false && norm(x.name)===n;})[0];
  if(i) return {role:'inspector',obj:i};
  return null;
}
function save(){ try{ localStorage.setItem(LS_KEY, JSON.stringify(DATA)); }catch(e){ toast('Could not save — storage may be full.'); } }

/* --------------------------------------------------------- tiny password hash */
function b2hex(buf){ return Array.prototype.map.call(new Uint8Array(buf),function(b){return b.toString(16).padStart(2,'0')}).join(''); }
async function hashPin(pin, salt){ var enc=new TextEncoder().encode(salt+':'+pin); var buf=await crypto.subtle.digest('SHA-256',enc); return b2hex(buf); }
function randSalt(){ return b2hex(crypto.getRandomValues(new Uint8Array(16))); }
function weakPassword(p){
  if(!p || p.length<6) return true;
  var low=p.toLowerCase();
  var banned=['123456','password','abc123','111111','qwerty','12345678','000000','abcdef','123123'];
  if(banned.indexOf(low)>=0) return true;
  if(/^(.)\1+$/.test(p)) return true; // all same character
  if(/^(abc|123|qwe)/.test(low)) return true;
  return false;
}

/* ------------------------------------------------------- lockout (3→10min) */
function lockKey(role,name,sc){ return role+'|'+norm(name)+'|'+(sc||''); }
function lockLeft(key){ var a=DATA.security.attempts[key]; if(a && a.lockUntil>Date.now()) return Math.ceil((a.lockUntil-Date.now())/1000); return 0; }
function registerFail(key){
  var a=DATA.security.attempts[key]||{n:0,lockUntil:0};
  if(a.lockUntil && a.lockUntil<=Date.now()){ a.n=0; a.lockUntil=0; }
  a.n++; var locked=false;
  if(a.n>=3){ a.lockUntil=Date.now()+600000; a.n=0; locked=true; }
  DATA.security.attempts[key]=a; save();
  return {locked:locked, left:3-a.n, secs: locked?600:0};
}
function clearAttempts(key){ delete DATA.security.attempts[key]; save(); }
function fmtSecs(s){ var m=Math.floor(s/60), ss=s%60; return m+'m '+ss+'s'; }

/* ---------------------------------------------------------------- helpers */
var $ = function(id){ return document.getElementById(id); };
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function uid(){ return Math.random().toString(36).slice(2,9)+Date.now().toString(36).slice(-4); }
function pad(n,l){ n=String(n); while(n.length<l) n='0'+n; return n; }
function today(){ var d=new Date(); return d.getFullYear()+'-'+pad(d.getMonth()+1,2)+'-'+pad(d.getDate(),2); }
function daysBetween(a,b){ return Math.round((new Date(b+'T00:00:00')-new Date(a+'T00:00:00'))/864e5); }
function toast(m){ var t=$('toast'); if(!t)return; t.textContent=m; t.style.display='block'; clearTimeout(toast._t); toast._t=setTimeout(function(){t.style.display='none'},2800); }
function esc1(w){ return String(w||'').split(/\s+/).map(function(x){return x.replace(/[^A-Za-z0-9]/g,'').charAt(0)}).join('').toUpperCase(); }
function norm(s){ return String(s||'').trim().replace(/\s+/g,' ').toLowerCase(); }

/* --------------------------------------------------------------- session */
function isAdmin(){ return DATA.session && DATA.session.role==='admin'; }
function isBursar(){ return DATA.session && DATA.session.role==='bursar'; }
function isInspector(){ return DATA.session && DATA.session.role==='inspector'; }
function readOnly(){ return isAdmin() || isInspector(); } // once inside a school, both can only look
function currentBursar(){ return isBursar() ? DATA.bursars.filter(function(b){return b.id===DATA.session.id;})[0] : null; }
function currentInspector(){ return isInspector() ? DATA.inspectors.filter(function(b){return b.id===DATA.session.id;})[0] : null; }
function actorName(){ if(isAdmin()) return DATA.admin.name; var b=currentBursar()||currentInspector(); return b?b.name:'—'; }

var CUR_SID = null; // the school currently open (admin must explicitly "Open" one)
function school(){ return DATA.schools.filter(function(s){return s.id===CUR_SID;})[0]||null; }
function cur(){ var s=school(); return (s&&s.ccy)||{code:'UGX',dec:0}; }
function r(n){ var k=Math.pow(10,cur().dec); return Math.round((+n||0)*k)/k; }
function money(n){ var c=cur(); return c.code+' '+r(n).toLocaleString('en-US',{minimumFractionDigits:c.dec,maximumFractionDigits:c.dec}); }
function toRate(n,code){ var rt=DATA.settings.rates||{UGX:1}; var base=rt[cur().code]||1, target=rt[code]||1; return n*base/target; }
function classesOf(s){ s=s||school(); return s&&s.type==='primary'?['P1','P2','P3','P4','P5','P6','P7']:['S1','S2','S3','S4','S5','S6']; }
function itemsOf(sc){ sc=sc||school(); return (sc&&sc.items&&sc.items.length)?sc.items:['School fees']; }
function term(){ var s=school(); if(!s) return null; return (s.terms||[]).filter(function(t){return t.id===s.cur;})[0]||null; }
function prefix(name){ return esc1(name); }
function newCode(){ var p=(prefix(school()&&school().name)||'ST').slice(0,4), c, ex=studentsOf(); do{ c=p+(1000+Math.floor(Math.random()*9000)); }while(ex.some(function(x){return x.code===c;})); return c; }
function rno(seq){ seq=((seq-1)%10000)+1; return (prefix(school()&&school().name)||'RCT')+'-'+pad(seq,5); }
function studentsOf(){ return DATA.students.filter(function(x){return x.sc===CUR_SID;}); }
function paymentsOf(){ return DATA.payments.filter(function(x){return x.sc===CUR_SID;}); }
function chargesOf(){ return DATA.charges.filter(function(x){return x.sc===CUR_SID;}); }
function student(id){ return DATA.students.filter(function(s){return s.id===id;})[0]; }
function log(a,d,sid){
  DATA.log.push({id:uid(),sc:CUR_SID,ts:Date.now(),by:actorName(),a:a,d:String(d||'').slice(0,300),sid:sid||null});
  if(isBursar()) alertAdmin(a,d); else if(isAdmin() && CUR_SID) alertBursars(CUR_SID,a,d);
  save();
}
function historyOf(sid){ return DATA.log.filter(function(x){return x.sid===sid;}).sort(function(a,b){return b.ts-a.ts;}); }
function note(sc,title,body,admin){ DATA.notes.push({id:uid(),sc:sc,ts:Date.now(),title:title,body:body||'',admin:!!admin,read:false}); }
function alertAdmin(a,d){ var s=school(); note(CUR_SID,(s?s.name+': ':'')+a, actorName()+' · '+d, true); }
function alertBursars(sc,a,d){ note(sc,a, actorName()+' · '+d, false); }
function avatar(s,lg){ var u=DATA.photos[s.id], c='av'+(lg?' lg':''); return u?'<img class="'+c+'" alt="" src="'+u+'">':'<span class="'+c+'">'+esc((s.name||'?').charAt(0).toUpperCase())+'</span>'; }

function balances(t){
  var tid=t?t.id:'', pr={}, cu={}, pd={}, pt={};
  chargesOf().forEach(function(c){ if(c.tid===tid) cu[c.sid]=(cu[c.sid]||0)+c.amt; else pr[c.sid]=(pr[c.sid]||0)+c.amt; });
  paymentsOf().forEach(function(p){ if(p.status!=='ok') return; pd[p.sid]=(pd[p.sid]||0)+ +p.amt; if(p.tid===tid) pt[p.sid]=(pt[p.sid]||0)+ +p.amt; });
  return studentsOf().map(function(s){
    var a=pr[s.id]||0,c=cu[s.id]||0,p=pd[s.id]||0,ar=r(Math.max(0,a-p)),cd=r(Math.max(0,c-Math.max(0,p-a)));
    return {s:s,prior:a,cur:c,paid:p,pt:pt[s.id]||0,arrears:ar,curdue:cd,due:r(ar+cd),credit:r(Math.max(0,p-a-c))};
  });
}
function dueOf(sid){ var row=balances(term()).filter(function(b){return b.s.id===sid;})[0]; return row?row.due:0; }
function setCharge(sid,tid,amt){
  var ex=DATA.charges.filter(function(c){return c.id===sid+'|'+tid;})[0];
  if(ex) ex.amt=amt; else DATA.charges.push({id:sid+'|'+tid,sc:CUR_SID,sid:sid,tid:tid,amt:amt});
  save();
}
function newSchool(name,type){
  var y=new Date().getFullYear(), f={}, items, cl, T2={Day:[350000,350000,450000,450000,500000,500000],Boarding:[650000,650000,650000,650000,700000,700000]};
  if(type==='primary'){ items=['Tuition','Lunch','Development']; cl=['P1','P2','P3','P4','P5','P6','P7']; ['Day','Boarding'].forEach(function(k){ cl.forEach(function(c){ items.forEach(function(i){ f[k+'|'+c+'|'+i]=0; }); }); }); }
  else { items=['School fees']; Object.keys(T2).forEach(function(k){ T2[k].forEach(function(a,i){ f[k+'|S'+(i+1)+'|School fees']=a; }); }); }
  return {id:'s'+Date.now().toString(36)+Math.random().toString(36).slice(2,5),name:name,motto:'',type:type==='primary'?'primary':'secondary',
    terms:[{id:'t1',yr:y,no:1,start:'',visit:'',end:''}],cur:'t1',fees:f,items:items,ccy:{code:'UGX',dec:0},big:1000000,counter:0,created:Date.now()};
}
function feeFor(s,sc){ sc=sc||school(); var f=(sc&&sc.fees)||{}, t=0; itemsOf(sc).forEach(function(i){ t+=+f[s.kind+'|'+s.cls+'|'+i]||0; }); return Math.max(0,t-(+s.disc||0)); }
function chargeAllForTerm(sc,tid){ DATA.students.filter(function(s){return s.sc===sc.id && s.active!==false;}).forEach(function(s){ setCharge(s.id,tid,feeFor(s,sc)); }); }

/* ------------------------------------------------------- expenses/income */
function ledgerOf(tid){ return DATA.ledger.filter(function(x){return x.sc===CUR_SID && (!tid||x.tid===tid);}); }
function ledgerTotals(tid){
  var rows=ledgerOf(tid).filter(function(x){return !x.voided;});
  var income=rows.filter(function(x){return x.type==='income';}).reduce(function(a,x){return a+ +x.amount;},0);
  var expense=rows.filter(function(x){return x.type==='expense';}).reduce(function(a,x){return a+ +x.amount;},0);
  return {income:income,expense:expense};
}

/* --------------------------------------------------------------- staff/payroll */
function staffOf(){ return DATA.staff.filter(function(s){return s.sc===CUR_SID && s.active!==false;}); }
function staffPaymentsOf(staffId,tid){
  return DATA.ledger.filter(function(x){return x.sc===CUR_SID && x.staffId===staffId && (!tid||x.tid===tid);}).sort(function(a,b){return b.ts-a.ts;});
}
function lastStaffPayment(staffId,tid){
  var rows=staffPaymentsOf(staffId,tid).filter(function(x){return !x.voided;});
  return rows.length?rows[0]:null;
}
/* "time taken to pay" = days between the term's start date and the date a staff member
   was actually paid that term's salary — averaged, per the current term and per the year. */
function payTimingStats(){
  var t=term(); if(!t) return null;
  var s=school(); if(!s) return null;
  var termIds=(s.terms||[]).filter(function(x){return x.yr===t.yr;}).map(function(x){return x.id;});
  var termsById={}; (s.terms||[]).forEach(function(x){termsById[x.id]=x;});
  var paid=DATA.ledger.filter(function(x){return x.sc===CUR_SID && x.staffId && !x.voided;});
  function avgDays(rows){
    var vals=rows.map(function(x){ var tt=termsById[x.tid]; if(!tt||!tt.start) return null; var d=daysBetween(tt.start,x.date); return d>=0?d:null; }).filter(function(v){return v!==null;});
    if(!vals.length) return null;
    return Math.round(vals.reduce(function(a,v){return a+v;},0)/vals.length);
  }
  return { term: avgDays(paid.filter(function(x){return x.tid===t.id;})), year: avgDays(paid.filter(function(x){return termIds.indexOf(x.tid)>-1;})) };
}
function staffCardHtml(st){
  var t=term(); if(!t) return '';
  var lp=lastStaffPayment(st.id,t.id);
  var due=(+st.salary||0)+(+st.allowance||0);
  return '<div class="it"><div><b>'+esc(st.name)+'</b><div class="mu">'+esc(st.role)+' · salary '+money(+st.salary||0)+' + allowance '+money(+st.allowance||0)+'</div>'+
    (lp?'<div class="mu">Paid '+money(lp.amount)+' on '+esc(lp.date)+'</div>':'<div class="mu">Not paid this term</div>')+'</div>'+
    (readOnly()?'':'<div class="ac">'+(lp?'<button class="dng" data-staff-void="'+st.id+'">Void</button>':'<button class="pri" data-staff-pay="'+st.id+'" data-amt="'+due+'">Pay</button>')+
    ' <button class="dng" data-staff-rm="'+st.id+'">Delete</button></div>')+'</div>';
}

/* ------------------------------------------------- activities / event fees */
/* For one-off charges that aren't part of the regular school fees — a seminar,
   a field study trip — set per-class, tracked and paid separately from fee balances. */
function activitiesOf(){ return DATA.activities.filter(function(a){return a.sc===CUR_SID && a.active!==false;}); }
function actPaymentsOf(actId,sid){
  return DATA.actPayments.filter(function(x){return x.sc===CUR_SID && x.actId===actId && (!sid||x.sid===sid) && !x.voided;});
}
function actFeeFor(act,s){ return +((act.fees||{})[s.cls])||0; }
function actPaidFor(act,s){ return actPaymentsOf(act.id,s.id).reduce(function(a,x){return a+ +x.amount;},0); }
function actTotals(act){
  var students=studentsOf().filter(function(s){return s.active!==false && actFeeFor(act,s)>0;});
  var expected=students.reduce(function(a,s){return a+actFeeFor(act,s);},0);
  var collected=actPaymentsOf(act.id).reduce(function(a,x){return a+ +x.amount;},0);
  return {expected:expected,collected:collected,students:students};
}
function activityCardHtml(act){
  var tt=actTotals(act);
  return '<div class="card"><h3>'+esc(act.title)+'</h3>'+
    '<div class="kp"><div><span class="mu">Expected</span><b>'+money(tt.expected)+'</b></div>'+
    '<div><span class="mu">Collected</span><b class="ok">'+money(tt.collected)+'</b></div>'+
    '<div><span class="mu">Balance</span><b class="'+(tt.expected-tt.collected>0?'bad':'ok')+'">'+money(Math.max(0,tt.expected-tt.collected))+'</b></div></div>'+
    (readOnly()?'':'<button class="pri" data-act-pay="'+act.id+'">Record a student payment</button> ')+
    '<button data-act-view="'+act.id+'">View by student</button>'+
    (readOnly()?'':' <button class="dng" data-act-rm="'+act.id+'">Delete</button>')+'</div>';
}
function showActivityBreakdown(actId){
  var act=DATA.activities.filter(function(a){return a.id===actId;})[0]; if(!act) return;
  var tt=actTotals(act);
  var rows=tt.students.slice().sort(function(a,b){return a.name.localeCompare(b.name);}).map(function(s){
    var fee=actFeeFor(act,s), paid=actPaidFor(act,s), bal=Math.max(0,fee-paid);
    return '<div class="it"><div>'+esc(s.name)+'<div class="mu">'+esc(s.cls)+'</div></div><div class="ac"><b class="'+(bal>0?'bad':'ok')+'">'+(bal>0?'Owes '+money(bal):'Paid')+'</b></div></div>';
  }).join('')||'<p class="mu">No students have a fee set for this activity (set class amounts when creating it).</p>';
  var o=document.createElement('div'); o.className='ov';
  o.innerHTML='<div class="rc" style="max-width:520px"><h3>'+esc(act.title)+' — by student</h3>'+rows+
    '<div class="noprint" style="margin-top:12px"><button id="actBrClose">Close</button></div></div>';
  document.body.appendChild(o);
  $('actBrClose').onclick=function(){ document.body.removeChild(o); };
}
function activitySectionHtml(){
  var acts=activitiesOf();
  var out='<div class="sect"><h3>Activities &amp; events (seminars, field study, etc.)</h3>';
  if(!readOnly()){
    out += '<div class="card fm"><h3>New activity</h3><label>Title</label><input id="actTitle" placeholder="e.g. Seminar, Field study trip">'+
      '<label style="margin-top:6px">Amount to be paid, by class</label>'+
      classesOf().map(function(c){ return '<div class="fgrid"><span class="mu">'+c+'</span><input type="number" data-actfee="'+c+'" placeholder="0"></div>'; }).join('')+
      '<button class="pri" id="actAdd" style="margin-top:8px">Create activity</button></div>';
  }
  out += acts.map(activityCardHtml).join('') || '<p class="mu">No activities yet.</p>';
  return out+'</div>';
}

/* ------------------------------------------------------- installment plans */
function planOf(s){ return Array.isArray(s.plan)?s.plan:[]; }
function overdueInstallments(s){
  return planOf(s).filter(function(x){return !x.done && x.due && daysBetween(today(),x.due)<0;});
}

/* ------------------------------------------------------------- reminders */
function runReminders(){
  var s=school(), t=term(); if(!s||!t) return;
  var R = s.rem = s.rem || {sentVisit:null,sentEnd:null,lastFee:0};
  [['visit','sentVisit','Visiting day'],['end','sentEnd','End of term']].forEach(function(k){
    var d=t[k[0]]; if(!d) return; var n=daysBetween(today(),d);
    if(n>=0 && n<=7 && R[k[1]]!==t.id+'|'+d){ R[k[1]]=t.id+'|'+d; note(CUR_SID,k[2]+(n?' in '+n+' day'+(n>1?'s':''):' is today'),'Check who still owes fees on Reports.',false); note(CUR_SID,k[2]+(n?' in '+n+' day'+(n>1?'s':''):' is today'),'Check who still owes fees on Reports.',true); }
  });
  var now=Date.now();
  if(!R.lastFee || now-R.lastFee>=7*864e5){
    var rows=balances(t).filter(function(b){return b.s.active!==false && b.due>0;});
    if(rows.length){ var tot=rows.reduce(function(a,b){return a+b.due;},0);
      note(CUR_SID,'Fees reminder',rows.length+' students still owe. Total outstanding '+money(tot)+'.',false);
      note(CUR_SID,'Fees reminder',rows.length+' students still owe. Total outstanding '+money(tot)+'.',true);
    }
    R.lastFee=now;
  }
  if(!R.lastPlan || now-R.lastPlan>=7*864e5){
    var owing2=[]; studentsOf().forEach(function(st){ var od=overdueInstallments(st); if(od.length) owing2.push({s:st,n:od.length}); });
    if(owing2.length){
      var msg=owing2.length+' student(s) have overdue installments: '+owing2.slice(0,5).map(function(x){return x.s.name;}).join(', ')+(owing2.length>5?'…':'')+'.';
      note(CUR_SID,'Overdue installments',msg,false); note(CUR_SID,'Overdue installments',msg,true);
    }
    R.lastPlan=now;
  }
  save();
}

/* ------------------------------------------------------------- search/sort */
function matchList(q,list){
  q=norm(q); if(!q) return [];
  var tk=q.split(/\s+/), out=[];
  list.forEach(function(s){
    var n=norm(s.name), c=norm(s.code||''), rank=-1;
    if(n.indexOf(q)===0) rank=0; else if((' '+n).indexOf(' '+q)>=0) rank=1; else if(c.indexOf(q)===0) rank=2;
    else if(n.indexOf(q)>=0) rank=3; else if(tk.every(function(t){return n.indexOf(t)>=0;})) rank=4;
    if(rank>=0) out.push({s:s,rank:rank});
  });
  out.sort(function(a,b){ return a.rank-b.rank || a.s.name.localeCompare(b.s.name); });
  return out.slice(0,8).map(function(x){return x.s;});
}
function attachSuggest(inp,getList,onPick){
  if(!inp || inp._suggestWired) return; inp._suggestWired=true;
  var box=document.createElement('div'); box.className='sg'; box.style.display='none'; inp.parentNode.appendChild(box);
  function show(){
    var L=matchList(inp.value,getList());
    box.innerHTML=L.map(function(s){return '<div class="sgi" data-id="'+s.id+'"><b>'+esc(s.name)+'</b><span>'+esc(s.cls||'')+' '+esc(s.kind||'')+' · '+esc(s.code||'')+'</span></div>';}).join('');
    box.style.display=L.length?'block':'none';
  }
  inp.addEventListener('input',show); inp.addEventListener('focus',show);
  inp.addEventListener('keydown',function(e){ if(e.keyCode===13){ var f=box.querySelector('.sgi'); if(f){ e.preventDefault(); box.style.display='none'; onPick(f.getAttribute('data-id')); } } });
  box.addEventListener('mousedown',function(e){ var d=e.target.closest('.sgi'); if(!d) return; e.preventDefault(); box.style.display='none'; onPick(d.getAttribute('data-id')); });
  document.addEventListener('click',function(e){ if(e.target!==inp) box.style.display='none'; });
}

/* ------------------------------------------------------------- image shrink */
function shrink(file,cb){
  var fr=new FileReader();
  fr.onload=function(){
    var im=new Image();
    im.onload=function(){
      var k=Math.min(1,260/Math.max(im.width,im.height)), c=document.createElement('canvas');
      c.width=Math.round(im.width*k); c.height=Math.round(im.height*k);
      c.getContext('2d').drawImage(im,0,0,c.width,c.height);
      cb(c.toDataURL('image/jpeg',0.75));
    };
    im.onerror=function(){ cb(null); };
    im.src=fr.result;
  };
  fr.onerror=function(){ cb(null); };
  fr.readAsDataURL(file);
}
var pendingPhoto=null; // data URL staged from the student add/edit form, committed on Save
var HOME_FIN=null; // financial trend series computed by BODY.home, read by wire() to draw the charts (script tags inserted via innerHTML never execute, so this can't be passed through the HTML string)

/* ------------------------------------------------------------------ theme */
var PAL = { ocean:['Ocean','#1b4b9b','#f28a1b'], forest:['Forest','#1f6f4a','#e0a82e'], royal:['Royal','#5b3ea8','#e84a8a'],
  teal:['Teal','#0f766e','#f2674a'], crimson:['Crimson','#b3262e','#1f3a6e'], slate:['Slate','#334155','#f59e0b'] };
function theme(){
  var s=DATA.settings, lk=s.look||{}, rt=document.documentElement, pal=PAL[s.style]||PAL.ocean;
  rt.style.setProperty('--pri',pal[1]); rt.style.setProperty('--acc',pal[2]);
  var m = lk.mode || 'auto';
  var dk = m==='dark' || (m==='auto' && window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches);
  rt.setAttribute('data-theme', dk?'dark':'light');
  return m;
}

/* ------------------------------------------------------------------ route */
var ROUTES = ['landing','login','home','schools','students','payments','receipts','finance','reports','notifications','settings'];
function go(r,qs){ location.hash = '#'+r+(qs?'?'+qs:''); }
function parseHash(){
  var h=(location.hash||'#landing').slice(1), i=h.indexOf('?');
  var route=i<0?h:h.slice(0,i), q={};
  if(i>=0){ h.slice(i+1).split('&').forEach(function(p){ var kv=p.split('='); if(kv[0]) q[decodeURIComponent(kv[0])]=decodeURIComponent(kv[1]||''); }); }
  if(ROUTES.indexOf(route)<0) route='landing';
  return {route:route, q:q};
}
function navFor(){
  var N=[['home','Home'],['students','Students'],['payments','Payments'],['finance','Finance'],['reports','Reports']];
  return N;
}

function render(){
  try{ renderInner(); }
  catch(e){
    var root=document.getElementById('root');
    if(root) root.innerHTML = '<div class="ctr"><div class="card"><b>Something went wrong loading the page.</b>'+
      '<p class="mu">This usually means your browser is blocking local storage for files opened this way (common for some browsers/editors with file:// pages). Try opening index.html directly in Chrome (not inside an editor\'s preview), or try another browser such as Firefox.</p>'+
      '<p class="mu" style="word-break:break-all">Technical detail: '+String((e&&e.message)||e)+'</p>'+
      '<button onclick="location.reload()">Reload</button></div></div>';
  }
}
function renderInner(){
  theme();
  var p = parseHash();
  var needAuth = ['home','schools','students','payments','receipts','finance','reports','notifications','settings'].indexOf(p.route)>=0;
  if(needAuth && !DATA.session){ go('login'); return; }
  if(!DATA.admin.pinHash && (p.route==='login'||needAuth)){ go('landing'); return; }
  var root=$('root');
  if(p.route==='landing') root.innerHTML = viewLanding();
  else if(p.route==='login') root.innerHTML = viewLogin();
  else {
    if(!isAdmin() && DATA.session){ CUR_SID = DATA.session.sc; }
    if(isAdmin() && p.route!=='schools' && !school()){ go('schools'); return; }
    if(needAuth && p.route!=='schools' && !school()){
      root.innerHTML = '<div class="ctr"><div class="card"><b>No school assigned yet.</b><p class="mu">Ask the admin to assign you to a school.</p><button onclick="App.logout()">Log out</button></div></div>';
      wire(p.route,p.q); return;
    }
    if(school()) runReminders();
    root.innerHTML = layout(p.route) + viewBody(p.route,p.q) + bottomNav(p.route);
  }
  wire(p.route,p.q);
  unreadBadgeTick();
}
window.addEventListener('hashchange',render);

/* ------------------------------------------------------------- landing/login */
function viewLanding(){
  var hasAdmin = !!DATA.admin.pinHash;
  var rem = DATA.remember;
  return '<div class="ld"><div class="hero"><span class="badge">Local • No Internet Needed</span>'+
    '<h1>Fees <span>Ledger</span></h1><div class="bar"></div>'+
    '<p class="lead">A simple way to track school fees, payments and receipts — stored right here on this device, no server, no card, no Wi-Fi required.</p></div>'+
    '<div class="wrapl">'+
    '<div class="panel"><h2>'+(hasAdmin?'Welcome back':'Set up this device')+'</h2>'+
    (hasAdmin
      ? ( (rem? '<p>Continue as <b>'+esc(rem.name||'')+'</b> ('+esc(rem.role)+'), or sign in as someone else.</p><div class="cta"><a class="bt a" id="remGo">CONTINUE</a></div><p class="mu" style="text-align:center">or</p>' : '')
          + '<p>Sign in to continue.</p><div class="cta"><a class="bt b" onclick="App.go(\'login\')">SIGN IN</a></div>')
      : '<p>This is a one-time setup. Choose the admin\'s name and a password to protect this device — everything then stays local to this browser. The admin can add bursar and inspector accounts afterwards.</p>'+
        '<div id="setupErr"></div>'+
        '<div class="fm"><label>Your full name</label><input id="suName" placeholder="e.g. Grace Nakato">'+
        '<label>Choose a password (6+ characters, not something like "123456")</label><input id="suPin" type="password" placeholder="••••••">'+
        '<label>Confirm password</label><input id="suPin2" type="password" placeholder="••••••">'+
        '<button class="pri" id="suGo" style="margin-top:14px;width:100%">Set up and continue</button></div>')+
    '</div>'+
    '<div class="foot">Institutional Ledger System</div>'+
    '</div></div>';
}
function viewLogin(){
  return '<div class="ld"><div class="top2"><a onclick="App.go(\'landing\')">&larr; Back</a></div>'+
    '<div class="wrapl" style="margin-top:30px;max-width:440px">'+
    '<div class="panel"><h2>Sign in</h2>'+
    '<div id="loginErr"></div><div id="loginBox">'+loginBoxName()+'</div></div></div></div>';
}
var LOGIN_FOUND = null;
function loginBoxName(){
  return '<div class="fm" id="nameStep"><label>Full name</label><input id="lgName" placeholder="Your full name" autocomplete="off">'+
    '<button class="pri" id="lgGo" style="width:100%">Continue</button></div><div id="pwStep"></div>';
}
function loginBoxPassword(found){
  var roleLabel = found.role==='admin'?'Admin':found.role==='bursar'?'Bursar':'Inspector';
  return '<div class="fm" id="pwStep2"><p class="mu">Signing in as <b>'+esc(found.obj.name)+'</b> ('+roleLabel+').</p>'+
    '<label>Password</label><input id="lgPin" type="password" placeholder="••••••">'+
    '<label><input type="checkbox" id="lgRem"> Remember me on this device</label>'+
    '<button class="pri" id="lgGo2" style="width:100%">Login as '+roleLabel.toLowerCase()+'</button> '+
    '<button id="lgBack" style="width:100%;margin-top:6px">Not you? Use a different name</button></div>';
}
async function doLoginUnified(){
  var found=LOGIN_FOUND, err=$('loginErr'), p=$('lgPin').value;
  if(!found) return;
  err.innerHTML='';
  var sc = found.role==='bursar'||found.role==='inspector' ? found.obj.sc : '';
  var key=lockKey(found.role,found.obj.name,sc), left=lockLeft(key);
  if(left>0){ err.innerHTML='<div class="al2">Too many attempts. Try again in '+fmtSecs(left)+'.</div>'; return; }
  var h=await hashPin(p, found.obj.salt);
  if(h!==found.obj.pinHash){ var f=registerFail(key); err.innerHTML='<div class="al2">'+(f.locked?('Too many attempts. Locked for 10 minutes.'):('Wrong password. '+f.left+' attempt(s) left.'))+'</div>'; return; }
  clearAttempts(key);
  var rem=$('lgRem') && $('lgRem').checked;
  if(found.role==='admin'){ DATA.session={role:'admin'}; if(rem) DATA.remember={role:'admin',name:DATA.admin.name}; save(); go('schools'); }
  else { DATA.session={role:found.role,id:found.obj.id,sc:found.obj.sc}; if(rem) DATA.remember={role:found.role,id:found.obj.id,sc:found.obj.sc,name:found.obj.name}; save(); go('home'); }
}

async function doSetup(){
  var name=$('suName').value.trim(), p1=$('suPin').value, p2=$('suPin2').value, err=$('setupErr');
  err.innerHTML='';
  if(name.length<3){ err.innerHTML='<div class="al2">Enter your full name.</div>'; return; }
  if(weakPassword(p1)){ err.innerHTML='<div class="al2">Choose a stronger password (6+ characters, not a simple pattern like "123456").</div>'; return; }
  if(p1!==p2){ err.innerHTML='<div class="al2">Passwords do not match.</div>'; return; }
  var salt=randSalt();
  DATA.admin={pinHash:await hashPin(p1,salt), salt:salt, name:name};
  DATA.session={role:'admin'}; save(); go('schools');
}
function doRemember(){
  var r=DATA.remember; if(!r) return;
  if(r.role==='admin') DATA.session={role:'admin'};
  else DATA.session={role:r.role,id:r.id,sc:r.sc};
  save(); go(isAdmin()?'schools':'home');
}

/* ---------------------------------------------------------------- layout */
function unread(){ return DATA.notes.filter(function(n){ return !n.read && n.sc===CUR_SID && (isAdmin()?n.admin:!n.admin); }).length; }
function unreadBadgeTick(){ var d=$('bellDot'); if(d){ var u=unread(); d.style.display=u?'inline-block':'none'; d.textContent=u>9?'9+':u; } }
var NAV_ICONS = {
  schools:'<path d="M4 21V9l8-5 8 5v12"/><path d="M9 21v-6h6v6"/>',
  home:'<path d="M4 11.5 12 5l8 6.5"/><path d="M6 10v10h12V10"/>',
  students:'<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3 2.7-5 6-5s6 2 6 5"/><circle cx="17" cy="9" r="2.3"/><path d="M15.5 20c.3-2 1.8-3.4 4-3.6"/>',
  payments:'<rect x="3" y="6" width="18" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M3 10h18"/>',
  receipts:'<path d="M6 3h12v18l-2.5-1.5L13 21l-2.5-1.5L8 21l-2-1.5z"/><path d="M9 8h6M9 12h6"/>',
  finance:'<path d="M3 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M15 12h4"/><circle cx="16.5" cy="12" r=".6" fill="currentColor"/>',
  reports:'<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>'
};
function navIcon(k){ return '<svg viewBox="0 0 24 24">'+(NAV_ICONS[k]||'')+'</svg>'; }
function bottomNav(page){
  var N = isAdmin() ? [['schools','Schools']].concat(navFor()) : navFor();
  return '<nav class="bnav">'+N.map(function(n){return '<a class="'+(n[0]===page?'on':'')+'" onclick="App.go(\''+n[0]+'\')">'+navIcon(n[0])+'<span>'+n[1]+'</span></a>';}).join('')+'</nav>';
}
function layout(page){
  var s=school(), un=unread();
  theme();
  return '<div class="top"><div class="row1"><div class="brand">'+esc(s?s.name:'Fees Ledger')+
    '<small>'+(s&&s.motto?esc(s.motto)+' · ':'')+(s?(s.type==='primary'?'Primary school':'Secondary school')+' · ':'')+'Fees Ledger'+(readOnly()?' · view only':'')+'</small></div>'+
    '<a class="bell" onclick="App.go(\'notifications\')">&#128276;<i class="dot" id="bellDot" style="display:'+(un?'inline-block':'none')+'">'+(un>9?'9+':un)+'</i></a>'+
    '<div class="dd"><button class="thm" id="menuBtn" title="Menu">&#8942;</button><div class="ddm" id="menuDrop">'+
      '<a onclick="App.go(\'settings\')">Settings</a><a id="menuLogout">Log out</a></div></div>'+
    '<span class="role">'+esc(actorName())+(isAdmin()?' (admin)':isInspector()?' (inspector)':'')+'</span></div></div>'+
    '<div class="wrap" id="body">';
}

function viewBody(route,q){ return (BODY[route]?BODY[route](q):'') + '</div>'; }
var BODY = {};

/* ----------------------------------------------------------------- SCHOOLS (admin only) */
BODY.schools = function(q){
  if(!isAdmin()){ go('home'); return ''; }
  if(q.edit) return formSchoolEdit(DATA.schools.filter(function(s){return s.id===q.edit;})[0]);
  var rows = DATA.schools.map(function(s){
    var n=DATA.students.filter(function(x){return x.sc===s.id;}).length, nb=DATA.bursars.filter(function(x){return x.sc===s.id;}).length;
    return '<div class="it"><div><b>'+esc(s.name)+'</b><div class="mu">'+(s.type==='primary'?'Primary':'Secondary')+' · '+n+' students · '+nb+' bursar(s)</div></div>'+
      '<div class="ac"><button data-open="'+s.id+'" class="pri">Open</button><button data-edit-school="'+s.id+'">Edit</button><button data-del-school="'+s.id+'" class="dng">Remove</button></div></div>';
  }).join('') || '<p class="mu">No schools yet. Add one below.</p>';
  var overview = DATA.schools.length ? ('<div class="card"><h3>Cross-school overview</h3>'+DATA.schools.map(schoolStatsRow).join('')+'</div>') : '';
  return '<h2>Schools</h2><div class="card">'+rows+'</div>'+overview+
    '<div class="card"><h3>Add a school</h3>'+
    '<div class="g"><div><label>Name</label><input id="nsName" placeholder="e.g. Hillview Primary"></div>'+
    '<div><label>Type</label><select id="nsType"><option value="secondary">Secondary</option><option value="primary">Primary</option></select></div></div>'+
    '<button class="pri" id="nsGo">Add school</button></div>'+
    '<div class="card"><h3>Exchange rates</h3><p class="mu">Reference rates (relative to UGX) used to show totals in another currency on Home. These do not move any money.</p>'+
    '<div id="rateList">'+Object.keys(DATA.settings.rates).map(function(c){return '<div class="g"><div><input value="'+esc(c)+'" disabled></div><div><input type="number" data-rate="'+esc(c)+'" value="'+DATA.settings.rates[c]+'"></div></div>';}).join('')+'</div>'+
    '<div class="g"><div><label>New currency code</label><input id="rateCode" placeholder="USD"></div><div><label>UGX per 1 unit</label><input id="rateVal" type="number" placeholder="3700"></div></div>'+
    '<button class="pri" id="rateAdd">Add/update rate</button> <button id="rateSaveAll">Save all rates</button></div>'+
    '<div class="card"><h3>Backup &amp; restore</h3><p class="mu">Download a backup file regularly. It is the only way to move your records to another device, or recover from a lost/reset phone.</p>'+
    '<button class="pri" id="bkDown">Download backup</button> <button id="bkUpBtn">Import a backup file</button><input type="file" id="bkFile" accept="application/json" style="display:none"></div>';
};
function schoolStatsRow(s){
  var cc=(s.ccy&&s.ccy.code)||'UGX', dec=(s.ccy&&s.ccy.dec)||0;
  var fmt=function(n){ var k=Math.pow(10,dec); return cc+' '+(Math.round((+n||0)*k)/k).toLocaleString('en-US',{minimumFractionDigits:dec,maximumFractionDigits:dec}); };
  var studs=DATA.students.filter(function(x){return x.sc===s.id;}), active=studs.filter(function(x){return x.active!==false;});
  var tid=s.cur;
  var collected=DATA.payments.filter(function(p){return p.sc===s.id && p.status==='ok' && p.tid===tid;}).reduce(function(a,p){return a+ +p.amt;},0);
  var paidAll=DATA.payments.filter(function(p){return p.sc===s.id && p.status==='ok';}).reduce(function(a,p){return a+ +p.amt;},0);
  var chargedAll=DATA.charges.filter(function(c){return c.sc===s.id;}).reduce(function(a,c){return a+ +c.amt;},0);
  var outstanding=Math.max(0,chargedAll-paidAll);
  return '<div class="it"><div><b>'+esc(s.name)+'</b><div class="mu">'+active.length+' active of '+studs.length+' students</div></div>'+
    '<div class="ac"><div>Collected this term: <b class="ok">'+fmt(collected)+'</b></div><div>Outstanding: <b class="bad">'+fmt(outstanding)+'</b></div></div></div>';
}
function formSchoolEdit(s){
  if(!s) return '<p class="mu">School not found.</p>';
  var bursars=DATA.bursars.filter(function(b){return b.sc===s.id;}), insps=DATA.inspectors.filter(function(b){return b.sc===s.id;});
  return '<h2>Edit school</h2><div class="card fm">'+
    '<label>Name</label><input id="esName" value="'+esc(s.name)+'">'+
    '<label>Motto</label><input id="esMotto" value="'+esc(s.motto||'')+'">'+
    '<div class="g"><div><label>Type</label><select id="esType"><option value="secondary"'+(s.type==='secondary'?' selected':'')+'>Secondary</option><option value="primary"'+(s.type==='primary'?' selected':'')+'>Primary</option></select></div>'+
    '<div><label>Currency code</label><input id="esCcy" value="'+esc((s.ccy&&s.ccy.code)||'UGX')+'"></div></div>'+
    '<button class="pri" id="esSave" data-id="'+s.id+'">Save</button> <button onclick="App.go(\'schools\')">Back</button></div>'+
    '<div class="card"><h3>Demo data</h3><p class="mu">Fills this school with a random set of demo students (20–100), spread across classes, with random guardians, phone numbers and real fee charges.</p>'+
    '<button id="esDemo" data-id="'+s.id+'">Add demo students</button></div>'+
    '<div class="card"><h3>Bursars for this school</h3>'+
    (bursars.map(function(b){ return '<div class="it"><div>'+esc(b.name)+(b.email?'<div class="mu">'+esc(b.email)+(b.phone?' · '+esc(b.phone):'')+'</div>':'')+(b.active===false?' <span class="chip d">disabled</span>':'')+'</div>'+
      '<div class="ac"><button data-reset-bursar="'+b.id+'">Reset password</button><button data-toggle-bursar="'+b.id+'">'+(b.active===false?'Enable':'Disable')+'</button></div></div>'; }).join('')||'<p class="mu">No bursars yet.</p>')+
    '<h3 style="margin-top:14px">Add a bursar</h3>'+
    '<div class="g"><div><label>Full name</label><input id="nbName"></div><div><label>Username</label><input id="nbUser"></div></div>'+
    '<div class="g"><div><label>Email</label><input id="nbEmail" type="email"></div><div><label>Phone</label><input id="nbPhone"></div></div>'+
    '<div class="g"><div><label>Password (6+ chars)</label><input id="nbPin" type="password"></div><div><label>Confirm password</label><input id="nbPin2" type="password"></div></div>'+
    '<button class="pri" id="nbGo" data-sc="'+s.id+'">Add bursar</button></div>'+
    '<div class="card"><h3>Inspectors (Headmaster/Director — read only) for this school</h3>'+
    (insps.map(function(b){ return '<div class="it"><div>'+esc(b.name)+(b.active===false?' <span class="chip d">disabled</span>':'')+'</div>'+
      '<div class="ac"><button data-reset-insp="'+b.id+'">Reset password</button><button data-toggle-insp="'+b.id+'">'+(b.active===false?'Enable':'Disable')+'</button></div></div>'; }).join('')||'<p class="mu">No inspectors yet.</p>')+
    '<h3 style="margin-top:14px">Add an inspector</h3>'+
    '<div class="g"><div><label>Full name</label><input id="niName"></div><div><label>Password (6+ chars)</label><input id="niPin" type="password"></div></div>'+
    '<button class="pri" id="niGo" data-sc="'+s.id+'">Add inspector</button></div>';
}

/* -------------------------------------------------------------------- HOME */
BODY.home = function(){
  var s=school(), t=term(), rows=balances(t), owing=rows.filter(function(x){return x.due>0;});
  var tot=owing.reduce(function(a,r2){return a+r2.due;},0);
  var recent=paymentsOf().filter(function(p){return p.status==='ok';}).sort(function(a,b){return b.ts-a.ts;}).slice(0,3);
  var rateCodes=Object.keys(DATA.settings.rates).filter(function(c){return c!==cur().code;});
  var fin=buildFinanceSeries(); HOME_FIN=fin;
  var bk=DATA.settings.lastBackup, bkDays=bk?daysBetween(new Date(bk).toISOString().slice(0,10),today()):null;
  var bkBanner = (!isInspector() && (!bk || bkDays>=14)) ?
    '<div class="lockmsg">'+(bk?'It has been '+bkDays+' day(s) since your last backup.':'You have never backed up this device.')+' A backup is the only copy of your records if this device is lost or reset. <a onclick="App.go(\'settings\')">Back up now</a>.</div>' : '';
  var odInst=[]; studentsOf().forEach(function(st){ var o=overdueInstallments(st); if(o.length) odInst.push(st); });
  var attnRows='';
  if(owing.length) attnRows += '<a class="al-row" onclick="App.go(\'students\')"><span>'+owing.length+' student(s) owe fees this term</span><b>'+money(tot)+'</b></a>';
  if(odInst.length) attnRows += '<a class="al-row" onclick="App.go(\'students\')"><span>'+odInst.length+' student(s) have overdue installments</span><span class="mu">View</span></a>';
  var attnCard = attnRows ? '<div class="attn"><h3>⚠ Needs attention</h3>'+attnRows+'</div>' : '';
  return '<h2>Home</h2>'+attnCard+
    '<div class="kp"><div><span class="mu">Students</span><b>'+studentsOf().length+'</b></div>'+
    '<div class="'+(owing.length?'r':'g')+'"><span class="mu">Owing</span><b class="'+(owing.length?'bad':'ok')+'">'+owing.length+'</b></div>'+
    '<div class="'+(tot>0?'r':'g')+'"><span class="mu">Total outstanding</span><b>'+money(tot)+'</b></div>'+
    '<div><span class="mu">Term</span><b>'+(t?('Term '+t.no+', '+t.yr):'—')+'</b></div></div>'+
    (rateCodes.length?'<div class="card"><label>Show outstanding total in</label><select id="homeRate"><option value="">'+cur().code+' (native)</option>'+rateCodes.map(function(c){return '<option value="'+c+'">'+c+'</option>';}).join('')+'</select><div id="homeRateOut" class="mu" style="margin-top:6px"></div></div>':'')+
    (fin?(
      '<div class="card"><h3>Fees collected vs outstanding</h3><canvas class="chartbox" id="chart1"></canvas>'+legendHtml([['Fees collected','#1b9e5a'],['Outstanding','#c0362c']])+'</div>'+
      '<div class="card"><h3>Income vs expenses</h3><canvas class="chartbox" id="chart2"></canvas>'+legendHtml([['Other income','#1b4b9b'],['Expenses','#f28a1b']])+'</div>'
    ):'<div class="card"><p class="mu">Set the term start date in Settings to see financial trend charts here.</p></div>')+
    '<div class="card"><h3>Recent transactions</h3>'+(recent.map(function(p){var st=student(p.sid);
      return '<div class="it"><div>'+(st?esc(st.name):'(removed student)')+'<div class="mu">'+esc(p.date)+' · '+esc(p.method)+' · '+esc(p.receipt)+'</div></div><div class="ac"><b>'+money(p.amt)+'</b></div></div>';
    }).join('')||'<p class="mu">No payments recorded yet.</p>')+'</div>'+
    bkBanner+
    (readOnly()?'':'<div class="card"><h3>Quick actions</h3><button class="pri float" onclick="App.go(\'students\')">Add / find a student</button> <button onclick="App.go(\'payments\')">Record a payment</button> <button onclick="App.go(\'reports\')">View reports</button></div>');
};
function legendHtml(items){
  return '<div class="legend">'+items.map(function(it){return '<span class="lg-item"><i style="background:'+it[1]+'"></i>'+esc(it[0])+'</span>';}).join('')+'</div>';
}
function buildFinanceSeries(){
  var t=term(); if(!t||!t.start) return null;
  var startD=new Date(t.start+'T00:00:00'), endD=new Date();
  if(isNaN(startD.getTime())) return null;
  if(endD<startD) endD=startD;
  var steps=Math.min(10,Math.max(4,Math.ceil((endD-startD)/864e5/7)));
  var charged=chargesOf().filter(function(c){return c.tid===t.id;}).reduce(function(a,c){return a+ +c.amt;},0);
  var pays=paymentsOf().filter(function(p){return p.tid===t.id && p.status==='ok';});
  var ledg=ledgerOf(t.id).filter(function(x){return !x.voided;});
  var labels=[],fees=[],outstanding=[],income=[],expense=[];
  for(var i=0;i<=steps;i++){
    var d=new Date(startD.getTime()+(endD-startD)*i/steps), ds=d.toISOString().slice(0,10);
    labels.push(ds.slice(5));
    var fp=pays.filter(function(p){return p.date<=ds;}).reduce(function(a,p){return a+ +p.amt;},0);
    fees.push(fp); outstanding.push(Math.max(0,charged-fp));
    income.push(ledg.filter(function(x){return x.type==='income' && x.date<=ds;}).reduce(function(a,x){return a+ +x.amount;},0));
    expense.push(ledg.filter(function(x){return x.type==='expense' && x.date<=ds;}).reduce(function(a,x){return a+ +x.amount;},0));
  }
  return {labels:labels,fees:fees,outstanding:outstanding,income:income,expense:expense};
}
function drawLineChart(canvas,series,labels){
  if(!canvas) return; var ctx=canvas.getContext('2d');
  var dpr=window.devicePixelRatio||1, w=canvas.clientWidth||300, h=canvas.clientHeight||160;
  canvas.width=w*dpr; canvas.height=h*dpr; ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);
  var all=[]; series.forEach(function(s){ all=all.concat(s.data); });
  var max=Math.max(1,Math.max.apply(null,all.concat([1])));
  var padL=6,padR=6,padT=8,padB=18, plotW=w-padL-padR, plotH=h-padT-padB, n=labels.length;
  var bd=getComputedStyle(document.documentElement).getPropertyValue('--bd')||'#ddd';
  var mu=getComputedStyle(document.documentElement).getPropertyValue('--mu')||'#667';
  ctx.strokeStyle=bd; ctx.lineWidth=1;
  for(var g=0;g<=3;g++){ var y=padT+plotH*g/3; ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(w-padR,y); ctx.stroke(); }
  series.forEach(function(s){
    ctx.strokeStyle=s.color; ctx.lineWidth=2.4; ctx.beginPath();
    s.data.forEach(function(v,i){
      var x=padL+(n>1?plotW*i/(n-1):0), y=padT+plotH-(v/max)*plotH;
      if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    });
    ctx.stroke();
    var lastV=s.data[s.data.length-1], lastX=padL+plotW, lastY=padT+plotH-(lastV/max)*plotH;
    ctx.fillStyle=s.color; ctx.beginPath(); ctx.arc(lastX,lastY,3.2,0,Math.PI*2); ctx.fill();
  });
  ctx.fillStyle=mu; ctx.font='10px system-ui';
  ctx.textAlign='left'; ctx.fillText(labels[0]||'',padL,h-3);
  ctx.textAlign='right'; ctx.fillText(labels[labels.length-1]||'',w-padR,h-3);
}

/* --------------------------------------------------------------- STUDENTS */
function groupByClass(list){
  var order=classesOf(), groups={};
  list.forEach(function(s){ (groups[s.cls]=groups[s.cls]||[]).push(s); });
  var out=[];
  order.forEach(function(c){ if(groups[c]){ groups[c].sort(function(a,b){return a.name.localeCompare(b.name);}); out.push({cls:c,items:groups[c]}); delete groups[c]; } });
  Object.keys(groups).sort().forEach(function(c){ groups[c].sort(function(a,b){return a.name.localeCompare(b.name);}); out.push({cls:c,items:groups[c]}); });
  return out;
}
function groupedListHtml(list,cardFn){
  var groups=groupByClass(list);
  return groups.map(function(g){
    return '<div class="grp" data-grp="'+esc(g.cls)+'"><h3 class="grp-head">'+esc(g.cls)+' <span class="mu">('+g.items.length+')</span></h3>'+g.items.map(cardFn).join('')+'</div>';
  }).join('');
}
function wireLiveSearch(inputId,wrapId){
  var inp=$(inputId), wrap=$(wrapId); if(!inp||!wrap) return;
  inp.addEventListener('input',function(){
    var qv=inp.value.toLowerCase().trim();
    wrap.querySelectorAll('.grp').forEach(function(grp){
      var any=false;
      grp.querySelectorAll('[data-sname]').forEach(function(card){
        var m=!qv || (card.getAttribute('data-sname')||'').indexOf(qv)>-1 || (card.getAttribute('data-scode')||'').indexOf(qv)>-1;
        card.style.display=m?'':'none'; if(m) any=true;
      });
      grp.style.display=any?'':'none';
    });
  });
}
BODY.students = function(q){
  if(q.add && !readOnly()) return formStudent(null);
  if(q.edit && !readOnly()) return formStudent(student(q.edit));
  var all=studentsOf().filter(function(s){return s.active!==false;});
  var t=term(), bals={}; balances(t).forEach(function(b){bals[b.s.id]=b;});
  var html = groupedListHtml(all,function(s){
    var b=bals[s.id];
    var acts = readOnly() ? '' : '<button data-pay="'+s.id+'" class="pri">Pay</button><button data-edit="'+s.id+'">Edit</button><button data-rm="'+s.id+'" class="dng">Remove</button>';
    return scard(s,b,acts);
  }) || '<p class="mu">No students yet — tap "+ Add student" above to get started.</p>';
  return '<h2>Students ('+all.length+')</h2>'+(readOnly()?'':'<button class="pri float" onclick="App.go(\'students\',\'add=1\')" style="margin-bottom:12px">+ Add student</button>')+
    '<div class="sw2"><input id="stuSearch" placeholder="Search a student by name or code..." autocomplete="off"></div>'+
    '<div id="stuListWrap">'+html+'</div>';
};
function scard(s,b,acts){
  var due=b&&b.due>0, od=overdueInstallments(s);
  return '<div class="sc" data-sname="'+esc((s.name||'').toLowerCase())+'" data-scode="'+esc((s.code||'').toLowerCase())+'"><div class="sc-top">'+avatar(s,true)+
    '<div class="sc-info"><b class="sc-name">'+esc(s.name)+'</b><div class="mu">'+esc(s.kind)+' · '+esc(s.cls)+' · '+esc(s.code)+(s.disc?' · discount '+money(s.disc):'')+'</div>'+
    (b?'<div class="sc-owe '+(due?'b':'o')+'">'+(due?'Owes '+money(b.due):'Paid up')+'</div>':'')+
    (b&&b.credit>0?'<span class="chip o">Credit '+money(b.credit)+'</span>':'')+
    (od.length?'<span class="chip b">'+od.length+' overdue installment'+(od.length>1?'s':'')+'</span>':'')+'</div>'+
    '<div class="sc-g"><div class="mu">Guardian</div><b>'+esc(s.gn||'-')+'</b><div>'+(s.gp?'<a href="tel:'+esc(s.gp)+'">'+esc(s.gp)+'</a>':'<span class="mu">no phone</span>')+'</div></div></div>'+
    '<div class="sc-act">'+(acts||'')+' <button data-hist="'+s.id+'">History</button></div></div>';
}
function showHistory(sid){
  var s=student(sid); if(!s) return;
  var rows=historyOf(sid);
  var o=document.createElement('div'); o.className='ov';
  o.innerHTML='<div class="rc" style="max-width:520px"><h3>History — '+esc(s.name)+'</h3>'+
    (rows.map(function(x){ return '<div class="it"><div>'+esc(x.a)+'<div class="mu">'+esc(x.d||'')+'</div></div><div class="ac mu">'+new Date(x.ts).toLocaleString()+'<div>'+esc(x.by)+'</div></div></div>'; }).join('')||'<p class="mu">No recorded activity yet.</p>')+
    '<div class="noprint" style="margin-top:12px"><button id="histClose">Close</button></div></div>';
  document.body.appendChild(o);
  $('histClose').onclick=function(){ document.body.removeChild(o); };
}
function formStudent(s){
  s = s || {id:null,name:'',cls:classesOf()[0],kind:'Day',code:newCode(),gn:'',gp:'',disc:0};
  pendingPhoto=null;
  var existingPhoto = s.id ? DATA.photos[s.id] : null;
  return '<h2>'+(s.id?'Edit student':'Add student')+'</h2><div class="card fm">'+
    '<label>Photo</label><div style="display:flex;align-items:center;gap:10px"><span id="stPhotoPrev">'+(existingPhoto?'<img class="av lg" src="'+existingPhoto+'">':'<span class="av lg">?</span>')+'</span>'+
    '<label class="btn" style="margin:0">Choose photo<input type="file" id="stPhoto" accept="image/*" style="display:none"></label></div>'+
    '<label>Full name</label><input id="stName" value="'+esc(s.name)+'">'+
    '<div class="g"><div><label>Class</label><select id="stCls">'+classesOf().map(function(c){return '<option'+(c===s.cls?' selected':'')+'>'+c+'</option>';}).join('')+'</select></div>'+
    '<div><label>Day/Boarding</label><select id="stKind"><option'+(s.kind==='Day'?' selected':'')+'>Day</option><option'+(s.kind==='Boarding'?' selected':'')+'>Boarding</option></select></div></div>'+
    '<label>Pay code</label><input id="stCode" value="'+esc(s.code)+'">'+
    '<label>Guardian name</label><input id="stGn" value="'+esc(s.gn)+'">'+
    '<label>Guardian phone</label><input id="stGp" value="'+esc(s.gp)+'" placeholder="e.g. 07xxxxxxxx (dial it the normal local way)">'+
    '<label>Discount</label><input id="stDisc" type="number" value="'+(s.disc||0)+'">'+
    '<button class="pri" id="stSave" data-id="'+(s.id||'')+'">Save</button> <button onclick="App.go(\'students\')">Cancel</button></div>'+
    (s.id?planSectionHtml(s):'<p class="mu" style="margin-top:8px">Save the student first, then you can add an installment plan.</p>');
}
function planSectionHtml(s){
  var plan=planOf(s);
  return '<div class="card"><h3>Installment plan</h3>'+
    (plan.length?plan.map(function(x,i){ return '<div class="it"><div>'+money(x.amount)+' due '+esc(x.due)+(x.note?' — '+esc(x.note):'')+(x.done?' <span class="chip o">paid/done</span>':(daysBetween(today(),x.due)<0?' <span class="chip b">overdue</span>':''))+'</div>'+
      '<div class="ac"><button data-plan-done="'+s.id+'|'+i+'">'+(x.done?'Mark not done':'Mark done')+'</button><button class="dng" data-plan-rm="'+s.id+'|'+i+'">Remove</button></div></div>'; }).join('') : '<p class="mu">No installments yet.</p>')+
    '<div class="g" style="margin-top:8px"><div><label>Due date</label><input id="plDue" type="date"></div><div><label>Amount</label><input id="plAmt" type="number"></div></div>'+
    '<label>Note (optional)</label><input id="plNote" placeholder="e.g. 2nd installment">'+
    '<button class="pri" id="plAdd" data-id="'+s.id+'">Add installment</button></div>';
}

/* --------------------------------------------------------------- PAYMENTS */
BODY.payments = function(q){
  var sid=q.sid, s=sid?student(sid):null;
  var t=term();
  var body = '<h2>Payments</h2>';
  if(s){
    var b=balances(t).filter(function(x){return x.s.id===s.id;})[0];
    body += '<div class="card">'+scard(s,b,'')+'</div>';
    if(!readOnly()){
      body += '<div class="card fm"><h3>Record a payment</h3>'+
        '<label>Amount</label><input id="pmAmt" type="number" placeholder="0">'+
        '<div id="pmWarn" class="mu"></div>'+
        '<label>Method</label><select id="pmMethod"><option>Mobile money</option><option>Bank</option><option>Cash</option></select>'+
        '<label>Reference (optional)</label><input id="pmRef">'+
        '<label>Date</label><input id="pmDate" type="date" value="'+today()+'">'+
        '<button class="pri" id="pmGo" data-sid="'+s.id+'">Record payment</button></div>';
    }
    body += '<div class="card"><h3>Payment history</h3>'+paymentsOf().filter(function(p){return p.sid===s.id;}).sort(function(a,b2){return b2.ts-a.ts;}).map(function(p){
        return '<div class="it"><div>'+esc(p.date)+' · '+esc(p.method)+(p.status==='void'?' <span class="chip b">voided</span>':'')+'<div class="mu">'+esc(p.receipt)+'</div></div><div class="ac"><b>'+money(p.amt)+'</b><div><button data-receipt="'+p.id+'">Receipt</button>'+(p.status==='ok'&&!readOnly()?' <button data-void="'+p.id+'" class="dng">Void</button>':'')+'</div></div></div>';
      }).join('')+'</div>';
  } else {
    var plist=studentsOf().filter(function(x){return x.active!==false;});
    var pbody=groupedListHtml(plist,function(st){
      return '<div class="it" data-sname="'+esc((st.name||'').toLowerCase())+'" data-scode="'+esc((st.code||'').toLowerCase())+'"><div>'+esc(st.name)+'<div class="mu">'+esc(st.cls)+' · '+esc(st.code)+'</div></div><div class="ac"><button data-goto="'+st.id+'" class="pri">Open</button></div></div>';
    }) || '<p class="mu">No students yet.</p>';
    body += '<p class="mu">Find a student below, or <a onclick="App.go(\'receipts\')">view all receipts</a>.</p>'+
      '<div class="sw2"><input id="paySearch" placeholder="Search a student by name or code..." autocomplete="off"></div>'+
      '<div id="payListWrap">'+pbody+'</div>';
  }
  return body;
};

/* -------------------------------------------------------------- RECEIPTS */
BODY.receipts = function(){
  var rows = paymentsOf().filter(function(p){return p.status==='ok';}).sort(function(a,b){return b.ts-a.ts;});
  return '<h2>Receipts</h2><p class="mu"><a onclick="App.go(\'payments\')">&larr; Back to payments</a></p><div class="card">'+(rows.map(function(p){ var st=student(p.sid);
    return '<div class="it"><div>'+esc(p.receipt)+'<div class="mu">'+(st?esc(st.name):'')+' · '+esc(p.date)+'</div></div><div class="ac"><b>'+money(p.amt)+'</b><div><button data-receipt="'+p.id+'">View</button></div></div></div>';
  }).join('')||'<p class="mu">No receipts yet.</p>')+'</div>';
};

/* ------------------------------------------------------- FINANCE (expenses/income) */
BODY.finance = function(){
  var t=term(), rows=ledgerOf(t?t.id:null).filter(function(x){return !x.staffId;}).sort(function(a,b){return b.ts-a.ts;});
  var tot=ledgerTotals(t?t.id:null);
  var body='<h2>Finance — expenses &amp; income</h2>'+
    '<div class="kp"><div><span class="mu">Other income</span><b class="ok">'+money(tot.income)+'</b></div>'+
    '<div><span class="mu">Expenses</span><b class="bad">'+money(tot.expense)+'</b></div>'+
    '<div><span class="mu">Net (income − expenses)</span><b>'+money(tot.income-tot.expense)+'</b></div></div>';
  if(!readOnly()){
    body += '<div class="card fm"><h3>Add an entry</h3>'+
      '<label>Title</label><input id="lgTitle" list="lgSuggest" placeholder="e.g. Electricity bill, Donation, Registration fee">'+
      '<datalist id="lgSuggest"><option value="Registration fee"><option value="Admission fee"><option value="Application fee">'+
      '<option value="Holiday fieldwork"><option value="Donation"><option value="Electricity bill"><option value="Water bill"><option value="Stationery"></datalist>'+
      '<div class="g"><div><label>Amount</label><input id="lgAmt" type="number" placeholder="0"></div>'+
      '<div><label>Type</label><select id="lgType"><option value="expense">Expense</option><option value="income">Income</option></select></div></div>'+
      '<label>Date</label><input id="lgDate" type="date" value="'+today()+'">'+
      '<button class="pri" id="lgAdd">Add entry</button></div>';
  }
  body += '<div class="card"><h3>Entries this term</h3>'+(rows.map(function(x){
    return '<div class="it"><div>'+esc(x.title)+(x.voided?' <span class="chip b">voided</span>':'')+'<div class="mu">'+esc(x.date)+' · '+(x.type==='income'?'Income':'Expense')+' · '+esc(x.by||'')+'</div></div>'+
      '<div class="ac"><b class="'+(x.type==='income'?'ok':'bad')+'">'+(x.type==='income'?'+':'-')+money(x.amount)+'</b>'+
      (!readOnly()?'<div><button data-led-edit="'+x.id+'">Edit</button>'+(!x.voided?' <button class="dng" data-led-void="'+x.id+'">Void</button>':'')+'</div>':'')+'</div></div>';
  }).join('')||'<p class="mu">No entries yet.</p>')+'</div>';
  body += staffSectionHtml();
  body += activitySectionHtml();
  return body;
};
function staffSectionHtml(){
  var list=staffOf(), stats=payTimingStats();
  var out='<div class="sect"><h3>Staff &amp; payroll</h3>';
  if(stats && (stats.term!==null || stats.year!==null)){
    out += '<div class="kp"><div><span class="mu">Avg. time to pay — this term</span><b>'+(stats.term!==null?stats.term+' day'+(stats.term===1?'':'s'):'—')+'</b></div>'+
      '<div><span class="mu">Avg. time to pay — this year</span><b>'+(stats.year!==null?stats.year+' day'+(stats.year===1?'':'s'):'—')+'</b></div></div>';
  }
  if(!readOnly()){
    out += '<div class="card fm"><h3>Add staff</h3>'+
      '<label>Name</label><input id="stfName">'+
      '<div class="g"><div><label>Role</label><input id="stfRole" placeholder="e.g. Teacher, Cook, Head teacher"></div>'+
      '<div><label>Salary</label><input id="stfSalary" type="number" placeholder="0"></div></div>'+
      '<label>Allowance</label><input id="stfAllow" type="number" placeholder="0">'+
      '<button class="pri" id="stfAdd">Add staff member</button></div>';
  }
  out += '<div class="card">'+(list.map(staffCardHtml).join('')||'<p class="mu">No staff added yet.</p>')+'</div></div>';
  return out;
}

/* --------------------------------------------------------------- REPORTS */
BODY.reports = function(){
  var t=term(), rows=balances(t);
  var tot=rows.reduce(function(a,r2){return a+r2.due;},0), np=rows.filter(function(r2){return r2.due>0&&r2.pt===0;}).length, hp=rows.filter(function(r2){return r2.due>0&&r2.pt>0;}).length;
  var maxDue=Math.max(1,Math.max.apply(null,rows.map(function(r2){return r2.due;}).concat([1])));
  return '<h2>Reports</h2><div class="kp"><div><span class="mu">Not paid</span><b class="bad">'+np+'</b></div><div><span class="mu">Part paid</span><b>'+hp+'</b></div>'+
    '<div><span class="mu">Total outstanding</span><b>'+money(tot)+'</b></div><div><span class="mu">Students</span><b>'+rows.length+'</b></div></div>'+
    '<button class="pri" id="genReport" style="margin-bottom:10px">Generate printable term report</button> '+
    '<button id="genFinReport" style="margin-bottom:10px">Generate finance report (no student fees)</button>'+
    '<div class="card"><h3>Balances by student</h3>'+rows.filter(function(r2){return r2.due>0;}).sort(function(a,b){return b.due-a.due;}).map(function(r2){
      return bar(r2.s.name, r2.due, maxDue);
    }).join('')+'</div>';
};
function bar(label,val,max){ var w=max>0?Math.min(100,Math.round(val/max*100)):0; return '<div class="br"><span>'+esc(label)+'</span><div class="tr"><i style="width:'+w+'%"></i></div><b>'+money(val)+'</b></div>'; }
function termReportText(){
  var s=school(), t=term();
  var rows=balances(t).filter(function(r2){return r2.s.active!==false;});
  var feesCollected=rows.reduce(function(a,r2){return a+r2.pt;},0);
  var outstanding=rows.reduce(function(a,r2){return a+r2.due;},0);
  var lt=ledgerTotals(t?t.id:null);
  var net=feesCollected+lt.income-lt.expense;
  return {s:s,t:t,feesCollected:feesCollected,outstanding:outstanding,income:lt.income,expense:lt.expense,net:net,
    plain:(esc2(s.name)+' — Term report\n'+'Term '+(t?t.no:'')+', '+(t?t.yr:'')+'\nGenerated '+new Date().toLocaleString()+'\n\n'+
      'Fees collected: '+money(feesCollected)+'\n'+'Other income: '+money(lt.income)+'\n'+'Expenses: '+money(lt.expense)+'\n'+
      'Net total: '+money(net)+'\n'+'Fees still outstanding: '+money(outstanding))};
}
function esc2(s){ return String(s==null?'':s); }
/* An "independent" report — income and expenses only, with no student-fee data at all. */
function financeReportText(){
  var s=school(), t=term();
  var rows=ledgerOf(t?t.id:null).filter(function(x){return !x.voided;});
  function groupBy(type){
    var g={};
    rows.filter(function(x){return x.type===type;}).forEach(function(x){
      var cat = x.staffId ? 'Staff salaries' : x.title;
      g[cat]=(g[cat]||0)+ +x.amount;
    });
    return g;
  }
  var incomeG=groupBy('income'), expenseG=groupBy('expense');
  var income=Object.keys(incomeG).reduce(function(a,k){return a+incomeG[k];},0);
  var expense=Object.keys(expenseG).reduce(function(a,k){return a+expenseG[k];},0);
  var actTot=activitiesOf().reduce(function(a,act){ var tt=actTotals(act); return a+tt.collected; },0);
  var lines=function(g){ return Object.keys(g).sort(function(a,b){return g[b]-g[a];}).map(function(k){return '  '+k+': '+money(g[k]);}).join('\n'); };
  var plain=esc2(s.name)+' — Finance report (independent of student fees)\n'+'Term '+(t?t.no:'')+', '+(t?t.yr:'')+'\nGenerated '+new Date().toLocaleString()+'\n\n'+
    'Income:\n'+(lines(incomeG)||'  (none)')+'\nTotal income: '+money(income)+'\n\n'+
    'Expenses:\n'+(lines(expenseG)||'  (none)')+'\nTotal expenses: '+money(expense)+'\n\n'+
    'Activity/event fees collected (seminars, field study, etc.): '+money(actTot)+'\n\n'+
    'Net (income − expenses): '+money(income-expense);
  return {s:s,t:t,incomeG:incomeG,expenseG:expenseG,income:income,expense:expense,actTot:actTot,plain:plain};
}
function showFinanceReport(){
  var r=financeReportText(), s=r.s, t=r.t;
  function rowsHtml(g){ return Object.keys(g).sort(function(a,b){return g[b]-g[a];}).map(function(k){return '<div class="it"><span class="mu">'+esc(k)+'</span><b>'+money(g[k])+'</b></div>';}).join('')||'<p class="mu">None recorded.</p>'; }
  var o=document.createElement('div'); o.className='ov';
  o.innerHTML='<div class="rc" style="max-width:640px"><div class="wm"><span>'+esc(s.name)+'</span></div>'+
    '<h3>'+esc(s.name)+'</h3><div class="mu" style="text-align:center">Finance report — Term '+(t?t.no:'')+', '+(t?t.yr:'')+' (independent of student fees)</div>'+
    '<div class="it"><span class="mu">Generated</span><b>'+new Date().toLocaleString()+'</b></div>'+
    '<h3 style="margin-top:10px">Income — '+money(r.income)+'</h3>'+rowsHtml(r.incomeG)+
    '<h3 style="margin-top:10px">Expenses — '+money(r.expense)+'</h3>'+rowsHtml(r.expenseG)+
    '<div class="it" style="margin-top:8px"><span class="mu">Activity/event fees collected</span><b>'+money(r.actTot)+'</b></div>'+
    '<div class="it"><span class="mu">Net (income − expenses)</span><b>'+money(r.income-r.expense)+'</b></div>'+
    '<div class="noprint" style="margin-top:12px"><button class="pri" id="frPrint">Print / Export as PDF</button> '+
    '<a class="btn" id="frWa" target="_blank" href="https://wa.me/?text='+encodeURIComponent(r.plain)+'">Share via WhatsApp</a> '+
    '<a class="btn" id="frSms" href="sms:?body='+encodeURIComponent(r.plain)+'">Share via SMS</a> '+
    '<button id="frCopy">Copy text</button> <button id="frClose">Close</button></div></div>';
  document.body.appendChild(o);
  $('frClose').onclick=function(){ document.body.removeChild(o); };
  $('frPrint').onclick=function(){ window.print(); };
  $('frCopy').onclick=function(){ if(navigator.clipboard) navigator.clipboard.writeText(r.plain).then(function(){toast('Copied.');}); else toast('Copy not supported on this browser.'); };
}
/* Guardian numbers are stored the way you'd dial them locally (e.g. 07xxxxxxxx) —
   that's what works for the Call link. WhatsApp needs the international form
   (country code, no leading 0), so convert only when building a wa.me link. */
function toIntlPhone(local){
  var cc=String(DATA.settings.countryCode||'256').replace(/[^0-9]/g,'');
  var d=String(local||'').replace(/[^0-9]/g,'');
  if(!d) return '';
  if(d.charAt(0)==='0') return cc+d.slice(1);
  if(d.indexOf(cc)===0) return d;
  return cc+d;
}
function showTermReport(){
  var r=termReportText(), s=r.s, t=r.t;
  var share='Share';
  var o=document.createElement('div'); o.className='ov';
  o.innerHTML='<div class="rc" style="max-width:640px"><div class="wm"><span>'+esc(s.name)+'</span></div>'+
    '<h3>'+esc(s.name)+'</h3><div class="mu" style="text-align:center">Term report — Term '+(t?t.no:'')+', '+(t?t.yr:'')+'</div>'+
    '<div class="it"><span class="mu">Generated</span><b>'+new Date().toLocaleString()+'</b></div>'+
    '<div class="it"><span class="mu">Fees collected</span><b class="ok">'+money(r.feesCollected)+'</b></div>'+
    '<div class="it"><span class="mu">Other income</span><b class="ok">'+money(r.income)+'</b></div>'+
    '<div class="it"><span class="mu">Expenses</span><b class="bad">'+money(r.expense)+'</b></div>'+
    '<div class="it"><span class="mu">Net total</span><b>'+money(r.net)+'</b></div>'+
    '<div class="it"><span class="mu">Fees still outstanding</span><b class="bad">'+money(r.outstanding)+'</b></div>'+
    '<div class="noprint" style="margin-top:12px"><button class="pri" id="trPrint">Print / Export as PDF</button> '+
    '<a class="btn" id="trWa" target="_blank" href="https://wa.me/?text='+encodeURIComponent(r.plain)+'">Share via WhatsApp</a> '+
    '<a class="btn" id="trSms" href="sms:?body='+encodeURIComponent(r.plain)+'">Share via SMS</a> '+
    '<button id="trCopy">Copy text</button> <button id="trClose">Close</button></div></div>';
  document.body.appendChild(o);
  $('trClose').onclick=function(){ document.body.removeChild(o); };
  $('trPrint').onclick=function(){ window.print(); };
  $('trCopy').onclick=function(){ if(navigator.clipboard) navigator.clipboard.writeText(r.plain).then(function(){toast('Copied.');}); else toast('Copy not supported on this browser.'); };
}

/* ---------------------------------------------------------- NOTIFICATIONS */
BODY.notifications = function(){
  var list=DATA.notes.filter(function(n){return n.sc===CUR_SID && (isAdmin()?n.admin:!n.admin);}).sort(function(a,b){return b.ts-a.ts;});
  return '<h2>Notifications</h2>'+(list.map(function(n){
    return '<div class="card nt'+(n.read?' done':' un')+'" data-note="'+n.id+'">'+
      '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px"><span class="nt-title">'+esc(n.title)+'</span>'+(n.read?'<span class="chip o">Done</span>':'')+'</div>'+
      '<div class="mu">'+new Date(n.ts).toLocaleString()+'</div></div>';
  }).join('')||'<p class="mu">No notifications.</p>');
};
function openNotification(id){
  var n=DATA.notes.filter(function(x){return x.id===id;})[0]; if(!n) return;
  if(!n.read){ n.read=true; save(); render(); }
  var o=document.createElement('div'); o.className='ov center';
  o.innerHTML='<div class="rc" style="max-width:480px"><h3>'+esc(n.title)+'</h3>'+
    '<div class="mu" style="text-align:center;margin-bottom:8px">'+new Date(n.ts).toLocaleString()+'</div>'+
    '<p style="white-space:pre-wrap">'+esc(n.body||'')+'</p>'+
    '<div class="noprint" style="margin-top:12px;text-align:center"><button class="pri" id="ntClose">Close</button></div></div>';
  document.body.appendChild(o);
  $('ntClose').onclick=function(){ document.body.removeChild(o); };
}

/* -------------------------------------------------------------- SETTINGS */
BODY.settings = function(){
  var s=school();
  var lk=DATA.settings.look||{}, mode=lk.mode||'auto';
  var out = '<h2>Settings</h2>';
  out += '<div class="sect"><h3>Appearance</h3><div class="card fm"><label>Theme</label><select id="setMode">'+
    '<option value="auto"'+(mode==='auto'?' selected':'')+'>Default (follow device)</option>'+
    '<option value="light"'+(mode==='light'?' selected':'')+'>Light</option>'+
    '<option value="dark"'+(mode==='dark'?' selected':'')+'>Dark</option></select>'+
    '<button class="pri" id="setModeGo" style="margin-top:8px">Apply theme</button></div></div>';
  if(isInspector()){
    out += '<div class="card"><p class="mu">Inspectors have view-only access. Settings can only be changed by the bursar or admin.</p></div>';
    out += '<div class="sect"><h3>Contact the admin</h3><div class="card">'+contactLinksHtml(DATA.admin.phone,DATA.admin.email)+'</div></div>';
  } else if(s && !isAdmin()){ // bursar: owns theme/term/fees/backup for their school
    var t=term();
    out += '<div class="sect"><h3>Theme</h3><div class="card fm"><label>Color style</label><select id="setStyle">'+Object.keys(PAL).map(function(k){return '<option value="'+k+'"'+(DATA.settings.style===k?' selected':'')+'>'+PAL[k][0]+'</option>';}).join('')+'</select>'+
      '<button class="pri" id="setStyleGo" style="margin-top:8px">Apply style</button></div></div>'+
      '<div class="sect"><h3>Term period &amp; Visiting Day</h3><div class="card fm">'+
      '<div class="g"><div><label>Term no.</label><input id="tNo" type="number" value="'+(t?t.no:1)+'"></div><div><label>Year</label><input id="tYr" type="number" value="'+(t?t.yr:new Date().getFullYear())+'"></div></div>'+
      '<label>Term start</label><input id="tStart" type="date" value="'+(t?t.start:'')+'">'+
      '<label>Visiting day</label><input id="tVisit" type="date" value="'+(t?t.visit:'')+'">'+
      '<label>Term end</label><input id="tEnd" type="date" value="'+(t?t.end:'')+'">'+
      '<button class="pri" id="tSave" style="margin-top:8px">Save term dates</button></div>'+
      '<div class="card"><label><input type="checkbox" id="setPromote"> Promote all students to the next class</label>'+
      '<button class="pri" id="setNewTerm" style="margin-top:8px">Start a brand-new term</button></div></div>'+
      '<div class="sect"><h3>Amount to be paid, by class</h3><div class="card fm" id="feeGrid">'+feeGridHtml(s)+'<button class="pri" id="feeSave" style="margin-top:10px">Save fees</button></div></div>'+
      '<div class="sect"><h3>Guardian WhatsApp country code</h3><div class="card fm"><label>Country calling code (digits only, no +)</label><input id="setCC" value="'+esc(DATA.settings.countryCode||'256')+'" placeholder="e.g. 256 for Uganda">'+
      '<p class="mu">Keep entering guardian numbers the normal local way (e.g. 07xxxxxxxx) — this code is only used to format the WhatsApp link so it reaches the right number.</p>'+
      '<button class="pri" id="setCCGo" style="margin-top:4px">Save code</button></div></div>'+
      '<div class="sect"><h3>Contact the admin</h3><div class="card">'+contactLinksHtml(DATA.admin.phone,DATA.admin.email)+'</div></div>'+
      '<div class="sect"><h3>Your password</h3><div class="card fm"><label>Current password</label><input id="setOld" type="password">'+
      '<label>New password (6+ chars)</label><input id="setNew" type="password"><p class="mu">Only the admin can reset a forgotten bursar password.</p><button class="pri" id="setPwGo">Change password</button></div></div>';
  } else if(isAdmin()){
    out += '<div class="sect"><h3>Admin password</h3><div class="card fm"><label>Current password</label><input id="setOld" type="password">'+
      '<label>New password (6+ chars)</label><input id="setNew" type="password"><button class="pri" id="setPwGo">Change password</button></div></div>';
    out += '<div class="sect"><h3>Your contact info</h3><div class="card fm"><p class="mu">Bursars and inspectors can reach you using the details below.</p>'+
      '<label>Phone</label><input id="setAdPhone" value="'+esc(DATA.admin.phone||'')+'" placeholder="e.g. 07xxxxxxxx">'+
      '<label>Email</label><input id="setAdEmail" type="email" value="'+esc(DATA.admin.email||'')+'" placeholder="e.g. you@example.com">'+
      '<button class="pri" id="setAdContactGo" style="margin-top:8px">Save contact info</button></div></div>';
    if(s){
      out += '<div class="sect"><h3>School (inspect)</h3><div class="card"><p><b>'+esc(s.name)+'</b></p>'+(s.motto?'<p class="mu">'+esc(s.motto)+'</p>':'')+'<p class="mu">Currency: '+esc((s.ccy&&s.ccy.code)||'UGX')+'. Edit school details from the Schools page.</p></div></div>';
      var scBursars=DATA.bursars.filter(function(b){return b.sc===s.id && b.active!==false;});
      out += '<div class="sect"><h3>Contact your bursar'+(scBursars.length===1?'':'s')+'</h3><div class="card">'+
        (scBursars.length?scBursars.map(function(b){
          return '<div class="it"><div>'+esc(b.name)+'</div><div class="ac">'+contactLinksHtml(b.phone,b.email)+'</div></div>';
        }).join(''):'<p class="mu">No bursar added for this school yet.</p>')+'</div></div>';
    }
  }
  out += '<div class="sect"><h3>Data</h3><div class="card"><button id="setBkDown" class="pri">Download backup</button> <button id="setBkUpBtn">Import backup</button><input type="file" id="setBkFile" accept="application/json" style="display:none"></div></div>';
  out += '<div class="sect"><div class="card"><button id="setLogout" class="dng">Log out</button> <label style="display:inline-block;margin-left:10px"><input type="checkbox" id="setForget"> Forget this device (clear remembered login)</label></div></div>';
  return out;
};
function contactLinksHtml(phone,email){
  var parts=[];
  if(phone){ parts.push('<a class="btn" href="tel:'+esc(phone)+'">&#128222; Call</a>'); parts.push('<a class="btn" href="sms:'+esc(phone)+'">&#128172; SMS</a>'); }
  if(email){ parts.push('<a class="btn" href="mailto:'+esc(email)+'">&#9993; Email</a>'); }
  return parts.length?parts.join(' '):'<p class="mu">No contact info has been added yet.</p>';
}
function feeGridHtml(sc){
  var classes=classesOf(sc), kinds=['Day','Boarding'], items=itemsOf(sc);
  return classes.map(function(c){
    return '<div class="sect" style="margin-top:8px"><b>'+c+'</b>'+kinds.map(function(k){
      return items.map(function(i){
        var key=k+'|'+c+'|'+i, val=(sc.fees||{})[key]||0;
        return '<div class="fgrid"><span class="mu">'+k+'</span><span class="mu">'+esc(i)+'</span><input type="number" data-fee="'+key+'" value="'+val+'"></div>';
      }).join('');
    }).join('')+'</div>';
  }).join('');
}

/* -------------------------------------------------------- demo data */
var FIRST=['Grace','John','Mary','Peter','Esther','David','Ruth','Moses','Sarah','Brian','Joy','Allan','Irene','Samuel','Diana','Isaac','Patience','Noah','Faith','Victor'];
var LAST=['Nakato','Okello','Namuli','Ssebunya','Atim','Mugisha','Nantongo','Kato','Auma','Byaruhanga','Namata','Wasswa','Achan','Kigozi','Nabirye'];
function rnd(arr){ return arr[Math.floor(Math.random()*arr.length)]; }
function demoPhone(){ return '07'+(Math.floor(Math.random()*9)+1)+Math.floor(10000000+Math.random()*89999999); }
function addDemoStudents(sc){
  var n = 20+Math.floor(Math.random()*81);
  var classes = classesOf(sc);
  var tt=(sc.terms||[]).filter(function(x){return x.id===sc.cur;})[0];
  for(var i=0;i<n;i++){
    var name = rnd(FIRST)+' '+rnd(LAST);
    var cls = rnd(classes), kind = Math.random()<0.5?'Day':'Boarding';
    var code; var ex = DATA.students.filter(function(x){return x.sc===sc.id;});
    do{ code=(esc1(sc.name)||'ST').slice(0,4)+(1000+Math.floor(Math.random()*9000)); }while(ex.some(function(x){return x.code===code;}));
    var stu = {id:uid(),sc:sc.id,active:true,created:Date.now(),name:name,cls:cls,kind:kind,code:code, gn:rnd(FIRST)+' '+rnd(LAST),gp:demoPhone(),disc:0};
    DATA.students.push(stu);
    if(tt) setCharge(stu.id, tt.id, feeFor(stu,sc));
  }
  save(); return n;
}

/* -------------------------------------------------------- backup/restore */
function exportData(){
  return { v:4, exported:Date.now(), admin:{name:DATA.admin.name,phone:DATA.admin.phone,email:DATA.admin.email}, bursars:DATA.bursars, inspectors:DATA.inspectors, staff:DATA.staff, activities:DATA.activities, actPayments:DATA.actPayments, schools:DATA.schools, students:DATA.students,
    payments:DATA.payments, charges:DATA.charges, notes:DATA.notes, log:DATA.log, ledger:DATA.ledger, photos:DATA.photos, settings:DATA.settings };
}
function downloadBackup(){
  DATA.settings.lastBackup=Date.now(); save();
  var blob=new Blob([JSON.stringify(exportData())],{type:'application/json'});
  var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='ledger-backup-'+today()+'.json';
  document.body.appendChild(a); a.click(); setTimeout(function(){document.body.removeChild(a);},500);
  toast('Backup downloaded.');
}
function importBackup(file){
  var fr=new FileReader();
  fr.onload=function(){
    var d; try{ d=JSON.parse(fr.result); }catch(e){ toast('That file is not valid JSON.'); return; }
    if(!d || !Array.isArray(d.schools)){ toast('That file is not a valid backup.'); return; }
    ['schools','students','payments','charges','notes','log','bursars','inspectors','ledger','staff','activities','actPayments'].forEach(function(k){ if(Array.isArray(d[k])) DATA[k]=d[k]; });
    if(d.photos) DATA.photos=d.photos;
    if(d.settings) DATA.settings=d.settings;
    if(d.admin){ if(d.admin.phone!==undefined) DATA.admin.phone=d.admin.phone; if(d.admin.email!==undefined) DATA.admin.email=d.admin.email; }
    save(); toast('Backup imported.'); render();
  };
  fr.readAsText(file);
}

/* --------------------------------------------------------- overpay modal */
function confirmOverpay(excess,onYes){
  var o=document.createElement('div'); o.className='ov';
  o.innerHTML='<div class="rc"><h3>Amount exceeds balance</h3><p>This payment is '+money(excess)+' more than what is currently owed.</p>'+
    '<p class="mu">Carry the extra as credit toward next term?</p>'+
    '<button class="pri" id="opYes">Yes, record and carry forward</button><button id="opNo">Cancel</button></div>';
  document.body.appendChild(o);
  $('opYes').onclick=function(){ document.body.removeChild(o); onYes(); };
  $('opNo').onclick=function(){ document.body.removeChild(o); };
}

/* ------------------------------------------------------------ swipe nav */
function wireSwipe(){
  var wrap=$('body'); if(!wrap) return;
  var startX=0,startY=0,active=false;
  wrap.addEventListener('touchstart',function(e){ if(e.touches.length!==1) return; startX=e.touches[0].clientX; startY=e.touches[0].clientY; active=true; },{passive:true});
  wrap.addEventListener('touchend',function(e){
    if(!active) return; active=false;
    var dx=(e.changedTouches[0].clientX-startX), dy=(e.changedTouches[0].clientY-startY);
    if(Math.abs(dx)<70 || Math.abs(dy)>60) return;
    var N = isAdmin() ? [['schools','Schools']].concat(navFor()) : navFor();
    var cur2=parseHash().route, i=N.findIndex(function(n){return n[0]===cur2;});
    if(i<0) return;
    var ni = dx<0 ? i+1 : i-1;
    if(ni>=0 && ni<N.length) go(N[ni][0]);
  },{passive:true});
}

/* ----------------------------------------------------------------- wire */
function wire(route,q){
  var menuBtn=$('menuBtn'), menuDrop=$('menuDrop');
  if(menuBtn){ menuBtn.onclick=function(e){ e.stopPropagation(); menuDrop.classList.toggle('open'); };
    document.addEventListener('click',function(){ menuDrop.classList.remove('open'); }); }
  var menuLogout=$('menuLogout'); if(menuLogout) menuLogout.onclick=doLogout;
  wireSwipe();
  document.querySelectorAll('[data-hist]').forEach(function(b){ b.onclick=function(){ showHistory(b.getAttribute('data-hist')); }; });

  if(route==='landing'){ var suGo=$('suGo'); if(suGo) suGo.onclick=doSetup; var remGo=$('remGo'); if(remGo) remGo.onclick=doRemember; }

  if(route==='login'){
    LOGIN_FOUND=null;
    var nameGo=function(){
      var name=$('lgName').value.trim(), err=$('loginErr');
      err.innerHTML='';
      if(name.length<2){ err.innerHTML='<div class="al2">Enter your full name.</div>'; return; }
      var found=findAccount(name);
      if(!found){ err.innerHTML='<div class="al2">No account matches that name. Check with the admin.</div>'; return; }
      LOGIN_FOUND=found;
      $('pwStep').innerHTML=loginBoxPassword(found);
      $('lgGo2').onclick=doLoginUnified;
      $('lgPin').addEventListener('keydown',function(e){if(e.keyCode===13)doLoginUnified();});
      $('lgPin').focus();
      $('lgBack').onclick=function(){ LOGIN_FOUND=null; $('loginBox').innerHTML=loginBoxName(); wire('login',{}); };
    };
    var g=$('lgGo'); if(g) g.onclick=nameGo;
    var nI=$('lgName'); if(nI) nI.addEventListener('keydown',function(e){if(e.keyCode===13)nameGo();});
  }

  if(route==='schools'){
    if(q.edit){
      var esSave=$('esSave'); if(esSave) esSave.onclick=function(){
        var s=DATA.schools.filter(function(x){return x.id===esSave.getAttribute('data-id');})[0]; if(!s) return;
        s.name=$('esName').value.trim()||s.name; s.motto=$('esMotto').value.trim(); s.type=$('esType').value==='primary'?'primary':'secondary';
        s.ccy=s.ccy||{}; s.ccy.code=$('esCcy').value.trim()||'UGX'; save(); toast('Saved.'); render();
      };
      var esDemo=$('esDemo'); if(esDemo) esDemo.onclick=function(){
        var s=DATA.schools.filter(function(x){return x.id===esDemo.getAttribute('data-id');})[0]; if(!s) return;
        var n=addDemoStudents(s); toast('Added '+n+' demo students.'); render();
      };
      document.querySelectorAll('[data-reset-bursar]').forEach(function(b){ b.onclick=async function(){
        var bu=DATA.bursars.filter(function(x){return x.id===b.getAttribute('data-reset-bursar');})[0]; if(!bu) return;
        var np=prompt('New password for '+bu.name+' (6+ characters, not weak):'); if(np===null) return;
        if(weakPassword(np)){ toast('That password is too weak.'); return; }
        var salt=randSalt(); bu.pinHash=await hashPin(np,salt); bu.salt=salt; save(); toast('Password reset. Tell '+bu.name+' the new password: '+np);
      }; });
      document.querySelectorAll('[data-toggle-bursar]').forEach(function(b){ b.onclick=function(){ var bu=DATA.bursars.filter(function(x){return x.id===b.getAttribute('data-toggle-bursar');})[0]; if(bu){ bu.active=bu.active===false; save(); render(); } }; });
      document.querySelectorAll('[data-reset-insp]').forEach(function(b){ b.onclick=async function(){
        var bu=DATA.inspectors.filter(function(x){return x.id===b.getAttribute('data-reset-insp');})[0]; if(!bu) return;
        var np=prompt('New password for '+bu.name+' (6+ characters, not weak):'); if(np===null) return;
        if(weakPassword(np)){ toast('That password is too weak.'); return; }
        var salt=randSalt(); bu.pinHash=await hashPin(np,salt); bu.salt=salt; save(); toast('Password reset. New password: '+np);
      }; });
      document.querySelectorAll('[data-toggle-insp]').forEach(function(b){ b.onclick=function(){ var bu=DATA.inspectors.filter(function(x){return x.id===b.getAttribute('data-toggle-insp');})[0]; if(bu){ bu.active=bu.active===false; save(); render(); } }; });
      var nbGo=$('nbGo'); if(nbGo) nbGo.onclick=async function(){
        var sc=nbGo.getAttribute('data-sc'), name=$('nbName').value.trim(), p=$('nbPin').value, p2=$('nbPin2').value;
        if(name.length<3){ toast('Enter a name.'); return; }
        if(weakPassword(p)){ toast('Choose a stronger password.'); return; }
        if(p!==p2){ toast('Passwords do not match.'); return; }
        if(nameExists(name)){ toast('That name is already used by another account on this device. Names must be unique.'); return; }
        var salt=randSalt();
        DATA.bursars.push({id:uid(),name:name,name_norm:norm(name),sc:sc,email:$('nbEmail').value.trim(),phone:$('nbPhone').value.trim(),username:$('nbUser').value.trim(),pinHash:await hashPin(p,salt),salt:salt,active:true});
        save(); toast('Bursar added.'); render();
      };
      var niGo=$('niGo'); if(niGo) niGo.onclick=async function(){
        var sc=niGo.getAttribute('data-sc'), name=$('niName').value.trim(), p=$('niPin').value;
        if(name.length<3){ toast('Enter a name.'); return; } if(weakPassword(p)){ toast('Choose a stronger password.'); return; }
        if(nameExists(name)){ toast('That name is already used by another account on this device. Names must be unique.'); return; }
        var salt=randSalt();
        DATA.inspectors.push({id:uid(),name:name,name_norm:norm(name),sc:sc,pinHash:await hashPin(p,salt),salt:salt,active:true});
        save(); toast('Inspector added.'); render();
      };
    } else {
      document.querySelectorAll('[data-open]').forEach(function(b){ b.onclick=function(){ CUR_SID=b.getAttribute('data-open'); go('home'); }; });
      document.querySelectorAll('[data-edit-school]').forEach(function(b){ b.onclick=function(){ go('schools','edit='+b.getAttribute('data-edit-school')); }; });
      document.querySelectorAll('[data-del-school]').forEach(function(b){ b.onclick=function(){ var id=b.getAttribute('data-del-school'); if(!confirm('Remove this school and all its records? This cannot be undone.'))return;
        DATA.schools=DATA.schools.filter(function(s){return s.id!==id;});
        DATA.bursars=DATA.bursars.filter(function(x){return x.sc!==id;}); DATA.inspectors=DATA.inspectors.filter(function(x){return x.sc!==id;});
        ['students','payments','charges','notes','log','ledger'].forEach(function(k){ DATA[k]=DATA[k].filter(function(x){return x.sc!==id;}); });
        if(CUR_SID===id) CUR_SID=null; save(); render(); }; });
      var nsGo=$('nsGo'); if(nsGo) nsGo.onclick=function(){ var n=$('nsName').value.trim(); if(n.length<2){toast('Enter a name.');return;}
        var s=newSchool(n,$('nsType').value); DATA.schools.push(s); CUR_SID=s.id; save(); go('home'); };
      var rateAdd=$('rateAdd'); if(rateAdd) rateAdd.onclick=function(){
        var c=$('rateCode').value.trim().toUpperCase(), v=+$('rateVal').value; if(!c||!v){ toast('Enter a code and rate.'); return; }
        DATA.settings.rates[c]=v; save(); toast('Rate saved.'); render();
      };
      var rateSaveAll=$('rateSaveAll'); if(rateSaveAll) rateSaveAll.onclick=function(){
        document.querySelectorAll('[data-rate]').forEach(function(inp){ DATA.settings.rates[inp.getAttribute('data-rate')]=+inp.value||1; });
        save(); toast('Rates saved.');
      };
      var bkDown=$('bkDown'); if(bkDown) bkDown.onclick=downloadBackup;
      var bkUpBtn=$('bkUpBtn'); if(bkUpBtn) bkUpBtn.onclick=function(){ $('bkFile').click(); };
      var bkFile=$('bkFile'); if(bkFile) bkFile.onchange=function(){ if(bkFile.files[0]) importBackup(bkFile.files[0]); };
    }
  }

  if(route==='home'){
    var fd=HOME_FIN;
    if(fd){
      var c1=$('chart1'); if(c1) drawLineChart(c1,[{color:'#1b9e5a',data:fd.fees},{color:'#c0362c',data:fd.outstanding}],fd.labels);
      var c2=$('chart2'); if(c2) drawLineChart(c2,[{color:'#1b4b9b',data:fd.income},{color:'#f28a1b',data:fd.expense}],fd.labels);
    }
    var homeRate=$('homeRate'); if(homeRate) homeRate.onchange=function(){
      var t=term(), tot=balances(t).filter(function(b){return b.due>0;}).reduce(function(a,b){return a+b.due;},0);
      var out=$('homeRateOut');
      if(!homeRate.value){ out.textContent=''; return; }
      out.textContent='≈ '+homeRate.value+' '+Math.round(toRate(tot,homeRate.value)).toLocaleString('en-US');
    };
  }

  if(route==='students'){
    wireLiveSearch('stuSearch','stuListWrap');
    if((q.add||q.edit) && !readOnly()){
      var stPhoto=$('stPhoto'); if(stPhoto) stPhoto.onchange=function(){ var f=stPhoto.files[0]; if(!f) return;
        shrink(f,function(durl){ if(!durl){ toast('Could not read that image.'); return; } pendingPhoto=durl; $('stPhotoPrev').innerHTML='<img class="av lg" src="'+durl+'">'; }); };
      var stSave=$('stSave'); if(stSave) stSave.onclick=function(){
        var id=stSave.getAttribute('data-id')||uid();
        var ex=student(id)||{id:id,sc:CUR_SID,active:true,created:Date.now()};
        ex.name=$('stName').value.trim(); ex.cls=$('stCls').value; ex.kind=$('stKind').value;
        ex.code=$('stCode').value.trim(); ex.gn=$('stGn').value.trim(); ex.gp=$('stGp').value.trim(); ex.disc=+$('stDisc').value||0;
        if(!ex.name){ toast('Enter a name.'); return; }
        if(!DATA.students.some(function(s){return s.id===ex.id;})) DATA.students.push(ex);
        if(pendingPhoto){ DATA.photos[ex.id]=pendingPhoto; pendingPhoto=null; }
        var t0=term(); if(t0) setCharge(ex.id, t0.id, feeFor(ex));
        save(); log(stSave.getAttribute('data-id')?'Edited student':'Added student', ex.name, ex.id); go('students','edit='+ex.id);
      };
      var plAdd=$('plAdd'); if(plAdd) plAdd.onclick=function(){
        var sid=plAdd.getAttribute('data-id'), s2=student(sid); if(!s2) return;
        var due=$('plDue').value, amt=+$('plAmt').value||0; if(!due||!amt){ toast('Enter a due date and amount.'); return; }
        s2.plan=planOf(s2); s2.plan.push({due:due,amount:amt,note:$('plNote').value.trim(),done:false});
        save(); toast('Installment added.'); render();
      };
      document.querySelectorAll('[data-plan-done]').forEach(function(b){ b.onclick=function(){
        var parts=b.getAttribute('data-plan-done').split('|'), s2=student(parts[0]); if(!s2) return;
        s2.plan=planOf(s2); var it=s2.plan[+parts[1]]; if(it){ it.done=!it.done; save(); render(); }
      }; });
      document.querySelectorAll('[data-plan-rm]').forEach(function(b){ b.onclick=function(){
        var parts=b.getAttribute('data-plan-rm').split('|'), s2=student(parts[0]); if(!s2) return;
        s2.plan=planOf(s2); s2.plan.splice(+parts[1],1); save(); render();
      }; });
    } else if(!readOnly()) {
      document.querySelectorAll('[data-pay]').forEach(function(b){ b.onclick=function(){ go('payments','sid='+b.getAttribute('data-pay')); }; });
      document.querySelectorAll('[data-edit]').forEach(function(b){ b.onclick=function(){ go('students','edit='+b.getAttribute('data-edit')); }; });
      document.querySelectorAll('[data-rm]').forEach(function(b){ b.onclick=function(){ var id=b.getAttribute('data-rm'); if(!confirm('Remove this student?'))return;
        var s=student(id); if(s){ s.active=false; save(); log('Removed student', s.name, s.id); render(); } }; });
    }
  }

  if(route==='payments'){
    wireLiveSearch('paySearch','payListWrap');
    document.querySelectorAll('[data-goto]').forEach(function(b){ b.onclick=function(){ go('payments','sid='+b.getAttribute('data-goto')); }; });
    var pmAmt=$('pmAmt'), pmWarn=$('pmWarn');
    if(pmAmt){
      var sidNow=$('pmGo')?$('pmGo').getAttribute('data-sid'):null;
      pmAmt.addEventListener('input',function(){
        var due=dueOf(sidNow), amt=+pmAmt.value||0;
        pmWarn.innerHTML = (amt>due) ? '<span class="bad">This exceeds the current balance ('+money(due)+') by '+money(amt-due)+'.</span>' : '';
      });
    }
    var pmGo=$('pmGo'); if(pmGo) pmGo.onclick=function(){
      var sid=pmGo.getAttribute('data-sid'), amt=+$('pmAmt').value||0;
      if(amt<=0){ toast('Enter an amount.'); return; }
      var t=term(); if(!t){ toast('No active term set.'); return; }
      var due=dueOf(sid);
      function record(){
        school().counter=(school().counter||0)+1;
        var seq=school().counter, p={id:uid(),sc:CUR_SID,sid:sid,tid:t.id,amt:amt,method:$('pmMethod').value,ref:$('pmRef').value.trim(),
          date:$('pmDate').value||today(),receipt:rno(seq),status:'ok',by:actorName(),ts:Date.now()};
        DATA.payments.push(p); save(); log('Recorded payment', money(amt)+' for '+((student(sid)||{}).name||''), sid); showReceipt(p); render();
      }
      if(amt>due) confirmOverpay(amt-due, record); else record();
    };
    document.querySelectorAll('[data-receipt]').forEach(function(b){ b.onclick=function(){ var p=DATA.payments.filter(function(x){return x.id===b.getAttribute('data-receipt');})[0]; if(p) showReceipt(p); }; });
    document.querySelectorAll('[data-void]').forEach(function(b){ b.onclick=function(){ var id=b.getAttribute('data-void'); var reason=prompt('Reason for voiding this payment?'); if(reason===null)return;
      var p=DATA.payments.filter(function(x){return x.id===id;})[0]; if(p){ p.status='void'; p.reason=reason; save(); log('Voided payment', p.receipt, p.sid); render(); } }; });
  }

  if(route==='receipts'){
    document.querySelectorAll('[data-receipt]').forEach(function(b){ b.onclick=function(){ var p=DATA.payments.filter(function(x){return x.id===b.getAttribute('data-receipt');})[0]; if(p) showReceipt(p); }; });
  }

  if(route==='finance'){
    var lgAdd=$('lgAdd'); if(lgAdd) lgAdd.onclick=function(){
      var title=$('lgTitle').value.trim(), amt=+$('lgAmt').value||0, type=$('lgType').value, date=$('lgDate').value||today();
      if(!title){ toast('Enter a title.'); return; } if(amt<=0){ toast('Enter an amount.'); return; }
      var t=term(); if(!t){ toast('No active term set.'); return; }
      DATA.ledger.push({id:uid(),sc:CUR_SID,tid:t.id,type:type,title:title,amount:amt,date:date,by:actorName(),ts:Date.now(),voided:false});
      save(); log((type==='income'?'Added income':'Added expense'), title+' — '+money(amt)); toast('Entry added.'); render();
    };
    document.querySelectorAll('[data-led-void]').forEach(function(b){ b.onclick=function(){
      var x=DATA.ledger.filter(function(v){return v.id===b.getAttribute('data-led-void');})[0]; if(!x) return;
      if(!confirm('Void this entry?')) return; x.voided=true; save(); log('Voided '+x.type, x.title); render();
    }; });
    document.querySelectorAll('[data-led-edit]').forEach(function(b){ b.onclick=function(){
      var x=DATA.ledger.filter(function(v){return v.id===b.getAttribute('data-led-edit');})[0]; if(!x) return;
      var nt=prompt('Title', x.title); if(nt===null) return;
      var na=prompt('Amount', x.amount); if(na===null) return; na=+na||0;
      var nd=prompt('Date (YYYY-MM-DD)', x.date); if(nd===null) return;
      x.title=nt.trim()||x.title; x.amount=na||x.amount; x.date=nd||x.date; save(); log('Edited '+x.type, x.title); render();
    }; });
    var stfAdd=$('stfAdd'); if(stfAdd) stfAdd.onclick=function(){
      var name=$('stfName').value.trim(), role=$('stfRole').value.trim(), salary=+$('stfSalary').value||0, allow=+$('stfAllow').value||0;
      if(!name){ toast('Enter a name.'); return; }
      DATA.staff.push({id:uid(),sc:CUR_SID,active:true,created:Date.now(),name:name,role:role,salary:salary,allowance:allow});
      save(); log('Added staff', name); toast('Staff member added.'); render();
    };
    document.querySelectorAll('[data-staff-pay]').forEach(function(b){ b.onclick=function(){
      var id=b.getAttribute('data-staff-pay'), st=DATA.staff.filter(function(x){return x.id===id;})[0]; if(!st) return;
      var t=term(); if(!t){ toast('No active term set.'); return; }
      var def=b.getAttribute('data-amt')||((+st.salary||0)+(+st.allowance||0));
      var amtStr=prompt('Amount paid to '+st.name, def); if(amtStr===null) return;
      var amt=+amtStr||0; if(amt<=0){ toast('Enter an amount.'); return; }
      var date=prompt('Date (YYYY-MM-DD)', today()); if(date===null) return;
      DATA.ledger.push({id:uid(),sc:CUR_SID,tid:t.id,type:'expense',title:'Salary — '+st.name+(st.role?' ('+st.role+')':''),amount:amt,date:date||today(),by:actorName(),ts:Date.now(),voided:false,staffId:st.id});
      save(); log('Paid staff salary', st.name+' — '+money(amt)); toast('Payment recorded.'); render();
    }; });
    document.querySelectorAll('[data-staff-void]').forEach(function(b){ b.onclick=function(){
      var id=b.getAttribute('data-staff-void'), t=term(); if(!t) return;
      var lp=lastStaffPayment(id,t.id); if(!lp) return;
      if(!confirm('Void this salary payment?')) return;
      lp.voided=true; save(); log('Voided salary payment', lp.title); render();
    }; });
    document.querySelectorAll('[data-staff-rm]').forEach(function(b){ b.onclick=function(){
      var id=b.getAttribute('data-staff-rm'), st=DATA.staff.filter(function(x){return x.id===id;})[0]; if(!st) return;
      if(!confirm('Remove '+st.name+' from staff?')) return;
      st.active=false; save(); log('Removed staff', st.name); render();
    }; });
    var actAdd=$('actAdd'); if(actAdd) actAdd.onclick=function(){
      var title=$('actTitle').value.trim(); if(!title){ toast('Enter a title.'); return; }
      var fees={}; document.querySelectorAll('[data-actfee]').forEach(function(inp){ fees[inp.getAttribute('data-actfee')]=+inp.value||0; });
      DATA.activities.push({id:uid(),sc:CUR_SID,active:true,created:Date.now(),title:title,fees:fees});
      save(); log('Added activity', title); toast('Activity created.'); render();
    };
    document.querySelectorAll('[data-act-pay]').forEach(function(b){ b.onclick=function(){
      var actId=b.getAttribute('data-act-pay'), act=DATA.activities.filter(function(a){return a.id===actId;})[0]; if(!act) return;
      var q=prompt('Student name or pay code'); if(q===null) return; q=q.trim().toLowerCase(); if(!q){ toast('Enter a name or code.'); return; }
      var matches=studentsOf().filter(function(s){return s.active!==false && (s.code.toLowerCase()===q || s.name.toLowerCase().indexOf(q)>-1);});
      if(!matches.length){ toast('No matching student found.'); return; }
      var s=matches[0];
      if(matches.length>1 && matches.filter(function(m){return m.code.toLowerCase()===q;}).length){ s=matches.filter(function(m){return m.code.toLowerCase()===q;})[0]; }
      else if(matches.length>1){ toast(matches.length+' students match — try their exact pay code instead.'); return; }
      var bal=Math.max(0, actFeeFor(act,s)-actPaidFor(act,s));
      var amtStr=prompt('Amount paid by '+s.name+' (balance '+money(bal)+')', bal||''); if(amtStr===null) return;
      var amt=+amtStr||0; if(amt<=0){ toast('Enter an amount.'); return; }
      var date=prompt('Date (YYYY-MM-DD)', today()); if(date===null) return;
      DATA.actPayments.push({id:uid(),sc:CUR_SID,actId:act.id,sid:s.id,amount:amt,date:date||today(),ts:Date.now(),by:actorName(),voided:false});
      save(); log('Recorded activity payment', act.title+' — '+s.name+' — '+money(amt), s.id); toast('Payment recorded.'); render();
    }; });
    document.querySelectorAll('[data-act-view]').forEach(function(b){ b.onclick=function(){ showActivityBreakdown(b.getAttribute('data-act-view')); }; });
    document.querySelectorAll('[data-act-rm]').forEach(function(b){ b.onclick=function(){
      var id=b.getAttribute('data-act-rm'), act=DATA.activities.filter(function(a){return a.id===id;})[0]; if(!act) return;
      if(!confirm('Delete "'+act.title+'"? Recorded payments are kept but will no longer be shown.')) return;
      act.active=false; save(); log('Removed activity', act.title); render();
    }; });
  }

  if(route==='reports'){
    var genReport=$('genReport'); if(genReport) genReport.onclick=showTermReport;
    var genFinReport=$('genFinReport'); if(genFinReport) genFinReport.onclick=showFinanceReport;
  }

  if(route==='settings'){
    if(!isInspector()){
      var setStyleGo=$('setStyleGo'); if(setStyleGo) setStyleGo.onclick=function(){ DATA.settings.style=$('setStyle').value; save(); render(); toast('Style applied.'); };
      var setCCGo=$('setCCGo'); if(setCCGo) setCCGo.onclick=function(){
        var cc=$('setCC').value.replace(/[^0-9]/g,''); if(!cc){ toast('Enter a country code.'); return; }
        DATA.settings.countryCode=cc; save(); toast('Saved.');
      };
      var tSave=$('tSave'); if(tSave) tSave.onclick=function(){
        var t=term(); if(!t) return; t.no=+$('tNo').value||t.no; t.yr=+$('tYr').value||t.yr; t.start=$('tStart').value; t.visit=$('tVisit').value; t.end=$('tEnd').value;
        save(); toast('Term dates saved.'); render();
      };
      var setNewTerm=$('setNewTerm'); if(setNewTerm) setNewTerm.onclick=function(){
        var s=school(), t=term(); if(!s||!t) return;
        if(!confirm('Start a new term? Current balances are kept as history.')) return;
        var nt={id:'t'+Date.now().toString(36),yr:t.no>=3?t.yr+1:t.yr,no:t.no>=3?1:t.no+1,start:'',visit:'',end:''};
        s.terms=s.terms||[]; s.terms.push(nt); s.cur=nt.id; s.counter=0;
        if($('setPromote').checked){ var cls=classesOf(s); studentsOf().forEach(function(st){ var i=cls.indexOf(st.cls); if(i>=0 && i<cls.length-1) st.cls=cls[i+1]; }); }
        chargeAllForTerm(s, nt.id);
        save(); log('Started new term','Term '+nt.no+', '+nt.yr); toast('New term started.'); render();
      };
      var feeSave=$('feeSave'); if(feeSave) feeSave.onclick=function(){
        var s=school(); s.fees=s.fees||{};
        document.querySelectorAll('[data-fee]').forEach(function(inp){ s.fees[inp.getAttribute('data-fee')]=+inp.value||0; });
        chargeAllForTerm(s, s.cur); save(); toast('Fees saved and applied.'); render();
      };
      var setPwGo=$('setPwGo'); if(setPwGo) setPwGo.onclick=async function(){
        var oldp=$('setOld').value, np=$('setNew').value;
        var target = isAdmin() ? DATA.admin : currentBursar();
        if(!target) return;
        var h=await hashPin(oldp, target.salt);
        if(h!==target.pinHash){ toast('Current password is wrong.'); return; }
        if(weakPassword(np)){ toast('Choose a stronger password.'); return; }
        var salt=randSalt(); target.pinHash=await hashPin(np,salt); target.salt=salt; save(); toast('Password changed.');
      };
    }
    var setModeGo=$('setModeGo'); if(setModeGo) setModeGo.onclick=function(){ if(!DATA.settings.look) DATA.settings.look={}; DATA.settings.look.mode=$('setMode').value; save(); render(); toast('Theme applied.'); };
    var setAdContactGo=$('setAdContactGo'); if(setAdContactGo) setAdContactGo.onclick=function(){
      DATA.admin.phone=$('setAdPhone').value.trim(); DATA.admin.email=$('setAdEmail').value.trim();
      save(); toast('Contact info saved.'); render();
    };
    var setBkDown=$('setBkDown'); if(setBkDown) setBkDown.onclick=downloadBackup;
    var setBkUpBtn=$('setBkUpBtn'); if(setBkUpBtn) setBkUpBtn.onclick=function(){ $('setBkFile').click(); };
    var setBkFile=$('setBkFile'); if(setBkFile) setBkFile.onchange=function(){ if(setBkFile.files[0]) importBackup(setBkFile.files[0]); };
    var setLogout=$('setLogout'); if(setLogout) setLogout.onclick=doLogout;
    var setForget=$('setForget'); if(setForget) setForget.onchange=function(){ if(setForget.checked){ DATA.remember=null; save(); toast('This device will not be remembered.'); } };
  }

  if(route==='notifications'){
    document.querySelectorAll('[data-note]').forEach(function(el){ el.onclick=function(){ openNotification(el.getAttribute('data-note')); }; });
  }
}

function doLogout(){ DATA.session=null; save(); go('landing'); }

/* --------------------------------------------------------------- receipt */
function showReceipt(p){
  var s=student(p.sid)||{}, sc=school(), t=(sc.terms||[]).filter(function(x){return x.id===p.tid;})[0]||{};
  var row=function(a,b){ return '<div class="it"><span class="mu">'+a+'</span><b>'+b+'</b></div>'; };
  var plain=esc2(sc.name)+' — fee receipt '+esc2(p.receipt)+'\n'+'Student: '+esc2(s.name)+' ('+esc2(s.cls)+' '+esc2(s.kind)+')\n'+
    'Term '+(t.no||'')+', '+(t.yr||'')+'\nDate: '+esc2(p.date)+'\nAmount paid: '+money(p.amt);
  var o=document.createElement('div'); o.className='ov';
  o.innerHTML='<div class="rc"><div class="wm"><span>'+esc(sc.name)+'</span></div>'+
    '<h3>'+esc(sc.name)+'</h3><div class="mu" style="text-align:center">Fee receipt</div><div class="big">'+esc(p.receipt)+'</div>'+
    row('Student',esc(s.name)+' ('+esc(s.cls)+' '+esc(s.kind)+')')+row('Pay code',esc(s.code))+
    row('Term','Term '+(t.no||'')+', '+(t.yr||''))+row('Date',esc(p.date))+row('Method',esc(p.method))+
    row('Reference',esc(p.ref||'-'))+row('Recorded by',esc(p.by||''))+row('Amount paid','<span class="ok">'+money(p.amt)+'</span>')+
    (p.status==='void'?'<div class="al">Voided: '+esc(p.reason||'')+'</div>':'')+
    '<div class="noprint" style="margin-top:12px"><button class="pri" id="rcPrint">Print / Export as PDF</button> '+
    (s.gp?('<a class="btn" target="_blank" href="https://wa.me/'+encodeURIComponent(toIntlPhone(s.gp))+'?text='+encodeURIComponent(plain)+'">WhatsApp guardian</a> '+
      '<a class="btn" href="sms:'+esc(s.gp)+'?body='+encodeURIComponent(plain)+'">SMS guardian</a> ')
      : '')+
    '<button id="rcClose">Close</button></div></div>';
  document.body.appendChild(o);
  $('rcClose').onclick=function(){ document.body.removeChild(o); };
  $('rcPrint').onclick=function(){ window.print(); };
}

/* ------------------------------------------------------------------ boot */
window.onerror = function(msg){
  var root=document.getElementById('root');
  if(root && !root.innerHTML) root.innerHTML = '<div class="ctr"><div class="card"><b>Could not start the app.</b>'+
    '<p class="mu">Your browser likely blocked local storage for this page (common when a file is opened through an editor\'s built-in preview). Try opening index.html directly in a full browser like Chrome or Firefox instead of an editor\'s preview pane.</p>'+
    '<p class="mu" style="word-break:break-all">Technical detail: '+String(msg)+'</p></div></div>';
};
window.App = { go: go, logout: doLogout, testNote: function(title,body,admin){ note(CUR_SID,title,body,admin); save(); } };
load();
render();
// Only register a service worker when actually hosted (http/https) — on a
// file:// page (e.g. the combined single-file build) this is unsupported and
// browsers reject it outright, so it's skipped there rather than erroring.
if('serviceWorker' in navigator && /^https?:$/.test(location.protocol)){
  window.addEventListener('load', function(){
    navigator.serviceWorker.register('sw.js').catch(function(){ /* offline support just won't be available */ });
  });
}

})();
