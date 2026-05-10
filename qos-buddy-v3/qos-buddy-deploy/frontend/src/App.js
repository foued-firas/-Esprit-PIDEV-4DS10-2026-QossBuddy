import React, { useState, useEffect, useCallback, useRef } from 'react';

const API = 'http://localhost:8000/api';

const rCol = s => s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 30 ? '#f59e0b' : '#10b981';
const rLabel = s => s >= 80 ? 'Critical — Your connection is severely degraded'
  : s >= 60 ? 'High Risk — Your connection needs attention'
  : s >= 30 ? 'Moderate — Connection is acceptable but unstable'
  : 'Excellent — Your connection is performing well';
const decLabel = d => ({ IMMEDIATE: '⚠️ Act immediately', URGENT: '🔶 Act as soon as possible', ROUTINE: '🔷 Monitor closely', NONE: '✅ No action needed right now' }[d] || d);
const latCol  = v => v < 100 ? '#10b981' : v < 200 ? '#f59e0b' : '#ef4444';
const losCol  = v => v === 0 ? '#10b981' : v < 1 ? '#f59e0b' : '#ef4444';
const mosCol  = v => v >= 4 ? '#10b981' : v >= 3.6 ? '#f59e0b' : '#ef4444';
const secMap  = {
  CLEAN:    { cls: 'ok',   label: '✅ Network is secure',           hint: 'No threats detected on your network.' },
  LOW:      { cls: 'warn', label: '⚠️ Low security risk',           hint: 'Minor suspicious activity detected.' },
  MEDIUM:   { cls: 'warn', label: '⚠️ Moderate threat detected',    hint: 'Unusual traffic patterns observed.' },
  HIGH:     { cls: 'bad',  label: '🚨 High threat detected',         hint: 'Significant network attack in progress.' },
  CRITICAL: { cls: 'crit', label: '🔴 CRITICAL — Disconnect now!',  hint: 'Severe attack detected. Disconnect immediately.' },
};
const fmtUptime = s => { if (!s) return '0s'; if (s < 60) return s+'s'; if (s < 3600) return Math.floor(s/60)+'m '+(s%60)+'s'; return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m'; };

const friendlyAction = action => {
  const a = (action||'').toLowerCase();
  if (a.includes('redemarr')||a.includes('restart')||a.includes('router')) return 'Restart your router — unplug it for 30 seconds, then plug it back in.';
  if (a.includes('fai')||a.includes('isp')||a.includes('provider')) return 'Call your internet provider — the issue may be on their end.';
  if (a.includes('cable')||a.includes('fil')) return 'Check your cables — make sure all network cables are firmly connected.';
  if (a.includes('canal')||a.includes('channel')||a.includes('frequen')) return 'Switch Wi-Fi channel — too many devices on the same channel can slow you down.';
  if (a.includes('5ghz')||a.includes('5 ghz')) return 'Switch to 5 GHz Wi-Fi — it is faster and less congested.';
  if (a.includes('rapproch')||a.includes('closer')||a.includes('signal')) return 'Move closer to your router — a stronger signal means better performance.';
  if (a.includes('secu')||a.includes('attack')||a.includes('threat')) return 'A security threat was detected — disconnect from this network immediately.';
  if (a.includes('bandwid')||a.includes('bande')) return 'Reduce bandwidth usage — pause downloads or streaming while on a video call.';
  if (a.includes('surveil')||a.includes('monitor')||a.includes('watch')) return 'Keep an eye on your connection — no action needed yet, but things may change.';
  return action;
};

const friendlyFeature = f => {
  const m = { latency_ms:'Response time (ms)', mean_latency_ms:'Average response time', packet_loss_rate_pct:'Packets lost (%)', jitter_ms:'Connection instability', throughput_mbps:'Download speed (Mbps)', mos_proxy:'Call quality score', risk_score:'Computed risk score', instability_score:'Network instability', bandwidth_utilization_pct:'Bandwidth in use', network_load:'Network load level', rsrp_estimated:'Signal strength', sinr_estimated:'Signal-to-noise ratio', latency_trend:'Latency trend (rising/falling)', spike:'Sudden latency spike', congestion_level:'Network congestion' };
  return m[f] || f.replace(/_/g,' ');
};

const AUTH_KEY = 'qosbuddy_user';
const getUser = () => { try { return JSON.parse(localStorage.getItem(AUTH_KEY)); } catch { return null; } };
const saveUser = u => localStorage.setItem(AUTH_KEY, JSON.stringify(u));
const clearUser = () => localStorage.removeItem(AUTH_KEY);
const getUsers = () => { try { return JSON.parse(localStorage.getItem('qosbuddy_users')) || {}; } catch { return {}; } };
const saveUsers = u => localStorage.setItem('qosbuddy_users', JSON.stringify(u));

function LogoSVG({ size=36 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="36" y2="36"><stop stopColor="#3b82f6"/><stop offset="1" stopColor="#6366f1"/></linearGradient></defs>
      <rect width="36" height="36" rx="10" fill="url(#lg)"/>
      <circle cx="18" cy="18" r="9" stroke="white" strokeWidth="2" fill="none"/>
      <circle cx="18" cy="18" r="3" fill="white"/>
      <line x1="18" y1="6" x2="18" y2="9" stroke="white" strokeWidth="2" strokeLinecap="round"/>
      <line x1="18" y1="27" x2="18" y2="30" stroke="white" strokeWidth="2" strokeLinecap="round"/>
      <line x1="6" y1="18" x2="9" y2="18" stroke="white" strokeWidth="2" strokeLinecap="round"/>
      <line x1="27" y1="18" x2="30" y2="18" stroke="white" strokeWidth="2" strokeLinecap="round"/>
    </svg>
  );
}

function Panel({ title, children, full }) {
  return (
    <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:16, padding:20, gridColumn: full ? '1/-1' : undefined }}>
      <div style={{ fontSize:11, fontWeight:800, color:'#475569', textTransform:'uppercase', letterSpacing:'.08em', marginBottom:14 }}>{title}</div>
      {children}
    </div>
  );
}

function Btn({ label, gradient, plain, disabled, onClick }) {
  return (
    <button onClick={onClick} disabled={disabled}
      style={{ padding:'11px 20px', borderRadius:11, border: plain?'1px solid #1e2d45':'none', background: plain?'#141d2e':gradient, color: plain?'#94a3b8':'#fff', fontSize:13, fontWeight:700, cursor: disabled?'not-allowed':'pointer', opacity: disabled?.45:1, transition:'transform .15s,opacity .2s', fontFamily:'inherit' }}
      onMouseOver={e=>!disabled&&(e.currentTarget.style.transform='translateY(-2px)')}
      onMouseOut={e=>(e.currentTarget.style.transform='')}>
      {label}
    </button>
  );
}

function MiniChart({ data, field, label, color, maxY }) {
  const vals = data.map(d=>d[field]);
  const max = maxY||Math.max(...vals,1);
  const W=400, H=60, n=vals.length;
  const pts = vals.map((v,i)=>`${(i/(n-1||1))*W},${H-(v/max)*H}`).join(' ');
  const cur = vals[vals.length-1]?.toFixed(1)||'0';
  return (
    <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:14, padding:20, marginBottom:12 }}>
      <div style={{ fontSize:11, fontWeight:700, color:'#64748b', marginBottom:10 }}>{label}</div>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width:'100%', height:70, display:'block', overflow:'visible' }}>
        <polyline points={pts} fill="none" stroke={color} strokeWidth="2"/>
        {vals.map((v,i)=><circle key={i} cx={(i/(n-1||1))*W} cy={H-(v/max)*H} r="3" fill={color}/>)}
      </svg>
      <div style={{ display:'flex', justifyContent:'space-between', fontSize:10, color:'#64748b', marginTop:4 }}>
        <span>{data[0]?.t}</span>
        <span style={{ color, fontWeight:700 }}>Current: {cur}</span>
        <span>{data[data.length-1]?.t}</span>
      </div>
    </div>
  );
}

function AuthWall({ view, setView, form, setForm, error, onLogin, onRegister }) {
  return (
    <div style={{ minHeight:'100vh', background:'#080c14', display:'flex', alignItems:'center', justifyContent:'center', padding:24, fontFamily:'"DM Sans",system-ui,sans-serif' }}>
      <div style={{ width:'100%', maxWidth:440 }}>
        <div style={{ textAlign:'center', marginBottom:40 }}>
          <div style={{ display:'inline-flex', alignItems:'center', gap:12, marginBottom:24 }}>
            <LogoSVG size={42}/>
            <div>
              <div style={{ fontSize:22, fontWeight:900, color:'#e2e8f0' }}>QoS Buddy</div>
              <div style={{ fontSize:11, color:'#64748b' }}>by MindForge</div>
            </div>
          </div>
          <h2 style={{ fontSize:28, fontWeight:900, color:'#e2e8f0', marginBottom:8 }}>{view==='login'?'Welcome back':'Create your account'}</h2>
          <p style={{ color:'#64748b', fontSize:14 }}>{view==='login'?'Sign in to access your network dashboard':'Start monitoring your network for free'}</p>
        </div>
        <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20, padding:32 }}>
          {view==='register'&&(
            <div style={{ marginBottom:16 }}>
              <label style={{ fontSize:13, fontWeight:700, color:'#94a3b8', display:'block', marginBottom:8 }}>Full Name</label>
              <input value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder="John Doe"
                style={{ width:'100%', background:'#0f1623', border:'1px solid #1e2d45', borderRadius:10, padding:'12px 16px', color:'#e2e8f0', fontSize:14, outline:'none', fontFamily:'inherit' }}/>
            </div>
          )}
          <div style={{ marginBottom:16 }}>
            <label style={{ fontSize:13, fontWeight:700, color:'#94a3b8', display:'block', marginBottom:8 }}>Email Address</label>
            <input type="email" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} placeholder="you@example.com"
              style={{ width:'100%', background:'#0f1623', border:'1px solid #1e2d45', borderRadius:10, padding:'12px 16px', color:'#e2e8f0', fontSize:14, outline:'none', fontFamily:'inherit' }}/>
          </div>
          <div style={{ marginBottom:24 }}>
            <label style={{ fontSize:13, fontWeight:700, color:'#94a3b8', display:'block', marginBottom:8 }}>Password</label>
            <input type="password" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))} placeholder="••••••••"
              onKeyDown={e=>e.key==='Enter'&&(view==='login'?onLogin():onRegister())}
              style={{ width:'100%', background:'#0f1623', border:'1px solid #1e2d45', borderRadius:10, padding:'12px 16px', color:'#e2e8f0', fontSize:14, outline:'none', fontFamily:'inherit' }}/>
          </div>
          {error&&<div style={{ background:'rgba(239,68,68,.08)', border:'1px solid #ef4444', borderRadius:10, padding:'10px 14px', color:'#ef4444', fontSize:13, marginBottom:18 }}>⚠️ {error}</div>}
          <button onClick={view==='login'?onLogin:onRegister}
            style={{ width:'100%', padding:13, borderRadius:12, border:'none', background:'linear-gradient(135deg,#3b82f6,#6366f1)', color:'#fff', fontSize:15, fontWeight:800, cursor:'pointer', boxShadow:'0 4px 20px rgba(59,130,246,.3)', fontFamily:'inherit' }}>
            {view==='login'?'Sign In':'Create Account'}
          </button>
          <p style={{ textAlign:'center', fontSize:13, color:'#64748b', marginTop:20 }}>
            {view==='login'?"Don't have an account? ":"Already have an account? "}
            <span onClick={()=>setView(view==='login'?'register':'login')} style={{ color:'#93c5fd', cursor:'pointer', fontWeight:700 }}>
              {view==='login'?'Sign up free':'Sign in'}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser]             = useState(getUser);
  const [authView, setAuthView]     = useState('login');
  const [authForm, setAuthForm]     = useState({ email:'', password:'', name:'' });
  const [authError, setAuthError]   = useState('');
  const [tab, setTab]               = useState('home');
  const [status, setStatus]         = useState(null);
  const [data, setData]             = useState(null);
  const [isOnline, setIsOnline]     = useState(true);
  const [wasOnline, setWasOnline]   = useState(true);
  const [offlineBanner, setOfflineBanner] = useState(false);
  const [disconnectAlert, setDisconnectAlert] = useState(false);
  const [speedtest, setSpeedtest]   = useState(null);
  const [stRunning, setStRunning]   = useState(false);
  const [history, setHistory]       = useState([]);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError, setPdfError]     = useState('');
  const loopRef   = useRef(null);
  const stPollRef = useRef(null);

  const handleRegister = () => {
    setAuthError('');
    if (!authForm.name.trim()) return setAuthError('Please enter your full name.');
    if (!authForm.email.includes('@')) return setAuthError('Please enter a valid email address.');
    if (authForm.password.length < 6) return setAuthError('Password must be at least 6 characters.');
    const users = getUsers();
    if (users[authForm.email]) return setAuthError('This email is already registered. Please log in.');
    const newUser = { name:authForm.name, email:authForm.email, password:authForm.password, joinedAt:new Date().toLocaleDateString() };
    users[authForm.email] = newUser; saveUsers(users); saveUser(newUser); setUser(newUser);
  };
  const handleLogin = () => {
    setAuthError('');
    const users = getUsers(); const found = users[authForm.email];
    if (!found) return setAuthError('No account found with this email.');
    if (found.password !== authForm.password) return setAuthError('Incorrect password.');
    saveUser(found); setUser(found);
  };
  const handleLogout = () => { clearUser(); setUser(null); setTab('home'); };

  const fetchAll = useCallback(async () => {
    try {
      const [sRes, dRes] = await Promise.all([fetch(`${API}/status`), fetch(`${API}/data`)]);
      if (!sRes.ok) throw new Error('down');
      const s = await sRes.json(); const d = await dRes.json();
      setStatus(s); setData(d);
      const online = s.is_online !== false;
      if (!online && wasOnline) setOfflineBanner(true);
      if (online && !wasOnline) setOfflineBanner(false);
      setIsOnline(online); setWasOnline(online);
      if (d.ready) {
        if ((d.risk_score||0) >= 80 || d.security?.status === 'CRITICAL' || d.security?.status === 'HIGH') setDisconnectAlert(true);
        setHistory(prev => {
          const next = [...prev, { t:new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'}), lat:d.kpis?.latency_ms||0, loss:d.kpis?.packet_loss_pct||0, thr:d.kpis?.throughput_mbps||0, risk:d.risk_score||0 }];
          return next.slice(-30);
        });
      }
    } catch { setIsOnline(false); setOfflineBanner(true); setWasOnline(false); }
  }, [wasOnline]);

  useEffect(() => { fetchAll(); loopRef.current = setInterval(fetchAll, 5000); return () => clearInterval(loopRef.current); }, [fetchAll]);

  useEffect(() => {
    if (stRunning) { stPollRef.current = setInterval(async () => { try { const r = await fetch(`${API}/speedtest/result`); const j = await r.json(); setStRunning(j.running); if (!j.running && j.result) setSpeedtest(j.result); } catch {} }, 2000); }
    else clearInterval(stPollRef.current);
    return () => clearInterval(stPollRef.current);
  }, [stRunning]);

  const startPipeline = async mode => { try { const r = await fetch(`${API}/start/${mode}`); const j = await r.json(); if (j.error) alert(j.error); else setTimeout(fetchAll,1500); } catch { alert('Cannot reach Flask server on port 8000.'); } };
  const stopPipeline  = async () => { try { await fetch(`${API}/stop`); setTimeout(fetchAll,1500); } catch {} };
  const downloadPdf   = async () => {
    setPdfLoading(true); setPdfError('');
    try {
      const r = await fetch(`${API}/pdf`);
      if (!r.ok) { const j = await r.json().catch(()=>({})); setPdfError(j.error||'Could not generate report. Run the pipeline for at least 30 seconds first.'); return; }
      const blob = await r.blob(); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href=url; a.download='qos_buddy_report.pdf'; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    } catch(e) { setPdfError('Network error: '+e.message); } finally { setPdfLoading(false); }
  };
  const runSpeedtest = async () => {
    if (!isOnline) { alert('No internet connection available.'); return; }
    try { const r = await fetch(`${API}/speedtest/run`,{method:'POST'}); const j = await r.json(); if (j.error) alert(j.error); else setStRunning(true); } catch { alert('Cannot reach the server.'); }
  };

  const running = status?.pipeline_running;
  const rs  = data?.risk_score || 0;
  const col = rCol(rs);
  const kpi = data?.kpis || {};
  const topOffset = (offlineBanner ? 44 : 0) + (disconnectAlert ? 50 : 0);

  if (!user) return <AuthWall view={authView} setView={setAuthView} form={authForm} setForm={setAuthForm} error={authError} onLogin={handleLogin} onRegister={handleRegister}/>;

  return (
    <div style={{ background:'#080c14', minHeight:'100vh', color:'#e2e8f0', fontFamily:'"DM Sans",system-ui,sans-serif' }}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}@keyframes spin{to{transform:rotate(360deg)}}@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}`}</style>

      {offlineBanner&&(
        <div style={{ position:'fixed', top:0, left:0, right:0, zIndex:9999, background:'#7f1d1d', color:'#fca5a5', padding:'12px 24px', display:'flex', justifyContent:'space-between', alignItems:'center', borderBottom:'2px solid #ef4444', fontSize:14, fontWeight:700 }}>
          <span>⚠️ &nbsp; YOU ARE OFFLINE — Wi-Fi disconnected. Data is no longer updating.</span>
          <button onClick={()=>setOfflineBanner(false)} style={{ background:'none', border:'1px solid #ef4444', color:'#fca5a5', borderRadius:6, padding:'4px 12px', cursor:'pointer' }}>✕</button>
        </div>
      )}

      {disconnectAlert&&(
        <div style={{ position:'fixed', top: offlineBanner?44:0, left:0, right:0, zIndex:9998, background:'linear-gradient(135deg,#7f1d1d,#991b1b)', color:'#fff', padding:'14px 24px', display:'flex', justifyContent:'space-between', alignItems:'center', borderBottom:'3px solid #ef4444', fontSize:14, fontWeight:800, boxShadow:'0 4px 30px rgba(239,68,68,.4)' }}>
          <span>🔴 &nbsp; HIGH RISK DETECTED — We strongly recommend disconnecting from this network immediately.</span>
          <button onClick={()=>setDisconnectAlert(false)} style={{ background:'rgba(255,255,255,.15)', border:'1px solid rgba(255,255,255,.3)', color:'#fff', borderRadius:8, padding:'5px 14px', cursor:'pointer', fontWeight:700, fontFamily:'inherit' }}>Dismiss</button>
        </div>
      )}

      <nav style={{ position:'fixed', top:topOffset, left:0, right:0, zIndex:100, background:'rgba(8,12,20,.95)', backdropFilter:'blur(20px)', borderBottom:'1px solid #1e2d45', display:'flex', alignItems:'center', justifyContent:'space-between', padding:'0 28px', height:60, transition:'top .3s' }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <LogoSVG/>
          <div>
            <div style={{ fontWeight:800, fontSize:16, letterSpacing:'-.02em' }}>QoS Buddy</div>
            <div style={{ fontSize:10, color:'#64748b' }}>by MindForge</div>
          </div>
        </div>
        <div style={{ display:'flex', gap:6 }}>
          {[['home','Home'],['dashboard','Dashboard'],['speedtest','Speed Test'],['history','History']].map(([id,label])=>(
            <button key={id} onClick={()=>setTab(id)} style={{ background:tab===id?'rgba(59,130,246,.12)':'transparent', border:tab===id?'1px solid rgba(59,130,246,.3)':'1px solid transparent', color:tab===id?'#93c5fd':'#64748b', borderRadius:8, padding:'6px 14px', cursor:'pointer', fontSize:13, fontWeight:tab===id?700:400, transition:'all .2s', fontFamily:'inherit' }}>
              {label}
            </button>
          ))}
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20, padding:'5px 14px', fontSize:12, display:'flex', alignItems:'center', gap:7 }}>
            <div style={{ width:7, height:7, borderRadius:'50%', background:!isOnline?'#ef4444':running?'#10b981':'#64748b', animation:running&&isOnline?'pulse 2s infinite':'none' }}/>
            <span style={{ color:!isOnline?'#ef4444':'#94a3b8' }}>{!isOnline?'Offline':running?`${status?.total_captures||0} readings`:'Idle'}</span>
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:8, background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20, padding:'5px 14px', cursor:'pointer' }} onClick={()=>setTab('account')}>
            <div style={{ width:26, height:26, borderRadius:'50%', background:'linear-gradient(135deg,#3b82f6,#6366f1)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:12, fontWeight:800, color:'#fff' }}>{user.name[0].toUpperCase()}</div>
            <span style={{ fontSize:12, color:'#94a3b8' }}>{user.name.split(' ')[0]}</span>
          </div>
        </div>
      </nav>

      {/* HOME */}
      {tab==='home'&&(
        <div style={{ paddingTop: topOffset+60 }}>
          <section style={{ minHeight:'90vh', display:'flex', alignItems:'center', justifyContent:'center', textAlign:'center', padding:'80px 24px 60px', background:'radial-gradient(ellipse 80% 60% at 50% 0%,rgba(59,130,246,.12) 0%,transparent 70%)' }}>
            <div style={{ maxWidth:720, animation:'fadeIn .6s' }}>
              <div style={{ display:'inline-flex', alignItems:'center', gap:8, background:'rgba(59,130,246,.08)', border:'1px solid rgba(59,130,246,.2)', color:'#93c5fd', borderRadius:20, padding:'6px 18px', fontSize:12, fontWeight:700, letterSpacing:'.07em', marginBottom:28 }}>🛰️ Real-time AI Network Intelligence</div>
              <h1 style={{ fontSize:'clamp(44px,8vw,84px)', fontWeight:900, lineHeight:1.02, marginBottom:16, background:'linear-gradient(135deg,#fff 20%,#475569)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>
                Your Network,{' '}
                <span style={{ background:'linear-gradient(135deg,#3b82f6,#818cf8)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>Understood.</span>
              </h1>
              <p style={{ fontSize:'clamp(15px,2vw,19px)', color:'#94a3b8', lineHeight:1.7, marginBottom:38, maxWidth:580, margin:'0 auto 38px' }}>QoS Buddy uses 6 specialized AI agents to monitor your connection in real time — detecting problems before they happen and telling you exactly what to do about them, in plain English.</p>
              <div style={{ display:'flex', gap:14, justifyContent:'center', flexWrap:'wrap', marginBottom:56 }}>
                <button onClick={()=>setTab('dashboard')} style={{ padding:'14px 36px', borderRadius:14, border:'none', background:'linear-gradient(135deg,#3b82f6,#6366f1)', color:'#fff', fontSize:15, fontWeight:800, cursor:'pointer', boxShadow:'0 4px 24px rgba(59,130,246,.4)', fontFamily:'inherit' }}>Open Dashboard</button>
                <button onClick={()=>document.getElementById('how')?.scrollIntoView({behavior:'smooth'})} style={{ padding:'14px 36px', borderRadius:14, border:'1px solid #1e2d45', background:'transparent', color:'#94a3b8', fontSize:15, fontWeight:700, cursor:'pointer', fontFamily:'inherit' }}>How It Works</button>
              </div>
              <div style={{ display:'flex', justifyContent:'center', border:'1px solid #1e2d45', borderRadius:18, overflow:'hidden', maxWidth:580, margin:'0 auto' }}>
                {[['6','AI Agents'],[status?.total_captures||'—','Readings'],['< 8s','Update Rate'],['100%','Automated']].map(([v,l])=>(
                  <div key={l} style={{ flex:1, padding:'20px 16px', textAlign:'center', borderRight:'1px solid #1e2d45' }}>
                    <div style={{ fontSize:28, fontWeight:900 }}>{v}</div>
                    <div style={{ fontSize:11, color:'#64748b', marginTop:3 }}>{l}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section style={{ padding:'96px 24px', maxWidth:1100, margin:'0 auto' }}>
            <div style={{ textAlign:'center', marginBottom:56 }}>
              <div style={{ display:'inline-block', background:'rgba(99,102,241,.08)', border:'1px solid rgba(99,102,241,.25)', color:'#818cf8', borderRadius:20, padding:'4px 16px', fontSize:11, fontWeight:700, letterSpacing:'.07em', marginBottom:14 }}>WHY IT MATTERS</div>
              <h2 style={{ fontSize:'clamp(24px,4vw,44px)', fontWeight:900, marginBottom:14 }}>A bad connection costs more than you think</h2>
              <p style={{ color:'#94a3b8', fontSize:15, maxWidth:540, margin:'0 auto', lineHeight:1.7 }}>Network quality affects every aspect of your digital life. QoS Buddy gives you the visibility and intelligence to stay in control — before problems become visible.</p>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(240px,1fr))', gap:16 }}>
              {[
                ['📞','Crystal-clear calls','Poor latency and jitter ruin voice and video calls. Our AI detects degradation before your next meeting is interrupted.'],
                ['⚡','Early warning system','Instead of waiting for a crash, QoS Buddy warns you minutes before a problem becomes visible to you.'],
                ['🛡️','Network security shield','Port scans, DDoS attempts, and brute-force attacks are automatically identified and flagged in real time.'],
                ['🤖','Explainable AI decisions','Every alert comes with a plain-English explanation of exactly why it was triggered — no guesswork, no jargon.'],
                ['📊','Multi-horizon prediction','Know your risk level not just now, but 20 seconds, 1 minute, and 5 minutes into the future.'],
                ['📄','Automatic PDF report','A full session report is generated automatically at the end — ready to share with your IT team or archive.'],
              ].map(([icon,title,desc])=>(
                <div key={title} style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:18, padding:'26px 22px', transition:'border-color .3s,transform .3s', cursor:'default' }}
                  onMouseOver={e=>{e.currentTarget.style.borderColor='#3b82f6';e.currentTarget.style.transform='translateY(-4px)';}}
                  onMouseOut={e=>{e.currentTarget.style.borderColor='#1e2d45';e.currentTarget.style.transform='';}}>
                  <div style={{ fontSize:30, marginBottom:16 }}>{icon}</div>
                  <h3 style={{ fontSize:15, fontWeight:800, marginBottom:8 }}>{title}</h3>
                  <p style={{ fontSize:13, color:'#94a3b8', lineHeight:1.65 }}>{desc}</p>
                </div>
              ))}
            </div>
          </section>

          <section id="how" style={{ padding:'96px 24px', background:'#0f1623' }}>
            <div style={{ maxWidth:1100, margin:'0 auto' }}>
              <div style={{ textAlign:'center', marginBottom:56 }}>
                <div style={{ display:'inline-block', background:'rgba(59,130,246,.08)', border:'1px solid rgba(59,130,246,.2)', color:'#93c5fd', borderRadius:20, padding:'4px 16px', fontSize:11, fontWeight:700, letterSpacing:'.07em', marginBottom:14 }}>HOW IT WORKS</div>
                <h2 style={{ fontSize:'clamp(24px,4vw,44px)', fontWeight:900, marginBottom:14 }}>6 agents. 1 mission.</h2>
                <p style={{ color:'#94a3b8', fontSize:15, maxWidth:520, margin:'0 auto', lineHeight:1.7 }}>Each AI agent specializes in one task. Together they form a complete, self-organizing intelligence layer for your network.</p>
              </div>
              <div style={{ overflowX:'auto', paddingBottom:12 }}>
                <div style={{ display:'flex', gap:0, width:'max-content', margin:'0 auto' }}>
                  {[
                    {n:1,color:'#3b82f6',title:'Data Collector',desc:'Measures your network speed and quality every 8 seconds.',tech:'Autoencoder · Isolation Forest · SVM'},
                    {n:2,color:'#6366f1',title:'Network Classifier',desc:'Compares your readings to international standards (ITU-T/Cisco) and rates your connection.',tech:'Random Forest · Threshold rules'},
                    {n:3,color:'#10b981',title:'Risk Predictor',desc:'Analyzes trends to predict what will happen in the next few minutes.',tech:'XGBoost · LSTM neural network'},
                    {n:4,color:'#ef4444',title:'Threat Detector',desc:'Scans traffic patterns to identify attacks or suspicious behavior.',tech:'Anomaly detection · Rule engine'},
                    {n:5,color:'#f59e0b',title:'Action Advisor',desc:'Decides what you should do, ranked by urgency, in plain English.',tech:'Decision engine · Priority ranking'},
                    {n:6,color:'#8b5cf6',title:'Report Generator',desc:'Explains every decision transparently and creates your PDF report.',tech:'SHAP · Explainable AI (XAI)'},
                  ].map((a,i,arr)=>(
                    <React.Fragment key={a.n}>
                      <div style={{ background:'#141d2e', border:`1px solid ${a.color}44`, borderRadius:16, padding:'22px 18px', width:168, flexShrink:0, transition:'transform .2s', cursor:'default' }}
                        onMouseOver={e=>e.currentTarget.style.transform='translateY(-6px)'}
                        onMouseOut={e=>e.currentTarget.style.transform=''}>
                        <div style={{ width:30, height:30, borderRadius:'50%', background:a.color, display:'flex', alignItems:'center', justifyContent:'center', fontWeight:900, fontSize:14, color:'#fff', marginBottom:14 }}>{a.n}</div>
                        <div style={{ fontWeight:800, fontSize:13, marginBottom:8, color:'#e2e8f0', lineHeight:1.3 }}>{a.title}</div>
                        <div style={{ fontSize:12, color:'#94a3b8', lineHeight:1.55, marginBottom:12 }}>{a.desc}</div>
                        <div style={{ background:`${a.color}12`, border:`1px solid ${a.color}30`, borderRadius:6, padding:'4px 8px', fontSize:10, color:a.color, fontWeight:700 }}>{a.tech}</div>
                      </div>
                      {i<arr.length-1&&<div style={{ display:'flex', alignItems:'center', padding:'0 8px', color:'#1e2d45', fontSize:20, alignSelf:'center' }}>→</div>}
                    </React.Fragment>
                  ))}
                </div>
              </div>
              <p style={{ textAlign:'center', color:'#475569', fontSize:13, marginTop:24 }}>Results from each agent are passed to the next — building a complete, progressive analysis of your network.</p>
            </div>
          </section>

          <section style={{ padding:'96px 24px', maxWidth:900, margin:'0 auto', textAlign:'center' }}>
            <div style={{ display:'inline-block', background:'rgba(16,185,129,.08)', border:'1px solid rgba(16,185,129,.25)', color:'#34d399', borderRadius:20, padding:'4px 16px', fontSize:11, fontWeight:700, letterSpacing:'.07em', marginBottom:24 }}>WHAT IS QoS?</div>
            <h2 style={{ fontSize:'clamp(22px,4vw,40px)', fontWeight:900, marginBottom:20 }}>Quality of Service — the standard your network should meet</h2>
            <p style={{ color:'#94a3b8', fontSize:16, lineHeight:1.8, marginBottom:32 }}>Quality of Service (QoS) measures how well your network delivers data — not just speed, but <strong style={{ color:'#e2e8f0' }}>reliability, consistency, and responsiveness</strong>. A high-QoS connection means your calls never drop, your video never buffers, and your downloads never mysteriously stall.</p>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))', gap:14 }}>
              {[['< 100ms','Target latency','#10b981'],['0%','Ideal packet loss','#10b981'],['> 4.0','MOS call quality','#3b82f6'],['> 50 Mbps','Good download speed','#6366f1']].map(([v,l,c])=>(
                <div key={l} style={{ background:'#141d2e', border:`1px solid ${c}30`, borderRadius:14, padding:'20px 16px' }}>
                  <div style={{ fontSize:26, fontWeight:900, color:c, marginBottom:6 }}>{v}</div>
                  <div style={{ fontSize:12, color:'#64748b' }}>{l}</div>
                </div>
              ))}
            </div>
          </section>

          <footer style={{ borderTop:'1px solid #1e2d45', padding:'32px 24px', textAlign:'center', color:'#475569', fontSize:13 }}>
            <strong style={{ color:'#94a3b8' }}>QoS Buddy</strong> — built by <strong style={{ color:'#94a3b8' }}>MindForge</strong>
            <div style={{ marginTop:6, fontSize:11 }}>Artificial Intelligence · Network Monitoring · Explainable AI · Speedtest by Ookla</div>
          </footer>
        </div>
      )}

      {/* DASHBOARD */}
      {tab==='dashboard'&&(
        <div style={{ paddingTop:topOffset+60 }}>
          <div style={{ maxWidth:1100, margin:'0 auto', padding:'32px 24px 80px', animation:'fadeIn .4s' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:14, marginBottom:20 }}>
              <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:14, padding:'12px 18px', display:'flex', alignItems:'center', gap:10 }}>
                <span style={{ fontSize:22 }}>{isOnline?'📶':'📵'}</span>
                <div>
                  <div style={{ fontWeight:700, fontSize:14 }}>{status?.network_name||'Detecting...'}</div>
                  <div style={{ fontSize:11, marginTop:2, color:isOnline?'#10b981':'#ef4444' }}>{isOnline?'● Connected':'● Disconnected'}</div>
                </div>
              </div>
              <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
                <Btn label="▶ Demo Mode"       gradient="linear-gradient(135deg,#3b82f6,#6366f1)" disabled={running} onClick={()=>startPipeline('demo')}/>
                <Btn label="📡 Live Network"   gradient="linear-gradient(135deg,#10b981,#059669)" disabled={running} onClick={()=>startPipeline('run')}/>
                <Btn label="⏹ Stop"           gradient="linear-gradient(135deg,#ef4444,#b91c1c)" disabled={!running} onClick={stopPipeline}/>
                <Btn label={pdfLoading?'⏳ Generating...':'⬇ Download Report'} plain disabled={pdfLoading} onClick={downloadPdf}/>
              </div>
            </div>
            {pdfError&&<div style={{ background:'rgba(239,68,68,.08)', border:'1px solid #ef4444', borderRadius:10, padding:'10px 16px', color:'#ef4444', fontSize:13, marginBottom:14 }}>⚠️ {pdfError}</div>}
            <div style={{ display:'flex', gap:0, marginBottom:20, background:'#141d2e', border:'1px solid #1e2d45', borderRadius:16, overflow:'hidden' }}>
              {[['6','AI Agents'],[status?.total_captures||0,'Readings'],[status?.total_alerts||0,'Alerts'],[fmtUptime(status?.uptime_sec),'Uptime']].map(([v,l])=>(
                <div key={l} style={{ flex:1, padding:'14px 20px', textAlign:'center', borderRight:'1px solid #1e2d45' }}>
                  <div style={{ fontSize:22, fontWeight:900 }}>{v}</div>
                  <div style={{ fontSize:11, color:'#64748b', marginTop:2 }}>{l}</div>
                </div>
              ))}
            </div>
            {!running&&!data?.ready?(
              <div style={{ textAlign:'center', padding:'64px 24px', background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20 }}>
                <div style={{ width:44, height:44, borderRadius:'50%', border:'3px solid #1e2d45', borderTopColor:'#3b82f6', animation:'spin 1s linear infinite', margin:'0 auto 16px' }}/>
                <p style={{ color:'#64748b', fontSize:15 }}>Click <strong style={{ color:'#93c5fd' }}>Demo Mode</strong> to start monitoring your network</p>
              </div>
            ):data?.ready&&<LiveDashboard d={data} col={col} rs={rs} kpi={kpi}/>}
            <div style={{ textAlign:'right', fontSize:11, color:'#1e2d45', marginTop:10 }}>Last updated: {new Date().toLocaleTimeString()}</div>
          </div>
        </div>
      )}

      {/* SPEEDTEST */}
      {tab==='speedtest'&&(
        <div style={{ paddingTop:topOffset+60, maxWidth:860, margin:'0 auto', padding:`${topOffset+100}px 24px 80px`, animation:'fadeIn .4s' }}>
          <div style={{ textAlign:'center', marginBottom:48 }}>
            <div style={{ display:'inline-block', background:'rgba(99,102,241,.08)', border:'1px solid rgba(99,102,241,.25)', color:'#818cf8', borderRadius:20, padding:'4px 16px', fontSize:11, fontWeight:700, letterSpacing:'.07em', marginBottom:14 }}>SPEED TEST BY OOKLA</div>
            <h2 style={{ fontSize:'clamp(24px,4vw,42px)', fontWeight:900, marginBottom:12 }}>How fast is your connection?</h2>
            <p style={{ color:'#94a3b8', fontSize:15, lineHeight:1.7, maxWidth:460, margin:'0 auto' }}>Measure your real download speed, upload speed, and ping — powered by Ookla Speedtest servers worldwide.</p>
          </div>
          {!isOnline&&<div style={{ background:'rgba(239,68,68,.08)', border:'1px solid #ef4444', borderRadius:14, padding:24, textAlign:'center', marginBottom:24 }}><div style={{ fontSize:36, marginBottom:12 }}>📵</div><div style={{ color:'#ef4444', fontWeight:700 }}>No internet connection — speed test unavailable</div></div>}
          <div style={{ textAlign:'center', marginBottom:32 }}>
            <button onClick={runSpeedtest} disabled={stRunning||!isOnline} style={{ padding:'16px 52px', borderRadius:14, border:'none', background:stRunning||!isOnline?'#1e2d45':'linear-gradient(135deg,#3b82f6,#6366f1)', color:'#fff', fontSize:16, fontWeight:800, cursor:stRunning||!isOnline?'not-allowed':'pointer', opacity:stRunning||!isOnline?.5:1, boxShadow:!stRunning&&isOnline?'0 4px 24px rgba(59,130,246,.4)':'none', fontFamily:'inherit' }}>
              {stRunning?'⏳ Testing...':'⚡ Run Speed Test'}
            </button>
          </div>
          {stRunning&&<div style={{ textAlign:'center', padding:48, background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20, marginBottom:24 }}><div style={{ width:48, height:48, borderRadius:'50%', border:'3px solid #1e2d45', borderTopColor:'#3b82f6', animation:'spin 1s linear infinite', margin:'0 auto 16px' }}/><p style={{ color:'#64748b' }}>Running speed test... this may take 30–60 seconds</p></div>}
          {speedtest&&!stRunning&&(
            speedtest.error?(
              <div style={{ background:'rgba(239,68,68,.08)', border:'1px solid #ef4444', borderRadius:14, padding:24 }}><div style={{ color:'#ef4444', fontWeight:700 }}>⚠️ {speedtest.error}</div></div>
            ):(()=>{
              const isEst = speedtest.source?.includes('estimation');
              const dlCol = speedtest.download_mbps>50?'#10b981':speedtest.download_mbps>10?'#3b82f6':'#f59e0b';
              const ulCol = speedtest.upload_mbps>20?'#10b981':speedtest.upload_mbps>5?'#6366f1':'#f59e0b';
              const piCol = speedtest.ping_ms<50?'#10b981':speedtest.ping_ms<150?'#f59e0b':'#ef4444';
              return (
                <div>
                  {isEst&&<div style={{ background:'rgba(245,158,11,.08)', border:'1px solid #f59e0b', borderRadius:10, padding:'10px 16px', color:'#f59e0b', fontSize:13, marginBottom:16 }}>ℹ️ speedtest-cli not installed — values estimated from pipeline metrics. For real Ookla measurements: pip install speedtest-cli</div>}
                  <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:16, marginBottom:24 }}>
                    {[['⬇','Download',speedtest.download_mbps,'Mbps',dlCol],['⬆','Upload',speedtest.upload_mbps,'Mbps',ulCol],['🏓','Ping',speedtest.ping_ms,'ms',piCol]].map(([icon,lbl,val,unit,c])=>(
                      <div key={lbl} style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20, padding:'32px 24px', textAlign:'center' }}>
                        <div style={{ fontSize:34, marginBottom:10 }}>{icon}</div>
                        <div style={{ fontSize:38, fontWeight:900, color:c }}>{val}</div>
                        <div style={{ fontSize:13, color:'#94a3b8' }}>{unit}</div>
                        <div style={{ fontSize:12, color:'#64748b', marginTop:8 }}>{lbl}</div>
                      </div>
                    ))}
                  </div>
                  <Panel title="Test Details">
                    {[['Server',speedtest.server_name],['Country',speedtest.server_country],['ISP',speedtest.isp],['Source',speedtest.source],['Tested at',speedtest.timestamp]].filter(([,v])=>v).map(([k,v])=>(
                      <div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'7px 0', borderBottom:'1px solid rgba(255,255,255,.04)' }}>
                        <span style={{ fontSize:12, color:'#64748b' }}>{k}</span>
                        <span style={{ fontSize:12, fontWeight:700 }}>{v}</span>
                      </div>
                    ))}
                  </Panel>
                </div>
              );
            })()
          )}
        </div>
      )}

      {/* HISTORY */}
      {tab==='history'&&(
        <div style={{ paddingTop:topOffset+60, maxWidth:1100, margin:'0 auto', padding:`${topOffset+100}px 24px 80px`, animation:'fadeIn .4s' }}>
          <div style={{ textAlign:'center', marginBottom:48 }}>
            <div style={{ display:'inline-block', background:'rgba(99,102,241,.08)', border:'1px solid rgba(99,102,241,.25)', color:'#818cf8', borderRadius:20, padding:'4px 16px', fontSize:11, fontWeight:700, letterSpacing:'.07em', marginBottom:14 }}>HISTORY</div>
            <h2 style={{ fontSize:'clamp(24px,4vw,42px)', fontWeight:900, marginBottom:12 }}>Connection over time</h2>
            <p style={{ color:'#94a3b8', fontSize:14 }}>Last 30 measurements collected by the AI monitoring pipeline</p>
          </div>
          {history.length===0?(
            <div style={{ textAlign:'center', padding:60, background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20 }}><p style={{ color:'#64748b' }}>No data yet — start the pipeline in the Dashboard tab.</p></div>
          ):(
            <>
              {[['Risk Score','risk','#ef4444',100],['Response Time (ms)','lat','#f97316',null],['Download Speed (Mbps)','thr','#3b82f6',null]].map(([lbl,field,color,maxY])=>(
                <MiniChart key={field} data={history} field={field} label={lbl} color={color} maxY={maxY}/>
              ))}
              <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:14, overflow:'hidden', marginTop:16 }}>
                <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', padding:'12px 20px', borderBottom:'1px solid #1e2d45', fontSize:11, fontWeight:700, color:'#64748b' }}>
                  <span>TIME</span><span>RISK</span><span>LATENCY</span><span>LOSS</span><span>SPEED</span>
                </div>
                {[...history].reverse().map((h,i)=>(
                  <div key={i} style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', padding:'9px 20px', borderBottom:'1px solid rgba(255,255,255,.03)', fontSize:12 }}>
                    <span style={{ color:'#64748b' }}>{h.t}</span>
                    <span style={{ color:rCol(h.risk), fontWeight:700 }}>{Math.round(h.risk)}/100</span>
                    <span style={{ color:latCol(h.lat) }}>{h.lat.toFixed(1)} ms</span>
                    <span style={{ color:losCol(h.loss) }}>{h.loss.toFixed(2)}%</span>
                    <span style={{ color:'#3b82f6' }}>{h.thr.toFixed(1)} Mbps</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* ACCOUNT */}
      {tab==='account'&&(
        <div style={{ paddingTop:topOffset+60, maxWidth:560, margin:'0 auto', padding:`${topOffset+100}px 24px 80px`, animation:'fadeIn .4s' }}>
          <div style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:20, padding:32, textAlign:'center' }}>
            <div style={{ width:72, height:72, borderRadius:'50%', background:'linear-gradient(135deg,#3b82f6,#6366f1)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:28, fontWeight:900, color:'#fff', margin:'0 auto 20px' }}>{user.name[0].toUpperCase()}</div>
            <h2 style={{ fontSize:22, fontWeight:900, marginBottom:4 }}>{user.name}</h2>
            <p style={{ color:'#64748b', marginBottom:6 }}>{user.email}</p>
            <p style={{ color:'#475569', fontSize:12, marginBottom:28 }}>Member since {user.joinedAt}</p>
            <div style={{ display:'flex', flexDirection:'column', gap:12, marginBottom:28 }}>
              {[['Total readings this session',status?.total_captures||0,'#3b82f6'],['Alerts triggered',status?.total_alerts||0,'#ef4444'],['Network monitored',status?.network_name||'—','#e2e8f0']].map(([lbl,val,c])=>(
                <div key={lbl} style={{ background:'#0f1623', border:'1px solid #1e2d45', borderRadius:12, padding:'14px 20px', display:'flex', justifyContent:'space-between' }}>
                  <span style={{ color:'#64748b', fontSize:13 }}>{lbl}</span>
                  <span style={{ fontWeight:700, color:c }}>{val}</span>
                </div>
              ))}
            </div>
            <button onClick={handleLogout} style={{ width:'100%', padding:13, borderRadius:12, border:'1px solid #ef4444', background:'rgba(239,68,68,.08)', color:'#ef4444', cursor:'pointer', fontWeight:700, fontSize:14, fontFamily:'inherit' }}>Sign Out</button>
          </div>
        </div>
      )}

      {tab!=='home'&&(
        <footer style={{ borderTop:'1px solid #1e2d45', padding:'32px 24px', textAlign:'center', color:'#475569', fontSize:13 }}>
          <strong style={{ color:'#94a3b8' }}>QoS Buddy</strong> — built by <strong style={{ color:'#94a3b8' }}>MindForge</strong>
          <div style={{ marginTop:6, fontSize:11 }}>Artificial Intelligence · Network Monitoring · Explainable AI · Speedtest by Ookla</div>
        </footer>
      )}
    </div>
  );
}

function LiveDashboard({ d, col, rs, kpi }) {
  const sec    = d.security || {};
  const secSt  = sec.status || 'CLEAN';
  const secCfg = secMap[secSt] || secMap.CLEAN;
  const rfp    = Math.round((parseFloat(d.rf_confidence)||0)*100);
  const R=30, C=2*Math.PI*R, offset=C*(1-rs/100);
  const lat=parseFloat(kpi.latency_ms)||0, los=parseFloat(kpi.packet_loss_pct)||0;
  const thr=parseFloat(kpi.throughput_mbps)||0, mos=parseFloat(kpi.mos_proxy)||0;

  return (
    <div style={{ animation:'fadeIn .4s' }}>
      <div style={{ borderRadius:20, padding:'24px 26px', marginBottom:14, border:`1.5px solid ${col}`, background:`${col}08`, display:'flex', alignItems:'center', gap:24, flexWrap:'wrap' }}>
        <div style={{ position:'relative', width:80, height:80, flexShrink:0 }}>
          <svg width="80" height="80" viewBox="0 0 80 80" style={{ transform:'rotate(-90deg)' }}>
            <circle cx="40" cy="40" r={R} fill="none" stroke="rgba(255,255,255,.06)" strokeWidth="8"/>
            <circle cx="40" cy="40" r={R} fill="none" stroke={col} strokeWidth="8" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={offset} style={{ transition:'stroke-dashoffset .8s' }}/>
          </svg>
          <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', textAlign:'center' }}>
            <div style={{ fontSize:20, fontWeight:900, color:col }}>{Math.round(rs)}</div>
            <div style={{ fontSize:10, color:'#64748b' }}>/100</div>
          </div>
        </div>
        <div style={{ flex:1 }}>
          <div style={{ fontSize:19, fontWeight:900, color:col, marginBottom:5 }}>{rLabel(rs)}</div>
          <div style={{ fontSize:13, color:'#94a3b8', marginBottom:12 }}>{decLabel(d.decision_raw)}</div>
          <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
            <span style={{ background:'rgba(99,102,241,.1)', border:'1px solid rgba(99,102,241,.25)', color:'#818cf8', borderRadius:20, padding:'4px 14px', fontSize:12, fontWeight:700 }}>Detected: {d.rf_class} — {rfp}% confidence</span>
          </div>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:14 }}>
        {[[lat.toFixed(1),'ms','Response Time',latCol(lat),'Under 100ms is ideal. Above 200ms, you will notice lag on calls and games.'],[los.toFixed(2),'%','Packets Lost',losCol(los),'0% is perfect. Above 1%, calls and video streams will be affected.'],[thr.toFixed(1),'Mbps','Download Speed','#3b82f6','50+ Mbps is good for HD video calls. Higher means more headroom.'],[mos.toFixed(2),'/5','Call Quality',mosCol(mos),'Score above 4.0 means excellent call quality. Below 3.6 is noticeable.']].map(([v,unit,lbl,c,tip])=>(
          <div key={lbl} title={tip} style={{ background:'#141d2e', border:'1px solid #1e2d45', borderRadius:14, padding:'18px 14px', textAlign:'center', cursor:'help' }}>
            <div style={{ fontSize:22, fontWeight:900, color:c }}>{v}<small style={{ fontSize:12, fontWeight:400, color:'#64748b' }}> {unit}</small></div>
            <div style={{ fontSize:10, color:'#64748b', textTransform:'uppercase', letterSpacing:'.05em', marginTop:4 }}>{lbl}</div>
            <div style={{ height:3, borderRadius:2, background:c, marginTop:10, opacity:.6 }}/>
          </div>
        ))}
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginBottom:14 }}>
        <Panel title="Risk Prediction — What's coming?">
          {[20,60,300].map(h=>{
            const hd=(d.horizons||{})[h]||{}, sc=hd.score||0, c=rCol(sc);
            return (
              <div key={h} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
                <span style={{ fontSize:12, color:'#64748b', width:96, flexShrink:0 }}>{h===20?'In 20 seconds':h===60?'In 1 minute':'In 5 minutes'}</span>
                <div style={{ flex:1, height:6, background:'rgba(255,255,255,.05)', borderRadius:3, overflow:'hidden' }}><div style={{ height:'100%', width:`${sc}%`, background:c, borderRadius:3, transition:'width .6s' }}/></div>
                <span style={{ fontSize:12, fontWeight:700, color:c, width:52, textAlign:'right' }}>{Math.round(sc)}/100</span>
              </div>
            );
          })}
        </Panel>

        <Panel title="Security Status">
          <div style={{ fontSize:14, fontWeight:700, color:secCfg.cls==='ok'?'#34d399':secCfg.cls==='crit'?'#ef4444':'#f59e0b', marginBottom:8 }}>{secCfg.label}</div>
          <div style={{ fontSize:13, color:'#94a3b8', marginBottom:8 }}>{secCfg.hint}</div>
          <div style={{ fontSize:12, color:'#64748b' }}>{sec.n_events} event(s) detected</div>
          <div style={{ fontSize:12, color:'#475569', marginTop:4 }}>{(sec.attacks||[]).length?sec.attacks.join(' · '):'No known attack patterns detected.'}</div>
          {(secSt==='HIGH'||secSt==='CRITICAL')&&(
            <div style={{ marginTop:14, padding:'12px 16px', background:'rgba(239,68,68,.1)', border:'1px solid #ef4444', borderRadius:10, color:'#ef4444', fontSize:13, fontWeight:700 }}>
              🔴 Disconnect from this network as soon as possible — it poses a serious risk to your device and data.
            </div>
          )}
        </Panel>

        <Panel title="Connection Details">
          {[['Signal Strength',kpi.rsrp_category],['Critical Alerts',d.n_critical,d.n_critical>0?'#ef4444':'#10b981'],['Minor Warnings',d.n_warnings,d.n_warnings>0?'#f59e0b':'#10b981'],['Total Readings',d.total_captures,'#3b82f6'],['Total Alerts',d.total_alerts,'#ef4444']].map(([lbl,val,c])=>(
            <div key={lbl} style={{ display:'flex', justifyContent:'space-between', padding:'7px 0', borderBottom:'1px solid rgba(255,255,255,.04)' }}>
              <span style={{ fontSize:12, color:'#64748b' }}>{lbl}</span>
              <span style={{ fontSize:13, fontWeight:700, color:c||'#e2e8f0' }}>{val}</span>
            </div>
          ))}
        </Panel>

        <Panel title="What should you do?">
          {(d.actions||[]).length?d.actions.slice(0,5).map((a,i)=>{
            const p=a.priority||4;
            const pC={1:['rgba(239,68,68,.15)','#ef4444','URGENT'],2:['rgba(249,115,22,.15)','#f97316','IMPORTANT'],3:['rgba(245,158,11,.15)','#f59e0b','PLAN AHEAD'],4:['rgba(59,130,246,.12)','#93c5fd','FYI']};
            const [bg,tc,pl]=pC[p]||pC[4];
            return (
              <div key={i} style={{ display:'flex', gap:10, padding:'8px 0', borderBottom:'1px solid rgba(255,255,255,.04)' }}>
                <span style={{ background:bg, color:tc, fontSize:9, fontWeight:900, padding:'3px 8px', borderRadius:4, flexShrink:0, marginTop:2, letterSpacing:'.04em' }}>{pl}</span>
                <span style={{ fontSize:12, color:'#94a3b8', lineHeight:1.5 }}>{friendlyAction(a.label||a.action)}</span>
              </div>
            );
          }):<span style={{ fontSize:13, color:'#64748b' }}>Your network is stable — no action needed right now.</span>}
        </Panel>
      </div>

      {(d.shap_features||[]).length>0&&(
        <Panel title="Why was this alert triggered? — Top contributing factors" full>
          <p style={{ fontSize:12, color:'#94a3b8', marginBottom:14, lineHeight:1.6 }}>These are the network metrics that most influenced the current risk score. Red means the metric is worsening your connection; green means it is helping.</p>
          {d.shap_features.map((f,i)=>{
            const abs=Math.abs(f.shap_value), pct=Math.min(100,(abs/0.5)*100);
            const c=f.shap_value>0?'#ef4444':'#10b981';
            return (
              <div key={i} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
                <span style={{ fontSize:12, color:'#64748b', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{friendlyFeature(f.feature)}</span>
                <div style={{ width:80, height:5, background:'rgba(255,255,255,.05)', borderRadius:3, overflow:'hidden', flexShrink:0 }}>
                  <div style={{ height:'100%', width:`${pct}%`, background:c, borderRadius:3 }}/>
                </div>
                <span style={{ fontSize:11, fontWeight:700, color:c, width:56, textAlign:'right' }}>{f.shap_value>0?'+':''}{f.shap_value.toFixed(3)}</span>
              </div>
            );
          })}
        </Panel>
      )}
    </div>
  );
}
