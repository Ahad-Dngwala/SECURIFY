import { useState, useEffect, useRef, useCallback } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from "recharts";

// ─── Tokens ────────────────────────────────────────────────────
const C = {
  bg: "#FAF7F2", surf: "#FFFFFF", surfW: "#F7F4EF", surfT: "#F0EDE7",
  acc: "#C8883A", accL: "#F5E6CC", accM: "#E6A23C",
  txt: "#2C2816", txt2: "#7A7060", txtM: "#A89F8F",
  ok: "#5E9E6F", okB: "#EAF4EC",
  warn: "#D4824A", warnB: "#FDF0E6",
  err: "#B85555", errB: "#F9ECEC",
  info: "#3D7FC1", infoB: "#EAF2FB",
  bdr: "rgba(180,160,120,.16)", bdrM: "rgba(180,160,120,.28)",
  sh: "0 1px 8px rgba(100,80,40,.07)",
  shM: "0 4px 20px rgba(100,80,40,.12)",
};

const SERVERS = [
  { id: "aws",   name: "AWS",   label: "Amazon Web Services",  color: "#FF9900", colorDark: "#7A4500", region: "us-east-1",     icon: "A" },
  { id: "azure", name: "Azure", label: "Microsoft Azure",       color: "#0078D4", colorDark: "#003A57", region: "eastus",        icon: "Z" },
  { id: "gcp",   name: "GCP",   label: "Google Cloud Platform", color: "#4285F4", colorDark: "#0D2D6A", region: "us-central1",   icon: "G" },
];

const ATTACKS = [
  { id: "ddos",  label: "DDoS",                 icon: "⚡", sev: "HIGH",   desc: "Overwhelms server with massive request floods" },
  { id: "brute", label: "Brute Force",           icon: "🔑", sev: "MEDIUM", desc: "Repeated login attempts to crack credentials" },
  { id: "sqli",  label: "SQL Injection",         icon: "💉", sev: "MEDIUM", desc: "Malicious SQL payloads targeting the database" },
  { id: "priv",  label: "Privilege Escalation",  icon: "🔺", sev: "HIGH",   desc: "Attempts to gain unauthorized higher-level access" },
];

// ─── Log Factory ───────────────────────────────────────────────
let _lid = 0;
function mkLog(serverId, attackId = null) {
  const ts = new Date().toLocaleTimeString("en-US", { hour12: false });
  const ips = ["192.168.1.4","45.33.12.87","185.220.100.1","10.0.0.23","91.108.4.0","172.16.5.9"];
  const ip = ips[Math.floor(Math.random() * ips.length)];
  if (attackId) {
    const msgs = {
      ddos:  [`[ALERT] DDoS flood: ${Math.floor(Math.random()*700+300)} req/s from ${ip}`, `[ALERT] SYN flood — ${Math.floor(Math.random()*400+100)} pkt/s`, `[WARN] Rate limiter breached — ${ip}`],
      brute: [`[ALERT] ${Math.floor(Math.random()*30+8)} failed logins — ${ip}`, `[ALERT] Credential stuffing pattern`, `[WARN] Auth lockout triggered for ${ip}`],
      sqli:  [`[ALERT] SQL injection payload detected`, `[WARN] Abnormal DB query from ${ip}`, `[ALERT] Possible data exfiltration attempt`],
      priv:  [`[ALERT] Privilege escalation — ${ip}`, `[ALERT] Unauthorized sudo — ${ip}`, `[WARN] Role tampering detected`],
    };
    const arr = msgs[attackId]; return { id: ++_lid, ts, type: "attack", text: arr[Math.floor(Math.random()*arr.length)], ip };
  }
  const normals = [
    `[INFO] Health check OK — ${Math.floor(Math.random()*15+3)}ms`,`[INFO] IAM policy evaluated — ${ip}`,
    `[INFO] API call: GetObject — ${ip}`,`[INFO] TLS handshake — ${ip}`,
    `[INFO] Auto-scale event: +1 instance`,`[INFO] Snapshot OK — ${(Math.random()*2+0.5).toFixed(1)}GB`,
  ];
  const warns = [`[WARN] Elevated rate from ${ip}`,`[WARN] Unusual geo-location — ${ip}`];
  const r = Math.random();
  if (r < 0.75) return { id: ++_lid, ts, type: "info", text: normals[Math.floor(Math.random()*normals.length)], ip };
  return { id: ++_lid, ts, type: "warn", text: warns[Math.floor(Math.random()*warns.length)], ip };
}

function mkJob(serverId, attackId, logs) {
  const atk = ATTACKS.find(a => a.id === attackId);
  const srv = SERVERS.find(s => s.id === serverId);
  const conf = Math.floor(Math.random() * 12 + 86);
  const factors = [
    { label: "Abnormal request rate",       weight: +(Math.random()*0.2+0.78).toFixed(2) },
    { label: "Foreign IP / geo anomaly",    weight: +(Math.random()*0.2+0.62).toFixed(2) },
    { label: "Failed authentication spike", weight: +(Math.random()*0.2+0.50).toFixed(2) },
    { label: "Unusual event sequence",      weight: +(Math.random()*0.2+0.35).toFixed(2) },
  ];
  const ips = ["185.220.100.1","45.33.12.87","91.108.4.0"];
  return {
    id: `JOB-${Date.now()}`,
    serverId, serverName: srv.name, serverColor: srv.color,
    attackId, attackLabel: atk.label, attackIcon: atk.icon,
    severity: atk.sev,
    confidence: conf,
    timestamp: new Date().toISOString(),
    status: "completed",
    logsCount: logs.length,
    attackLogs: logs.filter(l => l.type === "attack").length,
    sourceIP: ips[Math.floor(Math.random() * ips.length)],
    logs: [...logs],
    factors,
    timeline: Array.from({length:10},(_,i)=>({ t:`${String(i+8).padStart(2,"0")}:00`, normal: Math.floor(Math.random()*30+10), attacks: i >= 7 ? Math.floor(Math.random()*20+8) : Math.floor(Math.random()*4) })),
    rawFeatures: { request_rate: Math.floor(Math.random()*600+200), failed_logins: Math.floor(Math.random()*30+5), bytes_transferred: `${(Math.random()*3+0.5).toFixed(1)} MB`, geo_anomaly: true, privilege_escalation: attackId==="priv"?Math.floor(Math.random()*4+1):0 },
  };
}

// ─── Shared Nav ────────────────────────────────────────────────
function Nav({ page, setPage }) {
  return (
    <nav style={{ background: C.surf, borderBottom: `1px solid ${C.bdr}`, padding: "0 20px", height: 54, display:"flex", alignItems:"center", justifyContent:"space-between", boxShadow: C.sh, position:"sticky", top:0, zIndex:50 }}>
      <div style={{ display:"flex", alignItems:"center", gap:9 }}>
        <div style={{ width:32, height:32, background:C.acc, borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center", color:"white", fontWeight:800, fontSize:15 }}>S</div>
        <div>
          <div style={{ fontWeight:700, fontSize:16, letterSpacing:"-.3px", lineHeight:1 }}>S@curify</div>
          <div style={{ fontSize:9, color:C.txtM, letterSpacing:".08em", textTransform:"uppercase" }}>Multi-Cloud IDS</div>
        </div>
      </div>
      <div style={{ display:"flex", gap:4, background:C.surfW, borderRadius:8, padding:3, border:`1px solid ${C.bdr}` }}>
        {[["home","Servers"],["jobs","Job History"]].map(([p,l]) => (
          <button key={p} onClick={()=>setPage(p)} style={{ padding:"5px 14px", borderRadius:6, border:"none", cursor:"pointer", fontSize:12, fontWeight:600, fontFamily:"inherit", transition:"all .18s", background: page===p ? C.surf : "transparent", color: page===p ? C.acc : C.txt2, boxShadow: page===p ? C.sh : "none" }}>{l}</button>
        ))}
      </div>
      <div style={{ width:30, height:30, borderRadius:"50%", background:C.accL, border:`1px solid ${C.bdr}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:12, fontWeight:700, color:C.acc }}>A</div>
    </nav>
  );
}

// ─── SERVER CARD (Home) ────────────────────────────────────────
function ServerCard({ server, onJobSaved }) {
  const [logs, setLogs] = useState(() => Array.from({length:6}, () => mkLog(server.id)));
  const [paused, setPaused] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [simState, setSimState] = useState("idle"); // idle|running|done
  const [result, setResult] = useState(null);
  const logRef = useRef(null);
  const menuRef = useRef(null);

  // background stream
  useEffect(() => {
    if (paused || simState === "running") return;
    const iv = setInterval(() => {
      setLogs(p => [...p.slice(-30), mkLog(server.id)]);
    }, 2000 + Math.random()*800);
    return () => clearInterval(iv);
  }, [paused, simState, server.id]);

  useEffect(() => { if (!paused) logRef.current?.scrollIntoView({ behavior:"smooth" }); }, [logs, paused]);

  // close menu on outside click
  useEffect(() => {
    const h = e => { if (menuRef.current && !menuRef.current.contains(e.target)) setMenuOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const simulate = useCallback(() => {
    if (!selectedAttack || simState === "running") return;
    setMenuOpen(false);
    setSimState("running");
    setResult(null);
    let count = 0;
    const newAttackLogs = [];
    const iv = setInterval(() => {
      const l = mkLog(server.id, selectedAttack.id);
      newAttackLogs.push(l);
      setLogs(p => [...p.slice(-30), l]);
      count++;
      if (count >= 5) {
        clearInterval(iv);
        const job = mkJob(server.id, selectedAttack.id, [...logs, ...newAttackLogs]);
        setResult(job);
        setSimState("done");
        onJobSaved(job);
      }
    }, 450);
  }, [selectedAttack, simState, server.id, logs, onJobSaved]);

  const logColor = t => t==="attack" ? C.err : t==="warn" ? C.warn : C.txt2;
  const logTagBg = t => t==="attack" ? C.errB : t==="warn" ? C.warnB : C.okB;
  const logTagColor = t => t==="attack" ? C.err : t==="warn" ? C.warn : C.ok;

  return (
    <div style={{ background:C.surf, borderRadius:16, border:`1px solid ${C.bdr}`, boxShadow:C.sh, overflow:"hidden", display:"flex", flexDirection:"column" }}>
      {/* Card Header */}
      <div style={{ padding:"12px 14px", background:C.surfW, borderBottom:`1px solid ${C.bdr}`, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:34, height:34, borderRadius:9, background:server.color+"22", border:`1px solid ${server.color}44`, display:"flex", alignItems:"center", justifyContent:"center", fontWeight:800, fontSize:14, color:server.color }}>{server.icon}</div>
          <div>
            <div style={{ fontWeight:700, fontSize:14, color:C.txt }}>{server.name}</div>
            <div style={{ fontSize:10, color:C.txtM }}>{server.label} · {server.region}</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          <div style={{ display:"flex", alignItems:"center", gap:5 }}>
            <div style={{ width:6, height:6, borderRadius:"50%", background:C.ok, animation:"pulse 2s infinite" }} />
            <span style={{ fontSize:10, color:C.ok, fontWeight:600 }}>Online</span>
          </div>
          {/* 3-dot menu */}
          <div style={{ position:"relative" }} ref={menuRef}>
            <button onClick={()=>setMenuOpen(o=>!o)} style={{ width:28, height:28, borderRadius:7, border:`1px solid ${C.bdr}`, background: menuOpen ? C.surfW : "transparent", cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center", gap:2 }}>
              {[0,1,2].map(i => <div key={i} style={{ width:4, height:4, borderRadius:"50%", background:C.txt2 }} />)}
            </button>
            {menuOpen && (
              <div style={{ position:"absolute", right:0, top:34, width:220, background:C.surf, border:`1px solid ${C.bdr}`, borderRadius:12, boxShadow:C.shM, zIndex:20, overflow:"hidden", animation:"fadeIn .15s ease" }}>
                <div style={{ padding:"8px 12px 4px", fontSize:9, fontWeight:700, color:C.txtM, textTransform:"uppercase", letterSpacing:".08em" }}>Choose Attack Type</div>
                {ATTACKS.map(atk => (
                  <button key={atk.id} onClick={() => { setSelectedAttack(atk); setMenuOpen(false); }} style={{ width:"100%", padding:"9px 12px", border:"none", background: selectedAttack?.id===atk.id ? C.accL : "transparent", cursor:"pointer", display:"flex", alignItems:"center", gap:9, textAlign:"left", fontFamily:"inherit", transition:"background .15s", borderBottom:`1px solid ${C.bdr}` }}>
                    <span style={{ fontSize:14 }}>{atk.icon}</span>
                    <div>
                      <div style={{ fontSize:12, fontWeight:600, color:C.txt }}>{atk.label}</div>
                      <div style={{ fontSize:10, color:C.txtM }}>{atk.desc}</div>
                    </div>
                    {selectedAttack?.id===atk.id && <div style={{ marginLeft:"auto", width:6, height:6, borderRadius:"50%", background:C.acc }} />}
                  </button>
                ))}
                {selectedAttack && (
                  <button onClick={simulate} style={{ width:"100%", padding:"10px 12px", border:"none", background:`linear-gradient(135deg,${C.acc},${C.accM})`, cursor:"pointer", fontWeight:700, fontSize:12, color:"white", fontFamily:"inherit" }}>
                    ⚡ Simulate {selectedAttack.label}
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Terminal */}
      <div style={{ background:C.surfT, flex:1 }}>
        <div style={{ padding:"6px 12px", borderBottom:`1px solid ${C.bdr}`, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <div style={{ display:"flex", gap:4 }}>
            {["#D96C6C","#E6A23C","#7FB77E"].map((c,i)=><div key={i} style={{ width:8, height:8, borderRadius:"50%", background:c }} />)}
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            {simState==="running" && <span style={{ fontSize:9, color:C.warn, fontWeight:700, animation:"pulse 1s infinite" }}>● SIMULATING</span>}
            {simState==="idle" && <span style={{ fontSize:9, color:C.ok, fontWeight:600 }}>● LIVE</span>}
            <button onClick={()=>setPaused(p=>!p)} style={{ fontSize:9, padding:"2px 6px", borderRadius:4, border:`1px solid ${C.bdr}`, background:"transparent", cursor:"pointer", color:C.txtM, fontFamily:"'JetBrains Mono',monospace" }}>{paused?"▶ RESUME":"⏸ PAUSE"}</button>
          </div>
        </div>
        <div style={{ height:180, overflowY:"auto", padding:"8px 10px", fontFamily:"'JetBrains Mono',monospace" }}>
          {logs.slice(-20).map(l => (
            <div key={l.id} style={{ marginBottom:3, fontSize:10.5, lineHeight:1.6, animation:"fadeIn .25s ease" }}>
              <span style={{ color:C.txtM }}>{l.ts} </span>
              <span style={{ padding:"1px 4px", borderRadius:3, fontSize:8.5, fontWeight:700, marginRight:4, background:logTagBg(l.type), color:logTagColor(l.type) }}>{l.type.toUpperCase()}</span>
              <span style={{ color:logColor(l.type) }}>{l.text}</span>
            </div>
          ))}
          <div ref={logRef} />
        </div>
      </div>

      {/* Output Strip */}
      {result ? (
        <div style={{ borderTop:`1px solid ${C.bdr}`, padding:"12px 14px", background:C.surf }}>
          <div style={{ fontSize:9, fontWeight:700, color:C.txtM, textTransform:"uppercase", letterSpacing:".08em", marginBottom:8 }}>Last Simulation Result</div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8 }}>
            {/* Detection */}
            <div style={{ background:result.severity==="HIGH"?C.errB:C.warnB, borderRadius:9, padding:"8px 10px" }}>
              <div style={{ fontSize:9, color:C.txtM, fontWeight:600, marginBottom:3 }}>Detection</div>
              <div style={{ fontSize:11, fontWeight:700, color:result.severity==="HIGH"?C.err:C.warn }}>{result.attackIcon} {result.attackLabel}</div>
              <div style={{ fontSize:9, color:result.severity==="HIGH"?C.err:C.warn, marginTop:2 }}>{result.severity}</div>
            </div>
            {/* Confidence */}
            <div style={{ background:C.surfW, borderRadius:9, padding:"8px 10px" }}>
              <div style={{ fontSize:9, color:C.txtM, fontWeight:600, marginBottom:3 }}>Confidence</div>
              <div style={{ fontSize:18, fontWeight:700, color:C.acc }}>{result.confidence}<span style={{ fontSize:11 }}>%</span></div>
              <div style={{ height:3, borderRadius:2, background:C.bdr, marginTop:4 }}>
                <div style={{ height:"100%", borderRadius:2, background:C.acc, width:`${result.confidence}%`, transition:"width 1s ease" }} />
              </div>
            </div>
            {/* Explanation */}
            <div style={{ background:C.surfW, borderRadius:9, padding:"8px 10px" }}>
              <div style={{ fontSize:9, color:C.txtM, fontWeight:600, marginBottom:4 }}>Top Reason</div>
              {result.factors.slice(0,2).map((f,i) => (
                <div key={i} style={{ marginBottom:3 }}>
                  <div style={{ fontSize:9, color:C.txt, fontWeight:500, marginBottom:2, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{f.label}</div>
                  <div style={{ height:2, borderRadius:2, background:C.bdr }}>
                    <div style={{ height:"100%", borderRadius:2, background:i===0?C.err:C.warn, width:`${Math.round(f.weight*100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display:"flex", justifyContent:"flex-end", marginTop:8 }}>
            <span style={{ fontSize:10, color:C.info, fontWeight:600, cursor:"pointer" }}>Saved to Job History →</span>
          </div>
        </div>
      ) : (
        <div style={{ borderTop:`1px solid ${C.bdr}`, padding:"10px 14px", background:C.surfW, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <span style={{ fontSize:11, color:C.txtM }}>
            {selectedAttack ? `Ready: ${selectedAttack.icon} ${selectedAttack.label}` : "Select attack via ⋯ menu"}
          </span>
          {selectedAttack && (
            <button onClick={simulate} disabled={simState==="running"} style={{ padding:"5px 12px", borderRadius:7, border:"none", background:simState==="running"?C.surfW:`linear-gradient(135deg,${C.acc},${C.accM})`, color:simState==="running"?C.txtM:"white", fontSize:11, fontWeight:700, cursor:simState==="running"?"not-allowed":"pointer", fontFamily:"inherit" }}>
              {simState==="running"?"Running...":"⚡ Simulate"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ─── HOME PAGE ─────────────────────────────────────────────────
function HomePage({ jobs, onJobSaved }) {
  return (
    <div style={{ padding:"20px", maxWidth:1200, margin:"0 auto" }}>
      <div style={{ marginBottom:20 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:C.txt, marginBottom:4 }}>Cloud Servers</h1>
        <p style={{ fontSize:13, color:C.txt2 }}>Monitor and simulate attacks on individual cloud environments. Each server runs an isolated detection session.</p>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:16 }}>
        {SERVERS.map(srv => <ServerCard key={srv.id} server={srv} onJobSaved={onJobSaved} />)}
      </div>
      {jobs.length > 0 && (
        <div style={{ marginTop:20, padding:"12px 16px", background:C.accL, borderRadius:12, border:`1px solid ${C.acc}44`, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <span style={{ fontSize:13, fontWeight:600, color:C.acc }}>{jobs.length} job{jobs.length>1?"s":""} saved to history</span>
          <span style={{ fontSize:12, color:C.acc }}>Switch to Job History tab to review →</span>
        </div>
      )}
    </div>
  );
}

// ─── JOBS DASHBOARD ────────────────────────────────────────────
function JobsDashboard({ jobs, onSelectJob }) {
  const [filter, setFilter] = useState({ server:"All", severity:"All", attack:"All" });
  const [sort, setSort] = useState("newest");

  const filtered = jobs
    .filter(j => (filter.server==="All" || j.serverName===filter.server) && (filter.severity==="All" || j.severity===filter.severity) && (filter.attack==="All" || j.attackId===filter.attack))
    .sort((a,b) => sort==="newest" ? new Date(b.timestamp)-new Date(a.timestamp) : sort==="confidence" ? b.confidence-a.confidence : b.attackLogs-a.attackLogs);

  const sevColor = s => s==="HIGH" ? C.err : s==="MEDIUM" ? C.warn : C.ok;
  const sevBg = s => s==="HIGH" ? C.errB : s==="MEDIUM" ? C.warnB : C.okB;

  return (
    <div style={{ padding:"20px", maxWidth:1200, margin:"0 auto" }}>
      <div style={{ marginBottom:20 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:C.txt, marginBottom:4 }}>Job History</h1>
        <p style={{ fontSize:13, color:C.txt2 }}>All simulation runs are saved here. Filter by server, severity or attack type, then click any job to see the full detail view.</p>
      </div>

      {jobs.length === 0 ? (
        <div style={{ textAlign:"center", padding:"60px 20px", background:C.surf, borderRadius:16, border:`1px solid ${C.bdr}` }}>
          <div style={{ fontSize:36, marginBottom:12 }}>🛡️</div>
          <div style={{ fontSize:15, fontWeight:700, color:C.txt, marginBottom:6 }}>No jobs yet</div>
          <div style={{ fontSize:13, color:C.txtM }}>Run a simulation from the Servers page to create your first job.</div>
        </div>
      ) : (
        <>
          {/* Filters */}
          <div style={{ background:C.surf, borderRadius:12, padding:"12px 16px", border:`1px solid ${C.bdr}`, marginBottom:14, display:"flex", gap:12, flexWrap:"wrap", alignItems:"center" }}>
            {[
              { key:"server", label:"Server", opts:["All",...SERVERS.map(s=>s.name)] },
              { key:"severity", label:"Severity", opts:["All","HIGH","MEDIUM"] },
              { key:"attack", label:"Attack", opts:["All",...ATTACKS.map(a=>a.id)] },
            ].map(f => (
              <div key={f.key} style={{ display:"flex", alignItems:"center", gap:6 }}>
                <span style={{ fontSize:11, color:C.txtM, fontWeight:600 }}>{f.label}:</span>
                <select value={filter[f.key]} onChange={e=>setFilter(p=>({...p,[f.key]:e.target.value}))} style={{ padding:"4px 8px", borderRadius:7, border:`1px solid ${C.bdr}`, background:C.surfW, color:C.txt, fontSize:11, fontFamily:"inherit", cursor:"pointer" }}>
                  {f.opts.map(o=><option key={o} value={o}>{f.key==="attack"&&o!=="All"?ATTACKS.find(a=>a.id===o)?.label||o:o}</option>)}
                </select>
              </div>
            ))}
            <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:6 }}>
              <span style={{ fontSize:11, color:C.txtM, fontWeight:600 }}>Sort:</span>
              <select value={sort} onChange={e=>setSort(e.target.value)} style={{ padding:"4px 8px", borderRadius:7, border:`1px solid ${C.bdr}`, background:C.surfW, color:C.txt, fontSize:11, fontFamily:"inherit", cursor:"pointer" }}>
                <option value="newest">Newest first</option>
                <option value="confidence">Confidence</option>
                <option value="attacks">Attack logs</option>
              </select>
            </div>
            <span style={{ fontSize:11, color:C.txtM }}>{filtered.length} result{filtered.length!==1?"s":""}</span>
          </div>

          {/* Job Cards Grid */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))", gap:12 }}>
            {filtered.map(job => {
              const srv = SERVERS.find(s=>s.id===job.serverId);
              return (
                <div key={job.id} onClick={()=>onSelectJob(job)} style={{ background:C.surf, borderRadius:14, border:`1px solid ${C.bdr}`, boxShadow:C.sh, cursor:"pointer", transition:"all .18s", overflow:"hidden" }}
                  onMouseEnter={e=>{e.currentTarget.style.boxShadow=C.shM;e.currentTarget.style.transform="translateY(-2px)"}}
                  onMouseLeave={e=>{e.currentTarget.style.boxShadow=C.sh;e.currentTarget.style.transform="translateY(0)"}}>
                  {/* Card top accent */}
                  <div style={{ height:3, background:job.severity==="HIGH"?C.err:C.warn }} />
                  <div style={{ padding:"12px 14px" }}>
                    {/* Header row */}
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:10 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                        <div style={{ width:30, height:30, borderRadius:8, background:srv.color+"20", border:`1px solid ${srv.color}40`, display:"flex", alignItems:"center", justifyContent:"center", fontWeight:800, fontSize:13, color:srv.color }}>{srv.icon}</div>
                        <div>
                          <div style={{ fontSize:12, fontWeight:700, color:C.txt }}>{job.serverName}</div>
                          <div style={{ fontSize:9, color:C.txtM, fontFamily:"'JetBrains Mono',monospace" }}>{job.id}</div>
                        </div>
                      </div>
                      <span style={{ padding:"3px 8px", borderRadius:20, background:sevBg(job.severity), color:sevColor(job.severity), fontSize:9, fontWeight:700 }}>{job.severity}</span>
                    </div>

                    {/* Attack */}
                    <div style={{ padding:"8px 10px", background:sevBg(job.severity), borderRadius:8, marginBottom:10, display:"flex", alignItems:"center", gap:8 }}>
                      <span style={{ fontSize:16 }}>{job.attackIcon}</span>
                      <div>
                        <div style={{ fontSize:12, fontWeight:700, color:sevColor(job.severity) }}>{job.attackLabel}</div>
                        <div style={{ fontSize:10, color:C.txtM }}>Source: {job.sourceIP}</div>
                      </div>
                    </div>

                    {/* 3 outputs */}
                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:6, marginBottom:10 }}>
                      <div style={{ background:C.surfW, borderRadius:7, padding:"6px 8px", textAlign:"center" }}>
                        <div style={{ fontSize:8, color:C.txtM, fontWeight:600, textTransform:"uppercase", marginBottom:2 }}>Detection</div>
                        <div style={{ fontSize:11, fontWeight:700, color:sevColor(job.severity) }}>✓ Yes</div>
                      </div>
                      <div style={{ background:C.surfW, borderRadius:7, padding:"6px 8px", textAlign:"center" }}>
                        <div style={{ fontSize:8, color:C.txtM, fontWeight:600, textTransform:"uppercase", marginBottom:2 }}>Confidence</div>
                        <div style={{ fontSize:14, fontWeight:700, color:C.acc }}>{job.confidence}%</div>
                      </div>
                      <div style={{ background:C.surfW, borderRadius:7, padding:"6px 8px", textAlign:"center" }}>
                        <div style={{ fontSize:8, color:C.txtM, fontWeight:600, textTransform:"uppercase", marginBottom:2 }}>Logs</div>
                        <div style={{ fontSize:11, fontWeight:700, color:C.txt }}>{job.logsCount}</div>
                      </div>
                    </div>

                    {/* SHAP preview */}
                    <div>
                      {job.factors.slice(0,2).map((f,i)=>(
                        <div key={i} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                          <span style={{ fontSize:10, color:C.txt2, flex:1, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{f.label}</span>
                          <div style={{ width:50, height:3, borderRadius:2, background:C.bdr, flexShrink:0 }}>
                            <div style={{ height:"100%", borderRadius:2, background:i===0?C.err:C.warn, width:`${Math.round(f.weight*100)}%` }} />
                          </div>
                          <span style={{ fontSize:9, color:C.txtM, width:22, textAlign:"right" }}>{Math.round(f.weight*100)}%</span>
                        </div>
                      ))}
                    </div>

                    {/* Footer */}
                    <div style={{ marginTop:10, paddingTop:8, borderTop:`1px solid ${C.bdr}`, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                      <span style={{ fontSize:9, color:C.txtM }}>{new Date(job.timestamp).toLocaleString()}</span>
                      <span style={{ fontSize:10, color:C.acc, fontWeight:600 }}>View detail →</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

// ─── JOB DETAIL ────────────────────────────────────────────────
function JobDetail({ job, onBack }) {
  const srv = SERVERS.find(s=>s.id===job.serverId);
  const sevColor = s => s==="HIGH" ? C.err : s==="MEDIUM" ? C.warn : C.ok;
  const sevBg = s => s==="HIGH" ? C.errB : s==="MEDIUM" ? C.warnB : C.okB;
  const [expandedLog, setExpandedLog] = useState(false);

  return (
    <div style={{ padding:"20px", maxWidth:1100, margin:"0 auto" }}>
      {/* Breadcrumb */}
      <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:16 }}>
        <button onClick={onBack} style={{ padding:"5px 12px", borderRadius:7, border:`1px solid ${C.bdr}`, background:C.surf, cursor:"pointer", fontSize:12, fontWeight:600, color:C.txt2, fontFamily:"inherit" }}>← Back</button>
        <span style={{ fontSize:12, color:C.txtM }}>Job History /</span>
        <span style={{ fontSize:12, color:C.txt, fontWeight:600 }}>{job.id}</span>
      </div>

      {/* Hero */}
      <div style={{ background:C.surf, borderRadius:16, border:`1px solid ${C.bdr}`, boxShadow:C.sh, padding:"18px 20px", marginBottom:14, display:"flex", alignItems:"flex-start", justifyContent:"space-between", flexWrap:"wrap", gap:14 }}>
        <div style={{ display:"flex", alignItems:"center", gap:14 }}>
          <div style={{ width:48, height:48, borderRadius:12, background:srv.color+"22", border:`1px solid ${srv.color}44`, display:"flex", alignItems:"center", justifyContent:"center", fontWeight:800, fontSize:22, color:srv.color }}>{srv.icon}</div>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
              <span style={{ fontSize:20, fontWeight:700, color:C.txt }}>{job.serverName}</span>
              <span style={{ padding:"3px 10px", borderRadius:20, background:sevBg(job.severity), color:sevColor(job.severity), fontSize:11, fontWeight:700 }}>{job.severity}</span>
            </div>
            <div style={{ fontSize:13, color:C.txt2 }}>{job.attackIcon} {job.attackLabel} · {new Date(job.timestamp).toLocaleString()}</div>
            <div style={{ fontSize:11, color:C.txtM, fontFamily:"'JetBrains Mono',monospace", marginTop:2 }}>{job.id} · Source IP: {job.sourceIP}</div>
          </div>
        </div>
        {/* 3 main outputs */}
        <div style={{ display:"flex", gap:10 }}>
          {[
            { label:"Detection",   val: `${job.attackIcon} ${job.attackLabel}`, sub: "Confirmed attack", col: sevColor(job.severity), bg: sevBg(job.severity) },
            { label:"Confidence",  val: `${job.confidence}%`, sub: "AI certainty score", col: C.acc, bg: C.accL },
            { label:"Attack Logs", val: `${job.attackLogs}`, sub: `of ${job.logsCount} total`, col: C.txt, bg: C.surfW },
          ].map(o => (
            <div key={o.label} style={{ background:o.bg, borderRadius:12, padding:"12px 16px", minWidth:110, border:`1px solid ${C.bdr}` }}>
              <div style={{ fontSize:9, fontWeight:700, color:C.txtM, textTransform:"uppercase", letterSpacing:".08em", marginBottom:4 }}>{o.label}</div>
              <div style={{ fontSize:20, fontWeight:700, color:o.col, marginBottom:2 }}>{o.val}</div>
              <div style={{ fontSize:10, color:C.txtM }}>{o.sub}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 320px", gap:14 }}>
        {/* LEFT col */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
          {/* Timeline */}
          <div style={{ background:C.surf, borderRadius:14, border:`1px solid ${C.bdr}`, padding:"14px 16px", boxShadow:C.sh }}>
            <div style={{ fontSize:13, fontWeight:700, marginBottom:12 }}>Attack Timeline</div>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={job.timeline} margin={{ top:4, right:4, bottom:0, left:-20 }}>
                <defs>
                  <linearGradient id="gN2" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={C.acc} stopOpacity={.2}/><stop offset="95%" stopColor={C.acc} stopOpacity={0}/></linearGradient>
                  <linearGradient id="gA2" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={C.err} stopOpacity={.25}/><stop offset="95%" stopColor={C.err} stopOpacity={0}/></linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fontSize:10, fill:C.txtM }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize:10, fill:C.txtM }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background:C.surf, border:`1px solid ${C.bdr}`, borderRadius:8, fontSize:11 }} />
                <Area type="monotone" dataKey="normal" stroke={C.acc} strokeWidth={2} fill="url(#gN2)" dot={false} />
                <Area type="monotone" dataKey="attacks" stroke={C.err} strokeWidth={2} fill="url(#gA2)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Full log replay */}
          <div style={{ background:C.surf, borderRadius:14, border:`1px solid ${C.bdr}`, overflow:"hidden", boxShadow:C.sh }}>
            <div style={{ padding:"10px 14px", borderBottom:`1px solid ${C.bdr}`, display:"flex", alignItems:"center", justifyContent:"space-between", background:C.surfW }}>
              <div style={{ fontSize:13, fontWeight:700 }}>Full Log Replay</div>
              <div style={{ display:"flex", gap:8 }}>
                <span style={{ fontSize:10, color:C.txtM }}>{job.logs.length} entries</span>
                <button onClick={()=>setExpandedLog(p=>!p)} style={{ fontSize:10, padding:"2px 8px", borderRadius:5, border:`1px solid ${C.bdr}`, background:"transparent", cursor:"pointer", color:C.acc, fontFamily:"inherit" }}>{expandedLog?"Collapse":"Expand all"}</button>
              </div>
            </div>
            <div style={{ height: expandedLog ? "auto" : 220, overflowY: expandedLog ? "visible" : "auto", padding:"8px 12px", fontFamily:"'JetBrains Mono',monospace", background:C.surfT }}>
              {job.logs.map(l => (
                <div key={l.id} style={{ marginBottom:3, fontSize:10.5, lineHeight:1.65 }}>
                  <span style={{ color:C.txtM }}>{l.ts} </span>
                  <span style={{ padding:"1px 4px", borderRadius:3, fontSize:8.5, fontWeight:700, marginRight:4,
                    background:l.type==="attack"?C.errB:l.type==="warn"?C.warnB:C.okB,
                    color:l.type==="attack"?C.err:l.type==="warn"?C.warn:C.ok }}>{l.type.toUpperCase()}</span>
                  <span style={{ color:l.type==="attack"?C.err:l.type==="warn"?C.warn:C.txt2 }}>{l.text}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Raw features */}
          <div style={{ background:C.surf, borderRadius:14, border:`1px solid ${C.bdr}`, padding:"14px 16px", boxShadow:C.sh }}>
            <div style={{ fontSize:13, fontWeight:700, marginBottom:10 }}>Raw SHAP Features</div>
            <div style={{ background:C.surfT, borderRadius:10, padding:"12px 14px", fontFamily:"'JetBrains Mono',monospace", fontSize:11 }}>
              {Object.entries(job.rawFeatures).map(([k,v])=>(
                <div key={k} style={{ marginBottom:5, display:"flex", gap:12 }}>
                  <span style={{ color:C.acc, minWidth:160 }}>{k}</span>
                  <span style={{ color:C.txtM }}>= </span>
                  <span style={{ color:C.txt, fontWeight:500 }}>{String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT col — XAI Panel */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
          {/* Why flagged */}
          <div style={{ background:C.surf, borderRadius:14, border:`1.5px solid ${sevColor(job.severity)}55`, padding:"14px 16px", boxShadow:`0 4px 20px ${sevColor(job.severity)}18` }}>
            <div style={{ fontSize:11, fontWeight:700, color:C.txtM, textTransform:"uppercase", letterSpacing:".08em", marginBottom:12 }}>Why was this flagged?</div>
            {/* Confidence ring visual */}
            <div style={{ textAlign:"center", marginBottom:14 }}>
              <svg viewBox="0 0 80 80" width={80} style={{ display:"block", margin:"0 auto" }}>
                <circle cx="40" cy="40" r="32" fill="none" stroke={C.bdr} strokeWidth="8" />
                <circle cx="40" cy="40" r="32" fill="none" stroke={sevColor(job.severity)} strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={`${job.confidence*2.01} 999`} strokeDashoffset="50" style={{ transition:"stroke-dasharray 1s ease" }} />
                <text x="40" y="45" textAnchor="middle" fontSize="16" fontWeight="700" fill={C.txt} fontFamily="Plus Jakarta Sans">{job.confidence}%</text>
              </svg>
              <div style={{ fontSize:11, fontWeight:600, color:sevColor(job.severity), marginTop:4 }}>Confidence Score</div>
            </div>
            {/* Factors */}
            {job.factors.map((f,i) => (
              <div key={i} style={{ marginBottom:10 }}>
                <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, marginBottom:3 }}>
                  <span style={{ color:C.txt, fontWeight:500 }}>{f.label}</span>
                  <span style={{ color:C.acc, fontWeight:700 }}>{Math.round(f.weight*100)}%</span>
                </div>
                <div style={{ height:5, borderRadius:3, background:C.surfW }}>
                  <div style={{ height:"100%", borderRadius:3, background:i===0?C.err:i===1?C.warn:C.acc, width:`${Math.round(f.weight*100)}%`, transition:"width .8s ease", transitionDelay:`${i*.1}s` }} />
                </div>
              </div>
            ))}
          </div>

          {/* Summary Card */}
          <div style={{ background:C.surf, borderRadius:14, border:`1px solid ${C.bdr}`, padding:"14px 16px", boxShadow:C.sh }}>
            <div style={{ fontSize:11, fontWeight:700, color:C.txtM, textTransform:"uppercase", letterSpacing:".08em", marginBottom:10 }}>Incident Summary</div>
            {[
              ["Server", job.serverName],["Region", srv.region],
              ["Attack Type", job.attackLabel],["Severity", job.severity],
              ["Source IP", job.sourceIP],["Total Logs", job.logsCount],
              ["Attack Logs", job.attackLogs],["Status", "Completed"],
            ].map(([k,v])=>(
              <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:`1px solid ${C.bdr}`, fontSize:11 }}>
                <span style={{ color:C.txtM }}>{k}</span>
                <span style={{ color:C.txt, fontWeight:600 }}>{v}</span>
              </div>
            ))}
          </div>

          {/* MITRE tag */}
          <div style={{ background:C.infoB, borderRadius:12, padding:"10px 14px", border:`1px solid ${C.info}33` }}>
            <div style={{ fontSize:9, fontWeight:700, color:C.info, textTransform:"uppercase", letterSpacing:".08em", marginBottom:5 }}>MITRE ATT&CK</div>
            <div style={{ fontSize:11, color:C.info, fontWeight:600 }}>
              {job.attackId==="ddos" ? "T1499 — Endpoint Denial of Service" : job.attackId==="brute" ? "T1110 — Brute Force" : job.attackId==="sqli" ? "T1190 — Exploit Public App" : "T1068 — Exploitation for Privilege Escalation"}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── ROOT ──────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState("home");
  const [jobs, setJobs] = useState([]);
  const [selectedJob, setSelectedJob] = useState(null);

  const handleJobSaved = useCallback((job) => {
    setJobs(prev => [job, ...prev]);
  }, []);

  const handleSelectJob = (job) => {
    setSelectedJob(job);
    setPage("detail");
  };

  const handleBack = () => {
    setSelectedJob(null);
    setPage("jobs");
  };

  return (
    <div style={{ minHeight:"100vh", background:C.bg, fontFamily:"'Plus Jakarta Sans','Outfit',sans-serif", color:C.txt }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
        ::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:${C.sand};border-radius:4px}
        button:active{transform:scale(.97)}
      `}</style>
      <Nav page={page==="detail"?"jobs":page} setPage={(p)=>{ setSelectedJob(null); setPage(p); }} />
      {page==="home" && <HomePage jobs={jobs} onJobSaved={handleJobSaved} />}
      {page==="jobs" && <JobsDashboard jobs={jobs} onSelectJob={handleSelectJob} />}
      {page==="detail" && selectedJob && <JobDetail job={selectedJob} onBack={handleBack} />}
    </div>
  );
}
