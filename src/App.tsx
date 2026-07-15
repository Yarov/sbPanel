import { useEffect, useState } from "react";
import { supabase, hasSupabase } from "./supabase";
import { parseCsv, toObjects } from "./lib/csv";
import { ingest, SOURCES, SourceId, IngestResult } from "./lib/ingest";
import { Donut, BarsH } from "./Charts";

type Profile = { scotiaId: string; name: string };
type Finding = {
  id: string; finding_key: string; source: string; epm: string | null; asset: string | null;
  title: string; cve: string | null; severity_scanner: string | null; severity_scotia: string | null;
  status: string; first_observed: string; kri_status: string | null; remaining_days: number | null;
  area: string | null; plataforma: string | null; responsable: string | null;
};
type Alert = { id: string; kind: string; message: string; severity: string | null; acknowledged: boolean; created_at: string };
type AppScan = { source: string; project_name: string; epm: string | null; policy_status: string | null; risk_level: string | null; crit: number; high: number; med: number; low: number };
type Row = { label: string; abiertos?: number; total?: number; criticos?: number };

const PROFILE_KEY = "scotia_profile";
const SEVS = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["open", "resurfaced", "fixed"];
const sevClass = (s?: string | null) => `sev sev-${(s || "").toLowerCase()}`;
const toData = (rows: Row[]) => rows.map((r) => ({ label: r.label, value: r.abiertos ?? r.total ?? 0 }));

// ---------- Login ----------
function Login({ onDone }: { onDone: (p: Profile) => void }) {
  const [scotiaId, setScotiaId] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!scotiaId.trim() || !name.trim()) return setError("ScotiaID y nombre son obligatorios");
    const p = { scotiaId: scotiaId.trim(), name: name.trim() };
    localStorage.setItem(PROFILE_KEY, JSON.stringify(p));
    onDone(p);
  }
  return (
    <main className="login">
      <div className="login-card">
        <h1 className="login-brand">Scotia · Reporter</h1>
        <p className="login-sub">Gestión de vulnerabilidades · ingresa tus datos</p>
        <form onSubmit={submit}>
          <input value={scotiaId} onChange={(e) => setScotiaId(e.currentTarget.value)} placeholder="ScotiaID" autoFocus />
          <input value={name} onChange={(e) => setName(e.currentTarget.value)} placeholder="Nombre completo" />
          <button type="submit">Entrar</button>
        </form>
        {error && <p className="error">{error}</p>}
      </div>
    </main>
  );
}

// ---------- Cargar CSV ----------
function Upload({ onDone }: { onDone: () => void }) {
  const [source, setSource] = useState<SourceId>("tenable");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<(IngestResult & { rows: number }) | null>(null);
  const [phase, setPhase] = useState("");
  const [prog, setProg] = useState<{ done: number; total: number; rows: number } | null>(null);
  const [t0, setT0] = useState(0);
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!busy) return;
    const id = setInterval(() => setTick((t) => t + 1), 500);
    return () => clearInterval(id);
  }, [busy]);

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr(""); setRes(null); setProg(null); setT0(performance.now());
    try {
      setPhase("Leyendo archivo…");
      const text = await file.text();
      setPhase("Parseando CSV…");
      const objs = toObjects(parseCsv(text));
      if (!objs.length) throw new Error("El CSV no tiene filas de datos.");
      setPhase(`Cargando ${objs.length.toLocaleString()} filas…`);
      const r = await ingest(source, objs, (done, total) => setProg({ done, total, rows: objs.length }));
      setRes({ ...r, rows: objs.length });
      onDone();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false); setProg(null); setPhase(""); e.target.value = "";
    }
  }

  const pct = prog && prog.total ? Math.round((prog.done / prog.total) * 100) : 0;
  const secs = busy && t0 ? ((performance.now() - t0) / 1000).toFixed(0) : "0";

  return (
    <div className="panel">
      <h2>Cargar escaneo (CSV)</h2>
      <p className="hint">Elige la fuente y sube el CSV. La conciliación es automática: detecta nuevas,
        cierra las que ya no aparecen, <b>reabre y alerta</b> las que resurgen.</p>
      <div className="sources">
        {SOURCES.map((s) => (
          <button key={s.id} className={`src ${source === s.id ? "active" : ""}`} onClick={() => !busy && setSource(s.id)}>
            {s.label}<span className="src-grain">{s.grain}</span>
          </button>
        ))}
      </div>
      <label className={`dropzone ${busy ? "busy" : ""}`}>
        <input type="file" accept=".csv,text/csv" onChange={onFile} disabled={busy} hidden />
        {busy ? (prog
          ? `⏳ Procesando ${prog.rows.toLocaleString()} filas · lote ${prog.done}/${prog.total} · ${pct}% · ${secs}s`
          : `⏳ ${phase}`) : `Suelta o elige el CSV de ${SOURCES.find((s) => s.id === source)!.label}`}
      </label>
      {busy && prog && <div className="progress"><div className="progress-bar" style={{ width: `${Math.max(pct, 3)}%` }} /></div>}
      {err && <p className="error">⚠️ {err}</p>}
      {res && (
        <div className="ingest-result">
          <p>✅ Procesadas <b>{res.rows.toLocaleString()}</b> filas.</p>
          <div className="chips">
            {Object.entries(res.summary).map(([k, v]) => <span key={k} className={`chip chip-${k}`}>{k}: <b>{v}</b></span>)}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Dashboard (métricas + gráficas) ----------
function Dashboard() {
  const [kpi, setKpi] = useState<any>({});
  const [sev, setSev] = useState<Row[]>([]);
  const [area, setArea] = useState<Row[]>([]);
  const [plat, setPlat] = useState<Row[]>([]);
  const [resp, setResp] = useState<Row[]>([]);
  const [debt, setDebt] = useState<any[]>([]);
  const [cross, setCross] = useState<any[]>([]);
  const [scans, setScans] = useState<AppScan[]>([]);

  async function load() {
    const [k, sv, ar, pl, rs, d, c, sc] = await Promise.all([
      supabase.from("v_kpi").select("*").maybeSingle(),
      supabase.from("v_by_severity").select("*"),
      supabase.from("v_by_area").select("*").limit(8),
      supabase.from("v_by_plataforma").select("*").limit(8),
      supabase.from("v_by_responsable").select("*").limit(8),
      supabase.from("v_hidden_debt").select("asset,title,true_age_days").order("true_age_days", { ascending: false }).limit(8),
      supabase.from("v_cross_layer").select("*").order("capas", { ascending: false }).limit(8),
      supabase.from("app_scans").select("*").order("crit", { ascending: false }).limit(30),
    ]);
    setKpi(k.data ?? {});
    setSev((sv.data ?? []) as Row[]);
    setArea((ar.data ?? []) as Row[]);
    setPlat((pl.data ?? []) as Row[]);
    setResp((rs.data ?? []) as Row[]);
    setDebt(d.data ?? []);
    setCross(c.data ?? []);
    setScans((sc.data ?? []) as AppScan[]);
  }
  useEffect(() => {
    load();
    const ch = supabase.channel("dash")
      .on("postgres_changes", { event: "*", schema: "public", table: "findings" }, () => load())
      .on("postgres_changes", { event: "*", schema: "public", table: "app_scans" }, () => load())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);

  return (
    <div>
      <div className="kpis">
        <Kpi n={kpi.total ?? 0} label="Hallazgos" />
        <Kpi n={kpi.abiertos ?? 0} label="Abiertos" />
        <Kpi n={kpi.criticos ?? 0} label="Críticos" tone="red" />
        <Kpi n={kpi.resurfaced ?? 0} label="Resurfaced" tone="amber" />
        <Kpi n={kpi.areas ?? 0} label="Áreas" />
        <Kpi n={kpi.responsables ?? 0} label="Responsables" />
      </div>

      <div className="charts">
        <div className="chart-card">
          <h3>Por severidad</h3>
          {sev.length ? <Donut data={toData(sev)} /> : <Empty />}
        </div>
        <div className="chart-card">
          <h3>Por Área</h3>
          {area.length ? <BarsH data={toData(area)} /> : <Empty />}
        </div>
        <div className="chart-card">
          <h3>Por Plataforma</h3>
          {plat.length ? <BarsH data={toData(plat)} color="#60a5fa" /> : <Empty />}
        </div>
        <div className="chart-card">
          <h3>Top Responsables</h3>
          {resp.length ? <BarsH data={toData(resp)} color="#fbbf24" /> : <Empty />}
        </div>
      </div>

      {debt.length > 0 && (
        <Insight title="🔴 Deuda oculta (KRI dice IN_TIME pero llevan años)" items={debt.map((d: any) => ({
          key: d.asset + d.title, main: d.title, meta: `${d.asset} · ${d.true_age_days} días reales`,
        }))} />
      )}
      {cross.length > 0 && (
        <Insight title="🔀 Riesgo cruzado (riesgo en varias capas)" items={cross.map((c: any) => ({
          key: c.epm, main: `EPM ${c.epm}`, meta: `${c.capas} capas · ${c.fuentes}`,
        }))} />
      )}

      {scans.length > 0 && (
        <div className="panel">
          <h3>Scorecard por aplicación (AppSec)</h3>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead><tr><th>Fuente</th><th>Proyecto</th><th>EPM</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Policy</th></tr></thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.source + s.project_name}>
                    <td className="mono">{s.source}</td><td>{s.project_name}</td><td>{s.epm ?? "—"}</td>
                    <td className={s.crit ? "hot" : ""}>{s.crit}</td><td className={s.high ? "warn" : ""}>{s.high}</td>
                    <td>{s.med}</td><td>{s.low}</td><td>{s.policy_status ?? s.risk_level ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Hallazgos (búsqueda avanzada) ----------
function Hallazgos() {
  const PAGE = 50;
  const [rows, setRows] = useState<Finding[]>([]);
  const [count, setCount] = useState(0);
  const [page, setPage] = useState(0);
  const [q, setQ] = useState("");
  const [f, setF] = useState({ sev: "", status: "", source: "", area: "" });
  const [areas, setAreas] = useState<string[]>([]);

  useEffect(() => {
    supabase.from("v_by_area").select("label").limit(100).then((r) =>
      setAreas(((r.data ?? []) as any[]).map((x) => x.label)));
  }, []);

  useEffect(() => {
    let cancel = false;
    (async () => {
      let query = supabase.from("findings").select("*", { count: "exact" });
      const term = q.trim().replace(/[,()]/g, " ");
      if (term) query = query.or(`asset.ilike.*${term}*,title.ilike.*${term}*,cve.ilike.*${term}*,epm.ilike.*${term}*,responsable.ilike.*${term}*`);
      if (f.sev) query = query.eq("severity_scanner", f.sev);
      if (f.status) query = query.eq("status", f.status);
      if (f.source) query = query.eq("source", f.source);
      if (f.area) query = query.eq("area", f.area);
      query = query.order("last_seen", { ascending: false }).range(page * PAGE, page * PAGE + PAGE - 1);
      const { data, count } = await query;
      if (!cancel) { setRows((data ?? []) as Finding[]); setCount(count ?? 0); }
    })();
    return () => { cancel = true; };
  }, [q, f, page]);

  const set = (k: string, v: string) => { setF((p) => ({ ...p, [k]: v })); setPage(0); };
  const pages = Math.ceil(count / PAGE);

  return (
    <div className="panel">
      <div className="filters-bar">
        <input className="search grow" value={q} onChange={(e) => { setQ(e.currentTarget.value); setPage(0); }}
          placeholder="🔎 Buscar activo, título, CVE, EPM, responsable…" />
        <select value={f.sev} onChange={(e) => set("sev", e.currentTarget.value)}>
          <option value="">Severidad</option>{SEVS.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.status} onChange={(e) => set("status", e.currentTarget.value)}>
          <option value="">Estado</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.source} onChange={(e) => set("source", e.currentTarget.value)}>
          <option value="">Fuente</option>{SOURCES.map((s) => <option key={s.id} value={s.id}>{s.id}</option>)}
        </select>
        <select value={f.area} onChange={(e) => set("area", e.currentTarget.value)}>
          <option value="">Área</option>{areas.map((a) => <option key={a}>{a}</option>)}
        </select>
      </div>
      <p className="hint">{count.toLocaleString()} hallazgos</p>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr><th>Sev</th><th>Estado</th><th>Activo</th><th>Título</th><th>EPM</th><th>Área</th><th>Responsable</th><th>KRI</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td><span className={sevClass(r.severity_scanner)}>{r.severity_scanner ?? "—"}</span></td>
                <td><span className={`st st-${r.status}`}>{r.status}</span></td>
                <td className="mono">{r.asset}</td>
                <td className="clip">{r.title}</td>
                <td>{r.epm ?? "—"}</td>
                <td>{r.area ?? "—"}</td>
                <td>{r.responsable ?? "—"}</td>
                <td>{r.kri_status ?? "—"}{r.remaining_days != null ? ` · ${r.remaining_days}d` : ""}</td>
              </tr>
            ))}
            {!rows.length && <tr><td colSpan={8} className="empty">Sin resultados.</td></tr>}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="pager">
          <button className="ghost" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← Anterior</button>
          <span>Página {page + 1} de {pages}</span>
          <button className="ghost" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Siguiente →</button>
        </div>
      )}
    </div>
  );
}

// ---------- Alertas ----------
function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  async function load() {
    const { data } = await supabase.from("alerts").select("*").order("created_at", { ascending: false }).limit(300);
    setAlerts((data ?? []) as Alert[]);
  }
  useEffect(() => {
    load();
    const ch = supabase.channel("al").on("postgres_changes", { event: "*", schema: "public", table: "alerts" }, () => load()).subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);
  async function ack(id: string) { await supabase.from("alerts").update({ acknowledged: true }).eq("id", id); load(); }
  return (
    <div className="panel">
      <h2>Alertas ({alerts.filter((a) => !a.acknowledged).length} sin atender)</h2>
      <ul className="alerts">
        {alerts.map((a) => (
          <li key={a.id} className={`alert ${a.acknowledged ? "ack" : ""}`}>
            <span className={`akind akind-${a.kind}`}>{a.kind}</span>
            <span className="amsg">{a.message}</span>
            {!a.acknowledged && <button className="ghost" onClick={() => ack(a.id)}>Atender</button>}
          </li>
        ))}
        {!alerts.length && <li className="empty">Sin alertas.</li>}
      </ul>
    </div>
  );
}

function Kpi({ n, label, tone }: { n: number; label: string; tone?: string }) {
  return <div className={`kpi ${tone ? "kpi-" + tone : ""}`}><div className="kpi-n">{Number(n).toLocaleString()}</div><div className="kpi-l">{label}</div></div>;
}
function Insight({ title, items }: { title: string; items: { key: string; main: string; meta: string }[] }) {
  return (
    <div className="insight">
      <div className="insight-h">{title} <span className="insight-c">{items.length}</span></div>
      <ul>{items.slice(0, 8).map((i) => <li key={i.key}><span className="clip">{i.main}</span><span className="insight-m">{i.meta}</span></li>)}</ul>
    </div>
  );
}
function Empty() { return <div className="empty">Sin datos. Carga un CSV.</div>; }

// ---------- Raíz ----------
function App() {
  const [profile, setProfile] = useState<Profile | null>(() => {
    const raw = localStorage.getItem(PROFILE_KEY);
    return raw ? (JSON.parse(raw) as Profile) : null;
  });
  const [tab, setTab] = useState<"dash" | "find" | "upload" | "alerts">("dash");
  const [reload, setReload] = useState(0);

  if (!hasSupabase) return <main className="login"><div className="login-card"><h1 className="login-brand">Falta Supabase</h1></div></main>;
  if (!profile) return <Login onDone={setProfile} />;

  return (
    <main className="container">
      <div className="header">
        <h1>Scotia · Reporter</h1>
        <div className="header-right">
          <span className="user-chip">{profile.name} · {profile.scotiaId}</span>
          <button className="ghost" onClick={() => { localStorage.removeItem(PROFILE_KEY); setProfile(null); }}>Salir</button>
        </div>
      </div>
      <nav className="tabs">
        <button className={tab === "dash" ? "active" : ""} onClick={() => setTab("dash")}>Dashboard</button>
        <button className={tab === "find" ? "active" : ""} onClick={() => setTab("find")}>Hallazgos</button>
        <button className={tab === "upload" ? "active" : ""} onClick={() => setTab("upload")}>Cargar CSV</button>
        <button className={tab === "alerts" ? "active" : ""} onClick={() => setTab("alerts")}>Alertas</button>
      </nav>
      {tab === "dash" && <Dashboard key={reload} />}
      {tab === "find" && <Hallazgos />}
      {tab === "upload" && <Upload onDone={() => setReload((r) => r + 1)} />}
      {tab === "alerts" && <Alerts />}
    </main>
  );
}

export default App;
