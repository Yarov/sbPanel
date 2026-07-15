import { useEffect, useMemo, useState } from "react";
import { supabase, hasSupabase } from "./supabase";
import { parseCsv, toObjects } from "./lib/csv";
import { ingest, SOURCES, SourceId, IngestResult } from "./lib/ingest";

type Profile = { scotiaId: string; name: string };
type Finding = {
  id: string; finding_key: string; source: string; epm: string | null; asset: string | null;
  title: string; cve: string | null; severity_scanner: string | null; severity_scotia: string | null;
  cvss: number | null; vpr: number | null; status: string; first_observed: string;
  kri_status: string | null; remaining_days: number | null;
};
type Alert = { id: string; kind: string; message: string; severity: string | null; acknowledged: boolean; created_at: string };
type AppScan = { source: string; project_name: string; epm: string | null; risk_level: string | null; policy_status: string | null; crit: number; high: number; med: number; low: number };
type Debt = { asset: string; title: string; true_age_days: number };
type Cross = { epm: string; capas: number; fuentes: string };

const PROFILE_KEY = "scotia_profile";
const sevClass = (s?: string | null) => `sev sev-${(s || "").toLowerCase()}`;

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

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr(""); setRes(null);
    try {
      const objs = toObjects(parseCsv(await file.text()));
      if (!objs.length) throw new Error("El CSV no tiene filas de datos.");
      const r = await ingest(source, objs);
      setRes({ ...r, rows: objs.length });
      onDone();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
      e.target.value = "";
    }
  }

  return (
    <div className="panel">
      <h2>Cargar escaneo (CSV)</h2>
      <p className="hint">Elige la fuente y sube el CSV. La conciliación es automática: detecta nuevas,
        cierra las que ya no aparecen, <b>reabre y alerta</b> las que resurgen.</p>
      <div className="sources">
        {SOURCES.map((s) => (
          <button key={s.id} className={`src ${source === s.id ? "active" : ""}`} onClick={() => setSource(s.id)}>
            {s.label}<span className="src-grain">{s.grain}</span>
          </button>
        ))}
      </div>
      <label className={`dropzone ${busy ? "busy" : ""}`}>
        <input type="file" accept=".csv,text/csv" onChange={onFile} disabled={busy} hidden />
        {busy ? "Procesando…" : `Suelta o elige el CSV de ${SOURCES.find((s) => s.id === source)!.label}`}
      </label>
      {err && <p className="error">{err}</p>}
      {res && (
        <div className="ingest-result">
          <p>✅ Procesadas <b>{res.rows}</b> filas.</p>
          <div className="chips">
            {Object.entries(res.summary).map(([k, v]) => (
              <span key={k} className={`chip chip-${k}`}>{k}: <b>{v}</b></span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Dashboard ----------
function Dashboard() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<AppScan[]>([]);
  const [debt, setDebt] = useState<Debt[]>([]);
  const [cross, setCross] = useState<Cross[]>([]);
  const [q, setQ] = useState("");

  async function load() {
    const [f, s, d, c] = await Promise.all([
      supabase.from("findings").select("*").order("last_seen", { ascending: false }).limit(500),
      supabase.from("app_scans").select("*").order("crit", { ascending: false }).limit(200),
      supabase.from("v_hidden_debt").select("asset,title,true_age_days").order("true_age_days", { ascending: false }),
      supabase.from("v_cross_layer").select("*").order("capas", { ascending: false }),
    ]);
    setFindings((f.data ?? []) as Finding[]);
    setScans((s.data ?? []) as AppScan[]);
    setDebt((d.data ?? []) as Debt[]);
    setCross((c.data ?? []) as Cross[]);
  }
  useEffect(() => {
    load();
    const ch = supabase.channel("dash")
      .on("postgres_changes", { event: "*", schema: "public", table: "findings" }, () => load())
      .on("postgres_changes", { event: "*", schema: "public", table: "app_scans" }, () => load())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);

  const kpi = useMemo(() => {
    const open = findings.filter((f) => f.status !== "fixed");
    return {
      total: findings.length,
      open: open.length,
      resurfaced: findings.filter((f) => f.status === "resurfaced").length,
      critical: open.filter((f) => (f.severity_scanner || "").toLowerCase() === "critical").length,
      debt: debt.length,
    };
  }, [findings, debt]);

  const resurfaced = findings.filter((f) => f.status === "resurfaced");
  const recast = findings.filter(
    (f) => f.status !== "fixed" &&
      ["critical", "high"].includes((f.severity_scanner || "").toLowerCase()) &&
      (f.severity_scotia || "").toLowerCase() === "low"
  );
  const visible = findings.filter((f) => {
    if (!q) return true;
    const s = `${f.asset} ${f.title} ${f.cve} ${f.epm}`.toLowerCase();
    return s.includes(q.toLowerCase());
  });

  return (
    <div>
      <div className="kpis">
        <Kpi n={kpi.total} label="Hallazgos" />
        <Kpi n={kpi.open} label="Abiertos" />
        <Kpi n={kpi.critical} label="Críticos" tone="red" />
        <Kpi n={kpi.resurfaced} label="Resurfaced" tone="amber" />
        <Kpi n={kpi.debt} label="Deuda oculta" tone="red" />
      </div>

      {debt.length > 0 && (
        <Insight title="🔴 Deuda oculta (KRI dice IN_TIME pero llevan años)" items={debt.map((d) => ({
          key: d.asset + d.title, main: d.title, meta: `${d.asset} · ${d.true_age_days} días reales`,
        }))} />
      )}
      {resurfaced.length > 0 && (
        <Insight title="♻️ Resurfaced (cerradas que volvieron)" items={resurfaced.map((f) => ({
          key: f.id, main: f.title, meta: `${f.asset} · ${f.severity_scanner}`,
        }))} />
      )}
      {recast.length > 0 && (
        <Insight title="⚖️ Recast sospechoso (scanner alto → Scotia Low)" items={recast.map((f) => ({
          key: f.id, main: f.title, meta: `${f.asset} · ${f.severity_scanner} → ${f.severity_scotia}`,
        }))} />
      )}
      {cross.length > 0 && (
        <Insight title="🔀 Riesgo cruzado (riesgo en varias capas)" items={cross.map((c) => ({
          key: c.epm, main: `EPM ${c.epm}`, meta: `${c.capas} capas · ${c.fuentes}`,
        }))} />
      )}

      {scans.length > 0 && (
        <div className="panel">
          <h3>Scorecard por aplicación (AppSec)</h3>
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
      )}

      <div className="panel">
        <div className="panel-head">
          <h3>Hallazgos ({visible.length})</h3>
          <input className="search" value={q} onChange={(e) => setQ(e.currentTarget.value)} placeholder="Buscar activo, CVE, app…" />
        </div>
        <table className="tbl">
          <thead><tr><th>Sev</th><th>Estado</th><th>Activo</th><th>Título</th><th>EPM</th><th>KRI</th></tr></thead>
          <tbody>
            {visible.slice(0, 200).map((f) => (
              <tr key={f.id}>
                <td><span className={sevClass(f.severity_scanner)}>{f.severity_scanner ?? "—"}</span></td>
                <td><span className={`st st-${f.status}`}>{f.status}</span></td>
                <td className="mono">{f.asset}</td>
                <td>{f.title}</td>
                <td>{f.epm ?? "—"}</td>
                <td>{f.kri_status ?? "—"}{f.remaining_days != null ? ` · ${f.remaining_days}d` : ""}</td>
              </tr>
            ))}
            {!visible.length && <tr><td colSpan={6} className="empty">Sin hallazgos. Carga un CSV.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Kpi({ n, label, tone }: { n: number; label: string; tone?: string }) {
  return <div className={`kpi ${tone ? "kpi-" + tone : ""}`}><div className="kpi-n">{n}</div><div className="kpi-l">{label}</div></div>;
}
function Insight({ title, items }: { title: string; items: { key: string; main: string; meta: string }[] }) {
  return (
    <div className="insight">
      <div className="insight-h">{title} <span className="insight-c">{items.length}</span></div>
      <ul>{items.slice(0, 8).map((i) => <li key={i.key}><span>{i.main}</span><span className="insight-m">{i.meta}</span></li>)}</ul>
    </div>
  );
}

// ---------- Alertas ----------
function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  async function load() {
    const { data } = await supabase.from("alerts").select("*").order("created_at", { ascending: false }).limit(200);
    setAlerts((data ?? []) as Alert[]);
  }
  useEffect(() => {
    load();
    const ch = supabase.channel("al").on("postgres_changes", { event: "*", schema: "public", table: "alerts" }, () => load()).subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);
  async function ack(id: string) {
    await supabase.from("alerts").update({ acknowledged: true }).eq("id", id);
    load();
  }
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

// ---------- Raíz ----------
function App() {
  const [profile, setProfile] = useState<Profile | null>(() => {
    const raw = localStorage.getItem(PROFILE_KEY);
    return raw ? (JSON.parse(raw) as Profile) : null;
  });
  const [tab, setTab] = useState<"dash" | "upload" | "alerts">("dash");
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
        <button className={tab === "upload" ? "active" : ""} onClick={() => setTab("upload")}>Cargar CSV</button>
        <button className={tab === "alerts" ? "active" : ""} onClick={() => setTab("alerts")}>Alertas</button>
      </nav>
      {tab === "dash" && <Dashboard key={reload} />}
      {tab === "upload" && <Upload onDone={() => setReload((r) => r + 1)} />}
      {tab === "alerts" && <Alerts />}
    </main>
  );
}

export default App;
