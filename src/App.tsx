import { useEffect, useRef, useState } from "react";
import { supabase, hasSupabase } from "./supabase";
import { ingestFile, SOURCES, SourceId, IngestResult } from "./lib/ingest";
import { Donut, StackH, Aging, KRI_COLORS } from "./Charts";
import {
  AlertOctagon, Layers, RotateCcw, ShieldAlert, ShieldX, CircleAlert, Scale,
  Loader2, Search, CheckCircle2, AlertTriangle, X, ChevronLeft, ChevronRight,
} from "lucide-react";

function AlertIcon({ kind }: { kind: string }) {
  const p = { size: 15 };
  if (kind === "kev") return <ShieldAlert {...p} className="i-red" />;
  if (kind === "appsec_critical") return <AlertOctagon {...p} className="i-red" />;
  if (kind === "resurfaced") return <RotateCcw {...p} className="i-red" />;
  if (kind === "policy") return <ShieldX {...p} className="i-blue" />;
  return <CircleAlert {...p} className="i-amber" />;
}

type Profile = { scotiaId: string; name: string };
type Finding = {
  id: string; finding_key: string; source: string; epm: string | null; asset: string | null;
  title: string; cve: string | null; severity_scanner: string | null; severity_scotia: string | null;
  status: string; first_observed: string; kri_status: string | null; remaining_days: number | null;
  area: string | null; plataforma: string | null; responsable: string | null;
  it_vp: string | null; it_manager: string | null; app_name: string | null;
  sla_days: number | null; exposed_internet: boolean | null;
};
type Alert = { id: string; kind: string; message: string; severity: string | null; acknowledged: boolean; created_at: string };
type AppScan = { source: string; project_name: string; epm: string | null; policy_status: string | null; risk_level: string | null; crit: number; high: number; med: number; low: number };
const PROFILE_KEY = "scotia_profile";
const SEVS = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["open", "resurfaced", "fixed"];
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
  const [res, setRes] = useState<IngestResult | null>(null);
  const [phase, setPhase] = useState("");
  const [prog, setProg] = useState<{ rows: number; bytes: number; total: number } | null>(null);
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
      setPhase("Leyendo y cargando…");
      const r = await ingestFile(source, file, setProg);
      setRes(r);
      onDone();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false); setProg(null); setPhase(""); e.target.value = "";
    }
  }

  // El streaming no sabe cuántas filas hay hasta terminar: el avance se mide
  // en bytes leídos del archivo, que sí se conocen desde el principio.
  const pct = prog && prog.total ? Math.round((prog.bytes / prog.total) * 100) : 0;
  const secs = busy && t0 ? ((performance.now() - t0) / 1000).toFixed(0) : "0";
  const mb = (b: number) => (b / 1e6).toFixed(1);

  return (
    <div className="panel">
      <h2>Cargar escaneo (CSV)</h2>
      <p className="hint">Elige la fuente y sube el CSV. La conciliación es automática: detecta nuevas,
        cierra las que ya no aparecen, <b>reabre y alerta</b> las que resurgen.</p>
      {source === "tenable" && (
        <p className="hint hint-warn"><AlertTriangle size={14} /> El export de Tenable viene en xlsx con
          91 columnas, y el navegador <b>no puede leer xlsx</b> (es un zip: habría que
          descomprimirlo entero en memoria). Pásalo antes por{" "}
          <code>python3 scripts/clean_tenable.py archivo.xlsx</code> — deja las 37 columnas
          que usa el dashboard en un CSV ~90% más ligero.</p>
      )}
      <div className="sources">
        {SOURCES.map((s) => (
          <button key={s.id} className={`src ${source === s.id ? "active" : ""}`} onClick={() => !busy && setSource(s.id)}>
            {s.label}<span className="src-grain">{s.grain}</span>
          </button>
        ))}
      </div>
      <label className={`dropzone ${busy ? "busy" : ""}`}>
        <input type="file" accept=".csv,text/csv" onChange={onFile} disabled={busy} hidden />
        {busy ? (
          <span className="dz-busy"><Loader2 size={16} className="spin" />
            {prog
              ? `${prog.rows.toLocaleString()} filas · ${mb(prog.bytes)}/${mb(prog.total)} MB · ${pct}% · ${secs}s`
              : phase}
          </span>
        ) : `Suelta o elige el CSV de ${SOURCES.find((s) => s.id === source)!.label}`}
      </label>
      {busy && prog && <div className="progress"><div className="progress-bar" style={{ width: `${Math.max(pct, 3)}%` }} /></div>}
      {err && <p className="error"><AlertTriangle size={15} /> {err}</p>}
      {res && (
        <div className="ingest-result">
          <p className="ok-line"><CheckCircle2 size={16} className="i-green" /> Procesadas <b>{res.rows.toLocaleString()}</b> filas.</p>
          <div className="chips">
            {Object.entries(res.summary).map(([k, v]) => <span key={k} className={`chip chip-${k}`}>{k}: <b>{v}</b></span>)}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Dashboard (métricas + gráficas filtrables) ----------
const EMPTY_M = { kpi: {}, by_severity: [], by_kri: [], by_it_vp: [], by_it_manager: [], by_app: [], by_age: [] };
const EMPTY_F = {
  it_vp: "", it_manager: "", app: "", severity: "", kri: "",
  status: "", source: "", area: "", plataforma: "", responsable: "",
};
type Org = { it_vp: string; it_manager: string; app_name: string; epm: string; abiertos: number };

function Dashboard() {
  const [m, setM] = useState<any>(EMPTY_M);
  const [debt, setDebt] = useState<any[]>([]);
  const [recast, setRecast] = useState<any[]>([]);
  const [cross, setCross] = useState<any[]>([]);
  const [scans, setScans] = useState<AppScan[]>([]);
  const [f, setF] = useState(EMPTY_F);
  const [org, setOrg] = useState<Org[]>([]);
  const [opts, setOpts] = useState<Record<string, string[]>>({});
  const fRef = useRef(f); fRef.current = f;

  useEffect(() => {
    supabase.from("v_org_tree").select("it_vp,it_manager,app_name,epm,abiertos").then((r) =>
      setOrg((r.data ?? []) as Org[]));
    supabase.from("v_filter_options").select("*").then((r) => {
      const o: Record<string, string[]> = {};
      for (const x of (r.data ?? []) as any[]) (o[x.kind] ??= []).push(x.label);
      for (const k in o) o[k].sort();
      setOpts(o);
    });
  }, []);

  async function load() {
    const g = fRef.current;
    const { data } = await supabase.rpc("dashboard_metrics", {
      p_it_vp: g.it_vp || null, p_it_manager: g.it_manager || null, p_app: g.app || null,
      p_severity: g.severity || null, p_kri: g.kri || null, p_status: g.status || null,
      p_source: g.source || null, p_area: g.area || null,
      p_plataforma: g.plataforma || null, p_responsable: g.responsable || null,
    });
    setM(data ?? EMPTY_M);
    const [d, rc, c, sc] = await Promise.all([
      supabase.from("v_hidden_debt").select("asset,title,true_age_days,sla_days,it_vp").order("true_age_days", { ascending: false }).limit(8),
      supabase.from("v_recast").select("title,asset,severity_scanner,severity_scotia,it_vp").limit(8),
      supabase.from("v_cross_layer").select("*").order("capas", { ascending: false }).limit(8),
      supabase.from("app_scans").select("*").order("crit", { ascending: false }).limit(30),
    ]);
    setDebt(d.data ?? []); setRecast(rc.data ?? []);
    setCross(c.data ?? []); setScans((sc.data ?? []) as AppScan[]);
  }
  useEffect(() => { load(); }, [f]);
  useEffect(() => {
    const ch = supabase.channel("dash")
      .on("postgres_changes", { event: "*", schema: "public", table: "findings" }, () => load())
      .on("postgres_changes", { event: "*", schema: "public", table: "app_scans" }, () => load())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);

  const kpi = m.kpi ?? {};
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));
  const active = Object.values(f).some(Boolean);

  // La cascada: el VP acota los managers, y VP+manager acotan las apps.
  // v_org_tree son pocas filas (distintos), así que se cascadea en cliente.
  const uniq = (xs: string[]) => [...new Set(xs)].sort();
  const vps = uniq(org.map((o) => o.it_vp));
  const managers = uniq(org.filter((o) => !f.it_vp || o.it_vp === f.it_vp).map((o) => o.it_manager));
  const apps = uniq(org
    .filter((o) => (!f.it_vp || o.it_vp === f.it_vp) && (!f.it_manager || o.it_manager === f.it_manager))
    .map((o) => o.app_name));

  // Al cambiar el VP, el manager/app elegidos pueden quedar fuera de su rama.
  const pickVp = (v: string) => setF((p) => ({ ...p, it_vp: v, it_manager: "", app: "" }));
  const pickMgr = (v: string) => setF((p) => ({ ...p, it_manager: v, app: "" }));

  return (
    <div>
      <div className="filters-bar">
        <select className="grow" value={f.it_vp} onChange={(e) => pickVp(e.currentTarget.value)}>
          <option value="">Todos los IT VP ({vps.length})</option>
          {vps.map((a) => <option key={a}>{a}</option>)}
        </select>
        <select className="grow" value={f.it_manager} onChange={(e) => pickMgr(e.currentTarget.value)}>
          <option value="">Todos los IT Manager ({managers.length})</option>
          {managers.map((a) => <option key={a}>{a}</option>)}
        </select>
        <select className="grow" value={f.app} onChange={(e) => set("app", e.currentTarget.value)}>
          <option value="">Todas las apps ({apps.length})</option>
          {apps.map((a) => <option key={a}>{a}</option>)}
        </select>
      </div>
      <div className="filters-bar">
        <select value={f.severity} onChange={(e) => set("severity", e.currentTarget.value)}>
          <option value="">Severidad</option>{SEVS.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.kri} onChange={(e) => set("kri", e.currentTarget.value)}>
          <option value="">KRI</option>{(opts.kri ?? []).map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.status} onChange={(e) => set("status", e.currentTarget.value)}>
          <option value="">Estado</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.source} onChange={(e) => set("source", e.currentTarget.value)}>
          <option value="">Fuente</option>{SOURCES.map((s) => <option key={s.id} value={s.id}>{s.id}</option>)}
        </select>
        <select value={f.area} onChange={(e) => set("area", e.currentTarget.value)}>
          <option value="">Área</option>{(opts.area ?? []).map((a) => <option key={a}>{a}</option>)}
        </select>
        <select value={f.responsable} onChange={(e) => set("responsable", e.currentTarget.value)}>
          <option value="">Responsable</option>{(opts.responsable ?? []).map((a) => <option key={a}>{a}</option>)}
        </select>
        {active && <button className="ghost btn-i" onClick={() => setF(EMPTY_F)}><X size={14} /> Limpiar</button>}
      </div>

      <div className="kpis">
        <Kpi n={kpi.abiertos ?? 0} label="Abiertos" />
        <Kpi n={kpi.criticos ?? 0} label="Críticos" tone="red" />
        <Kpi n={kpi.fuera_sla ?? 0} label="Fuera de SLA" tone="red" />
        <Kpi n={kpi.resurfaced ?? 0} label="Resurfaced" tone="amber" />
        <Kpi n={kpi.expuestos ?? 0} label="Expuestos a internet" tone="amber" />
        <Kpi n={kpi.vps ?? 0} label="IT VP" />
        <Kpi n={kpi.managers ?? 0} label="IT Manager" />
        <Kpi n={kpi.apps ?? 0} label="Aplicaciones" />
      </div>

      <div className="charts">
        <div className="chart-card">
          <h3>Por severidad</h3>
          {m.by_severity?.length ? <Donut data={m.by_severity} onSelect={(l) => set("severity", l)} /> : <Empty />}
        </div>
        <div className="chart-card">
          <h3>Estado KRI</h3>
          {m.by_kri?.length ? <Donut data={m.by_kri} unit="abiertos" colors={KRI_COLORS} onSelect={(l) => set("kri", l)} /> : <Empty />}
        </div>
        <div className="chart-card wide">
          <h3>Por IT VP <span className="h3-sub">clic para filtrar</span></h3>
          {m.by_it_vp?.length ? <StackH data={m.by_it_vp} onSelect={(l) => pickVp(l)} /> : <Empty />}
        </div>
        <div className="chart-card wide">
          <h3>Por IT Manager <span className="h3-sub">clic para filtrar</span></h3>
          {m.by_it_manager?.length ? <StackH data={m.by_it_manager} onSelect={(l) => pickMgr(l)} /> : <Empty />}
        </div>
        <div className="chart-card wide">
          <h3>Top aplicaciones</h3>
          {m.by_app?.length ? <StackH data={m.by_app} onSelect={(l) => set("app", l)} /> : <Empty />}
        </div>
        <div className="chart-card">
          <h3>Antigüedad de lo abierto</h3>
          {m.by_age?.length ? <Aging data={m.by_age} /> : <Empty />}
        </div>
      </div>

      {debt.length > 0 && (
        <Insight icon={<AlertOctagon size={15} className="i-red" />} title="Deuda oculta (KRI dice IN_TIME pero ya vencieron)" items={debt.map((d: any) => ({
          key: d.asset + d.title, main: d.title,
          meta: `${d.asset} · ${d.true_age_days}d reales vs SLA ${d.sla_days}d · ${d.it_vp ?? "sin VP"}`,
        }))} />
      )}
      {recast.length > 0 && (
        <Insight icon={<Scale size={15} className="i-amber" />} title="Recast sospechoso (el scanner dice Critical/High, Scotia lo bajó a Low)" items={recast.map((r: any) => ({
          key: r.asset + r.title, main: r.title,
          meta: `${r.severity_scanner} → ${r.severity_scotia} · ${r.asset} · ${r.it_vp ?? "sin VP"}`,
        }))} />
      )}
      {cross.length > 0 && (
        <Insight icon={<Layers size={15} className="i-blue" />} title="Riesgo cruzado (riesgo en varias capas)" items={cross.map((c: any) => ({
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
  const [f, setF] = useState({ sev: "", status: "", source: "", it_vp: "", it_manager: "" });
  const [org, setOrg] = useState<Org[]>([]);

  useEffect(() => {
    supabase.from("v_org_tree").select("it_vp,it_manager,app_name,epm,abiertos").then((r) =>
      setOrg((r.data ?? []) as Org[]));
  }, []);

  useEffect(() => {
    let cancel = false;
    (async () => {
      let query = supabase.from("findings").select("*", { count: "exact" });
      const term = q.trim().replace(/[,()]/g, " ");
      if (term) query = query.or(`asset.ilike.*${term}*,title.ilike.*${term}*,cve.ilike.*${term}*,epm.ilike.*${term}*,app_name.ilike.*${term}*,it_vp.ilike.*${term}*,it_manager.ilike.*${term}*`);
      if (f.sev) query = query.eq("severity_scanner", f.sev);
      if (f.status) query = query.eq("status", f.status);
      if (f.source) query = query.eq("source", f.source);
      if (f.it_vp) query = query.eq("it_vp", f.it_vp);
      if (f.it_manager) query = query.eq("it_manager", f.it_manager);
      query = query.order("last_seen", { ascending: false }).range(page * PAGE, page * PAGE + PAGE - 1);
      const { data, count } = await query;
      if (!cancel) { setRows((data ?? []) as Finding[]); setCount(count ?? 0); }
    })();
    return () => { cancel = true; };
  }, [q, f, page]);

  const uniq = (xs: string[]) => [...new Set(xs)].sort();
  const vps = uniq(org.map((o) => o.it_vp));
  const managers = uniq(org.filter((o) => !f.it_vp || o.it_vp === f.it_vp).map((o) => o.it_manager));

  const set = (k: string, v: string) => { setF((p) => ({ ...p, [k]: v })); setPage(0); };
  const pages = Math.ceil(count / PAGE);

  return (
    <div className="panel">
      <div className="filters-bar">
        <div className="search-wrap grow">
          <Search size={16} className="i-muted" />
          <input value={q} onChange={(e) => { setQ(e.currentTarget.value); setPage(0); }}
            placeholder="Buscar activo, título, CVE, EPM, app, IT VP, IT Manager…" />
        </div>
        <select value={f.it_vp} onChange={(e) => { setF((p) => ({ ...p, it_vp: e.currentTarget.value, it_manager: "" })); setPage(0); }}>
          <option value="">IT VP</option>{vps.map((a) => <option key={a}>{a}</option>)}
        </select>
        <select value={f.it_manager} onChange={(e) => set("it_manager", e.currentTarget.value)}>
          <option value="">IT Manager</option>{managers.map((a) => <option key={a}>{a}</option>)}
        </select>
        <select value={f.sev} onChange={(e) => set("sev", e.currentTarget.value)}>
          <option value="">Severidad</option>{SEVS.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.status} onChange={(e) => set("status", e.currentTarget.value)}>
          <option value="">Estado</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={f.source} onChange={(e) => set("source", e.currentTarget.value)}>
          <option value="">Fuente</option>{SOURCES.map((s) => <option key={s.id} value={s.id}>{s.id}</option>)}
        </select>
      </div>
      <p className="hint">{count.toLocaleString()} hallazgos</p>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr><th>Sev</th><th>Estado</th><th>Activo</th><th>Título</th><th>App</th><th>IT VP</th><th>IT Manager</th><th>KRI</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td><span className={sevClass(r.severity_scanner)}>{r.severity_scanner ?? "—"}</span></td>
                <td><span className={`st st-${r.status}`}>{r.status}</span></td>
                <td className="mono">{r.asset}</td>
                <td className="clip">{r.title}</td>
                <td className="clip">{r.app_name ?? r.epm ?? "—"}</td>
                <td>{r.it_vp ?? "—"}</td>
                <td>{r.it_manager ?? "—"}</td>
                <td>{r.kri_status ?? "—"}{r.remaining_days != null ? ` · ${r.remaining_days}d` : ""}</td>
              </tr>
            ))}
            {!rows.length && <tr><td colSpan={8} className="empty">Sin resultados.</td></tr>}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="pager">
          <button className="ghost btn-i" disabled={page === 0} onClick={() => setPage((p) => p - 1)}><ChevronLeft size={15} /> Anterior</button>
          <span>Página {page + 1} de {pages}</span>
          <button className="ghost btn-i" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Siguiente <ChevronRight size={15} /></button>
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
            <span className={`akind akind-${a.kind}`}><AlertIcon kind={a.kind} />{a.kind}</span>
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
function Insight({ icon, title, items }: { icon?: React.ReactNode; title: string; items: { key: string; main: string; meta: string }[] }) {
  return (
    <div className="insight">
      <div className="insight-h">{icon}<span>{title}</span> <span className="insight-c">{items.length}</span></div>
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
