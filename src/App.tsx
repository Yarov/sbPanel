import { useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase, hasSupabase } from "./supabase";
import { ingestFile, SOURCES, SourceId, IngestResult } from "./lib/ingest";
import { Donut, StackH, Aging, Trend, TopBars, KRI_COLORS } from "./Charts";
import {
  AlertOctagon, Layers, ShieldX, Scale,
  Loader2, Search, CheckCircle2, AlertTriangle, X, ChevronLeft, ChevronRight,
} from "lucide-react";

type Finding = {
  finding_key: string; source: string; epm: string | null; asset: string | null;
  title: string; cve: string | null; severity_scanner: string | null; severity_scotia: string | null;
  status: string; first_observed: string; kri_status: string | null; remaining_days: number | null;
  it_vp: string | null; it_manager: string | null; app_name: string | null;
  sla_days: number | null; edad_dias: number; vencido_real: boolean; usage: string | null;
};
type Activity = {
  id: number; at: string; event: string; finding_key: string; de: string | null; a: string | null;
  title: string | null; asset: string | null; app_name: string | null; it_vp: string | null;
  severity_scanner: string | null; source_file: string | null; loaded_by: string | null;
};
type Load = {
  load_id: string; state: string; started_at: string; loaded_by: string | null;
  source_file: string | null; data_date: string | null; rows_seen: number;
  rows_closed: number; epms_seen: number; blocked_reason: string | null;
};
type AppScan = { source: string; project_name: string; epm: string | null; policy_status: string | null; risk_level: string | null; crit: number; high: number; med: number; low: number };
const SEVS = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["open", "resurfaced", "fixed", "not_observed"];
const sevClass = (s?: string | null) => `sev sev-${(s || "").toLowerCase()}`;

// ---------- Login (Supabase Auth) ----------
// Antes esto era un localStorage.setItem con tu nombre: cualquiera con la URL
// entraba. La data trae hostnames de PROD con sus CVEs abiertos, así que ahora
// exige sesión de verdad y la RLS solo responde a `authenticated`.
function Login() {
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    const { error } = await supabase.auth.signInWithPassword({
      email: email.trim(), password: pass,
    });
    if (error) setErr(error.message);
    setBusy(false);
  }

  return (
    <main className="login">
      <div className="login-card">
        <h1 className="login-brand">Scotia · Reporter</h1>
        <p className="login-sub">Gestión de vulnerabilidades</p>
        <form onSubmit={submit}>
          <input type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)}
            placeholder="Correo" autoFocus autoComplete="username" />
          <input type="password" value={pass} onChange={(e) => setPass(e.currentTarget.value)}
            placeholder="Contraseña" autoComplete="current-password" />
          <button type="submit" disabled={busy}>{busy ? "Entrando…" : "Entrar"}</button>
        </form>
        {err && <p className="error"><AlertTriangle size={15} /> {err}</p>}
        <p className="login-foot">Las cuentas se dan de alta en Supabase → Authentication.</p>
      </div>
    </main>
  );
}

// ---------- Cargar CSV ----------
function Upload({ onDone, quien }: { onDone: () => void; quien: string }) {
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
      const r = await ingestFile(source, file, setProg, quien);
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
  it_vp: "", it_manager: "", app: "", severity: "", kri: "", status: "", usage: "",
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
  const [ej, setEj] = useState<any>(null);
  const fRef = useRef(f); fRef.current = f;

  useEffect(() => {
    supabase.rpc("metricas_ejecutivas", { p_source: "tenable" }).then((r) => setEj(r.data));
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
      p_usage: g.usage || null,
    });
    setM(data ?? EMPTY_M);
    const [d, rc, c, sc] = await Promise.all([
      supabase.from("v_hidden_debt").select("asset,title,edad_dias,sla_days,it_vp").order("edad_dias", { ascending: false }).limit(8),
      supabase.from("v_recast_log").select("*").order("at", { ascending: false }).limit(8),
      supabase.from("v_cross_layer").select("*").order("capas", { ascending: false }).limit(8),
      supabase.from("v_app_scans").select("*").order("crit", { ascending: false }).limit(30),
    ]);
    setDebt(d.data ?? []); setRecast(rc.data ?? []);
    setCross(c.data ?? []); setScans((sc.data ?? []) as AppScan[]);
  }
  useEffect(() => { load(); }, [f]);
  useEffect(() => {
    // Solo el acta: una carga movía 63,600 filas de findings y cada una emitía
    // un mensaje de realtime evaluado contra RLS por suscriptor.
    const ch = supabase.channel("dash")
      .on("postgres_changes", { event: "*", schema: "bronze", table: "loads" }, () => load())
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
        <select value={f.usage} onChange={(e) => set("usage", e.currentTarget.value)}>
          <option value="">Ambiente</option>{(opts.usage ?? []).map((a) => <option key={a}>{a}</option>)}
        </select>
        {active && <button className="ghost btn-i" onClick={() => setF(EMPTY_F)}><X size={14} /> Limpiar</button>}
      </div>

      <div className="kpis">
        <Kpi n={kpi.abiertos ?? 0} label="Abiertos" />
        <Kpi n={kpi.criticos ?? 0} label="Críticos" tone="red" />
        <Kpi n={kpi.vencidos ?? 0} label="Vencidos (SLA real)" tone="red" />
        <Kpi n={kpi.deuda_oculta ?? 0} label="Deuda oculta" tone="red" />
        <Kpi n={kpi.resurfaced ?? 0} label="Resurfaced" tone="amber" />
        <Kpi n={kpi.no_observados ?? 0} label="No observados" tone="amber" />
        <Kpi n={kpi.prod ?? 0} label="En producción" />
        <Kpi n={kpi.expuestos ?? 0} label="Expuestos" tone="amber" />
        <Kpi n={kpi.vps ?? 0} label="IT VP" />
        <Kpi n={kpi.apps ?? 0} label="Aplicaciones" />
      </div>

      {ej && (
        <div className="charts">
          <div className="chart-card wide">
            <h3>Nuevos vs remediados por carga <span className="h3-sub">¿ganamos o perdemos terreno?</span></h3>
            {ej.nuevos_vs_atendidos?.length ? <Trend data={ej.nuevos_vs_atendidos} /> : <Empty />}
          </div>
          <div className="chart-card gauge-card">
            <h3>Cumplimiento SLA</h3>
            <div className="gauge">
              <div className={`gauge-n ${(ej.sla_compliance ?? 100) < 80 ? "i-red" : "i-green"}`}>
                {ej.sla_compliance != null ? `${ej.sla_compliance}%` : "—"}
              </div>
              <div className="gauge-l">abiertos dentro de plazo</div>
              <div className="gauge-sub">MTTR: {ej.mttr_dias != null ? `${ej.mttr_dias} días` : "s/d"} · {ej.kpi?.cargas ?? 0} cargas</div>
            </div>
          </div>
          <div className="chart-card">
            <h3>Top apps que más incumplen SLA</h3>
            {ej.top_incumplen?.length ? <TopBars data={ej.top_incumplen} color="#fbbf24" /> : <Empty />}
          </div>
        </div>
      )}

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
          meta: `${d.asset} · ${d.edad_dias}d reales vs SLA ${d.sla_days}d · ${d.it_vp ?? "sin VP"}`,
        }))} />
      )}
      {recast.length > 0 && (
        <Insight icon={<Scale size={15} className="i-amber" />} title="Recast: el banco cambió la severidad (quién y cuándo)" items={recast.map((r: any) => ({
          key: r.finding_key + r.at, main: r.title ?? r.finding_key,
          meta: `escáner: ${r.severidad_escaner} · banco: ${r.severidad_antes ?? "—"} → ${r.severidad_despues} · ${r.loaded_by ?? "?"} el ${(r.at ?? "").slice(0, 10)}`,
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
              <tr key={r.finding_key}>
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

// ---------- Actividad (la bitácora) + acta de cargas ----------
// Reemplaza la pestaña de Alertas. Antes eran alertas que la ingesta inventaba
// al vuelo; ahora son los cambios que de verdad ocurrieron, con su carga y autor.
const EV: Record<string, { txt: string; cls: string }> = {
  new: { txt: "nuevo", cls: "amber" },
  fixed: { txt: "remediado", cls: "green" },
  resurfaced: { txt: "reabierto", cls: "red" },
  not_observed: { txt: "no observado", cls: "amber" },
  reobserved: { txt: "reaparece", cls: "amber" },
  recast: { txt: "recast", cls: "red" },
  reassigned: { txt: "reasignado", cls: "blue" },
  sla_changed: { txt: "cambió SLA", cls: "blue" },
};

function Actividad() {
  const [rows, setRows] = useState<Activity[]>([]);
  const [loads, setLoads] = useState<Load[]>([]);
  const [ev, setEv] = useState("");

  async function load() {
    let q = supabase.from("v_activity").select("*").order("at", { ascending: false }).limit(200);
    if (ev) q = q.eq("event", ev);
    const [a, l] = await Promise.all([
      q, supabase.from("v_loads").select("*").order("started_at", { ascending: false }).limit(12),
    ]);
    setRows((a.data ?? []) as Activity[]);
    setLoads((l.data ?? []) as Load[]);
  }
  useEffect(() => { load(); }, [ev]);
  useEffect(() => {
    const ch = supabase.channel("act")
      .on("postgres_changes", { event: "*", schema: "bronze", table: "loads" }, () => load())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);

  const frenadas = loads.filter((l) => l.state === "pending_review");

  return (
    <div>
      {frenadas.length > 0 && (
        <div className="panel">
          <h3><AlertTriangle size={15} className="i-amber" /> Cargas frenadas ({frenadas.length})</h3>
          <p className="hint">Nada se cerró. Revisa el motivo antes de reintentar.</p>
          <ul className="alerts">
            {frenadas.map((l) => (
              <li key={l.load_id} className="alert">
                <span className="akind akind-policy"><ShieldX size={15} className="i-amber" />frenada</span>
                <span className="amsg"><b>{l.source_file}</b> · {l.blocked_reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="panel">
        <h3>Acta de cargas</h3>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead><tr><th>Archivo</th><th>Estado</th><th>Fecha del dato</th><th>Filas</th>
              <th>No obs.</th><th>Apps</th><th>Por</th><th>Cuándo</th></tr></thead>
            <tbody>
              {loads.map((l) => (
                <tr key={l.load_id}>
                  <td className="clip">{l.source_file ?? "—"}</td>
                  <td><span className={`st st-${l.state}`}>{l.state}</span></td>
                  <td className="mono">{l.data_date?.slice(0, 10) ?? "—"}</td>
                  <td>{l.rows_seen.toLocaleString()}</td>
                  <td className={l.rows_closed ? "warn" : ""}>{l.rows_closed.toLocaleString()}</td>
                  <td>{l.epms_seen}</td>
                  <td>{l.loaded_by ?? "—"}</td>
                  <td className="mono">{l.started_at.slice(0, 16).replace("T", " ")}</td>
                </tr>
              ))}
              {!loads.length && <tr><td colSpan={8} className="empty">Sin cargas todavía.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="filters-bar">
          <h3 className="grow">Bitácora</h3>
          <select value={ev} onChange={(e) => setEv(e.currentTarget.value)}>
            <option value="">Todos los eventos</option>
            {Object.entries(EV).map(([k, v]) => <option key={k} value={k}>{v.txt}</option>)}
          </select>
        </div>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead><tr><th>Cuándo</th><th>Evento</th><th>Hallazgo</th><th>App</th>
              <th>IT VP</th><th>Cambio</th><th>Carga</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.at.slice(0, 16).replace("T", " ")}</td>
                  <td><span className={`akind akind-${EV[r.event]?.cls ?? "blue"}`}>
                    {EV[r.event]?.txt ?? r.event}</span></td>
                  <td className="clip">{r.title ?? r.finding_key}</td>
                  <td className="clip">{r.app_name ?? "—"}</td>
                  <td>{r.it_vp ?? "—"}</td>
                  <td className="mono">{r.de ? `${r.de} → ${r.a}` : (r.a ?? "—")}</td>
                  <td className="clip">{r.source_file ?? "—"}{r.loaded_by ? ` · ${r.loaded_by}` : ""}</td>
                </tr>
              ))}
              {!rows.length && <tr><td colSpan={7} className="empty">Sin actividad.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// Barra de riesgo 0-100 con color por tramo (T0>66 rojo, medio ámbar, bajo gris).
function Risk({ score }: { score: number }) {
  const tono = score >= 66 ? "r" : score >= 33 ? "a" : "g";
  return (
    <span className="risk" title={`Risk score ${score}/100`}>
      <span className="risk-n">{score}</span>
      <span className="risk-bar"><span className={`risk-fill risk-${tono}`} style={{ width: `${Math.max(score, 4)}%` }} /></span>
    </span>
  );
}

// ---------- Gestión (la cola de remediación por app) ----------
type AppGestion = {
  epm: string; app_name: string | null; tier: string | null; usage: string | null;
  exposed_internet: boolean | null; mx_regulatory: boolean | null;
  it_vp: string | null; it_manager: string | null;
  contact_app: string | null; workflow_state: string; assignee: string | null;
  blocked_reason: string | null; updated_by: string | null; updated_at: string | null;
  abiertos: number; criticos: number; fuera_sla: number; vencidos: number;
  vencidos_altos: number; app_crit: number; risk_score: number;
  commitment_date: string | null; priority: string | null;
  compromiso_vencido: boolean; watchers: number;
};
type Watcher = { epm: string; watcher_type: string; watcher_id: string; added_by: string | null; added_at: string };
type WfEvent = { id: number; at: string; action: string; by_user: string; de: string | null; a: string | null; comment: string | null };

// Los estados humanos, con etiqueta y color. "atendido" es un reclamo sin
// verificar — el escáner es quien de verdad cierra.
const WF: Record<string, { txt: string; cls: string }> = {
  sin_asignar: { txt: "Sin asignar", cls: "gris" },
  asignado: { txt: "Asignado", cls: "blue" },
  en_atencion: { txt: "En atención", cls: "amber" },
  bloqueado_torre: { txt: "Torre no atiende", cls: "red" },
  atendido: { txt: "Atendido (sin verificar)", cls: "green" },
};
const WF_ESTADOS = Object.keys(WF);
const PRIOS: Record<string, { txt: string; cls: string }> = {
  urgent: { txt: "Urgente", cls: "r" }, high: { txt: "Alta", cls: "a" },
  normal: { txt: "Normal", cls: "b" }, low: { txt: "Baja", cls: "g" },
};

type VFinding = {
  finding_key: string; asset: string | null; title: string; cve: string | null;
  severity_scanner: string | null; vpr: number | null; status: string;
  kri_status: string | null; sla_days: number | null; edad_dias: number; vencido_real: boolean;
  es_falso_positivo: boolean; es_riesgo_aceptado: boolean; acepta_vence: string | null;
};

function Gestion() {
  const [rows, setRows] = useState<AppGestion[]>([]);
  const [f, setF] = useState({ estado: "", vp: "", solo_criticos: false });
  const [selEpm, setSelEpm] = useState<string | null>(null);

  async function load() {
    const { data } = await supabase.from("v_app_gestion").select("*")
      .order("risk_score", { ascending: false }).order("vencidos", { ascending: false });
    setRows((data ?? []) as AppGestion[]);
  }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    const ch = supabase.channel("gest")
      .on("postgres_changes", { event: "*", schema: "silver", table: "app_workflow" }, () => load())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, []);

  if (selEpm) return <AppDetail epm={selEpm} onBack={() => { setSelEpm(null); load(); }} />;

  const vps = [...new Set(rows.map((r) => r.it_vp).filter(Boolean) as string[])].sort();
  const vista = rows.filter((r) =>
    (!f.estado || r.workflow_state === f.estado) &&
    (!f.vp || r.it_vp === f.vp) &&
    (!f.solo_criticos || r.criticos > 0));

  return (
    <div className="panel">
      <div className="filters-bar">
        <h2 className="grow">Cola de remediación · {vista.length} apps</h2>
        <select value={f.vp} onChange={(e) => setF((p) => ({ ...p, vp: e.currentTarget.value }))}>
          <option value="">Todos los IT VP</option>{vps.map((v) => <option key={v}>{v}</option>)}
        </select>
        <select value={f.estado} onChange={(e) => setF((p) => ({ ...p, estado: e.currentTarget.value }))}>
          <option value="">Todo estado</option>{WF_ESTADOS.map((s) => <option key={s} value={s}>{WF[s].txt}</option>)}
        </select>
        <button className={`chip-toggle ${f.solo_criticos ? "on" : ""}`}
          onClick={() => setF((p) => ({ ...p, solo_criticos: !p.solo_criticos }))}>Solo con críticos</button>
      </div>
      <p className="hint">El riesgo (críticos, vencidos) lo dice el escáner. El estado es el seguimiento del equipo — no cambia el número. Clic en una app para gestionarla.</p>
      <div className="tbl-wrap">
        <table className="tbl tbl-click">
          <thead><tr><th className="num">Risk</th><th>App</th><th>IT VP</th><th>Estado</th><th>Asignado</th>
            <th className="num">Crít</th><th className="num">Venc.</th><th className="num">Abiertos</th></tr></thead>
          <tbody>
            {vista.map((r) => (
              <tr key={r.epm} onClick={() => setSelEpm(r.epm)}>
                <td className="num"><Risk score={r.risk_score} /></td>
                <td className="clip">{r.app_name ?? r.epm}
                  {r.exposed_internet ? <span className="badge badge-exp" title="Expuesta a internet">internet</span> : null}
                  {r.mx_regulatory ? <span className="badge badge-reg" title="App regulatoria (CNBV)">reg</span> : null}</td>
                <td className="clip">{r.it_vp ?? "—"}</td>
                <td>
                  <span className={`akind akind-${WF[r.workflow_state]?.cls ?? "gris"}`}>{WF[r.workflow_state]?.txt ?? r.workflow_state}</span>
                  {r.priority && r.priority !== "normal" ? <span className={`prio prio-${PRIOS[r.priority]?.cls}`} title={`Prioridad ${PRIOS[r.priority]?.txt}`}>⚑</span> : null}
                  {r.watchers > 0 ? <span className="obs-count" title={`${r.watchers} observador(es)`}>👁 {r.watchers}</span> : null}
                  {r.commitment_date ? <span className={`due ${r.compromiso_vencido ? "due-venc" : ""}`} title="Fecha de compromiso">{r.commitment_date.slice(5)}</span> : null}
                </td>
                <td>{r.assignee ?? "—"}</td>
                <td className={`num ${r.criticos ? "hot" : ""}`}>{r.criticos}</td>
                <td className={`num ${r.vencidos ? "warn" : ""}`}>{r.vencidos}</td>
                <td className="num">{r.abiertos}</td>
              </tr>
            ))}
            {!vista.length && <tr><td colSpan={8} className="empty">Sin apps. Carga un escaneo.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const APP_TABS = [
  { id: "seg", txt: "Seguimiento" }, { id: "vuln", txt: "Vulnerabilidades" },
  { id: "act", txt: "Actividad" }, { id: "cont", txt: "Contactos" },
] as const;

// Página de detalle de una app: cabecera identidad+riesgo + pestañas.
function AppDetail({ epm, onBack }: { epm: string; onBack: () => void }) {
  const [app, setApp] = useState<AppGestion | null>(null);
  const [log, setLog] = useState<WfEvent[]>([]);
  const [watchers, setWatchers] = useState<Watcher[]>([]);
  const [vulns, setVulns] = useState<VFinding[]>([]);
  const [tab, setTab] = useState<string>("seg");

  async function recargar() {
    const [a, l, w, v] = await Promise.all([
      supabase.from("v_app_gestion").select("*").eq("epm", epm).single(),
      supabase.from("v_workflow_log").select("*").eq("epm", epm).order("at", { ascending: false }).limit(100),
      supabase.from("v_app_watchers").select("*").eq("epm", epm),
      supabase.from("v_findings").select("finding_key,asset,title,cve,severity_scanner,vpr,status,kri_status,sla_days,edad_dias,vencido_real,es_falso_positivo,es_riesgo_aceptado,acepta_vence")
        .eq("epm", epm).order("vpr", { ascending: false, nullsFirst: false }),
    ]);
    setApp((a.data ?? null) as AppGestion | null);
    setLog((l.data ?? []) as WfEvent[]); setWatchers((w.data ?? []) as Watcher[]);
    setVulns((v.data ?? []) as VFinding[]);
  }
  useEffect(() => { recargar(); }, [epm]);

  if (!app) return <div className="panel"><Loader2 size={18} className="spin" /></div>;
  const discrepancia = (app.workflow_state === "atendido" || app.workflow_state === "en_atencion") && app.criticos > 0;

  return (
    <div>
      <button className="ghost btn-i back-btn" onClick={onBack}><ChevronLeft size={15} /> Volver a la cola</button>
      <div className="app-header">
        <div className="app-title-row">
          <div>
            <h2>{app.app_name ?? app.epm}
              {app.exposed_internet ? <span className="badge badge-exp">internet</span> : null}
              {app.mx_regulatory ? <span className="badge badge-reg">regulatoria</span> : null}
              {app.usage ? <span className="badge badge-neutral">{app.usage}</span> : null}
              {app.tier ? <span className="badge badge-neutral">Tier {app.tier}</span> : null}
            </h2>
            <span className="hint">{app.epm} · {app.it_vp ?? "sin VP"} › {app.it_manager ?? "sin manager"}</span>
          </div>
          <div className="app-state-big">
            <span className={`akind akind-${WF[app.workflow_state]?.cls ?? "gris"}`}>{WF[app.workflow_state]?.txt ?? app.workflow_state}</span>
            {app.priority && app.priority !== "normal" ? <span className={`prio prio-${PRIOS[app.priority]?.cls}`}>⚑ {PRIOS[app.priority]?.txt}</span> : null}
            {app.watchers > 0 ? <span className="obs-count">👁 {app.watchers}</span> : null}
          </div>
        </div>
        <div className="app-metrics">
          <div className="am"><div className="am-n"><Risk score={app.risk_score} /></div><div className="am-l">Risk</div></div>
          <div className={`am ${app.criticos ? "am-red" : ""}`}><div className="am-n">{app.criticos}</div><div className="am-l">Críticos</div></div>
          <div className={`am ${app.vencidos ? "am-red" : ""}`}><div className="am-n">{app.vencidos}</div><div className="am-l">Vencidos SLA</div></div>
          <div className="am"><div className="am-n">{app.abiertos}</div><div className="am-l">Abiertos</div></div>
          <div className="am am-soft"><div className="am-l">— lo dice el escáner</div>
            <div className="am-sub">Asignado: <b>{app.assignee ?? "—"}</b>{app.commitment_date ? <> · Compromiso <b className={app.compromiso_vencido ? "i-red" : ""}>{app.commitment_date}</b></> : null}</div></div>
        </div>
        {discrepancia && (
          <div className="discrepancia"><AlertTriangle size={15} />
            Marcada <b>{WF[app.workflow_state]?.txt}</b> pero el escáner ve <b>{app.criticos} crítico(s) abiertos</b> — el fix no está confirmado. Marcar atendido NO cierra hallazgos: solo el próximo escaneo.</div>
        )}
        <nav className="app-tabs">
          {APP_TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
              {t.txt}{t.id === "vuln" ? ` · ${app.abiertos}` : ""}</button>
          ))}
        </nav>
      </div>

      {tab === "seg" && <SeguimientoTab app={app} log={log} watchers={watchers} onChange={recargar} />}
      {tab === "vuln" && <VulnsTab vulns={vulns} onChange={recargar} />}
      {tab === "act" && <div className="panel"><h3>Historial completo</h3><Timeline log={log} /></div>}
      {tab === "cont" && <ContactosTab app={app} watchers={watchers} />}
    </div>
  );
}

// Pestaña Seguimiento: timeline (lectura) + panel de acciones (escritura).
function SeguimientoTab({ app, log, watchers, onChange }: { app: AppGestion; log: WfEvent[]; watchers: Watcher[]; onChange: () => void }) {
  const [comentario, setComentario] = useState("");
  const [busy, setBusy] = useState(false);
  async function correr(fn: () => PromiseLike<{ error: any }>) {
    setBusy(true); const { error } = await fn(); setBusy(false);
    if (error) { alert(error.message); return; }
    onChange();
  }
  const comentar = () => { if (comentario) correr(() => supabase.rpc("wf_comment", { p_epm: app.epm, p_comment: comentario }).then((r) => { setComentario(""); return r; })); };
  return (
    <div className="seguimiento-grid">
      <div className="panel">
        <h3>Bitácora</h3>
        <div className="coment-box">
          <input value={comentario} onChange={(e) => setComentario(e.currentTarget.value)}
            placeholder="Escribir comentario…" onKeyDown={(e) => e.key === "Enter" && comentar()} />
          <button onClick={comentar} disabled={busy || !comentario}>Comentar</button>
        </div>
        <Timeline log={log} />
      </div>
      <AccionesPanel app={app} watchers={watchers} onChange={onChange} />
    </div>
  );
}

// Panel derecho: 4 cards de acción, cada una con su título.
function AccionesPanel({ app, watchers, onChange }: { app: AppGestion; watchers: Watcher[]; onChange: () => void }) {
  const [asignado, setAsignado] = useState(app.assignee ?? "");
  const [motivo, setMotivo] = useState(app.blocked_reason ?? "");
  const [fecha, setFecha] = useState(app.commitment_date ?? "");
  const [prio, setPrio] = useState(app.priority ?? "normal");
  const [nuevoObs, setNuevoObs] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => { setAsignado(app.assignee ?? ""); setMotivo(app.blocked_reason ?? ""); setFecha(app.commitment_date ?? ""); setPrio(app.priority ?? "normal"); }, [app.epm]);

  async function correr(fn: () => PromiseLike<{ error: any }>) {
    setBusy(true); setErr(""); const { error } = await fn(); setBusy(false);
    if (error) { setErr(error.message); return false; }
    onChange(); return true;
  }
  const bloqueando = false;
  const setEstado = (s: string) => correr(() => supabase.rpc("wf_set_state", { p_epm: app.epm, p_state: s, p_blocked_reason: motivo || null }));
  return (
    <div className="acciones">
      <div className="action-card">
        <label>Estado del seguimiento</label>
        <div className="wf-btns">
          {WF_ESTADOS.map((s) => (
            <button key={s} disabled={busy} className={`wf-btn wf-${WF[s].cls} ${app.workflow_state === s ? "on" : ""}`}
              onClick={() => setEstado(s)}>{WF[s].txt}</button>
          ))}
        </div>
        <input className="mt" value={motivo} onChange={(e) => setMotivo(e.currentTarget.value)}
          placeholder="Motivo del bloqueo (obligatorio para 'Torre no atiende')" />
      </div>
      <div className="action-card">
        <label>Responsable</label>
        <div className="row-inline">
          <input value={asignado} onChange={(e) => setAsignado(e.currentTarget.value)} placeholder="Nombre del responsable" />
          <button onClick={() => correr(() => supabase.rpc("wf_assign", { p_epm: app.epm, p_assignee: asignado }))} disabled={busy}>Asignar</button>
        </div>
      </div>
      <div className="action-card">
        <label>Fecha de compromiso y prioridad</label>
        <div className="row-inline">
          <input type="date" value={fecha} onChange={(e) => setFecha(e.currentTarget.value)} />
          <select value={prio} onChange={(e) => setPrio(e.currentTarget.value)}>
            {Object.entries(PRIOS).map(([k, v]) => <option key={k} value={k}>{v.txt}</option>)}
          </select>
          <button onClick={() => correr(() => supabase.rpc("wf_set_due", { p_epm: app.epm, p_commitment_date: fecha || null, p_priority: prio }))} disabled={busy}>Guardar</button>
        </div>
        <p className="hint">Del equipo — distinta del SLA del escáner.{app.compromiso_vencido && <b className="i-red"> · VENCIDO</b>}</p>
      </div>
      <div className="action-card">
        <label>Observadores ({watchers.length})</label>
        <ul className="wf-obs">
          {watchers.map((w) => (
            <li key={w.watcher_type + w.watcher_id}>
              <span className={`akind akind-${w.watcher_type === "grupo" ? "amber" : "blue"}`}>{w.watcher_type}</span>
              <span className="grow">{w.watcher_id}</span>
              <button className="ghost btn-i" onClick={() => correr(() => supabase.rpc("wf_watch", { p_epm: app.epm, p_watcher_id: w.watcher_id, p_watcher_type: w.watcher_type, p_remove: true }))} disabled={busy}><X size={13} /></button>
            </li>
          ))}
          {!watchers.length && <li className="empty">La torre se agrega sola al bloquear.</li>}
        </ul>
        <div className="row-inline">
          <input value={nuevoObs} onChange={(e) => setNuevoObs(e.currentTarget.value)} placeholder="correo del observador" />
          <button className="ghost" onClick={() => { if (nuevoObs) correr(() => supabase.rpc("wf_watch", { p_epm: app.epm, p_watcher_id: nuevoObs, p_watcher_type: "persona" }).then((r) => { setNuevoObs(""); return r; })); }} disabled={busy || !nuevoObs}>Agregar</button>
        </div>
      </div>
      {err && <p className="error"><AlertTriangle size={14} /> {err}</p>}
      {bloqueando}
    </div>
  );
}

// Timeline vertical agrupado por día.
function Timeline({ log }: { log: WfEvent[] }) {
  if (!log.length) return <div className="empty">Sin movimientos.</div>;
  const grupos: Record<string, WfEvent[]> = {};
  for (const e of log) { const d = e.at.slice(0, 10); (grupos[d] ??= []).push(e); }
  const hoy = new Date().toISOString().slice(0, 10);
  return (
    <div className="timeline">
      {Object.entries(grupos).map(([dia, evs]) => (
        <div key={dia} className="tl-day">
          <div className="tl-day-h">{dia === hoy ? "Hoy" : dia}</div>
          {evs.map((e) => (
            <div key={e.id} className="tl-entry">
              <span className={`tl-node tl-${e.action === "state" ? (WF[e.a ?? ""]?.cls ?? "b") : e.action === "comment" ? "b" : e.action === "due" ? "a" : "g"}`} />
              <div className="tl-body">
                <div className="tl-line"><b>{e.by_user}</b> <span className="tl-when">{e.at.slice(11, 16)}</span></div>
                <div className="tl-what">
                  {e.action === "assign" && <>asignó a <b>{e.a ?? "—"}</b></>}
                  {e.action === "state" && <>{WF[e.de ?? ""]?.txt ?? e.de ?? "—"} → <b>{WF[e.a ?? ""]?.txt ?? e.a}</b></>}
                  {e.action === "comment" && <>comentó</>}
                  {e.action === "due" && <>fijó compromiso → <b>{e.a}</b></>}
                  {e.action === "watch" && <>👁 {e.comment ?? "observador"} {e.a ?? e.de}</>}
                </div>
                {e.comment && e.action !== "watch" && <div className="tl-quote">“{e.comment}”</div>}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

// Pestaña Vulnerabilidades: los hallazgos de esta app, con triage por fila.
function VulnsTab({ vulns, onChange }: { vulns: VFinding[]; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  const abiertas = vulns.filter((v) => v.status !== "fixed" && v.status !== "not_observed");
  async function fp(v: VFinding) {
    setBusy(true);
    await supabase.rpc("fnd_false_positive", { p_finding_key: v.finding_key, p_reason: "marcado desde la app", p_undo: v.es_falso_positivo });
    setBusy(false); onChange();
  }
  async function aceptar(v: VFinding) {
    const aprob = prompt("¿Quién aprueba la aceptación de riesgo?"); if (!aprob) return;
    const just = prompt("Justificación / controles compensatorios:"); if (!just) return;
    const venc = prompt("Fecha de expiración (YYYY-MM-DD):"); if (!venc) return;
    setBusy(true);
    const { error } = await supabase.rpc("fnd_accept_risk", { p_finding_key: v.finding_key, p_aprobado_por: aprob, p_justificacion: just, p_fecha_expiracion: venc });
    setBusy(false); if (error) alert(error.message); else onChange();
  }
  return (
    <div className="panel">
      <h3>{abiertas.length} hallazgos abiertos <span className="hint">— la verdad del escáner, ningún estado humano los cierra</span></h3>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr><th>Sev</th><th className="num">VPR</th><th>Título</th><th>Activo</th><th>KRI</th><th className="num">SLA</th><th>Disposición</th><th></th></tr></thead>
          <tbody>
            {abiertas.map((v) => {
              const sla = v.sla_days != null ? v.edad_dias - v.sla_days : null;
              return (
                <tr key={v.finding_key} className={v.es_falso_positivo || v.es_riesgo_aceptado ? "row-muted" : ""}>
                  <td><span className={sevClass(v.severity_scanner)}>{v.severity_scanner ?? "—"}</span></td>
                  <td className="num">{v.vpr ?? "—"}</td>
                  <td className="clip">{v.title}</td>
                  <td className="mono clip">{v.asset}</td>
                  <td>{v.kri_status ?? "—"}</td>
                  <td className={`num ${v.vencido_real ? "warn" : ""}`}>{sla != null ? (sla > 0 ? `-${sla}d` : `${-sla}d`) : "—"}</td>
                  <td>
                    {v.es_falso_positivo ? <span className="badge badge-neutral">falso positivo</span> : null}
                    {v.es_riesgo_aceptado ? <span className="badge badge-reg" title={`Vence ${v.acepta_vence ?? ""}`}>riesgo aceptado</span> : null}
                  </td>
                  <td className="row-acts">
                    <button className="ghost btn-i" disabled={busy} onClick={() => fp(v)}>{v.es_falso_positivo ? "quitar FP" : "falso pos."}</button>
                    {!v.es_riesgo_aceptado && <button className="ghost btn-i" disabled={busy} onClick={() => aceptar(v)}>aceptar riesgo</button>}
                  </td>
                </tr>
              );
            })}
            {!abiertas.length && <tr><td colSpan={8} className="empty">Sin hallazgos abiertos.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Pestaña Contactos: cadena de escalamiento + observadores.
function ContactosTab({ app, watchers }: { app: AppGestion; watchers: Watcher[] }) {
  return (
    <div className="panel">
      <h3>Cadena de responsabilidad</h3>
      <ul className="cadena">
        <li><span className="cadena-rol">IT VP</span><b>{app.it_vp ?? "—"}</b></li>
        <li className="cadena-in"><span className="cadena-rol">IT Manager</span><b>{app.it_manager ?? "—"}</b></li>
        <li className="cadena-in2"><span className="cadena-rol">Contacto app</span><b>{app.contact_app ?? "—"}</b></li>
      </ul>
      <h3 className="mt2">Torre / escalamiento</h3>
      <p className="hint">Cuando el estado es "Torre no atiende", la torre entra como observador automáticamente.</p>
      <ul className="wf-obs">
        {watchers.map((w) => <li key={w.watcher_type + w.watcher_id}><span className={`akind akind-${w.watcher_type === "grupo" ? "amber" : "blue"}`}>{w.watcher_type}</span><span className="grow">{w.watcher_id}</span></li>)}
        {!watchers.length && <li className="empty">Sin observadores.</li>}
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
  const [session, setSession] = useState<Session | null>(null);
  const [cargando, setCargando] = useState(true);
  const [tab, setTab] = useState<"dash" | "find" | "gest" | "upload" | "act">("dash");
  const [reload, setReload] = useState(0);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session); setCargando(false);
    });
    const { data: sub } = supabase.auth.onAuthStateChange((_e, s) => setSession(s));
    return () => sub.subscription.unsubscribe();
  }, []);

  if (!hasSupabase) return <main className="login"><div className="login-card"><h1 className="login-brand">Falta Supabase</h1></div></main>;
  if (cargando) return <main className="login"><div className="login-card"><Loader2 size={20} className="spin" /></div></main>;
  if (!session) return <Login />;

  const quien = session.user.email ?? "";

  return (
    <main className="container">
      <div className="header">
        <h1>Scotia · Reporter</h1>
        <div className="header-right">
          <span className="user-chip">{quien}</span>
          <button className="ghost" onClick={() => supabase.auth.signOut()}>Salir</button>
        </div>
      </div>
      <nav className="tabs">
        <button className={tab === "dash" ? "active" : ""} onClick={() => setTab("dash")}>Dashboard</button>
        <button className={tab === "find" ? "active" : ""} onClick={() => setTab("find")}>Hallazgos</button>
        <button className={tab === "gest" ? "active" : ""} onClick={() => setTab("gest")}>Gestión</button>
        <button className={tab === "upload" ? "active" : ""} onClick={() => setTab("upload")}>Cargar CSV</button>
        <button className={tab === "act" ? "active" : ""} onClick={() => setTab("act")}>Actividad</button>
      </nav>
      {tab === "dash" && <Dashboard key={reload} />}
      {tab === "find" && <Hallazgos />}
      {tab === "gest" && <Gestion />}
      {tab === "upload" && <Upload quien={quien} onDone={() => setReload((r) => r + 1)} />}
      {tab === "act" && <Actividad />}
    </main>
  );
}

export default App;
