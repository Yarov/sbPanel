import { supabase } from "../supabase";
import { streamCsv, parseCsv, toObjects, Obj } from "./csv";

export type SourceId = "tenable" | "blackduck" | "checkmarx" | "webinspect";

export const SOURCES: { id: SourceId; label: string; grain: string }[] = [
  { id: "tenable", label: "Tenable (Infra)", grain: "hallazgos" },
  { id: "blackduck", label: "Blackduck (SCA)", grain: "por app" },
  { id: "checkmarx", label: "Checkmarx (SAST)", grain: "por app" },
  { id: "webinspect", label: "WebInspect (DAST)", grain: "por app" },
];

const num = (v?: string) => {
  const n = parseFloat((v || "").replace(/[^0-9.\-]/g, ""));
  return isNaN(n) ? null : n;
};
const int = (v?: string) => Math.trunc(num(v) ?? 0);

// Tenable escribe "TBD"/"None" como texto, no como celda vacía.
const PLACEHOLDERS = new Set(["", "tbd", "none", "n/a", "na", "-"]);
const nn = (v?: string) => {
  const s = (v ?? "").trim();
  return PLACEHOLDERS.has(s.toLowerCase()) ? null : s;
};

// "SI" | "Yes" -> true · "No" -> false · cualquier otra cosa -> null
const bool = (v?: string) => {
  const s = (v ?? "").trim().toLowerCase();
  if (s === "si" || s === "sí" || s === "yes" || s === "y") return true;
  if (s === "no" || s === "n") return false;
  return null;
};

// "120d" -> 120 · "30d" -> 30. El SLA lo dicta Tenable, no lo asumimos.
const slaDays = (v?: string) => {
  const n = num(v);
  return n && n > 0 ? Math.trunc(n) : null;
};

// Tenable ya trae la máquina de estados resuelta; no la re-derivamos.
const STATE: Record<string, string> = {
  NEW: "open", ACTIVE: "open", REOPENED: "resurfaced",
  RESURFACED: "resurfaced", FIXED: "fixed",
};
const status = (v?: string) => STATE[(v ?? "").trim().toUpperCase()] ?? "open";

const CHUNK = 1500; // filas por lote (evita el límite de tamaño del request)

export type IngestResult = { grain: "findings" | "app_scans"; rows: number; summary: Record<string, number> };
export type Progress = (p: { rows: number; bytes: number; total: number }) => void;

// Columnas que el CSV de Tenable debe traer (las produce scripts/clean_tenable.py).
// `state` y `Remediation time` son obligatorias: sin la primera todo entra como
// 'open' ignorando a Tenable, y sin la segunda el SLA cae a un default que pinta
// IN_TIME a un Critical de 15d que lleva 20 días vencido.
const TENABLE_REQUERIDAS = [
  "id", "asset.name", "definition.name", "severity", "state",
  "first_observed", "Remediation time", "KRI_STATUS",
  "EPM Code", "App Name", "IT VP", "IT Manager",
];

export function validarTenable(columns: string[]): string | null {
  const faltan = TENABLE_REQUERIDAS.filter((c) => !columns.includes(c));
  if (!faltan.length) return null;
  return `Al CSV le faltan columnas: ${faltan.join(", ")}. ` +
    `¿Lo pasaste por scripts/clean_tenable.py?`;
}

const mapTenable = (o: Obj) => ({
  // Sin `id` no hay hallazgo. Antes había un fallback a asset|plugin que fusionaba
  // filas distintas (mismo plugin, distinto puerto) en una sola, y si `id` venía
  // vacío en todo el archivo, las 63,600 colapsaban en una.
  finding_key: nn(o["id"]),
  source: "tenable",
  plugin_id: nn(o["definition.id"]),
  asset: nn(o["asset.name"]),
  title: nn(o["definition.name"]) ?? "(sin título)",
  cve: nn(o["definition.cve"]),
  severity_scanner: nn(o["severity"]),
  severity_scotia: nn(o["Scotiabank Severity"]),
  cvss: num(o["definition.cvss3.base_score"]),
  vpr: num(o["definition.vpr.score"]),

  // ciclo de vida: lo que Tenable ya calculó
  state_scanner: nn(o["state"]),
  status: status(o["state"]),
  first_observed: nn(o["first_observed"]),
  last_fixed: nn(o["last_fixed"]),
  resurfaced_date: nn(o["resurfaced_date"]),
  recast_reason: nn(o["recast_reason"]),
  age_in_days: num(o["age_in_days"]),

  // SLA / KRI
  kri_status: nn(o["KRI_STATUS"]),
  sla_days: slaDays(o["Remediation time"]),
  remaining_days: num(o["Remaining days"]),

  // jerarquía organizacional: el eje del filtrado
  epm: nn(o["EPM Code"]),
  app_name: nn(o["App Name"]),
  tier: nn(o["Tier"]),
  cia: bool(o["CIA"]),
  contact_app: nn(o["Contact App"]),
  it_manager: nn(o["IT Manager"]),
  it_vp: nn(o["IT VP"]),
  it_svp: nn(o["IT SVP"]),

  // clasificación secundaria
  area: nn(o["Area"]),
  plataforma: nn(o["Plataforma"]),
  responsable: nn(o["Responsable"]),
  owner: nn(o["Contact App"]),
  managed_by: nn(o["Managed By"]),
  pais: nn(o["Pais"]),
  lob: nn(o["Lob (Entity)"]),

  // riesgo
  exposed_internet: bool(o["Exposed to the internet"]),
  mx_regulatory: bool(o["MX Regulatory App"]),

  port: nn(o["port"]),
  protocol: nn(o["protocol"]),
  usage: nn(o["Usage"]),
  user_interface: nn(o["User Interface"]),
  last_seen: nn(o["last_seen"]),
});

/**
 * Tenable en streaming: parsea y sube al mismo tiempo. Cada lote se manda y se
 * suelta, así que la memoria no crece con el tamaño del archivo — un CSV de
 * 35 MB y uno de 350 MB usan lo mismo. Además, como cada lote espera su RPC,
 * el hilo principal nunca se bloquea y la UI no se congela.
 */
export async function ingestTenable(
  file: File, onProgress?: Progress, loadedBy?: string
): Promise<IngestResult> {
  // begin -> batch* -> commit. El lock de carga única vive en load_begin: si otro
  // analista está cargando, esto falla aquí y no a la mitad.
  const { data: loadId, error: e0 } = await supabase.rpc("load_begin", {
    p_source: "tenable", p_loaded_by: loadedBy ?? null, p_source_file: file.name,
  });
  if (e0) throw e0;

  const totals: Record<string, number> = {
    new: 0, updated: 0, resurfaced: 0, recast: 0, reassigned: 0, errores: 0,
  };
  let enviadas = 0;
  let validado = false;

  try {
    await streamCsv(file, async (objs, columns) => {
      if (!validado) {
        const problema = validarTenable(columns);
        if (problema) throw new Error(problema);
        validado = true;
      }
      const { data, error } = await supabase.rpc("load_batch", {
        p_load_id: loadId, p_rows: objs.map(mapTenable),
      });
      if (error) throw error;
      enviadas += objs.length;
      for (const k in totals) totals[k] += Number((data as any)?.[k] ?? 0);
    }, CHUNK, onProgress);

    // El cliente declara cuánto mandó; la base compara con lo que registró.
    // Si no cuadra, la carga no se confirma: así se atrapan lotes perdidos.
    const { data: fin, error: e2 } = await supabase.rpc("load_commit", {
      p_load_id: loadId, p_expected_rows: enviadas,
    });
    if (e2) throw e2;

    const r = fin as any;
    if (r?.state === "pending_review") {
      throw new Error(
        `Carga frenada, nada se cerró: ${r.motivo}\n\n` +
        `Si de verdad es correcto, confírmalo desde el acta de cargas.`
      );
    }
    return {
      grain: "findings", rows: enviadas,
      summary: { ...totals, no_observados: Number(r?.no_observados ?? 0) },
    };
  } catch (err) {
    // Sin esto, un error deja la carga 'in_progress' para siempre y el lock
    // bloquea todas las siguientes.
    await supabase.rpc("load_abort", {
      p_load_id: loadId, p_reason: String((err as any)?.message ?? err).slice(0, 500),
    });
    throw err;
  }
}

/** Punto de entrada único: Tenable va por stream, AppSec cabe de un golpe. */
export async function ingestFile(source: SourceId, file: File, onProgress?: Progress, loadedBy?: string): Promise<IngestResult> {
  if (source === "tenable") return ingestTenable(file, onProgress, loadedBy);
  const objs = toObjects(parseCsv(await file.text()));
  if (!objs.length) throw new Error("El CSV no tiene filas de datos.");
  return ingestAppSec(source, objs, onProgress);
}

// ---- AppSec: rollup por app (upsert por lotes, dedup por project_name) ----
// Son cientos de filas, no decenas de miles: no necesitan streaming.
async function ingestAppSec(
  source: SourceId,
  objs: Obj[],
  onProgress?: Progress
): Promise<IngestResult> {
  const mapped = objs.map((o) => {
    if (source === "checkmarx")
      return {
        source, project_name: o["Project Name"], project_key: o["PROJECT KEY"] || null, epm: o["EPM"] || null,
        risk_level: o["Risk Level"] || null,
        crit: int(o["Critical Vulnerabilities"]), high: int(o["High Vulnerabilities"]),
        med: int(o["Medium Vulnerabilities"]), low: int(o["Low Vulnerabilities"]),
        last_scan: o["Last Scan"] || null, detail: { pipeline: o["PIPELINE"] },
      };
    if (source === "webinspect")
      return {
        source, project_name: o["Project Name"],
        crit: int(o["Critical"]), high: int(o["High"]), med: int(o["Medium"]), low: int(o["Low"]),
        detail: { version: o["Version ID"], branch: o["Branch Name"] },
      };
    return {
      source, project_name: o["Project Name"], project_key: o["PROJECT KEY"] || null,
      crit: int(o["Critical Security Risk Count"]), high: int(o["High Security Risk Count"]),
      med: int(o["Medium Security Risk Count"]), low: int(o["Low Security Risk Count"]),
      policy_status: o["Policy Status"] || null, last_scan: o["Last Scan Date"] || null,
      detail: { license_crit: o["Critical License Risk Count"], policy: o["Policy Status Summaries"] },
    };
  });

  // dedup por project_name (evita conflicto doble en el upsert)
  const seen = new Map<string, any>();
  for (const r of mapped) if (r.project_name) seen.set(r.project_name, r);
  const rows = [...seen.values()];

  for (let i = 0; i < rows.length; i += CHUNK) {
    const { error } = await supabase.from("app_scans").upsert(rows.slice(i, i + CHUNK), { onConflict: "source,project_name" });
    if (error) throw error;
    onProgress?.({ rows: Math.min(i + CHUNK, rows.length), bytes: 0, total: 0 });
  }
  return { grain: "app_scans", rows: rows.length, summary: { cargados: rows.length } };
}
