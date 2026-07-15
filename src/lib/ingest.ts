import { supabase } from "../supabase";

type Obj = Record<string, string>;

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

const CHUNK = 1500; // filas por lote (evita el límite de tamaño del request)

export type IngestResult = { grain: "findings" | "app_scans"; summary: Record<string, number> };
export type Progress = (done: number, total: number) => void;

export async function ingest(
  source: SourceId,
  objs: Obj[],
  onProgress?: Progress
): Promise<IngestResult> {
  // ---- Tenable: por hallazgo, conciliación por lotes ----
  if (source === "tenable") {
    const rows = objs.map((o) => ({
      finding_key: o["id"] || `${o["asset.name"]}|${o["definition.id"]}`,
      epm: o["EPM Code"] || o["EPM"] || null,
      asset: o["asset.name"] || o["Server Name"] || null,
      title: o["definition.name"] || o["ID Vuln"] || "(sin título)",
      cve: o["definition.cve"] || null,
      severity_scanner: o["severity"] || null,
      severity_scotia: o["Scotiabank Severity"] || null,
      cvss: num(o["definition.cvss3.base_score"]),
      vpr: num(o["definition.vpr.score"]),
      first_observed: o["first_observed"] || null,
      kri_status: o["KRI_STATUS"] || null,
      remaining_days: num(o["Remaining days"]),
      sla_days: 120,
      owner: o["Responsable de remediación (implementación / ejecución)"] || o["Responsable"] || null,
      area: o["Area"] || o["Área"] || null,
      plataforma: o["Plataforma"] || null,
      responsable: o["Responsable"] || o["Responsable de remediación (implementación / ejecución)"] || null,
      detail: { port: o["port"], protocol: o["protocol"], pais: o["Pais"], lob: o["Lob (Entity)"] },
    }));

    const scanTime = new Date().toISOString();
    const totals: Record<string, number> = { new: 0, updated: 0, resurfaced: 0, fixed: 0, errores: 0 };
    const nChunks = Math.max(1, Math.ceil(rows.length / CHUNK));

    for (let i = 0; i < rows.length; i += CHUNK) {
      onProgress?.(Math.floor(i / CHUNK), nChunks + 1);
      const { data, error } = await supabase.rpc("ingest_findings", {
        p_source: "tenable",
        p_rows: rows.slice(i, i + CHUNK),
        p_scan_time: scanTime,
        p_close_missing: false,
      });
      if (error) throw error;
      for (const k in totals) totals[k] += Number((data as any)?.[k] ?? 0);
    }

    // cierre final de ausentes (una sola vez, con el snapshot ya completo)
    onProgress?.(nChunks, nChunks + 1);
    const { data: fin, error: e2 } = await supabase.rpc("ingest_findings", {
      p_source: "tenable",
      p_rows: [],
      p_scan_time: scanTime,
      p_close_missing: true,
    });
    if (e2) throw e2;
    totals.fixed += Number((fin as any)?.fixed ?? 0);
    onProgress?.(nChunks + 1, nChunks + 1);
    return { grain: "findings", summary: totals };
  }

  // ---- AppSec: rollup por app (upsert por lotes, dedup por project_name) ----
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

  const nChunks = Math.max(1, Math.ceil(rows.length / CHUNK));
  for (let i = 0; i < rows.length; i += CHUNK) {
    onProgress?.(Math.floor(i / CHUNK), nChunks);
    const { error } = await supabase.from("app_scans").upsert(rows.slice(i, i + CHUNK), { onConflict: "source,project_name" });
    if (error) throw error;
  }
  onProgress?.(nChunks, nChunks);
  return { grain: "app_scans", summary: { cargados: rows.length } };
}
