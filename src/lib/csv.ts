export type Obj = Record<string, string>;

/**
 * Parser de CSV incremental.
 *
 * La versión de un solo golpe recorría el texto completo con un `for`; el estado
 * (campo a medias, comillas abiertas, fila a medias) vivía en variables locales
 * de esa función. Aquí ese mismo estado vive en el objeto, así que sobrevive
 * entre pedazos y podemos alimentarlo con lo que vaya llegando del disco sin
 * tener nunca el archivo entero en memoria.
 */
export class CsvParser {
  private field = "";
  private row: string[] = [];
  private inQuotes = false;
  /**
   * Dentro de comillas, un `"` puede cerrar el campo o ser la mitad de un `""`
   * escapado — y no se sabe hasta ver el carácter siguiente, que puede venir en
   * el pedazo que todavía no llega. Por eso no se decide aquí: se marca y se
   * resuelve al leer el próximo carácter.
   */
  private pendingQuote = false;
  private header: string[] | null = null;

  /** Cabecera del archivo, disponible después del primer push que la complete. */
  get columns(): string[] | null {
    return this.header;
  }

  /** Alimenta un pedazo de texto; devuelve las filas que quedaron completas. */
  push(chunk: string): Obj[] {
    const out: Obj[] = [];
    for (let i = 0; i < chunk.length; i++) {
      const c = chunk[i];

      if (this.pendingQuote) {
        this.pendingQuote = false;
        if (c === '"') {
          this.field += '"'; // era un "" escapado, seguimos dentro de comillas
          continue;
        }
        this.inQuotes = false; // era el cierre; el carácter actual se procesa normal
      }

      if (this.inQuotes) {
        if (c === '"') this.pendingQuote = true;
        else this.field += c;
        continue;
      }

      if (c === '"') this.inQuotes = true;
      else if (c === ",") { this.row.push(this.field); this.field = ""; }
      else if (c === "\n") { this.row.push(this.field); this.field = ""; this.emit(out); }
      else if (c !== "\r") this.field += c;
    }
    return out;
  }

  /** Cierra la última fila si el archivo no termina en salto de línea. */
  end(): Obj[] {
    const out: Obj[] = [];
    this.pendingQuote = false;
    this.inQuotes = false;
    if (this.field.length || this.row.length) {
      this.row.push(this.field);
      this.field = "";
      this.emit(out);
    }
    return out;
  }

  private emit(out: Obj[]) {
    const row = this.row;
    this.row = [];
    if (!row.some((x) => x.trim() !== "")) return; // fila en blanco
    if (!this.header) {
      this.header = row.map((h) => h.trim());
      return;
    }
    const o: Obj = {};
    for (let i = 0; i < this.header.length; i++) o[this.header[i]] = (row[i] ?? "").trim();
    out.push(o);
  }
}

export type StreamProgress = (p: { rows: number; bytes: number; total: number }) => void;

/**
 * Lee un File por pedazos y entrega las filas en lotes. Nunca tiene el archivo
 * completo —ni todas las filas— en memoria: cada lote se procesa y se suelta.
 */
export async function streamCsv(
  file: File,
  onBatch: (objs: Obj[], columns: string[]) => Promise<void>,
  batchSize = 1500,
  onProgress?: StreamProgress
): Promise<number> {
  const parser = new CsvParser();
  const reader = file.stream().pipeThrough(new TextDecoderStream()).getReader();
  let batch: Obj[] = [];
  let rows = 0;
  let bytes = 0;

  const flush = async () => {
    if (!batch.length) return;
    await onBatch(batch, parser.columns ?? []);
    rows += batch.length;
    batch = [];
    onProgress?.({ rows, bytes, total: file.size });
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      for (const o of parser.push(value)) {
        batch.push(o);
        if (batch.length >= batchSize) await flush();
      }
      onProgress?.({ rows, bytes, total: file.size });
    }
  } finally {
    reader.releaseLock();
  }
  for (const o of parser.end()) batch.push(o);
  await flush();
  return rows;
}

// ---- API de un golpe: sigue sirviendo para los CSV chicos de AppSec ----
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (c !== "\r") field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim() !== ""));
}

export function toObjects(rows: string[][]): Obj[] {
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => h.trim());
  return rows.slice(1).map((r) => {
    const o: Obj = {};
    header.forEach((h, i) => (o[h] = (r[i] ?? "").trim()));
    return o;
  });
}
