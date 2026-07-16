#!/usr/bin/env python3
"""
Adelgaza el export de Tenable: xlsx de 91 columnas -> CSV con las 37 que usa el dashboard.

    python3 scripts/clean_tenable.py "all data tanable.xlsx"
    python3 scripts/clean_tenable.py entrada.xlsx salida.csv

Las 7 columnas que se tiran (software_vulns, output, definition.description,
definition.cpe, asset.tags, definition.see_also, definition.solution) son el 76%
del peso del archivo y el dashboard no usa ninguna.
"""

import csv
import sys
from datetime import datetime, date, time
from pathlib import Path

try:
    import openpyxl
except ImportError:
    sys.exit("Falta openpyxl. Instala con:  pip3 install openpyxl")

# Las 37 columnas que alimentan el dashboard. El orden aquí es el del CSV de salida.
KEEP = [
    # identidad
    "id", "definition.id",
    # activo
    "asset.name",
    # vulnerabilidad
    "definition.name", "definition.cve",
    "definition.cvss3.base_score", "definition.vpr.score",
    "severity", "Scotiabank Severity",
    # ciclo de vida — Tenable ya lo calcula, no lo re-derivamos
    "state", "first_observed", "last_seen", "last_fixed",
    "resurfaced_date", "recast_reason", "age_in_days",
    # SLA / KRI
    "KRI_STATUS", "Remediation time", "Remaining days",
    # jerarquía organizacional — el eje del filtrado
    "EPM Code", "All APMs", "App Name", "Tier", "CIA", "Contact App",
    "IT Manager", "IT VP", "IT SVP",
    # clasificación secundaria
    "Area", "Plataforma", "Responsable", "Managed By", "Pais", "Lob (Entity)",
    # riesgo y ambiente
    "Usage", "User Interface", "Exposed to the internet", "MX Regulatory App",
    # red — necesarias para la llave durable, no van en un jsonb
    "port", "protocol",
]

# 'All APMs' está en plural. En la muestra siempre trae un solo valor idéntico a
# 'EPM Code', pero si en el archivo completo llega a traer varios, aplanarlo en
# silencio perdería una relación 1-a-N. Se avisa, no se adivina.
MULTI = "All APMs"

# Se tiran a propósito. Si alguna reaparece en KEEP, el archivo vuelve a engordar.
DROP_PESADAS = [
    "software_vulns", "output", "definition.description", "definition.cpe",
    "asset.tags", "definition.see_also", "definition.solution",
]

# 'ID Vuln' es un duplicado exacto de 'id' (mismo UUID). Se descarta.
PROGRESO_CADA = 5_000


def tam(b):
    return f"{b / 1e6:,.1f} MB" if b >= 1e6 else f"{b / 1e3:,.0f} KB"


def celda(v):
    if v is None:
        return ""
    if isinstance(v, (datetime, date, time)):
        return v.isoformat()
    if isinstance(v, str):
        # 'None' literal: openpyxl no lo traduce, viene así desde Tenable
        return "" if v == "None" else v.strip()
    return str(v)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)

    entrada = Path(sys.argv[1])
    if not entrada.exists():
        sys.exit(f"No existe: {entrada}")
    salida = Path(sys.argv[2]) if len(sys.argv) > 2 else entrada.with_suffix(".slim.csv")

    b_in = entrada.stat().st_size
    print(f"Leyendo {entrada.name} ({tam(b_in)})…", file=sys.stderr)

    wb = openpyxl.load_workbook(entrada, read_only=True, data_only=True)
    ws = wb.worksheets[0]
    filas = ws.iter_rows(values_only=True)

    try:
        hdr = [str(h).strip() if h is not None else "" for h in next(filas)]
    except StopIteration:
        sys.exit("El archivo está vacío.")

    faltantes = [c for c in KEEP if c not in hdr]
    if faltantes:
        print(f"\n✗ El export cambió: faltan {len(faltantes)} columnas esperadas:", file=sys.stderr)
        for c in faltantes:
            print(f"    - {c}", file=sys.stderr)
        print("\nRevisa si Tenable las renombró antes de seguir.", file=sys.stderr)
        sys.exit(1)

    idx = [hdr.index(c) for c in KEEP]
    tiradas = [h for h in hdr if h not in KEEP]
    print(f"Columnas: {len(hdr)} → {len(KEEP)} (se tiran {len(tiradas)})", file=sys.stderr)

    n = 0
    sin_id = 0
    multi = 0
    i_multi = hdr.index(MULTI)
    i_id = hdr.index("id")
    with open(salida, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(KEEP)
        for fila in filas:
            if not any(c is not None for c in fila):
                continue
            if not celda(fila[i_id] if i_id < len(fila) else None):
                sin_id += 1
            if "," in celda(fila[i_multi] if i_multi < len(fila) else None):
                multi += 1
            w.writerow([celda(fila[i]) if i < len(fila) else "" for i in idx])
            n += 1
            if n % PROGRESO_CADA == 0:
                print(f"  {n:,} filas…", file=sys.stderr)

    # Sin `id` no hay hallazgo: si el xlsx trae fórmulas sin valores cacheados,
    # openpyxl devuelve None en todo y saldría un CSV entero sin llave.
    if sin_id:
        print(f"\n✗ {sin_id:,} filas ({100*sin_id/n:.1f}%) SIN `id`. Sin llave no hay hallazgo.",
              file=sys.stderr)
        print("  Si el xlsx se generó por código y nunca se abrió en Excel, puede no traer",
              file=sys.stderr)
        print("  valores cacheados y openpyxl lee None en todo.", file=sys.stderr)
        sys.exit(1)
    if multi:
        print(f"\n⚠ {multi:,} filas traen VARIOS valores en {MULTI!r} (separados por coma).",
              file=sys.stderr)
        print("  Es una relación 1-a-N que el modelo aplana. Avísale a Claude antes de cargar.",
              file=sys.stderr)

    b_out = salida.stat().st_size
    print(f"\n✓ {salida.name}", file=sys.stderr)
    print(f"  {n:,} filas · {tam(b_in)} → {tam(b_out)} "
          f"({100 - 100 * b_out / b_in:.0f}% menos)", file=sys.stderr)
    if n:
        print(f"  {b_out / n:,.0f} bytes/fila", file=sys.stderr)
    print(f"\nYa lo puedes subir a la PWA.", file=sys.stderr)


if __name__ == "__main__":
    main()
