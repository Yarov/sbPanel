# Scotia · Reporter

PWA de **gestión de vulnerabilidades** que unifica 4 escáneres (Tenable, Blackduck, Checkmarx,
WebInspect), con **ingesta por CSV con conciliación automática**, dashboard, insights y alertas.
Backend en **Supabase** (Postgres + Realtime). Tema Scotia dark.

## Qué hace

- **Carga de CSV** por fuente. Conciliación automática al subir:
  - nueva vulnerabilidad → se agrega (alerta si Crítica)
  - ya no aparece en el escaneo → se **cierra**
  - estaba cerrada y **reaparece** → se **reabre + alerta** ("salió de nuevo")
- **Motor de insights** automatizado:
  - 🔴 Deuda oculta (KRI dice IN_TIME pero la vuln lleva años)
  - ♻️ Resurfaced · ⚖️ Recast sospechoso · ⏰ Vencidos reales
- **Dashboard**: KPIs, scorecard por aplicación (EPM), tabla de hallazgos con búsqueda.
- **Alertas** en tiempo real.
- **Login** ScotiaID + nombre (estampa autoría).

## Arquitectura

```
  PWA (React/Vite)  ──►  Supabase (Postgres + Realtime)
   carga CSV, dashboard      ingest_findings() concilia + genera alertas
                             vistas v_hidden_debt / v_resurfaced / v_recast
```

- Grano **por hallazgo** (Tenable) → tabla `findings` con máquina de estados.
- Grano **por app** (Blackduck/Checkmarx/WebInspect, rollups) → tabla `app_scans`.
- El **EPM** es la llave que une todo. `project_epm_map` enriquece Blackduck (que no trae EPM).

## Base de datos

El esquema + el motor de ingesta están en [`supabase/schema.sql`](supabase/schema.sql).
Aplicar en Supabase → SQL Editor.

## Desarrollo

```bash
npm install
cp .env.example .env   # pon VITE_SUPABASE_URL y VITE_SUPABASE_ANON_KEY
npm run dev
```

## ⚠️ Seguridad

Es data **sensible** (vulns sin parchar de PROD). La RLS de la PoC está **abierta** y el hosting
en GitHub Pages es **público** — solo para PoC con datos ficticios. Para producción: hosting interno,
Supabase Auth + RLS por rol, y visto bueno de seguridad.
