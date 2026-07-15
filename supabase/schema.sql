-- ==========================================================================
-- Scotia Reporter — esquema unificado de vulnerabilidades + motor de ingesta
-- ==========================================================================

-- ---------- catálogos ----------
create table if not exists applications (
  epm text primary key,
  name text,
  tier text,
  cia_tier text,
  internet_exposed boolean default false,
  it_manager text,
  it_vp text,
  pais text,
  lob text,
  updated_at timestamptz default now()
);

create table if not exists project_epm_map (
  project_key text primary key,
  epm text
);

-- ---------- hallazgos (grano por vulnerabilidad) ----------
create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  finding_key text unique not null,           -- clave estable para dedup
  source text not null,                        -- tenable|blackduck|checkmarx|webinspect
  epm text,
  asset text,
  title text,
  cve text,
  cwe text,
  severity_scanner text,
  severity_scotia text,
  cvss numeric,
  vpr numeric,
  status text default 'open',                  -- open|fixed|resurfaced
  first_observed timestamptz default now(),    -- FECHA ORIGINAL, nunca se pisa
  last_seen timestamptz default now(),
  last_fixed timestamptz,
  resurfaced_date timestamptz,
  owner text,
  plan_date date,
  remediation_date date,
  kri_status text,
  sla_days int default 120,
  remaining_days int,
  detail jsonb default '{}'::jsonb,
  updated_at timestamptz default now()
);
create index if not exists idx_findings_source on findings(source);
create index if not exists idx_findings_epm on findings(epm);
create index if not exists idx_findings_status on findings(status);

-- ---------- resumen por app (grano AppSec: rollups) ----------
create table if not exists app_scans (
  id uuid primary key default gen_random_uuid(),
  source text not null,                        -- blackduck|checkmarx|webinspect
  project_name text not null,
  project_key text,
  epm text,
  risk_level text,
  policy_status text,
  crit int default 0,
  high int default 0,
  med int default 0,
  low int default 0,
  last_scan timestamptz,
  detail jsonb default '{}'::jsonb,
  updated_at timestamptz default now(),
  unique (source, project_name)
);

-- ---------- alertas ----------
create table if not exists alerts (
  id uuid primary key default gen_random_uuid(),
  finding_key text,
  epm text,
  kind text,                                   -- resurfaced|new_finding|kev|policy
  message text,
  severity text,
  acknowledged boolean default false,
  created_at timestamptz default now()
);

-- ==========================================================================
-- MOTOR: ingest_findings — conciliación con snapshot completo del scanner
-- ==========================================================================
create or replace function ingest_findings(
  p_source text,
  p_rows jsonb,
  p_scan_time timestamptz default now()
) returns jsonb
language plpgsql
security invoker
as $$
declare
  v_new int := 0; v_updated int := 0; v_resurfaced int := 0; v_fixed int := 0;
  r jsonb; v_key text; v_status text; v_title text; v_epm text; v_sev text;
begin
  for r in select value from jsonb_array_elements(p_rows) as value loop
    v_key := r->>'finding_key';
    v_sev := r->>'severity_scanner';
    select status, title, epm into v_status, v_title, v_epm
      from findings where finding_key = v_key;

    if not found then
      -- NUEVO
      insert into findings(finding_key, source, epm, asset, title, cve, cwe,
        severity_scanner, severity_scotia, cvss, vpr, status,
        first_observed, last_seen, owner, plan_date, kri_status, sla_days, remaining_days, detail)
      values (v_key, p_source, r->>'epm', r->>'asset', r->>'title', r->>'cve', r->>'cwe',
        v_sev, r->>'severity_scotia', (r->>'cvss')::numeric, (r->>'vpr')::numeric, 'open',
        coalesce((r->>'first_observed')::timestamptz, p_scan_time), p_scan_time,
        r->>'owner', (r->>'plan_date')::date, r->>'kri_status',
        coalesce((r->>'sla_days')::int,120), (r->>'remaining_days')::int,
        coalesce(r->'detail','{}'::jsonb));
      v_new := v_new + 1;
      if lower(coalesce(v_sev,'')) in ('critical','high') then
        insert into alerts(finding_key, epm, kind, message, severity)
        values (v_key, r->>'epm', 'new_finding',
          'Nuevo hallazgo '||v_sev||': '||coalesce(r->>'title',''), v_sev);
      end if;

    elsif v_status = 'fixed' then
      -- RESURFACED (había sido cerrado y volvió)
      update findings set status='resurfaced', resurfaced_date=p_scan_time,
        last_seen=p_scan_time, updated_at=now() where finding_key=v_key;
      v_resurfaced := v_resurfaced + 1;
      insert into alerts(finding_key, epm, kind, message, severity)
      values (v_key, v_epm, 'resurfaced',
        'REABIERTA (había sido cerrada y salió de nuevo): '||coalesce(v_title,''), v_sev);

    else
      -- sigue abierta → refresca
      update findings set last_seen=p_scan_time, severity_scanner=v_sev, updated_at=now()
        where finding_key=v_key;
      v_updated := v_updated + 1;
    end if;
  end loop;

  -- ausentes en este escaneo (snapshot completo) → cerrados
  update findings set status='fixed', last_fixed=p_scan_time, updated_at=now()
    where source=p_source and status in ('open','resurfaced') and last_seen < p_scan_time;
  get diagnostics v_fixed = row_count;

  return jsonb_build_object('new',v_new,'updated',v_updated,'resurfaced',v_resurfaced,'fixed',v_fixed);
end $$;

-- ==========================================================================
-- Vistas de insights (el análisis automatizado)
-- ==========================================================================
create or replace view v_hidden_debt as
  select finding_key, epm, asset, title, severity_scanner, first_observed, sla_days,
    (current_date - first_observed::date) as true_age_days, kri_status
  from findings
  where status in ('open','resurfaced') and kri_status = 'IN_TIME'
    and (current_date - first_observed::date) > coalesce(sla_days,120);

create or replace view v_resurfaced as
  select finding_key, epm, asset, title, severity_scanner, resurfaced_date
  from findings where status='resurfaced';

create or replace view v_recast as
  select finding_key, epm, asset, title, severity_scanner, severity_scotia
  from findings
  where status in ('open','resurfaced')
    and lower(severity_scanner) in ('critical','high')
    and lower(severity_scotia) = 'low';

create or replace view v_overdue as
  select finding_key, epm, asset, title, severity_scanner, first_observed,
    (current_date - first_observed::date) as true_age_days
  from findings
  where status in ('open','resurfaced')
    and (current_date - first_observed::date) > coalesce(sla_days,120);

-- ==========================================================================
-- Seguridad PoC: RLS abierta (cerrar con Auth para producción) + realtime
-- ==========================================================================
alter table applications enable row level security;
alter table project_epm_map enable row level security;
alter table findings enable row level security;
alter table app_scans enable row level security;
alter table alerts enable row level security;

do $$ declare t text;
begin
  foreach t in array array['applications','project_epm_map','findings','app_scans','alerts'] loop
    execute format('drop policy if exists poc_open on %I', t);
    execute format('create policy poc_open on %I for all to anon, authenticated using (true) with check (true)', t);
    execute format('grant all on %I to anon, authenticated', t);
  end loop;
end $$;

grant execute on function ingest_findings(text, jsonb, timestamptz) to anon, authenticated;

do $$ begin
  alter publication supabase_realtime add table findings;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table alerts;
exception when duplicate_object then null; end $$;
-- ==========================================================================
-- Análisis automático de AppSec al cargar (Blackduck/Checkmarx/WebInspect)
-- ==========================================================================
create or replace function trg_app_scan_analyze() returns trigger
language plpgsql security invoker as $$
declare v_key text := new.source || ':' || new.project_name;
begin
  -- KEV / Log4Shell (política de Blackduck menciona Log4j)
  if new.detail->>'policy' ilike '%log4j%' then
    if not exists (select 1 from alerts where finding_key=v_key and kind='kev' and not acknowledged) then
      insert into alerts(finding_key, epm, kind, message, severity)
      values (v_key, new.epm, 'kev',
        '💥 KEV/Log4Shell en '||new.project_name||' ('||new.source||')', 'Critical');
    end if;
  end if;
  -- Críticos de seguridad
  if coalesce(new.crit,0) > 0 then
    if not exists (select 1 from alerts where finding_key=v_key and kind='appsec_critical' and not acknowledged) then
      insert into alerts(finding_key, epm, kind, message, severity)
      values (v_key, new.epm, 'appsec_critical',
        new.crit||' crítico(s) en '||new.project_name||' ('||new.source||')', 'Critical');
    end if;
  end if;
  -- Política en violación
  if new.policy_status ilike '%violation%' then
    if not exists (select 1 from alerts where finding_key=v_key and kind='policy' and not acknowledged) then
      insert into alerts(finding_key, epm, kind, message, severity)
      values (v_key, new.epm, 'policy',
        'Política en violación: '||new.project_name, 'High');
    end if;
  end if;
  return new;
end $$;

drop trigger if exists app_scan_analyze on app_scans;
create trigger app_scan_analyze after insert or update on app_scans
  for each row execute function trg_app_scan_analyze();

-- ==========================================================================
-- Riesgo cruzado: apps (EPM) con riesgo Alto/Crítico en >= 2 capas
-- ==========================================================================
create or replace view v_cross_layer as
with risk as (
  select epm, 'tenable' as source from findings
    where epm is not null and status <> 'fixed'
      and lower(severity_scanner) in ('critical','high')
  union
  select epm, source from app_scans where epm is not null and (coalesce(crit,0)>0 or coalesce(high,0)>0)
)
select epm, count(distinct source) as capas, string_agg(distinct source, ', ') as fuentes
from risk group by epm having count(distinct source) >= 2;
