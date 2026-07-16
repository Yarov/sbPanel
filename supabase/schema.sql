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
-- Este archivo se aplica completo y de corrido, así que tiene que ser
-- idempotente. Más abajo (v2) estas vistas se redefinen con más columnas, y
-- `create or replace view` no puede quitarlas: sin el drop, re-aplicar truena.
drop view if exists v_hidden_debt cascade;
drop view if exists v_resurfaced cascade;
drop view if exists v_recast cascade;
drop view if exists v_overdue cascade;

create view v_hidden_debt as
  select finding_key, epm, asset, title, severity_scanner, first_observed, sla_days,
    (current_date - first_observed::date) as true_age_days, kri_status
  from findings
  where status in ('open','resurfaced') and kri_status = 'IN_TIME'
    and (current_date - first_observed::date) > coalesce(sla_days,120);

create view v_resurfaced as
  select finding_key, epm, asset, title, severity_scanner, resurfaced_date
  from findings where status='resurfaced';

create view v_recast as
  select finding_key, epm, asset, title, severity_scanner, severity_scotia
  from findings
  where status in ('open','resurfaced')
    and lower(severity_scanner) in ('critical','high')
    and lower(severity_scotia) = 'low';

create view v_overdue as
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
-- ingest_findings robusto: casts seguros + una fila mala no aborta la carga
create or replace function ingest_findings(
  p_source text, p_rows jsonb, p_scan_time timestamptz default now()
) returns jsonb
language plpgsql security invoker as $$
declare
  v_new int:=0; v_updated int:=0; v_resurfaced int:=0; v_fixed int:=0; v_errors int:=0;
  r jsonb; v_key text; v_status text; v_title text; v_epm text; v_sev text;
  v_first timestamptz; v_cvss numeric; v_vpr numeric; v_rem int; v_sla int;
begin
  for r in select value from jsonb_array_elements(p_rows) as value loop
    begin
      v_key := nullif(r->>'finding_key','');
      if v_key is null then v_errors:=v_errors+1; continue; end if;
      v_sev := r->>'severity_scanner';

      -- casts defensivos (datos reales pueden traer basura)
      begin v_first := (r->>'first_observed')::timestamptz; exception when others then v_first := p_scan_time; end;
      begin v_cvss := (r->>'cvss')::numeric;  exception when others then v_cvss := null; end;
      begin v_vpr  := (r->>'vpr')::numeric;   exception when others then v_vpr  := null; end;
      begin v_rem  := (r->>'remaining_days')::int; exception when others then v_rem := null; end;
      begin v_sla  := coalesce((r->>'sla_days')::int,120); exception when others then v_sla := 120; end;

      select status, title, epm into v_status, v_title, v_epm from findings where finding_key=v_key;

      if not found then
        insert into findings(finding_key,source,epm,asset,title,cve,cwe,severity_scanner,severity_scotia,
          cvss,vpr,status,first_observed,last_seen,owner,kri_status,sla_days,remaining_days,detail)
        values(v_key,p_source,r->>'epm',r->>'asset',coalesce(r->>'title','(sin título)'),r->>'cve',r->>'cwe',
          v_sev,r->>'severity_scotia',v_cvss,v_vpr,'open',coalesce(v_first,p_scan_time),p_scan_time,
          r->>'owner',r->>'kri_status',v_sla,v_rem,coalesce(r->'detail','{}'::jsonb));
        v_new:=v_new+1;
        if lower(coalesce(v_sev,'')) in ('critical','high') then
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,r->>'epm','new_finding','Nuevo hallazgo '||v_sev||': '||coalesce(r->>'title',''),v_sev);
        end if;

      elsif v_status='fixed' then
        update findings set status='resurfaced',resurfaced_date=p_scan_time,last_seen=p_scan_time,updated_at=now()
          where finding_key=v_key;
        v_resurfaced:=v_resurfaced+1;
        insert into alerts(finding_key,epm,kind,message,severity)
        values(v_key,v_epm,'resurfaced','REABIERTA (había sido cerrada y salió de nuevo): '||coalesce(v_title,''),v_sev);

      else
        update findings set last_seen=p_scan_time,severity_scanner=v_sev,updated_at=now() where finding_key=v_key;
        v_updated:=v_updated+1;
      end if;

    exception when others then
      v_errors := v_errors + 1;  -- fila mala: se salta, no tumba la carga
    end;
  end loop;

  update findings set status='fixed',last_fixed=p_scan_time,updated_at=now()
    where source=p_source and status in ('open','resurfaced') and last_seen<p_scan_time;
  get diagnostics v_fixed=row_count;

  return jsonb_build_object('new',v_new,'updated',v_updated,'resurfaced',v_resurfaced,'fixed',v_fixed,'errores',v_errors);
end $$;
-- ingest_findings por lotes: p_close_missing controla el cierre de ausentes.
-- El cliente manda N lotes con p_close_missing=false y una llamada final con true.
drop function if exists ingest_findings(text, jsonb, timestamptz);

create or replace function ingest_findings(
  p_source text,
  p_rows jsonb,
  p_scan_time timestamptz default now(),
  p_close_missing boolean default true
) returns jsonb
language plpgsql security invoker as $$
declare
  v_new int:=0; v_updated int:=0; v_resurfaced int:=0; v_fixed int:=0; v_errors int:=0;
  r jsonb; v_key text; v_status text; v_title text; v_epm text; v_sev text;
  v_first timestamptz; v_cvss numeric; v_vpr numeric; v_rem int; v_sla int;
begin
  for r in select value from jsonb_array_elements(coalesce(p_rows,'[]'::jsonb)) as value loop
    begin
      v_key := nullif(r->>'finding_key','');
      if v_key is null then v_errors:=v_errors+1; continue; end if;
      v_sev := r->>'severity_scanner';
      begin v_first := (r->>'first_observed')::timestamptz; exception when others then v_first := p_scan_time; end;
      begin v_cvss := (r->>'cvss')::numeric;  exception when others then v_cvss := null; end;
      begin v_vpr  := (r->>'vpr')::numeric;   exception when others then v_vpr  := null; end;
      begin v_rem  := (r->>'remaining_days')::int; exception when others then v_rem := null; end;
      begin v_sla  := coalesce((r->>'sla_days')::int,120); exception when others then v_sla := 120; end;

      select status, title, epm into v_status, v_title, v_epm from findings where finding_key=v_key;

      if not found then
        insert into findings(finding_key,source,epm,asset,title,cve,cwe,severity_scanner,severity_scotia,
          cvss,vpr,status,first_observed,last_seen,owner,kri_status,sla_days,remaining_days,detail)
        values(v_key,p_source,r->>'epm',r->>'asset',coalesce(r->>'title','(sin título)'),r->>'cve',r->>'cwe',
          v_sev,r->>'severity_scotia',v_cvss,v_vpr,'open',coalesce(v_first,p_scan_time),p_scan_time,
          r->>'owner',r->>'kri_status',v_sla,v_rem,coalesce(r->'detail','{}'::jsonb));
        v_new:=v_new+1;
        if lower(coalesce(v_sev,'')) in ('critical','high') then
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,r->>'epm','new_finding','Nuevo hallazgo '||v_sev||': '||coalesce(r->>'title',''),v_sev);
        end if;
      elsif v_status='fixed' then
        update findings set status='resurfaced',resurfaced_date=p_scan_time,last_seen=p_scan_time,updated_at=now()
          where finding_key=v_key;
        v_resurfaced:=v_resurfaced+1;
        insert into alerts(finding_key,epm,kind,message,severity)
        values(v_key,v_epm,'resurfaced','REABIERTA (había sido cerrada y salió de nuevo): '||coalesce(v_title,''),v_sev);
      else
        update findings set last_seen=p_scan_time,severity_scanner=v_sev,updated_at=now() where finding_key=v_key;
        v_updated:=v_updated+1;
      end if;
    exception when others then
      v_errors := v_errors + 1;
    end;
  end loop;

  -- cierre de ausentes SOLO en la llamada final (snapshot completo ya cargado)
  if p_close_missing then
    update findings set status='fixed',last_fixed=p_scan_time,updated_at=now()
      where source=p_source and status in ('open','resurfaced') and last_seen < p_scan_time;
    get diagnostics v_fixed = row_count;
  end if;

  return jsonb_build_object('new',v_new,'updated',v_updated,'resurfaced',v_resurfaced,'fixed',v_fixed,'errores',v_errors);
end $$;

grant execute on function ingest_findings(text, jsonb, timestamptz, boolean) to anon, authenticated;
-- columnas de clasificación
alter table findings add column if not exists area text;
alter table findings add column if not exists plataforma text;
alter table findings add column if not exists responsable text;
create index if not exists idx_findings_area on findings(area);
create index if not exists idx_findings_plataforma on findings(plataforma);
create index if not exists idx_findings_responsable on findings(responsable);

-- RPC actualizado: guarda area/plataforma/responsable (insert y update)
create or replace function ingest_findings(
  p_source text, p_rows jsonb, p_scan_time timestamptz default now(), p_close_missing boolean default true
) returns jsonb
language plpgsql security invoker as $$
declare
  v_new int:=0; v_updated int:=0; v_resurfaced int:=0; v_fixed int:=0; v_errors int:=0;
  r jsonb; v_key text; v_status text; v_title text; v_epm text; v_sev text;
  v_first timestamptz; v_cvss numeric; v_vpr numeric; v_rem int; v_sla int;
begin
  for r in select value from jsonb_array_elements(coalesce(p_rows,'[]'::jsonb)) as value loop
    begin
      v_key := nullif(r->>'finding_key',''); if v_key is null then v_errors:=v_errors+1; continue; end if;
      v_sev := r->>'severity_scanner';
      begin v_first := (r->>'first_observed')::timestamptz; exception when others then v_first := p_scan_time; end;
      begin v_cvss := (r->>'cvss')::numeric;  exception when others then v_cvss := null; end;
      begin v_vpr  := (r->>'vpr')::numeric;   exception when others then v_vpr  := null; end;
      begin v_rem  := (r->>'remaining_days')::int; exception when others then v_rem := null; end;
      begin v_sla  := coalesce((r->>'sla_days')::int,120); exception when others then v_sla := 120; end;

      select status, title, epm into v_status, v_title, v_epm from findings where finding_key=v_key;
      if not found then
        insert into findings(finding_key,source,epm,asset,title,cve,cwe,severity_scanner,severity_scotia,
          cvss,vpr,status,first_observed,last_seen,owner,kri_status,sla_days,remaining_days,area,plataforma,responsable,detail)
        values(v_key,p_source,r->>'epm',r->>'asset',coalesce(r->>'title','(sin título)'),r->>'cve',r->>'cwe',
          v_sev,r->>'severity_scotia',v_cvss,v_vpr,'open',coalesce(v_first,p_scan_time),p_scan_time,
          r->>'owner',r->>'kri_status',v_sla,v_rem,r->>'area',r->>'plataforma',r->>'responsable',coalesce(r->'detail','{}'::jsonb));
        v_new:=v_new+1;
        if lower(coalesce(v_sev,'')) in ('critical','high') then
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,r->>'epm','new_finding','Nuevo hallazgo '||v_sev||': '||coalesce(r->>'title',''),v_sev);
        end if;
      elsif v_status='fixed' then
        update findings set status='resurfaced',resurfaced_date=p_scan_time,last_seen=p_scan_time,
          area=r->>'area',plataforma=r->>'plataforma',responsable=r->>'responsable',updated_at=now()
          where finding_key=v_key;
        v_resurfaced:=v_resurfaced+1;
        insert into alerts(finding_key,epm,kind,message,severity)
        values(v_key,v_epm,'resurfaced','REABIERTA (había sido cerrada y salió de nuevo): '||coalesce(v_title,''),v_sev);
      else
        update findings set last_seen=p_scan_time,severity_scanner=v_sev,kri_status=r->>'kri_status',
          remaining_days=v_rem,area=r->>'area',plataforma=r->>'plataforma',responsable=r->>'responsable',updated_at=now()
          where finding_key=v_key;
        v_updated:=v_updated+1;
      end if;
    exception when others then v_errors := v_errors + 1; end;
  end loop;

  if p_close_missing then
    update findings set status='fixed',last_fixed=p_scan_time,updated_at=now()
      where source=p_source and status in ('open','resurfaced') and last_seen < p_scan_time;
    get diagnostics v_fixed = row_count;
  end if;
  return jsonb_build_object('new',v_new,'updated',v_updated,'resurfaced',v_resurfaced,'fixed',v_fixed,'errores',v_errors);
end $$;
grant execute on function ingest_findings(text, jsonb, timestamptz, boolean) to anon, authenticated;

-- ===== vistas de métricas (agregación server-side, escala a 66K) =====
create or replace view v_kpi as
  select count(*) total,
    count(*) filter (where status<>'fixed') abiertos,
    count(*) filter (where lower(severity_scanner)='critical' and status<>'fixed') criticos,
    count(*) filter (where status='resurfaced') resurfaced,
    count(distinct nullif(area,'')) areas,
    count(distinct nullif(responsable,'')) responsables
  from findings;

create or replace view v_by_area as
  select coalesce(nullif(area,''),'(sin área)') label,
    count(*) filter (where status<>'fixed') abiertos,
    count(*) filter (where lower(severity_scanner)='critical' and status<>'fixed') criticos,
    count(*) total
  from findings group by 1 order by abiertos desc;

create or replace view v_by_plataforma as
  select coalesce(nullif(plataforma,''),'(sin plataforma)') label,
    count(*) filter (where status<>'fixed') abiertos,
    count(*) filter (where lower(severity_scanner)='critical' and status<>'fixed') criticos,
    count(*) total
  from findings group by 1 order by abiertos desc;

create or replace view v_by_responsable as
  select coalesce(nullif(responsable,''),'(sin responsable)') label,
    count(*) filter (where status<>'fixed') abiertos,
    count(*) filter (where lower(severity_scanner)='critical' and status<>'fixed') criticos,
    count(*) total
  from findings group by 1 order by abiertos desc;

create or replace view v_by_severity as
  select coalesce(nullif(severity_scanner,''),'(sin sev)') label,
    count(*) filter (where status<>'fixed') abiertos, count(*) total
  from findings group by 1;

create or replace view v_by_status as
  select status label, count(*) total from findings group by 1;

grant select on v_kpi, v_by_area, v_by_plataforma, v_by_responsable, v_by_severity, v_by_status to anon, authenticated;
-- Métricas del dashboard, agregadas EN LA BASE y filtrables por área/plataforma/
-- responsable/severidad/fuente/estado. Devuelve todo en un JSON.
create or replace function dashboard_metrics(
  p_area text default null,
  p_plataforma text default null,
  p_responsable text default null,
  p_severity text default null,
  p_source text default null,
  p_status text default null
) returns jsonb
language sql security invoker stable as $$
  with f as (
    select * from findings
    where (p_area is null or area = p_area)
      and (p_plataforma is null or plataforma = p_plataforma)
      and (p_responsable is null or responsable = p_responsable)
      and (p_severity is null or severity_scanner = p_severity)
      and (p_source is null or source = p_source)
      and (p_status is null or status = p_status)
  )
  select jsonb_build_object(
    'kpi', (
      select jsonb_build_object(
        'total', count(*),
        'abiertos', count(*) filter (where status <> 'fixed'),
        'criticos', count(*) filter (where lower(severity_scanner)='critical' and status <> 'fixed'),
        'resurfaced', count(*) filter (where status='resurfaced'),
        'areas', count(distinct nullif(area,'')),
        'responsables', count(distinct nullif(responsable,''))
      ) from f
    ),
    'by_severity', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value)),'[]'::jsonb)
      from (select coalesce(nullif(severity_scanner,''),'(sin sev)') label,
              count(*) filter (where status<>'fixed') value from f group by 1) t
    ),
    'by_area', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value) order by value desc),'[]'::jsonb)
      from (select coalesce(nullif(area,''),'(sin área)') label,
              count(*) filter (where status<>'fixed') value from f group by 1 order by value desc limit 8) t
    ),
    'by_plataforma', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value) order by value desc),'[]'::jsonb)
      from (select coalesce(nullif(plataforma,''),'(sin plataforma)') label,
              count(*) filter (where status<>'fixed') value from f group by 1 order by value desc limit 8) t
    ),
    'by_responsable', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value) order by value desc),'[]'::jsonb)
      from (select coalesce(nullif(responsable,''),'(sin responsable)') label,
              count(*) filter (where status<>'fixed') value from f group by 1 order by value desc limit 8) t
    )
  );
$$;

grant execute on function dashboard_metrics(text,text,text,text,text,text) to anon, authenticated;

-- catálogos para los dropdowns (labels distintos, sobre TODO el universo)
create or replace view v_filter_options as
  select 'area' kind, coalesce(nullif(area,''),'(sin área)') label from findings
  union select 'plataforma', coalesce(nullif(plataforma,''),'(sin plataforma)') from findings
  union select 'responsable', coalesce(nullif(responsable,''),'(sin responsable)') from findings;
grant select on v_filter_options to anon, authenticated;

-- ==========================================================================
-- v2 — Jerarquía organizacional (IT VP / IT Manager) como eje del filtrado
-- El export real de Tenable trae 91 columnas e incluye el árbol org completo:
-- IT SVP -> IT VP -> IT Manager -> Contact App -> EPM / App Name.
-- ==========================================================================
alter table findings add column if not exists it_svp text;
alter table findings add column if not exists it_vp text;
alter table findings add column if not exists it_manager text;
alter table findings add column if not exists contact_app text;
alter table findings add column if not exists app_name text;
alter table findings add column if not exists tier text;
alter table findings add column if not exists cia boolean;
alter table findings add column if not exists managed_by text;
alter table findings add column if not exists pais text;
alter table findings add column if not exists lob text;
alter table findings add column if not exists exposed_internet boolean;
alter table findings add column if not exists mx_regulatory boolean;
alter table findings add column if not exists state_scanner text;
alter table findings add column if not exists recast_reason text;
alter table findings add column if not exists plugin_id text;
alter table findings add column if not exists age_in_days int;

create index if not exists idx_findings_it_vp on findings(it_vp);
create index if not exists idx_findings_it_manager on findings(it_manager);
create index if not exists idx_findings_app_name on findings(app_name);
create index if not exists idx_findings_kri on findings(kri_status);
-- el dashboard siempre filtra por "no cerrados": índice parcial
create index if not exists idx_findings_abiertos on findings(status) where status <> 'fixed';

-- ==========================================================================
-- ingest_findings v2 — confía en el `state` de Tenable en vez de re-derivarlo.
-- Tenable ya calcula NEW/ACTIVE/RESURFACED/FIXED + first_observed/last_fixed/
-- resurfaced_date. Re-derivarlo nos daba números que no cuadraban contra Tenable.
-- ==========================================================================
create or replace function ingest_findings(
  p_source text, p_rows jsonb, p_scan_time timestamptz default now(), p_close_missing boolean default true
) returns jsonb
language plpgsql security invoker as $$
declare
  v_new int:=0; v_updated int:=0; v_resurfaced int:=0; v_fixed int:=0; v_errors int:=0;
  r jsonb; v_key text; v_prev text; v_title text; v_epm text; v_sev text; v_st text;
  v_first timestamptz; v_cvss numeric; v_vpr numeric; v_rem int; v_sla int;
begin
  for r in select value from jsonb_array_elements(coalesce(p_rows,'[]'::jsonb)) as value loop
    begin
      v_key := nullif(r->>'finding_key',''); if v_key is null then v_errors:=v_errors+1; continue; end if;
      v_sev := r->>'severity_scanner';
      v_st  := coalesce(r->>'status','open');

      begin v_first := (r->>'first_observed')::timestamptz; exception when others then v_first := p_scan_time; end;
      begin v_cvss := (r->>'cvss')::numeric;  exception when others then v_cvss := null; end;
      begin v_vpr  := (r->>'vpr')::numeric;   exception when others then v_vpr  := null; end;
      begin v_rem  := (r->>'remaining_days')::int; exception when others then v_rem := null; end;
      -- sin SLA declarado por el scanner caemos a 120, pero solo como último recurso
      begin v_sla  := coalesce((r->>'sla_days')::int,120); exception when others then v_sla := 120; end;

      select status, title, epm into v_prev, v_title, v_epm from findings where finding_key=v_key;

      if not found then
        insert into findings(finding_key,source,epm,asset,title,cve,plugin_id,severity_scanner,severity_scotia,
          cvss,vpr,status,state_scanner,first_observed,last_seen,last_fixed,resurfaced_date,recast_reason,
          age_in_days,owner,kri_status,sla_days,remaining_days,area,plataforma,responsable,
          it_svp,it_vp,it_manager,contact_app,app_name,tier,cia,managed_by,pais,lob,
          exposed_internet,mx_regulatory,detail)
        values(v_key,p_source,r->>'epm',r->>'asset',coalesce(r->>'title','(sin título)'),r->>'cve',r->>'plugin_id',
          v_sev,r->>'severity_scotia',v_cvss,v_vpr,v_st,r->>'state_scanner',
          coalesce(v_first,p_scan_time),p_scan_time,
          nullif(r->>'last_fixed','')::timestamptz, nullif(r->>'resurfaced_date','')::timestamptz,
          r->>'recast_reason',(r->>'age_in_days')::numeric::int,
          r->>'owner',r->>'kri_status',v_sla,v_rem,r->>'area',r->>'plataforma',r->>'responsable',
          r->>'it_svp',r->>'it_vp',r->>'it_manager',r->>'contact_app',r->>'app_name',r->>'tier',
          (r->>'cia')::boolean,r->>'managed_by',r->>'pais',r->>'lob',
          (r->>'exposed_internet')::boolean,(r->>'mx_regulatory')::boolean,
          coalesce(r->'detail','{}'::jsonb));
        v_new:=v_new+1;
        if v_st='resurfaced' then v_resurfaced:=v_resurfaced+1; end if;
        if lower(coalesce(v_sev,'')) in ('critical','high') then
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,r->>'epm','new_finding','Nuevo hallazgo '||v_sev||': '||coalesce(r->>'title',''),v_sev);
        end if;

      else
        update findings set
          status=v_st, state_scanner=r->>'state_scanner', last_seen=p_scan_time,
          severity_scanner=v_sev, severity_scotia=r->>'severity_scotia', cvss=v_cvss, vpr=v_vpr,
          last_fixed=nullif(r->>'last_fixed','')::timestamptz,
          resurfaced_date=nullif(r->>'resurfaced_date','')::timestamptz,
          recast_reason=r->>'recast_reason', age_in_days=(r->>'age_in_days')::numeric::int,
          kri_status=r->>'kri_status', sla_days=v_sla, remaining_days=v_rem,
          area=r->>'area', plataforma=r->>'plataforma', responsable=r->>'responsable',
          it_svp=r->>'it_svp', it_vp=r->>'it_vp', it_manager=r->>'it_manager',
          contact_app=r->>'contact_app', app_name=r->>'app_name', tier=r->>'tier',
          cia=(r->>'cia')::boolean, managed_by=r->>'managed_by', pais=r->>'pais', lob=r->>'lob',
          exposed_internet=(r->>'exposed_internet')::boolean,
          mx_regulatory=(r->>'mx_regulatory')::boolean,
          updated_at=now()
        where finding_key=v_key;

        -- alerta solo en la TRANSICIÓN a resurfaced, no en cada carga
        if v_st='resurfaced' and v_prev is distinct from 'resurfaced' then
          v_resurfaced:=v_resurfaced+1;
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,v_epm,'resurfaced','REABIERTA (Tenable la marcó RESURFACED): '||coalesce(v_title,''),v_sev);
        else
          v_updated:=v_updated+1;
        end if;
      end if;
    exception when others then v_errors := v_errors + 1; end;
  end loop;

  if p_close_missing then
    update findings set status='fixed',last_fixed=coalesce(last_fixed,p_scan_time),updated_at=now()
      where source=p_source and status in ('open','resurfaced') and last_seen < p_scan_time;
    get diagnostics v_fixed = row_count;
  end if;
  return jsonb_build_object('new',v_new,'updated',v_updated,'resurfaced',v_resurfaced,'fixed',v_fixed,'errores',v_errors);
end $$;
grant execute on function ingest_findings(text, jsonb, timestamptz, boolean) to anon, authenticated;

-- ==========================================================================
-- Árbol organizacional: alimenta los filtros en cascada VP -> Manager -> App.
-- Son pocas filas (distintos), el front cascadea en cliente sin round-trips.
-- ==========================================================================
create or replace view v_org_tree as
  select
    coalesce(nullif(it_svp,''),    '(sin SVP)')     as it_svp,
    coalesce(nullif(it_vp,''),     '(sin VP)')      as it_vp,
    coalesce(nullif(it_manager,''),'(sin manager)') as it_manager,
    coalesce(nullif(epm,''),       '(sin EPM)')     as epm,
    coalesce(nullif(app_name,''),  '(sin app)')     as app_name,
    count(*) filter (where status <> 'fixed') as abiertos,
    count(*) filter (where lower(severity_scanner) in ('critical','high') and status <> 'fixed') as criticos
  from findings
  group by 1,2,3,4,5;
grant select on v_org_tree to anon, authenticated;

-- ==========================================================================
-- dashboard_metrics v2 — eje IT VP -> IT Manager -> App.
-- Area/Plataforma/Responsable siguen disponibles como filtros secundarios,
-- pero en data real vienen con placeholders ("APP Owner", "TBD") y no sirven
-- como eje principal.
-- ==========================================================================
drop function if exists dashboard_metrics(text,text,text,text,text,text);

create or replace function dashboard_metrics(
  p_it_vp text default null,
  p_it_manager text default null,
  p_app text default null,
  p_severity text default null,
  p_kri text default null,
  p_status text default null,
  p_source text default null,
  p_area text default null,
  p_plataforma text default null,
  p_responsable text default null,
  p_exposed boolean default null
) returns jsonb
language sql security invoker stable as $$
  with f as (
    select *, greatest(current_date - first_observed::date, 0) as edad
    from findings
    where (p_it_vp      is null or coalesce(nullif(it_vp,''),'(sin VP)') = p_it_vp)
      and (p_it_manager is null or coalesce(nullif(it_manager,''),'(sin manager)') = p_it_manager)
      and (p_app        is null or coalesce(nullif(app_name,''),'(sin app)') = p_app)
      -- El dropdown ofrece "(sin X)" como opción, así que el filtro tiene que
      -- machear igual que la etiqueta que muestra la gráfica.
      and (p_severity   is null or coalesce(nullif(severity_scanner,''),'(sin sev)') = p_severity)
      and (p_kri        is null or coalesce(nullif(kri_status,''),'(sin KRI)') = p_kri)
      and (p_status     is null or status = p_status)
      and (p_source     is null or source = p_source)
      and (p_area       is null or coalesce(nullif(area,''),'(sin área)') = p_area)
      and (p_plataforma is null or coalesce(nullif(plataforma,''),'(sin plataforma)') = p_plataforma)
      and (p_responsable is null or coalesce(nullif(responsable,''),'(sin responsable)') = p_responsable)
      and (p_exposed    is null or exposed_internet = p_exposed)
  ), abiertos as (select * from f where status <> 'fixed')
  select jsonb_build_object(
    'kpi', (select jsonb_build_object(
        'total',      (select count(*) from f),
        'abiertos',   (select count(*) from abiertos),
        'criticos',   (select count(*) from abiertos where lower(severity_scanner)='critical'),
        'resurfaced', (select count(*) from f where status='resurfaced'),
        'fuera_sla',  (select count(*) from abiertos where kri_status is not null and kri_status <> 'IN_TIME'),
        'expuestos',  (select count(*) from abiertos where exposed_internet),
        'vps',        (select count(distinct nullif(it_vp,'')) from abiertos),
        'managers',   (select count(distinct nullif(it_manager,'')) from abiertos),
        'apps',       (select count(distinct nullif(app_name,'')) from abiertos)
      )),
    'by_severity', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value)),'[]'::jsonb)
      from (select coalesce(nullif(severity_scanner,''),'(sin sev)') label, count(*) value
            from abiertos group by 1) t
    ),
    'by_kri', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value)),'[]'::jsonb)
      from (select coalesce(nullif(kri_status,''),'(sin KRI)') label, count(*) value
            from abiertos group by 1) t
    ),
    -- apilados por severidad: un VP con 200 Low no es un VP con 200 Critical
    'by_it_vp', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,
        'Critical',c,'High',h,'Medium',m,'Low',l,'value',c+h+m+l) order by c+h+m+l desc),'[]'::jsonb)
      from (select coalesce(nullif(it_vp,''),'(sin VP)') label,
              count(*) filter (where lower(severity_scanner)='critical') c,
              count(*) filter (where lower(severity_scanner)='high')     h,
              count(*) filter (where lower(severity_scanner)='medium')   m,
              count(*) filter (where lower(severity_scanner)='low')      l
            from abiertos group by 1 order by count(*) desc limit 10) t
    ),
    'by_it_manager', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,
        'Critical',c,'High',h,'Medium',m,'Low',l,'value',c+h+m+l) order by c+h+m+l desc),'[]'::jsonb)
      from (select coalesce(nullif(it_manager,''),'(sin manager)') label,
              count(*) filter (where lower(severity_scanner)='critical') c,
              count(*) filter (where lower(severity_scanner)='high')     h,
              count(*) filter (where lower(severity_scanner)='medium')   m,
              count(*) filter (where lower(severity_scanner)='low')      l
            from abiertos group by 1 order by count(*) desc limit 10) t
    ),
    'by_app', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,
        'Critical',c,'High',h,'Medium',m,'Low',l,'value',c+h+m+l) order by c+h+m+l desc),'[]'::jsonb)
      from (select coalesce(nullif(app_name,''),'(sin app)') label,
              count(*) filter (where lower(severity_scanner)='critical') c,
              count(*) filter (where lower(severity_scanner)='high')     h,
              count(*) filter (where lower(severity_scanner)='medium')   m,
              count(*) filter (where lower(severity_scanner)='low')      l
            from abiertos group by 1 order by count(*) desc limit 10) t
    ),
    'by_age', (
      select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value) order by ord),'[]'::jsonb)
      from (
        select b.label, b.ord, count(a.id) value
        from (values ('0-30d',1,0,30),('31-90d',2,31,90),('91-180d',3,91,180),
                     ('181-365d',4,181,365),('> 1 año',5,366,999999)) b(label,ord,lo,hi)
        left join abiertos a on a.edad between b.lo and b.hi
        group by b.label, b.ord
      ) t
    )
  );
$$;

grant execute on function dashboard_metrics(text,text,text,text,text,text,text,text,text,text,boolean) to anon, authenticated;

-- Catálogo de filtros secundarios (los primarios salen de v_org_tree)
create or replace view v_filter_options as
  select 'area' kind, coalesce(nullif(area,''),'(sin área)') label from findings
  union select 'plataforma', coalesce(nullif(plataforma,''),'(sin plataforma)') from findings
  union select 'responsable', coalesce(nullif(responsable,''),'(sin responsable)') from findings
  union select 'kri', coalesce(nullif(kri_status,''),'(sin KRI)') from findings
  union select 'tier', coalesce(nullif(tier,''),'(sin tier)') from findings;
grant select on v_filter_options to anon, authenticated;

-- Estas vistas cambian de columnas, así que hay que tirarlas: `create or replace
-- view` solo permite AGREGAR columnas al final, no reordenar ni renombrar.
drop view if exists v_hidden_debt;
drop view if exists v_overdue;
drop view if exists v_recast;

-- Deuda oculta v2: ahora el SLA es el REAL de Tenable (Remediation time),
-- no el 120 hardcodeado. Con SLA de 30d el hallazgo vence 4x más rápido.
create view v_hidden_debt as
  select finding_key, epm, app_name, it_vp, it_manager, asset, title, severity_scanner,
    first_observed, sla_days, kri_status,
    (current_date - first_observed::date) as true_age_days
  from findings
  where status <> 'fixed' and kri_status = 'IN_TIME'
    and (current_date - first_observed::date) > coalesce(sla_days,120);
grant select on v_hidden_debt to anon, authenticated;

create view v_overdue as
  select finding_key, epm, app_name, it_vp, it_manager, asset, title, severity_scanner,
    first_observed, sla_days, (current_date - first_observed::date) as true_age_days
  from findings
  where status <> 'fixed' and (current_date - first_observed::date) > coalesce(sla_days,120);
grant select on v_overdue to anon, authenticated;

-- Recast sospechoso: el scanner dice Critical/High, Scotia lo baja a Low
create view v_recast as
  select finding_key, epm, app_name, it_vp, it_manager, asset, title,
    severity_scanner, severity_scotia, recast_reason
  from findings
  where status <> 'fixed'
    and lower(severity_scanner) in ('critical','high')
    and lower(severity_scotia) = 'low';
grant select on v_recast to anon, authenticated;

-- ==========================================================================
-- Blindaje del cierre masivo.
-- Antes: "cierra lo que tenga last_seen < p_scan_time". Eso depende de que el
-- cliente mande el MISMO timestamp en las N llamadas del lote. Si un reintento
-- manda otro (o dos usuarios suben a la vez), la comparación se cumple para
-- TODO y cierras el universo entero.
-- Ahora: cada carga tiene un scan_id; se cierra lo que no traiga ese id.
-- Es imposible que "derive" con el tiempo.
-- ==========================================================================
alter table findings add column if not exists last_scan_id uuid;
create index if not exists idx_findings_scan on findings(source, last_scan_id);

create or replace function ingest_findings(
  p_source text, p_rows jsonb, p_scan_time timestamptz default now(),
  p_close_missing boolean default true, p_scan_id uuid default null
) returns jsonb
language plpgsql security invoker as $$
declare
  v_new int:=0; v_updated int:=0; v_resurfaced int:=0; v_fixed int:=0; v_errors int:=0;
  r jsonb; v_key text; v_prev text; v_title text; v_epm text; v_sev text; v_st text;
  v_first timestamptz; v_cvss numeric; v_vpr numeric; v_rem int; v_sla int;
begin
  for r in select value from jsonb_array_elements(coalesce(p_rows,'[]'::jsonb)) as value loop
    begin
      v_key := nullif(r->>'finding_key',''); if v_key is null then v_errors:=v_errors+1; continue; end if;
      v_sev := r->>'severity_scanner';
      v_st  := coalesce(r->>'status','open');

      begin v_first := (r->>'first_observed')::timestamptz; exception when others then v_first := p_scan_time; end;
      begin v_cvss := (r->>'cvss')::numeric;  exception when others then v_cvss := null; end;
      begin v_vpr  := (r->>'vpr')::numeric;   exception when others then v_vpr  := null; end;
      begin v_rem  := (r->>'remaining_days')::int; exception when others then v_rem := null; end;
      begin v_sla  := coalesce((r->>'sla_days')::int,120); exception when others then v_sla := 120; end;

      select status, title, epm into v_prev, v_title, v_epm from findings where finding_key=v_key;

      if not found then
        insert into findings(finding_key,source,epm,asset,title,cve,plugin_id,severity_scanner,severity_scotia,
          cvss,vpr,status,state_scanner,first_observed,last_seen,last_scan_id,last_fixed,resurfaced_date,
          recast_reason,age_in_days,owner,kri_status,sla_days,remaining_days,area,plataforma,responsable,
          it_svp,it_vp,it_manager,contact_app,app_name,tier,cia,managed_by,pais,lob,
          exposed_internet,mx_regulatory,detail)
        values(v_key,p_source,r->>'epm',r->>'asset',coalesce(r->>'title','(sin título)'),r->>'cve',r->>'plugin_id',
          v_sev,r->>'severity_scotia',v_cvss,v_vpr,v_st,r->>'state_scanner',
          coalesce(v_first,p_scan_time),p_scan_time,p_scan_id,
          nullif(r->>'last_fixed','')::timestamptz, nullif(r->>'resurfaced_date','')::timestamptz,
          r->>'recast_reason',(r->>'age_in_days')::numeric::int,
          r->>'owner',r->>'kri_status',v_sla,v_rem,r->>'area',r->>'plataforma',r->>'responsable',
          r->>'it_svp',r->>'it_vp',r->>'it_manager',r->>'contact_app',r->>'app_name',r->>'tier',
          (r->>'cia')::boolean,r->>'managed_by',r->>'pais',r->>'lob',
          (r->>'exposed_internet')::boolean,(r->>'mx_regulatory')::boolean,
          coalesce(r->'detail','{}'::jsonb));
        v_new:=v_new+1;
        if v_st='resurfaced' then v_resurfaced:=v_resurfaced+1; end if;
        if lower(coalesce(v_sev,'')) in ('critical','high') then
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,r->>'epm','new_finding','Nuevo hallazgo '||v_sev||': '||coalesce(r->>'title',''),v_sev);
        end if;

      else
        update findings set
          status=v_st, state_scanner=r->>'state_scanner', last_seen=p_scan_time, last_scan_id=p_scan_id,
          severity_scanner=v_sev, severity_scotia=r->>'severity_scotia', cvss=v_cvss, vpr=v_vpr,
          last_fixed=nullif(r->>'last_fixed','')::timestamptz,
          resurfaced_date=nullif(r->>'resurfaced_date','')::timestamptz,
          recast_reason=r->>'recast_reason', age_in_days=(r->>'age_in_days')::numeric::int,
          kri_status=r->>'kri_status', sla_days=v_sla, remaining_days=v_rem,
          area=r->>'area', plataforma=r->>'plataforma', responsable=r->>'responsable',
          it_svp=r->>'it_svp', it_vp=r->>'it_vp', it_manager=r->>'it_manager',
          contact_app=r->>'contact_app', app_name=r->>'app_name', tier=r->>'tier',
          cia=(r->>'cia')::boolean, managed_by=r->>'managed_by', pais=r->>'pais', lob=r->>'lob',
          exposed_internet=(r->>'exposed_internet')::boolean,
          mx_regulatory=(r->>'mx_regulatory')::boolean, updated_at=now()
        where finding_key=v_key;
        if v_st='resurfaced' and v_prev is distinct from 'resurfaced' then
          v_resurfaced:=v_resurfaced+1;
          insert into alerts(finding_key,epm,kind,message,severity)
          values(v_key,v_epm,'resurfaced','REABIERTA (Tenable la marcó RESURFACED): '||coalesce(v_title,''),v_sev);
        else
          v_updated:=v_updated+1;
        end if;
      end if;
    exception when others then v_errors := v_errors + 1; end;
  end loop;

  -- Cierra por scan_id, no por timestamp. Sin scan_id NO cierra nada: preferimos
  -- no cerrar a cerrar de más.
  if p_close_missing and p_scan_id is not null then
    update findings set status='fixed', last_fixed=coalesce(last_fixed,p_scan_time), updated_at=now()
      where source=p_source and status <> 'fixed'
        and last_scan_id is distinct from p_scan_id;
    get diagnostics v_fixed = row_count;
  end if;
  return jsonb_build_object('new',v_new,'updated',v_updated,'resurfaced',v_resurfaced,'fixed',v_fixed,'errores',v_errors);
end $$;

grant execute on function ingest_findings(text,jsonb,timestamptz,boolean,uuid) to anon, authenticated;
-- la firma vieja de 4 args queda muerta: un cliente sin scan_id no debe cerrar nada
drop function if exists ingest_findings(text, jsonb, timestamptz, boolean);
