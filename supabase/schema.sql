-- ==========================================================================
-- Scotia Reporter — esquema completo. Se aplica de corrido y es idempotente.
--
--   bronze.*   el acta de cada carga (el archivo vive en Storage)
--   silver.*   el modelo: el APM como entidad, el hallazgo, la bitácora
--   public.*   la capa de lectura del front (PostgREST solo expone public)
--
-- Reemplaza el modelo plano anterior, donde it_vp/it_manager se repetían en
-- cada una de las 63,636 filas de hallazgo.
-- ==========================================================================

-- ---------- baja del modelo viejo ----------
drop view   if exists v_kpi, v_by_area, v_by_plataforma, v_by_responsable,
                      v_by_severity, v_by_status, v_filter_options, v_org_tree,
                      v_hidden_debt, v_resurfaced, v_recast, v_overdue,
                      v_cross_layer cascade;
drop function if exists dashboard_metrics(text,text,text,text,text,text) cascade;
drop function if exists dashboard_metrics(text,text,text,text,text,text,text,text,text,text,boolean) cascade;
drop function if exists ingest_findings(text,jsonb,timestamptz) cascade;
drop function if exists ingest_findings(text,jsonb,timestamptz,boolean) cascade;
drop function if exists ingest_findings(text,jsonb,timestamptz,boolean,uuid) cascade;
drop function if exists trg_app_scan_analyze() cascade;
drop table if exists findings cascade;          -- reemplazada por silver.findings
drop table if exists applications cascade;      -- nunca se llenó; ahora silver.applications
drop table if exists project_epm_map cascade;   -- nunca se llenó ni se leyó
drop table if exists alerts cascade;            -- reemplazada por silver.finding_events

create schema if not exists bronze;
create schema if not exists silver;

-- ==========================================================================
-- BRONZE — el registro de cargas. El archivo vive en Storage; aquí su acta.
-- ==========================================================================
create table if not exists bronze.loads (
  load_id      uuid primary key default gen_random_uuid(),
  source       text not null,
  state        text not null default 'in_progress',   -- in_progress|complete|aborted|pending_review
  started_at   timestamptz not null default now(),
  finished_at  timestamptz,
  loaded_by    text,                                   -- ScotiaID de quien cargó
  source_file  text,
  file_path    text,                                   -- ruta en Storage del .csv.gz
  data_date    timestamptz,                            -- max(last_seen) DEL CONTENIDO, no del reloj del navegador
  rows_seen    int not null default 0,
  rows_closed  int not null default 0,
  epms_seen    int not null default 0,
  blocked_reason text,                                 -- por qué quedó en pending_review
  notes        text
);

-- Una sola carga en curso por fuente. Este índice ES la defensa contra la
-- aniquilación mutua: la segunda carga falla al empezar, no al final.
create unique index if not exists loads_one_in_progress
  on bronze.loads(source) where state = 'in_progress';
create index if not exists loads_state on bronze.loads(source, state, data_date desc);

-- ==========================================================================
-- SILVER — el APM como entidad
-- ==========================================================================
create table if not exists silver.applications (
  epm          text primary key,
  app_name     text,
  tier         text,
  cia          boolean,
  usage        text,                                   -- Prod|UAT/QAT/Pre-PROD|DR|IST|Dev
  user_interface text,
  exposed_internet boolean,
  mx_regulatory    boolean,
  contact_app  text,
  it_manager   text,
  it_vp        text,
  it_svp       text,
  lob          text,
  pais         text,
  first_load_id uuid,
  last_load_id  uuid,
  updated_at   timestamptz default now()
);
create index if not exists app_it_vp on silver.applications(it_vp);
create index if not exists app_it_manager on silver.applications(it_manager);

-- ==========================================================================
-- SILVER — el hallazgo. Solo estado actual; la historia vive en finding_events.
-- ==========================================================================
create table if not exists silver.findings (
  finding_key  text primary key,                       -- el `id` de Tenable
  -- El id de Tenable NO es durable: si reimaginan el host, el asset cambia de
  -- UUID y todos sus hallazgos reciben ids nuevos -> los viejos se cerrarían
  -- como "remediados" y los nuevos nacerían con first_observed = hoy, borrando
  -- la deuda de SLA sin parchar nada. Esta llave sobrevive a eso.
  durable_key  text not null,
  source       text not null,
  epm          text,
  asset        text,
  title        text,
  cve          text,
  plugin_id    text,
  port         text,
  protocol     text,

  -- plano 1: hechos del escáner
  severity_scanner text,
  cvss         numeric,
  vpr          numeric,
  state_scanner text,                                  -- NEW|ACTIVE|RESURFACED|FIXED
  status       text not null,                          -- open|fixed|resurfaced|not_observed
  first_observed timestamptz,
  last_seen    timestamptz,
  last_fixed   timestamptz,
  resurfaced_date timestamptz,
  age_in_days  int,

  -- plano 2: juicio del banco que viaja dentro del feed (NO es dato de máquina)
  severity_scotia text,
  recast_reason text,
  kri_status   text,
  sla_days     int,                                    -- NULL si no vino. Sin default silencioso.
  remaining_days int,

  last_load_id uuid,
  updated_at   timestamptz default now()
);
create index if not exists f_epm on silver.findings(epm);
create index if not exists f_durable on silver.findings(durable_key);
create index if not exists f_load on silver.findings(source, last_load_id);
create index if not exists f_abiertos on silver.findings(status) where status <> 'fixed';

-- ==========================================================================
-- SILVER — la bitácora. Append-only. Es lo único que no se puede reconstruir
-- después, así que se construye antes que cualquier gráfica.
-- ==========================================================================
create table if not exists silver.finding_events (
  id           bigserial primary key,
  finding_key  text not null,
  load_id      uuid not null,
  epm          text,
  event        text not null,   -- new|fixed|resurfaced|not_observed|reobserved|recast|reassigned|sla_changed
  at           timestamptz not null default now(),
  de           text,
  a            text
);
create index if not exists ev_finding on silver.finding_events(finding_key, at);
create index if not exists ev_load on silver.finding_events(load_id, event);
create index if not exists ev_tipo on silver.finding_events(event, at);

-- ==========================================================================
-- load_begin — abre la carga. Falla si ya hay una en curso.
-- ==========================================================================
create or replace function load_begin(
  p_source text, p_loaded_by text default null, p_source_file text default null
) returns uuid
language plpgsql security invoker as $$
declare v_id uuid;
begin
  insert into bronze.loads(source, loaded_by, source_file)
  values (p_source, p_loaded_by, p_source_file)
  returning load_id into v_id;
  return v_id;
exception when unique_violation then
  raise exception 'Ya hay una carga de % en curso. Espera a que termine o abórtala.', p_source
    using errcode = '55006';
end $$;

-- ==========================================================================
-- load_abort
-- ==========================================================================
create or replace function load_abort(p_load_id uuid, p_reason text default null)
returns void language sql security invoker as $$
  update bronze.loads set state='aborted', finished_at=now(), notes=p_reason
  where load_id=p_load_id and state='in_progress';
$$;

-- ==========================================================================
-- load_batch — ingiere un lote. Upsert de app + finding, y emite los eventos.
-- NO cierra nada: eso es exclusivo de load_commit, con el snapshot completo.
-- ==========================================================================
create or replace function load_batch(p_load_id uuid, p_rows jsonb)
returns jsonb
language plpgsql security invoker as $$
declare
  v_new int:=0; v_upd int:=0; v_resurf int:=0; v_recast int:=0; v_reassign int:=0; v_err int:=0;
  r jsonb; v_key text; v_dur text; v_epm text; v_st text; v_msg text;
  v_prev silver.findings%rowtype;
  v_prev_vp text; v_new_vp text;
  v_first timestamptz; v_maxseen timestamptz; v_seen timestamptz;
begin
  if not exists (select 1 from bronze.loads where load_id=p_load_id and state='in_progress') then
    raise exception 'La carga % no existe o ya no está en curso.', p_load_id using errcode='55006';
  end if;

  for r in select value from jsonb_array_elements(coalesce(p_rows,'[]'::jsonb)) as value loop
    begin
      v_key := nullif(r->>'finding_key','');
      -- Sin id no hay hallazgo. Antes había un fallback a asset|plugin que
      -- colapsaba filas distintas (mismo plugin, distinto puerto) en una sola.
      if v_key is null then v_err:=v_err+1; continue; end if;

      v_epm := nullif(r->>'epm','');
      v_dur := concat_ws('|', r->>'asset', r->>'plugin_id', r->>'port', r->>'protocol');
      v_st  := coalesce(r->>'status','open');
      begin v_first := (r->>'first_observed')::timestamptz; exception when others then v_first := null; end;
      begin v_seen  := (r->>'last_seen')::timestamptz;      exception when others then v_seen  := null; end;

      -- la app: se upserta desde el propio export, que ya trae el árbol org
      if v_epm is not null then
        insert into silver.applications(epm, app_name, tier, cia, usage, user_interface,
          exposed_internet, mx_regulatory, contact_app, it_manager, it_vp, it_svp, lob, pais,
          first_load_id, last_load_id)
        values (v_epm, r->>'app_name', r->>'tier', (r->>'cia')::boolean, r->>'usage',
          r->>'user_interface', (r->>'exposed_internet')::boolean, (r->>'mx_regulatory')::boolean,
          r->>'contact_app', r->>'it_manager', r->>'it_vp', r->>'it_svp', r->>'lob', r->>'pais',
          p_load_id, p_load_id)
        on conflict (epm) do update set
          app_name=excluded.app_name, tier=excluded.tier, cia=excluded.cia, usage=excluded.usage,
          user_interface=excluded.user_interface, exposed_internet=excluded.exposed_internet,
          mx_regulatory=excluded.mx_regulatory, contact_app=excluded.contact_app,
          it_manager=excluded.it_manager, it_vp=excluded.it_vp, it_svp=excluded.it_svp,
          lob=excluded.lob, pais=excluded.pais, last_load_id=p_load_id, updated_at=now();
      end if;

      select * into v_prev from silver.findings where finding_key=v_key;

      if not found then
        insert into silver.findings(finding_key, durable_key, source, epm, asset, title, cve,
          plugin_id, port, protocol, severity_scanner, cvss, vpr, state_scanner, status,
          first_observed, last_seen, last_fixed, resurfaced_date, age_in_days,
          severity_scotia, recast_reason, kri_status, sla_days, remaining_days, last_load_id)
        values (v_key, v_dur, r->>'source', v_epm, r->>'asset', coalesce(r->>'title','(sin título)'),
          r->>'cve', r->>'plugin_id', r->>'port', r->>'protocol',
          r->>'severity_scanner', (r->>'cvss')::numeric, (r->>'vpr')::numeric,
          r->>'state_scanner', v_st, v_first, coalesce(v_seen, now()),
          nullif(r->>'last_fixed','')::timestamptz, nullif(r->>'resurfaced_date','')::timestamptz,
          (r->>'age_in_days')::numeric::int, r->>'severity_scotia', r->>'recast_reason',
          r->>'kri_status', (r->>'sla_days')::numeric::int, (r->>'remaining_days')::numeric::int, p_load_id);
        v_new := v_new + 1;
        insert into silver.finding_events(finding_key, load_id, epm, event, a)
        values (v_key, p_load_id, v_epm, 'new', r->>'severity_scanner');
        if v_st='resurfaced' then
          v_resurf := v_resurf + 1;
          insert into silver.finding_events(finding_key, load_id, epm, event, a)
          values (v_key, p_load_id, v_epm, 'resurfaced', r->>'state_scanner');
        end if;

      else
        -- RECAST: el banco cambió la severidad. Es la decisión más consecuente
        -- del programa (apaga el reloj del SLA) y antes se sobrescribía sin dejar rastro.
        if v_prev.severity_scotia is distinct from (r->>'severity_scotia') then
          v_recast := v_recast + 1;
          insert into silver.finding_events(finding_key, load_id, epm, event, de, a)
          values (v_key, p_load_id, v_epm, 'recast', v_prev.severity_scotia, r->>'severity_scotia');
        end if;

        -- REASSIGNED: cambió el dueño. Distingue lo heredado de lo generado.
        select it_vp into v_prev_vp from silver.applications where epm = v_prev.epm;
        v_new_vp := r->>'it_vp';
        if v_prev.epm is distinct from v_epm then
          v_reassign := v_reassign + 1;
          insert into silver.finding_events(finding_key, load_id, epm, event, de, a)
          values (v_key, p_load_id, v_epm, 'reassigned', v_prev.epm, v_epm);
        end if;

        if v_prev.sla_days is distinct from (r->>'sla_days')::numeric::int then
          insert into silver.finding_events(finding_key, load_id, epm, event, de, a)
          values (v_key, p_load_id, v_epm, 'sla_changed', v_prev.sla_days::text, r->>'sla_days');
        end if;

        -- volvió a observarse algo que habíamos perdido de vista
        if v_prev.status = 'not_observed' then
          insert into silver.finding_events(finding_key, load_id, epm, event, a)
          values (v_key, p_load_id, v_epm, 'reobserved', v_st);
        end if;

        if v_st='resurfaced' and v_prev.status is distinct from 'resurfaced' then
          v_resurf := v_resurf + 1;
          insert into silver.finding_events(finding_key, load_id, epm, event, de, a)
          values (v_key, p_load_id, v_epm, 'resurfaced', v_prev.status, v_st);
        end if;
        if v_st='fixed' and v_prev.status is distinct from 'fixed' then
          insert into silver.finding_events(finding_key, load_id, epm, event, de, a)
          values (v_key, p_load_id, v_epm, 'fixed', v_prev.status, 'fixed (Tenable lo declaró)');
        end if;

        update silver.findings set
          durable_key=v_dur, epm=v_epm, asset=r->>'asset', title=coalesce(r->>'title', title),
          cve=r->>'cve', plugin_id=r->>'plugin_id', port=r->>'port', protocol=r->>'protocol',
          severity_scanner=r->>'severity_scanner', cvss=(r->>'cvss')::numeric, vpr=(r->>'vpr')::numeric,
          state_scanner=r->>'state_scanner', status=v_st,
          -- first_observed NUNCA se pisa: es la fecha de nacimiento real
          first_observed=coalesce(first_observed, v_first),
          last_seen=coalesce(v_seen, now()),
          last_fixed=nullif(r->>'last_fixed','')::timestamptz,
          resurfaced_date=nullif(r->>'resurfaced_date','')::timestamptz,
          age_in_days=(r->>'age_in_days')::numeric::int,
          severity_scotia=r->>'severity_scotia', recast_reason=r->>'recast_reason',
          kri_status=r->>'kri_status', sla_days=(r->>'sla_days')::numeric::int,
          remaining_days=(r->>'remaining_days')::numeric::int,
          last_load_id=p_load_id, updated_at=now()
        where finding_key=v_key;
        v_upd := v_upd + 1;
      end if;

      v_maxseen := greatest(v_maxseen, v_seen);
    exception when others then
      v_err := v_err + 1;
      -- Guarda el PRIMER error con su fila. Un contador pelón obliga a adivinar;
      -- el mensaje dice exactamente qué columna y qué valor lo tumbó.
      if v_msg is null then
        v_msg := format('%s | fila: %s', sqlerrm, left(r::text, 300));
      end if;
    end;
  end loop;

  -- data_date sale del CONTENIDO, no del reloj del navegador: así se detecta
  -- que subieron el archivo del mes pasado encima del de este mes.
  update bronze.loads set
    rows_seen = rows_seen + v_new + v_upd,
    data_date = greatest(data_date, v_maxseen),
    notes = coalesce(notes, v_msg)
  where load_id = p_load_id;

  return jsonb_build_object('new',v_new,'updated',v_upd,'resurfaced',v_resurf,
    'recast',v_recast,'reassigned',v_reassign,'errores',v_err,'primer_error',v_msg);
end $$;

-- ==========================================================================
-- load_commit — cierra la carga. Aquí viven TODAS las guardas.
--
-- El cliente declara cuántas filas mandó (p_expected_rows). Si no cuadra con lo
-- que la base contó, la carga no se confirma: eso atrapa lotes perdidos y el
-- `p_rows:[]` + close directo (que hoy cierra 63,600 con un curl sin autenticar).
--
-- p_force_close: solo para que un humano confirme un cierre grande a propósito,
-- viendo el número en pantalla.
-- ==========================================================================
create or replace function load_commit(
  p_load_id uuid,
  p_expected_rows int default null,
  p_force_close boolean default false
) returns jsonb
language plpgsql security invoker as $$
declare
  v_load bronze.loads%rowtype;
  v_prev_date timestamptz; v_prev_rows int;
  v_abiertos int; v_a_cerrar int; v_pct numeric; v_epms int;
  v_motivo text; v_cerrados int := 0;
begin
  select * into v_load from bronze.loads where load_id=p_load_id and state='in_progress';
  if not found then
    raise exception 'La carga % no existe o ya no está en curso.', p_load_id using errcode='55006';
  end if;

  select count(distinct epm) into v_epms from silver.findings where last_load_id = p_load_id;

  -- ---- GUARDA 1: lo que llegó es lo que el cliente dijo que mandó ----
  if p_expected_rows is not null and v_load.rows_seen <> p_expected_rows then
    v_motivo := format('El cliente declaró %s filas pero la base registró %s. Faltan lotes.',
                       p_expected_rows, v_load.rows_seen);
  end if;

  -- ---- GUARDA 2: nada que ingerir = nada que cerrar ----
  -- Mata el `{"p_rows":[], "p_close_missing":true}` de un solo golpe.
  if v_motivo is null and v_load.rows_seen = 0 then
    v_motivo := 'La carga no ingirió una sola fila; cerrar todo sería absurdo.';
  end if;

  -- ---- GUARDA 3: fuera de orden ----
  -- El archivo del mes pasado encima del de este mes cerraría los hallazgos
  -- más nuevos, que son justo los que más importan.
  select data_date, rows_seen into v_prev_date, v_prev_rows from bronze.loads
   where source=v_load.source and state='complete' order by data_date desc nulls last limit 1;
  if v_motivo is null and v_prev_date is not null and v_load.data_date is not null
     and v_load.data_date < v_prev_date then
    v_motivo := format('El archivo es MÁS VIEJO que la última carga (%s < %s). ¿Subiste el del mes pasado?',
                       v_load.data_date::date, v_prev_date::date);
  end if;

  -- Las guardas 1-3 NO son negociables: son bugs (lotes perdidos, carga vacía,
  -- archivo viejo), no juicios. p_force_close solo aplica de aquí para abajo,
  -- donde un humano SÍ puede saber algo que la base no ("sí, dimos de baja 50 apps").

  -- ---- GUARDA 4: el extracto disfrazado de universo ----
  if v_motivo is null and not p_force_close
     and v_prev_rows is not null and v_prev_rows > 0
     and v_load.rows_seen < v_prev_rows * 0.90 then
    v_motivo := format('Llegaron %s filas vs %s de la última carga (%s%%). Parece un extracto filtrado, no el universo.',
                       v_load.rows_seen, v_prev_rows, round(100.0*v_load.rows_seen/v_prev_rows));
  end if;

  -- ---- GUARDA 5: techo de cierre ----
  select count(*) into v_abiertos from silver.findings
   where source=v_load.source and status <> 'fixed';
  select count(*) into v_a_cerrar from silver.findings
   where source=v_load.source and status <> 'fixed'
     and (last_load_id is distinct from p_load_id);
  v_pct := case when v_abiertos > 0 then 100.0*v_a_cerrar/v_abiertos else 0 end;

  if v_motivo is null and v_pct > 10 and not p_force_close then
    v_motivo := format('Esta carga marcaría %s de %s hallazgos como no observados (%s%%). Lo normal es 2-5%%.',
                       v_a_cerrar, v_abiertos, round(v_pct,1));
  end if;

  -- ---- Si algo huele mal: NO se cierra. Queda para revisión humana. ----
  if v_motivo is not null then
    update bronze.loads set state='pending_review', finished_at=now(),
      blocked_reason=v_motivo, epms_seen=v_epms
    where load_id=p_load_id;
    return jsonb_build_object('state','pending_review','motivo',v_motivo,
      'rows',v_load.rows_seen,'a_cerrar',v_a_cerrar,'pct',round(v_pct,1));
  end if;

  -- ---- Ausente != remediado ----
  -- Tenable ya declara state=FIXED cuando de verdad se remedió (y eso lo procesa
  -- load_batch). Que algo no venga en el archivo NO prueba que se arregló: pudo
  -- ser un escaneo sin credenciales, un agente caído o una ventana de manto.
  -- Por eso 'not_observed' y no 'fixed': es honesto decir que no sabemos.
  -- `previos` se evalúa sobre el snapshot de la consulta, así que conserva el
  -- estado ANTERIOR: si leyéramos la tabla después del update, la bitácora diría
  -- 'not_observed -> not_observed' y perderíamos de dónde venía cada hallazgo.
  with previos as (
    select finding_key, epm, status from silver.findings
     where source=v_load.source and status in ('open','resurfaced')
       and last_load_id is distinct from p_load_id
  ), tocados as (
    update silver.findings f set status='not_observed', updated_at=now()
    from previos p where f.finding_key = p.finding_key
    returning f.finding_key
  )
  insert into silver.finding_events(finding_key, load_id, epm, event, de, a)
  select p.finding_key, p_load_id, p.epm, 'not_observed', p.status, 'ausente del archivo'
  from previos p;
  get diagnostics v_cerrados = row_count;

  update bronze.loads set state='complete', finished_at=now(),
    rows_closed=v_cerrados, epms_seen=v_epms
  where load_id=p_load_id;

  return jsonb_build_object('state','complete','rows',v_load.rows_seen,
    'no_observados',v_cerrados,'epms',v_epms,'data_date',v_load.data_date);
end $$;

-- ==========================================================================
-- AppSec (Blackduck/Checkmarx/WebInspect) — grano por app, no por hallazgo.
-- Se quedan aparte a propósito: mezclar granos en una tabla es lo que hace que
-- los números dejen de significar algo. Se unen con Tenable por el APM.
-- Checkmarx trae EPM y PROJECT KEY, así que puede enseñarle el mapeo a Blackduck.
-- ==========================================================================
create table if not exists silver.app_scans (
  source       text not null,
  project_name text not null,
  project_key  text,
  epm          text,
  risk_level   text,
  policy_status text,
  crit int default 0, high int default 0, med int default 0, low int default 0,
  last_scan    timestamptz,
  updated_at   timestamptz default now(),
  primary key (source, project_name)
);

create table if not exists silver.project_epm_map (
  project_key text primary key,
  epm         text not null,
  aprendido_de text,          -- de qué fuente salió el mapeo
  updated_at  timestamptz default now()
);

-- ==========================================================================
-- public.* — la capa de lectura. PostgREST solo expone public, así que el
-- modelo vive en silver y el front lee estas vistas.
-- ==========================================================================

-- El hallazgo con su app resuelta. Es lo que la tabla de Hallazgos consume.
create or replace view v_findings as
  select f.finding_key, f.durable_key, f.source, f.epm, f.asset, f.title, f.cve,
         f.port, f.protocol, f.severity_scanner, f.severity_scotia, f.cvss, f.vpr,
         f.status, f.state_scanner, f.first_observed, f.last_seen, f.last_fixed,
         f.kri_status, f.sla_days, f.remaining_days, f.recast_reason,
         a.app_name, a.tier, a.usage, a.exposed_internet, a.mx_regulatory,
         a.it_svp, a.it_vp, a.it_manager, a.contact_app,
         greatest(current_date - f.first_observed::date, 0) as edad_dias,
         (f.sla_days is not null
          and greatest(current_date - f.first_observed::date, 0) > f.sla_days) as vencido_real
  from silver.findings f
  left join silver.applications a using (epm);

-- La cascada IT VP -> IT Manager -> App. Pocas filas: el front cascadea en cliente.
create or replace view v_org_tree as
  select coalesce(nullif(a.it_svp,''),    '(sin SVP)')     as it_svp,
         coalesce(nullif(a.it_vp,''),     '(sin VP)')      as it_vp,
         coalesce(nullif(a.it_manager,''),'(sin manager)') as it_manager,
         a.epm,
         coalesce(nullif(a.app_name,''),  '(sin app)')     as app_name,
         count(*) filter (where f.status not in ('fixed','not_observed')) as abiertos,
         count(*) filter (where lower(f.severity_scanner) in ('critical','high')
                            and f.status not in ('fixed','not_observed'))  as criticos
  from silver.applications a
  left join silver.findings f using (epm)
  group by 1,2,3,4,5;

-- El acta de cargas. Es la pantalla que dice por qué una carga se frenó.
create or replace view v_loads as
  select load_id, source, state, started_at, finished_at, loaded_by, source_file,
         data_date, rows_seen, rows_closed, epms_seen, blocked_reason
  from bronze.loads;

-- La bitácora, legible. Reemplaza la tabla `alerts`: en vez de alertas que
-- alguien inventaba al vuelo, son los cambios que de verdad ocurrieron.
create or replace view v_activity as
  select e.id, e.at, e.event, e.finding_key, e.epm, e.de, e.a,
         f.title, f.asset, f.severity_scanner, f.severity_scotia,
         a.app_name, a.it_vp, a.it_manager,
         l.source_file, l.loaded_by
  from silver.finding_events e
  left join silver.findings f using (finding_key)
  left join silver.applications a on a.epm = e.epm
  left join bronze.loads l on l.load_id = e.load_id;

-- Deuda oculta: el KRI dice IN_TIME pero contra el SLA REAL ya venció.
create or replace view v_hidden_debt as
  select finding_key, epm, app_name, it_vp, it_manager, asset, title,
         severity_scanner, first_observed, sla_days, edad_dias, kri_status
  from v_findings
  where status not in ('fixed','not_observed') and kri_status = 'IN_TIME' and vencido_real;

-- Recast: aquí vive la pregunta de auditoría. Sale de la BITÁCORA, así que
-- tiene historia y autor — antes se sobrescribía y no se podía reconstruir.
create or replace view v_recast_log as
  select e.at, e.finding_key, e.de as severidad_antes, e.a as severidad_despues,
         f.severity_scanner as severidad_escaner, f.title, f.asset,
         a.app_name, a.it_vp, a.it_manager, l.source_file, l.loaded_by
  from silver.finding_events e
  join silver.findings f using (finding_key)
  left join silver.applications a on a.epm = e.epm
  left join bronze.loads l on l.load_id = e.load_id
  where e.event = 'recast';

-- Riesgo cruzado: ahora es un join honesto por APM, no un union improvisado.
create or replace view v_cross_layer as
  with riesgo as (
    select epm, 'tenable' as fuente from silver.findings
      where epm is not null and status not in ('fixed','not_observed')
        and lower(severity_scanner) in ('critical','high')
    union
    select epm, source from silver.app_scans
      where epm is not null and (coalesce(crit,0) > 0 or coalesce(high,0) > 0)
  )
  select r.epm, a.app_name, a.it_vp, count(distinct r.fuente) as capas,
         string_agg(distinct r.fuente, ', ') as fuentes
  from riesgo r left join silver.applications a using (epm)
  group by 1,2,3 having count(distinct r.fuente) >= 2;

create or replace view v_app_scans as select * from silver.app_scans;

-- ==========================================================================
-- dashboard_metrics — todo en un JSON, agregado en la base.
-- Eje: IT VP -> IT Manager -> App. Area/Plataforma/Responsable ya no son
-- filtros: en datos reales vienen "APP Owner", "TBD", "Asignación múltiple."
-- ==========================================================================
create or replace function dashboard_metrics(
  p_it_vp text default null, p_it_manager text default null, p_app text default null,
  p_severity text default null, p_kri text default null, p_status text default null,
  p_usage text default null, p_exposed boolean default null
) returns jsonb
language sql security invoker stable as $$
  with f as (
    select * from v_findings
    where (p_it_vp      is null or coalesce(nullif(it_vp,''),'(sin VP)') = p_it_vp)
      and (p_it_manager is null or coalesce(nullif(it_manager,''),'(sin manager)') = p_it_manager)
      and (p_app        is null or coalesce(nullif(app_name,''),'(sin app)') = p_app)
      and (p_severity   is null or coalesce(nullif(severity_scanner,''),'(sin sev)') = p_severity)
      and (p_kri        is null or coalesce(nullif(kri_status,''),'(sin KRI)') = p_kri)
      and (p_status     is null or status = p_status)
      and (p_usage      is null or coalesce(nullif(usage,''),'(sin ambiente)') = p_usage)
      and (p_exposed    is null or exposed_internet = p_exposed)
  ), ab as (select * from f where status not in ('fixed','not_observed'))
  select jsonb_build_object(
    'kpi', (select jsonb_build_object(
        'abiertos',     (select count(*) from ab),
        'criticos',     (select count(*) from ab where lower(severity_scanner)='critical'),
        'fuera_sla',    (select count(*) from ab where kri_status is not null and kri_status <> 'IN_TIME'),
        'vencidos',     (select count(*) from ab where vencido_real),
        'deuda_oculta', (select count(*) from ab where kri_status='IN_TIME' and vencido_real),
        'resurfaced',   (select count(*) from f  where status='resurfaced'),
        'no_observados',(select count(*) from f  where status='not_observed'),
        'expuestos',    (select count(*) from ab where exposed_internet),
        'prod',         (select count(*) from ab where usage = 'Prod'),
        'sin_sla',      (select count(*) from ab where sla_days is null),
        'vps',          (select count(distinct nullif(it_vp,'')) from ab),
        'managers',     (select count(distinct nullif(it_manager,'')) from ab),
        'apps',         (select count(distinct nullif(app_name,'')) from ab)
      )),
    'by_severity', (select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value)),'[]'::jsonb)
      from (select coalesce(nullif(severity_scanner,''),'(sin sev)') label, count(*) value
            from ab group by 1) t),
    'by_kri', (select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value)),'[]'::jsonb)
      from (select coalesce(nullif(kri_status,''),'(sin KRI)') label, count(*) value
            from ab group by 1) t),
    'by_it_vp', (select coalesce(jsonb_agg(jsonb_build_object('label',label,
        'Critical',c,'High',h,'Medium',m,'Low',l,'value',c+h+m+l) order by c+h+m+l desc),'[]'::jsonb)
      from (select coalesce(nullif(it_vp,''),'(sin VP)') label,
              count(*) filter (where lower(severity_scanner)='critical') c,
              count(*) filter (where lower(severity_scanner)='high')     h,
              count(*) filter (where lower(severity_scanner)='medium')   m,
              count(*) filter (where lower(severity_scanner)='low')      l
            from ab group by 1 order by count(*) desc limit 10) t),
    'by_it_manager', (select coalesce(jsonb_agg(jsonb_build_object('label',label,
        'Critical',c,'High',h,'Medium',m,'Low',l,'value',c+h+m+l) order by c+h+m+l desc),'[]'::jsonb)
      from (select coalesce(nullif(it_manager,''),'(sin manager)') label,
              count(*) filter (where lower(severity_scanner)='critical') c,
              count(*) filter (where lower(severity_scanner)='high')     h,
              count(*) filter (where lower(severity_scanner)='medium')   m,
              count(*) filter (where lower(severity_scanner)='low')      l
            from ab group by 1 order by count(*) desc limit 10) t),
    'by_app', (select coalesce(jsonb_agg(jsonb_build_object('label',label,
        'Critical',c,'High',h,'Medium',m,'Low',l,'value',c+h+m+l) order by c+h+m+l desc),'[]'::jsonb)
      from (select coalesce(nullif(app_name,''),'(sin app)') label,
              count(*) filter (where lower(severity_scanner)='critical') c,
              count(*) filter (where lower(severity_scanner)='high')     h,
              count(*) filter (where lower(severity_scanner)='medium')   m,
              count(*) filter (where lower(severity_scanner)='low')      l
            from ab group by 1 order by count(*) desc limit 10) t),
    'by_age', (select coalesce(jsonb_agg(jsonb_build_object('label',label,'value',value) order by ord),'[]'::jsonb)
      from (select b.label, b.ord, count(a.finding_key) value
            from (values ('0-30d',1,0,30),('31-90d',2,31,90),('91-180d',3,91,180),
                         ('181-365d',4,181,365),('> 1 año',5,366,999999)) b(label,ord,lo,hi)
            left join ab a on a.edad_dias between b.lo and b.hi
            group by b.label, b.ord) t)
  );
$$;

-- Catálogos para los dropdowns secundarios
create or replace view v_filter_options as
  select 'kri' kind, coalesce(nullif(kri_status,''),'(sin KRI)') label from silver.findings
  union select 'usage', coalesce(nullif(usage,''),'(sin ambiente)') from silver.applications
  union select 'tier',  coalesce(nullif(tier,''),'(sin tier)') from silver.applications;

-- ==========================================================================
-- Permisos. RLS abierta mientras dure la prueba: el techo de cierre de
-- load_commit es lo que impide que una llamada suelta cierre el universo.
-- Antes de datos reales en un sitio público, esto se cierra con Auth.
-- ==========================================================================
alter table bronze.loads            enable row level security;
alter table silver.applications     enable row level security;
alter table silver.findings         enable row level security;
alter table silver.finding_events   enable row level security;
alter table silver.app_scans        enable row level security;
alter table silver.project_epm_map  enable row level security;

do $$ declare t text; s text;
begin
  foreach t in array array['bronze.loads','silver.applications','silver.findings',
                           'silver.finding_events','silver.app_scans','silver.project_epm_map'] loop
    execute format('drop policy if exists prueba_abierta on %s', t);
    execute format('create policy prueba_abierta on %s for all to anon, authenticated using (true) with check (true)', t);
    execute format('grant all on %s to anon, authenticated', t);
  end loop;
end $$;

grant usage on schema bronze, silver to anon, authenticated;
grant usage, select on all sequences in schema silver to anon, authenticated;
grant select on v_findings, v_org_tree, v_loads, v_activity, v_hidden_debt,
                v_recast_log, v_cross_layer, v_app_scans, v_filter_options
      to anon, authenticated;
grant execute on function load_begin(text,text,text)            to anon, authenticated;
grant execute on function load_batch(uuid,jsonb)                to anon, authenticated;
grant execute on function load_commit(uuid,int,boolean)         to anon, authenticated;
grant execute on function load_abort(uuid,text)                 to anon, authenticated;
grant execute on function dashboard_metrics(text,text,text,text,text,text,text,boolean)
      to anon, authenticated;

-- Realtime: SOLO el acta de cargas. Antes `findings` estaba publicada y una
-- carga emitía 63,600 mensajes, cada uno evaluado contra RLS por suscriptor.
-- Un evento por carga da el mismo refresco con 4 órdenes de magnitud menos.
do $$ begin
  alter publication supabase_realtime add table bronze.loads;
exception when duplicate_object then null; when undefined_object then null; end $$;
