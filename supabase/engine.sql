-- ==========================================================================
-- MOTOR v2 — Tenable primero. Reemplaza el findings plano de schema.sql.
--
-- Qué cambia y por qué:
--  · bronze.loads     registro de cargas con lock de carga única. Dos analistas
--                     cargando a la vez se aniquilaban entre sí (reproducido:
--                     los dos archivos completos y correctos -> 50% cerrado en falso).
--  · silver.applications  el APM es una entidad, no columnas repetidas 63,636 veces.
--  · silver.finding_events  la bitácora. Sin esto no hay MTTR ni auditoría del recast.
--  · ausente != remediado.  Tenable ya dice state=FIXED explícitamente. Lo que
--                     desaparece del archivo pasa a 'not_observed': no sabemos.
--  · sla_days sin valor es NULL, nunca 120. El default silencioso reportaba
--                     IN_TIME a un Critical de SLA 15d que llevaba 20 días abierto.
-- ==========================================================================

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
  r jsonb; v_key text; v_dur text; v_epm text; v_st text;
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
          r->>'kri_status', (r->>'sla_days')::int, (r->>'remaining_days')::int, p_load_id);
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

        if v_prev.sla_days is distinct from (r->>'sla_days')::int then
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
          kri_status=r->>'kri_status', sla_days=(r->>'sla_days')::int,
          remaining_days=(r->>'remaining_days')::int,
          last_load_id=p_load_id, updated_at=now()
        where finding_key=v_key;
        v_upd := v_upd + 1;
      end if;

      v_maxseen := greatest(v_maxseen, v_seen);
    exception when others then v_err := v_err + 1;
    end;
  end loop;

  -- data_date sale del CONTENIDO, no del reloj del navegador: así se detecta
  -- que subieron el archivo del mes pasado encima del de este mes.
  update bronze.loads set
    rows_seen = rows_seen + v_new + v_upd,
    data_date = greatest(data_date, v_maxseen)
  where load_id = p_load_id;

  return jsonb_build_object('new',v_new,'updated',v_upd,'resurfaced',v_resurf,
    'recast',v_recast,'reassigned',v_reassign,'errores',v_err);
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
