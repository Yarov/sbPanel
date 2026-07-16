-- ==========================================================================
-- CERRAR LA PUERTA — córrelo YA en el SQL Editor de Supabase.
--
-- Estado actual (verificado, no teórico):
--   · La anon key está en el bundle publicado en GitHub Pages.
--   · Las políticas dejan pasar a `anon` con `for all ... using (true)`.
--   · `anon` tiene execute sobre las funciones de carga.
--
-- Con eso, un curl sin autenticar lee todos los hallazgos, y este otro los
-- cierra todos de un golpe:
--
--   POST /rest/v1/rpc/ingest_findings
--   {"p_rows":[], "p_close_missing":true, "p_scan_id":"0000...01"}
--   -> {"fixed": 63600}     (reproducido: 100 de 100)
--
-- Esto revoca a `anon`. La app deja de funcionar hasta que entre Auth
-- (el mismo commit la trae). Es a propósito: preferimos que se rompa a que siga abierta.
-- ==========================================================================

-- ---------- 1. quitarle a anon todo lo que tenga ----------
-- OJO: nada de `exception when ...` aquí. Un bloque plpgsql con EXCEPTION es una
-- subtransacción: si un esquema no existe y se atrapa el error, se revierten
-- TAMBIÉN los revokes de los esquemas anteriores que sí habían pasado — y el
-- grant se queda, tapado nada más por RLS. Se filtra por lo que existe.
do $$
declare s text;
begin
  for s in select nspname from pg_namespace
            where nspname in ('public', 'bronze', 'silver') loop
    execute format('revoke all on all tables in schema %I from anon', s);
    execute format('revoke all on all sequences in schema %I from anon', s);
    execute format('revoke all on all functions in schema %I from anon', s);
    execute format('revoke all on schema %I from anon', s);
    -- Postgres le da EXECUTE a PUBLIC en cada función nueva, y anon hereda de
    -- PUBLIC: sin esto, las funciones vuelven a nacer abiertas.
    execute format('revoke execute on all functions in schema %I from public', s);
    -- y que los objetos FUTUROS tampoco nazcan abiertos
    execute format('alter default privileges in schema %I revoke all on tables from anon', s);
    execute format('alter default privileges in schema %I revoke all on functions from anon', s);
    execute format('alter default privileges in schema %I revoke all on sequences from anon', s);
  end loop;
end $$;

-- ---------- 2. tirar las políticas que nombraban a anon ----------
do $$
declare r record;
begin
  for r in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname in ('public','bronze','silver')
      and ('anon' = any(roles) or roles = '{public}')
  loop
    execute format('drop policy if exists %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end $$;

-- ---------- 3. matar el motor viejo, que es el endpoint del cierre masivo ----------
drop function if exists ingest_findings(text, jsonb, timestamptz) cascade;
drop function if exists ingest_findings(text, jsonb, timestamptz, boolean) cascade;
drop function if exists ingest_findings(text, jsonb, timestamptz, boolean, uuid) cascade;

-- ---------- 4. verificación: esto debe salir VACÍO ----------
select 'anon todavía alcanza:' as chequeo,
       table_schema || '.' || table_name as objeto, privilege_type
from information_schema.role_table_grants
where grantee = 'anon' and table_schema in ('public','bronze','silver')
union all
select 'anon puede ejecutar:', n.nspname || '.' || p.proname, 'EXECUTE'
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname in ('public','bronze','silver')
  and has_function_privilege('anon', p.oid, 'EXECUTE')
union all
select 'política abierta a anon:', schemaname || '.' || tablename, policyname
from pg_policies
where schemaname in ('public','bronze','silver') and 'anon' = any(roles);

-- ==========================================================================
-- FALTA UNO, Y NO ES SQL:
--
-- La anon key lleva tiempo publicada en el bundle de GitHub Pages. Revocarle
-- permisos la vuelve inútil, pero da igual asumir que ya circuló:
--
--   Supabase → Settings → API → Rotate anon key
--
-- Y baja el sitio: Settings → Pages → Source: None (en el repo de GitHub).
-- ==========================================================================
