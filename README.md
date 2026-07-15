# Scotia · Tickets

PWA de seguimiento de tickets con **Supabase** como backend (DB + tiempo real, sin API propia que alojar).
Tema Scotia dark. Escala a muchos usuarios; todos le pegan al mismo proyecto Supabase por HTTPS.

## Stack

- **PWA**: React + Vite (instalable, tema oscuro)
- **Backend**: Supabase (Postgres + Realtime), el navegador le pega directo
- **Login**: ScotiaID + nombre (local, estampa cada ticket con quién lo creó)

## Puesta en marcha

### 1. Crear proyecto Supabase
En [supabase.com](https://supabase.com) crea un proyecto (free tier).

### 2. Crear la tabla `tickets`
En Supabase → **SQL Editor**, corre:

```sql
create table tickets (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text default '',
  priority text default 'media',
  assignee text default '',
  status text default 'abierto',
  author text default '',
  author_id text default '',
  created_at timestamptz default now()
);

-- PoC: acceso con la anon key (sin login de Supabase). Ajustar para producción.
alter table tickets enable row level security;
create policy "acceso_poc" on tickets for all using (true) with check (true);

-- Tiempo real
alter publication supabase_realtime add table tickets;
```

### 3. Configurar credenciales
Copia `.env.example` a `.env` y pega tu **Project URL** y **anon key**
(Supabase → Project Settings → API):

```
VITE_SUPABASE_URL=https://TU-PROYECTO.supabase.co
VITE_SUPABASE_ANON_KEY=tu-anon-key
```

### 4. Correr

```bash
npm install
npm run dev
```

## Notas

- La política RLS de arriba es **abierta para la PoC** (cualquiera con la anon key lee/escribe).
  Para producción se restringe con Supabase Auth + políticas por usuario.
- El login (ScotiaID + nombre) se guarda en el navegador y estampa el autor de cada ticket.
