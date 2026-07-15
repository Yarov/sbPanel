import { createClient } from "@supabase/supabase-js";

// Config pública del proyecto Supabase. La anon key es una clave de CLIENTE:
// va embebida en el navegador por diseño, así que es seguro tenerla aquí.
// Se puede sobreescribir con .env para otros entornos.
// PoC: la seguridad real es la RLS (hoy abierta). Para producción → Supabase Auth
// + RLS por usuario para cerrar el acceso.
const url =
  import.meta.env.VITE_SUPABASE_URL || "https://pcppfzboggdldyzyojhm.supabase.co";
const key =
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBjcHBmemJvZ2dkbGR5enlvamhtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQwODA3OTgsImV4cCI6MjA5OTY1Njc5OH0.IhN1pf5nrWWQ2eMR2mSUvfjYa6jpHMW9QtinPt7huhw";

/** true si hay credenciales de Supabase (siempre, por el default público). */
export const hasSupabase = Boolean(url && key);

export const supabase = hasSupabase ? createClient(url, key) : (null as never);
