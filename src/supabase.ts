import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL;
const key = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** true si las credenciales de Supabase están configuradas (.env). */
export const hasSupabase = Boolean(url && key);

// Cliente único. Si no hay credenciales, la app muestra la pantalla de setup.
export const supabase = hasSupabase ? createClient(url, key) : (null as never);
