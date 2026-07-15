import { useEffect, useMemo, useState } from "react";
import { supabase, hasSupabase } from "./supabase";

type Profile = { scotiaId: string; name: string };

type Ticket = {
  id: string;
  title: string;
  description: string;
  priority: string;
  assignee: string;
  status: string;
  author: string;
  author_id: string;
  created_at: string;
};

const STATUSES = ["abierto", "en_progreso", "resuelto"] as const;
const STATUS_LABEL: { [k: string]: string } = {
  abierto: "Abierto",
  en_progreso: "En progreso",
  resuelto: "Resuelto",
};
const PRIORITIES = ["baja", "media", "alta"] as const;
const PRIORITY_LABEL: { [k: string]: string } = {
  baja: "Baja",
  media: "Media",
  alta: "Alta",
};

const next = (arr: readonly string[], v: string) =>
  arr[(arr.indexOf(v) + 1) % arr.length];

const PROFILE_KEY = "scotia_profile";

// ---------- Setup (falta configurar Supabase) ----------
function Setup() {
  return (
    <main className="login">
      <div className="login-card">
        <h1 className="login-brand">Scotia · Tickets</h1>
        <p className="login-sub">Falta conectar Supabase para arrancar.</p>
        <ol className="setup-steps">
          <li>Crea un proyecto en <b>supabase.com</b> (gratis).</li>
          <li>Corre el SQL del <b>README</b> para crear la tabla <code>tickets</code>.</li>
          <li>Copia <code>.env.example</code> a <code>.env</code> y pega tu URL y anon key.</li>
          <li>Reinicia <code>npm run dev</code>.</li>
        </ol>
      </div>
    </main>
  );
}

// ---------- Login ----------
function Login({ onDone }: { onDone: (p: Profile) => void }) {
  const [scotiaId, setScotiaId] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!scotiaId.trim() || !name.trim()) {
      setError("ScotiaID y nombre son obligatorios");
      return;
    }
    const p = { scotiaId: scotiaId.trim(), name: name.trim() };
    localStorage.setItem(PROFILE_KEY, JSON.stringify(p));
    onDone(p);
  }

  return (
    <main className="login">
      <div className="login-card">
        <h1 className="login-brand">Scotia · Tickets</h1>
        <p className="login-sub">Ingresa tus datos para comenzar el seguimiento</p>
        <form onSubmit={submit}>
          <input
            value={scotiaId}
            onChange={(e) => setScotiaId(e.currentTarget.value)}
            placeholder="ScotiaID"
            autoFocus
          />
          <input
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
            placeholder="Nombre completo"
          />
          <button type="submit">Entrar</button>
        </form>
        {error && <p className="error">{error}</p>}
      </div>
    </main>
  );
}

// ---------- App de tickets ----------
function Tickets({ profile, onLogout }: { profile: Profile; onLogout: () => void }) {
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [online, setOnline] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("media");
  const [assignee, setAssignee] = useState("");
  const [filter, setFilter] = useState<string>("todos");
  const [error, setError] = useState("");

  async function load() {
    const { data, error } = await supabase
      .from("tickets")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) setError(error.message);
    else setTickets((data ?? []) as Ticket[]);
  }

  useEffect(() => {
    load();
    // Tiempo real: cualquier cambio en la tabla recarga la lista
    const channel = supabase
      .channel("tickets-changes")
      .on("postgres_changes", { event: "*", schema: "public", table: "tickets" }, () => load())
      .subscribe((status) => setOnline(status === "SUBSCRIBED"));
    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!title.trim()) {
      setError("El asunto no puede estar vacío");
      return;
    }
    const { error } = await supabase.from("tickets").insert({
      title: title.trim(),
      description: description.trim(),
      priority,
      assignee: assignee.trim(),
      status: "abierto",
      author: profile.name,
      author_id: profile.scotiaId,
    });
    if (error) {
      setError(error.message);
      return;
    }
    setTitle("");
    setDescription("");
    setAssignee("");
    setPriority("media");
    load();
  }

  async function setFieldValue(id: string, field: string, value: string) {
    await supabase.from("tickets").update({ [field]: value }).eq("id", id);
    load();
  }

  async function remove(id: string) {
    await supabase.from("tickets").delete().eq("id", id);
    load();
  }

  const counts = useMemo(() => {
    const c: { [k: string]: number } = { todos: tickets.length };
    for (const s of STATUSES) c[s] = tickets.filter((t) => t.status === s).length;
    return c;
  }, [tickets]);

  const visible =
    filter === "todos" ? tickets : tickets.filter((t) => t.status === filter);

  return (
    <main className="container">
      <div className="header">
        <h1>Scotia · Tickets</h1>
        <div className="header-right">
          <span className="user-chip" title={`ScotiaID: ${profile.scotiaId}`}>
            {profile.name} · {profile.scotiaId}
          </span>
          <span className={`peers ${online ? "online" : ""}`}>
            <span className="dot" />
            {online ? "en línea" : "conectando…"}
          </span>
        </div>
      </div>
      <div className="subtitle-row">
        <p className="subtitle">Tiempo real · {tickets.length} tickets</p>
        <div className="toolbar">
          <button className="ghost" onClick={onLogout}>Cambiar usuario</button>
        </div>
      </div>

      <form className="add-form" onSubmit={add}>
        <div className="form-row">
          <input
            value={title}
            onChange={(e) => setTitle(e.currentTarget.value)}
            placeholder="Asunto del ticket..."
            className="title-input"
          />
          <select value={priority} onChange={(e) => setPriority(e.currentTarget.value)}>
            {PRIORITIES.map((p) => (
              <option key={p} value={p}>{PRIORITY_LABEL[p]}</option>
            ))}
          </select>
        </div>
        <div className="form-row">
          <input
            value={assignee}
            onChange={(e) => setAssignee(e.currentTarget.value)}
            placeholder="Asignado a (opcional)"
          />
          <input
            value={description}
            onChange={(e) => setDescription(e.currentTarget.value)}
            placeholder="Descripción (opcional)"
          />
          <button type="submit">Crear ticket</button>
        </div>
      </form>
      {error && <p className="error">{error}</p>}

      <div className="filters">
        {["todos", ...STATUSES].map((f) => (
          <button
            key={f}
            className={`filter ${filter === f ? "active" : ""}`}
            onClick={() => setFilter(f)}
          >
            {f === "todos" ? "Todos" : STATUS_LABEL[f]}{" "}
            <span className="count">{counts[f] ?? 0}</span>
          </button>
        ))}
      </div>

      <ul className="records">
        {visible.map((t) => (
          <li key={t.id} className="ticket">
            <div className="ticket-main">
              <button
                className={`status status-${t.status}`}
                onClick={() => setFieldValue(t.id, "status", next(STATUSES, t.status))}
                title="Clic para cambiar estado"
              >
                {STATUS_LABEL[t.status] ?? t.status}
              </button>
              {t.priority && (
                <button
                  className={`prio prio-${t.priority}`}
                  onClick={() => setFieldValue(t.id, "priority", next(PRIORITIES, t.priority))}
                  title="Clic para cambiar prioridad"
                >
                  {PRIORITY_LABEL[t.priority] ?? t.priority}
                </button>
              )}
              <span className="record-title">{t.title}</span>
              <button className="delete" onClick={() => remove(t.id)} title="Borrar">×</button>
            </div>
            {t.description && <p className="ticket-desc">{t.description}</p>}
            <p className="record-meta">
              {t.assignee ? `→ ${t.assignee} · ` : ""}
              por {t.author || "anon"}
              {t.author_id ? ` (${t.author_id})` : ""} ·{" "}
              {new Date(t.created_at).toLocaleString()}
            </p>
          </li>
        ))}
        {visible.length === 0 && <li className="empty">Sin tickets aquí.</li>}
      </ul>
    </main>
  );
}

// ---------- Raíz ----------
function App() {
  const [profile, setProfile] = useState<Profile | null>(() => {
    const raw = localStorage.getItem(PROFILE_KEY);
    return raw ? (JSON.parse(raw) as Profile) : null;
  });

  if (!hasSupabase) return <Setup />;
  if (!profile) return <Login onDone={setProfile} />;
  return (
    <Tickets
      profile={profile}
      onLogout={() => {
        localStorage.removeItem(PROFILE_KEY);
        setProfile(null);
      }}
    />
  );
}

export default App;
