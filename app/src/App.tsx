import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";

type Profile = { scotia_id: string; name: string };

type Ticket = {
  id: string;
  title: string;
  description: string;
  priority: string;
  assignee: string;
  status: string;
  author: string;
  author_id: string;
  created_at: number;
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

// ---------- Pantalla de inicio ----------
function Login({ onDone }: { onDone: (p: Profile) => void }) {
  const [scotiaId, setScotiaId] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const p = await invoke<Profile>("set_profile", { scotiaId, name });
      onDone(p);
    } catch (err) {
      setError(String(err));
    }
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
function Tickets({ profile }: { profile: Profile }) {
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [peers, setPeers] = useState(0);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("media");
  const [assignee, setAssignee] = useState("");
  const [filter, setFilter] = useState<string>("todos");
  const [error, setError] = useState("");

  async function refresh() {
    setTickets(await invoke<Ticket[]>("list_tickets"));
  }

  useEffect(() => {
    refresh().catch(console.error);
    const unsubs = [
      listen<number>("peers-changed", (e) => setPeers(e.payload)),
      listen("doc-updated", () => refresh()),
    ];
    return () => unsubs.forEach((p) => p.then((un) => un()));
  }, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      setTickets(
        await invoke<Ticket[]>("add_ticket", { title, description, priority, assignee })
      );
      setTitle("");
      setDescription("");
      setAssignee("");
      setPriority("media");
    } catch (err) {
      setError(String(err));
    }
  }

  const setFieldValue = async (id: string, field: string, value: string) =>
    setTickets(await invoke<Ticket[]>("update_field", { id, field, value }));

  const remove = async (id: string) =>
    setTickets(await invoke<Ticket[]>("delete_ticket", { id }));

  async function exportDoc() {
    const path = await save({
      defaultPath: "scotia-tickets.scdb",
      filters: [{ name: "Scotia", extensions: ["scdb"] }],
    });
    if (path) await invoke("export_doc", { path });
  }

  async function importDoc() {
    const path = await open({
      multiple: false,
      filters: [{ name: "Scotia", extensions: ["scdb"] }],
    });
    if (typeof path === "string") {
      setTickets(await invoke<Ticket[]>("import_doc", { path }));
    }
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
          <span className="user-chip" title={`ScotiaID: ${profile.scotia_id}`}>
            {profile.name} · {profile.scotia_id}
          </span>
          <span className={`peers ${peers > 0 ? "online" : ""}`}>
            <span className="dot" />
            {peers > 0 ? `${peers} conectada${peers > 1 ? "s" : ""}` : "sin conexión"}
          </span>
        </div>
      </div>
      <div className="subtitle-row">
        <p className="subtitle">Seguimiento local-first · {tickets.length} tickets</p>
        <div className="toolbar">
          <button className="ghost" onClick={exportDoc}>Exportar</button>
          <button className="ghost" onClick={importDoc}>Importar</button>
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

// ---------- Raíz: decide login vs tickets ----------
function App() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    invoke<Profile | null>("get_profile")
      .then((p) => setProfile(p))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return null;
  if (!profile) return <Login onDone={setProfile} />;
  return <Tickets profile={profile} />;
}

export default App;
