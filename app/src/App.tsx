import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";

type Record = {
  id: string;
  title: string;
  author: string;
  status: string;
  created_at: number;
};

const STATUSES = ["pendiente", "en_progreso", "hecho"] as const;
const STATUS_LABEL: { [k: string]: string } = {
  pendiente: "Pendiente",
  en_progreso: "En progreso",
  hecho: "Hecho",
};

function nextStatus(s: string): string {
  const i = STATUSES.indexOf(s as (typeof STATUSES)[number]);
  return STATUSES[(i + 1) % STATUSES.length];
}

function App() {
  const [records, setRecords] = useState<Record[]>([]);
  const [peers, setPeers] = useState(0);
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState(localStorage.getItem("author") ?? "");
  const [filter, setFilter] = useState<string>("todos");
  const [error, setError] = useState("");

  async function refresh() {
    setRecords(await invoke<Record[]>("list_records"));
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
      localStorage.setItem("author", author);
      setRecords(await invoke<Record[]>("add_record", { title, author }));
      setTitle("");
    } catch (err) {
      setError(String(err));
    }
  }

  async function cycleStatus(r: Record) {
    setRecords(
      await invoke<Record[]>("update_status", { id: r.id, status: nextStatus(r.status) })
    );
  }

  async function remove(r: Record) {
    setRecords(await invoke<Record[]>("delete_record", { id: r.id }));
  }

  async function exportDoc() {
    const path = await save({
      defaultPath: "scotia-seguimiento.scdb",
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
      setRecords(await invoke<Record[]>("import_doc", { path }));
    }
  }

  const counts = useMemo(() => {
    const c: { [k: string]: number } = { todos: records.length };
    for (const s of STATUSES) c[s] = records.filter((r) => r.status === s).length;
    return c;
  }, [records]);

  const visible = filter === "todos" ? records : records.filter((r) => r.status === filter);

  return (
    <main className="container">
      <div className="header">
        <h1>Scotia Dashboard</h1>
        <span className={`peers ${peers > 0 ? "online" : ""}`}>
          <span className="dot" />
          {peers > 0 ? `${peers} conectada${peers > 1 ? "s" : ""}` : "sin conexión"}
        </span>
      </div>
      <div className="subtitle-row">
        <p className="subtitle">Seguimiento local-first · {records.length} registros</p>
        <div className="toolbar">
          <button className="ghost" onClick={exportDoc} title="Guardar una copia del seguimiento">
            Exportar
          </button>
          <button className="ghost" onClick={importDoc} title="Importar y fusionar otra copia">
            Importar
          </button>
        </div>
      </div>

      <form className="add-form" onSubmit={add}>
        <input
          value={author}
          onChange={(e) => setAuthor(e.currentTarget.value)}
          placeholder="Tu nombre"
          className="author-input"
        />
        <input
          value={title}
          onChange={(e) => setTitle(e.currentTarget.value)}
          placeholder="Nuevo registro de seguimiento..."
          className="title-input"
        />
        <button type="submit">Agregar</button>
      </form>
      {error && <p className="error">{error}</p>}

      <div className="filters">
        {["todos", ...STATUSES].map((f) => (
          <button
            key={f}
            className={`filter ${filter === f ? "active" : ""}`}
            onClick={() => setFilter(f)}
          >
            {f === "todos" ? "Todos" : STATUS_LABEL[f]} <span className="count">{counts[f] ?? 0}</span>
          </button>
        ))}
      </div>

      <ul className="records">
        {visible.map((r) => (
          <li key={r.id} className="record">
            <button
              className={`status status-${r.status}`}
              onClick={() => cycleStatus(r)}
              title="Clic para cambiar estado"
            >
              {STATUS_LABEL[r.status] ?? r.status}
            </button>
            <span className="record-title">{r.title}</span>
            <span className="record-meta">
              {r.author || "anon"} · {new Date(r.created_at).toLocaleDateString()}
            </span>
            <button className="delete" onClick={() => remove(r)} title="Borrar">
              ×
            </button>
          </li>
        ))}
        {visible.length === 0 && <li className="empty">Sin registros aquí.</li>}
      </ul>
    </main>
  );
}

export default App;
