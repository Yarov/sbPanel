import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type Record = {
  id: string;
  title: string;
  author: string;
  status: string;
  created_at: number;
};

function App() {
  const [records, setRecords] = useState<Record[]>([]);
  const [peers, setPeers] = useState(0);
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState(localStorage.getItem("author") ?? "");
  const [error, setError] = useState("");

  async function refresh() {
    setRecords(await invoke<Record[]>("list_records"));
  }

  useEffect(() => {
    refresh().catch(console.error);
    // Eventos del backend P2P
    const unsubs = [
      listen<number>("peers-changed", (e) => setPeers(e.payload)),
      listen("doc-updated", () => refresh()),
    ];
    return () => {
      unsubs.forEach((p) => p.then((un) => un()));
    };
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

  return (
    <main className="container">
      <div className="header">
        <h1>Scotia Dashboard</h1>
        <span className={`peers ${peers > 0 ? "online" : ""}`}>
          <span className="dot" />
          {peers > 0 ? `${peers} conectada${peers > 1 ? "s" : ""}` : "sin conexión"}
        </span>
      </div>
      <p className="subtitle">Seguimiento local-first · {records.length} registros</p>

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

      <ul className="records">
        {records.map((r) => (
          <li key={r.id} className="record">
            <span className={`status status-${r.status}`}>{r.status}</span>
            <span className="record-title">{r.title}</span>
            <span className="record-meta">
              {r.author || "anon"} · {new Date(r.created_at).toLocaleString()}
            </span>
          </li>
        ))}
        {records.length === 0 && <li className="empty">Sin registros todavía.</li>}
      </ul>
    </main>
  );
}

export default App;
