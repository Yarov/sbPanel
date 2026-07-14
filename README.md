# Scotia Dashboard

Dashboard de seguimiento **local-first + P2P** para red interna aislada (sin internet, sin servidor).
Cada máquina tiene una réplica completa; se sincronizan **directo entre sí por la LAN** cuando coinciden
conectadas. App de escritorio con **Tauri v2** (Rust) + **React**.

## Cómo funciona

- **CRDT (automerge):** merge sin conflictos, nadie pisa los datos de nadie.
- **P2P (libp2p):** descubrimiento por **mDNS** + propagación por **gossipsub**, sin punto central.
- **Local-first:** cada peer persiste su réplica en disco; funciona offline y sincroniza al reconectar.

> Límite conocido: si dos peers **nunca** coinciden conectados, no se sincronizan hasta que coincidan
> (se mitiga con propagación gossip A→B→C y, a futuro, export/import manual).

## Estructura

```
app/      # La app real (Tauri v2 + React-TS)
spike/    # Prototipo de de-risk P2P puro (Fase 0), CLI en Rust
```

## Desarrollo

```bash
cd app
npm install
npm run tauri dev
```

Probar dos instancias en la misma máquina (P2P local):

```bash
# ventana A: npm run tauri dev
# ventana B:
SCOTIA_DATA_DIR=/tmp/scotia-B app/src-tauri/target/debug/app
```

## Tests

```bash
cd app/src-tauri && cargo test
```

Incluye `sincroniza_dos_peers_en_lan`: levanta dos swarms reales y valida que un registro creado en A
llega a B por mDNS + gossipsub + merge.

## Builds (CI)

GitHub Actions (`.github/workflows/build.yml`) compila para **macOS (universal)** y **Windows** y sube los
instaladores como artefactos. Sin firma de código (PoC).
