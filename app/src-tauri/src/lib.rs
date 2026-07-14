mod crdt;
mod p2p;

use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager, State};
use tokio::sync::mpsc;

/// Perfil del usuario de esta máquina (identidad para el seguimiento).
#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    scotia_id: String,
    name: String,
}

/// Puente de eventos del swarm hacia la UI vía Tauri.
#[derive(Clone)]
struct TauriEvents(tauri::AppHandle);
impl p2p::Events for TauriEvents {
    fn peers_changed(&self, n: usize) {
        let _ = self.0.emit("peers-changed", n);
    }
    fn doc_updated(&self) {
        let _ = self.0.emit("doc-updated", ());
    }
}

struct AppState {
    store: Arc<Mutex<crdt::Store>>,
    /// Sufijo corto del peer id local — identifica esta máquina en los ids de record.
    local_short: String,
    /// Señala al swarm que el doc local cambió y debe propagarse.
    broadcast_tx: mpsc::UnboundedSender<()>,
    counter: AtomicU64,
    profile: Mutex<Option<Profile>>,
    profile_path: PathBuf,
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Carga la identidad libp2p persistida, o genera una nueva y la guarda.
/// Un peer id estable = "quién es esta máquina" a lo largo del tiempo.
fn load_or_create_keypair(path: &Path) -> Keypair {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(kp) = Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }
    let kp = Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        let _ = std::fs::write(path, bytes);
    }
    kp
}

#[tauri::command]
fn whoami(state: State<'_, AppState>) -> String {
    state.local_short.clone()
}

#[tauri::command]
fn get_profile(state: State<'_, AppState>) -> Option<Profile> {
    state.profile.lock().unwrap().clone()
}

#[tauri::command]
fn set_profile(
    state: State<'_, AppState>,
    scotia_id: String,
    name: String,
) -> Result<Profile, String> {
    let p = Profile {
        scotia_id: scotia_id.trim().to_string(),
        name: name.trim().to_string(),
    };
    if p.scotia_id.is_empty() || p.name.is_empty() {
        return Err("ScotiaID y nombre son obligatorios".into());
    }
    let bytes = serde_json::to_vec(&p).map_err(|e| e.to_string())?;
    std::fs::write(&state.profile_path, bytes).map_err(|e| e.to_string())?;
    *state.profile.lock().unwrap() = Some(p.clone());
    Ok(p)
}

#[tauri::command]
fn list_tickets(state: State<'_, AppState>) -> Vec<crdt::Ticket> {
    state.store.lock().unwrap().list_tickets()
}

#[tauri::command]
fn add_ticket(
    state: State<'_, AppState>,
    title: String,
    description: String,
    priority: String,
    assignee: String,
) -> Result<Vec<crdt::Ticket>, String> {
    let title = title.trim().to_string();
    if title.is_empty() {
        return Err("El asunto no puede estar vacío".into());
    }
    let priority = if priority.is_empty() { "media".into() } else { priority };

    // El autor sale del perfil (ScotiaID + nombre), no del formulario.
    let (author, author_id) = {
        let guard = state.profile.lock().unwrap();
        let p = guard.as_ref().ok_or("Configura tu perfil primero")?;
        (p.name.clone(), p.scotia_id.clone())
    };

    let n = state.counter.fetch_add(1, Ordering::Relaxed);
    // id único global: máquina + tiempo + contador local → sin colisiones entre peers.
    let id = format!("{}-{}-{}", state.local_short, now_millis(), n);

    let tickets = {
        let mut store = state.store.lock().unwrap();
        store
            .add_ticket(
                &id,
                &title,
                description.trim(),
                &priority,
                assignee.trim(),
                &author,
                &author_id,
                now_millis(),
            )
            .map_err(|e| e.to_string())?;
        store.save().map_err(|e| e.to_string())?;
        store.list_tickets()
    };

    // avisa al swarm para propagar de inmediato (ignora error si el swarm no arrancó)
    let _ = state.broadcast_tx.send(());
    Ok(tickets)
}

/// Actualiza un campo editable del ticket (status | priority | assignee).
#[tauri::command]
fn update_field(
    state: State<'_, AppState>,
    id: String,
    field: String,
    value: String,
) -> Result<Vec<crdt::Ticket>, String> {
    if !matches!(field.as_str(), "status" | "priority" | "assignee") {
        return Err(format!("campo no editable: {field}"));
    }
    let tickets = {
        let mut store = state.store.lock().unwrap();
        store.set_field(&id, &field, &value).map_err(|e| e.to_string())?;
        store.save().map_err(|e| e.to_string())?;
        store.list_tickets()
    };
    let _ = state.broadcast_tx.send(());
    Ok(tickets)
}

#[tauri::command]
fn delete_ticket(state: State<'_, AppState>, id: String) -> Result<Vec<crdt::Ticket>, String> {
    let tickets = {
        let mut store = state.store.lock().unwrap();
        store.delete_ticket(&id).map_err(|e| e.to_string())?;
        store.save().map_err(|e| e.to_string())?;
        store.list_tickets()
    };
    let _ = state.broadcast_tx.send(());
    Ok(tickets)
}

/// Exporta la réplica completa a un archivo (sneakernet: copiar por USB a un
/// peer que nunca coincide conectado).
#[tauri::command]
fn export_doc(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let bytes = state.store.lock().unwrap().snapshot();
    std::fs::write(&path, bytes).map_err(|e| e.to_string())
}

/// Importa un archivo exportado y lo mergea (nunca pisa datos locales).
#[tauri::command]
fn import_doc(state: State<'_, AppState>, path: String) -> Result<Vec<crdt::Ticket>, String> {
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let tickets = {
        let mut store = state.store.lock().unwrap();
        store.merge_bytes(&bytes).map_err(|e| e.to_string())?;
        store.save().map_err(|e| e.to_string())?;
        store.list_tickets()
    };
    let _ = state.broadcast_tx.send(());
    Ok(tickets)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // SCOTIA_DATA_DIR permite correr varias instancias en la misma máquina
            // (cada una con su identidad/datos) para probar el P2P localmente.
            let dir = match std::env::var("SCOTIA_DATA_DIR") {
                Ok(d) => std::path::PathBuf::from(d),
                Err(_) => app.path().app_data_dir()?,
            };
            std::fs::create_dir_all(&dir)?;

            let keypair = load_or_create_keypair(&dir.join("identity.key"));
            let peer_id = keypair.public().to_peer_id().to_base58();
            let local_short = peer_id[peer_id.len().saturating_sub(6)..].to_string();

            let store = crdt::Store::load(dir.join("scotia-records.automerge"))?;
            let store = Arc::new(Mutex::new(store));

            let profile_path = dir.join("profile.json");
            let profile: Option<Profile> = std::fs::read(&profile_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());

            let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel::<()>();

            app.manage(AppState {
                store: store.clone(),
                local_short,
                broadcast_tx,
                counter: AtomicU64::new(0),
                profile: Mutex::new(profile),
                profile_path,
            });

            // El swarm corre en su propio runtime tokio (thread dedicado) para
            // garantizar los drivers de IO/tiempo, independiente del runtime de Tauri.
            let handle = app.handle().clone();
            let store_for_task = store.clone();
            std::thread::spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("no pude crear runtime tokio: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let events = TauriEvents(handle);
                    if let Err(e) = p2p::run(keypair, store_for_task, events, broadcast_rx).await {
                        eprintln!("swarm P2P terminó con error: {e}");
                    }
                });
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            whoami,
            get_profile,
            set_profile,
            list_tickets,
            add_ticket,
            update_field,
            delete_ticket,
            export_doc,
            import_doc
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
