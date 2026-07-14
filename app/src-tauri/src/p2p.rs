//! Núcleo P2P: swarm libp2p (mDNS + gossipsub) integrado con el Store CRDT.
//!
//! Corre en su propio runtime tokio (thread dedicado). Sincroniza el documento
//! automerge entre peers de la LAN y avisa a la UI vía eventos Tauri:
//!   - `peers-changed` (usize): cuántas máquinas están conectadas ahora.
//!   - `doc-updated` (): entraron cambios de otro peer; la UI debe recargar.
//!
//! Lecciones del spike (Fase 0):
//!   - mDNS solo anuncia direcciones → hay que dialear.
//!   - Tie-break por peer id para evitar dials cruzados que rompen el handshake noise.
//!   - NO usar add_explicit_peer (gossipsub dialea solo y rompe el tie-break).

use crate::crdt::Store;
use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, identity::Keypair, mdns, multiaddr::Protocol, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const TOPIC: &str = "scotia-crdt";

/// Órdenes de la UI hacia el swarm.
pub enum Cmd {
    /// El doc local cambió; propágalo.
    Broadcast,
    /// Conecta a una máquina por "ip:puerto" o un multiaddr.
    Dial(String),
}

/// Salidas del swarm hacia la capa de UI. Desacopla el P2P de Tauri para poder
/// testear la sincronización headless (ver tests).
pub trait Events: Send + 'static {
    fn peers_changed(&self, n: usize);
    fn doc_updated(&self);
    /// Dirección LAN donde este nodo escucha ("ip:puerto"), para compartir.
    fn listen_addr(&self, addr: String);
}

/// Convierte "ip:puerto" (o un multiaddr "/ip4/.../tcp/...") en Multiaddr.
fn parse_dial_addr(s: &str) -> anyhow::Result<Multiaddr> {
    let s = s.trim();
    if s.starts_with('/') {
        Ok(s.parse()?)
    } else if let Some((ip, port)) = s.rsplit_once(':') {
        Ok(format!("/ip4/{}/tcp/{}", ip.trim(), port.trim()).parse()?)
    } else {
        anyhow::bail!("usa formato ip:puerto");
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/// Arranca el swarm y corre el loop de sincronización hasta que el proceso muere.
/// `broadcast_rx` recibe una señal cada vez que un comando local cambia el doc.
pub async fn run<E: Events>(
    keypair: Keypair,
    store: Arc<Mutex<Store>>,
    events: E,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
) -> Result<()> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .flood_publish(true)
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(Behaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let topic = gossipsub::IdentTopic::new(TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut connected: HashSet<PeerId> = HashSet::new();
    let mut rebroadcast = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = rebroadcast.tick() => {
                let data = store.lock().unwrap().snapshot();
                publish(&mut swarm, &topic, data);
            }
            Some(cmd) = cmd_rx.recv() => match cmd {
                Cmd::Broadcast => {
                    let data = store.lock().unwrap().snapshot();
                    publish(&mut swarm, &topic, data);
                }
                Cmd::Dial(addr) => match parse_dial_addr(&addr) {
                    Ok(ma) => {
                        println!("☎️  conectando a {ma}");
                        if let Err(e) = swarm.dial(ma) {
                            eprintln!("dial error: {e}");
                        }
                    }
                    Err(e) => eprintln!("dirección inválida '{addr}': {e}"),
                },
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    // publica la dirección LAN (ip:puerto) para compartir con otras máquinas
                    let mut ip = None;
                    let mut port = None;
                    for p in address.iter() {
                        match p {
                            Protocol::Ip4(a) => ip = Some(a.to_string()),
                            Protocol::Tcp(p) => port = Some(p),
                            _ => {}
                        }
                    }
                    if let (Some(ip), Some(port)) = (ip, port) {
                        if ip != "127.0.0.1" {
                            events.listen_addr(format!("{ip}:{port}"));
                        }
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    connected.insert(peer_id);
                    events.peers_changed(connected.len());
                    let data = store.lock().unwrap().snapshot();
                    publish(&mut swarm, &topic, data); // sincroniza al conectar
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                    if num_established == 0 {
                        connected.remove(&peer_id);
                        events.peers_changed(connected.len());
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    let local = *swarm.local_peer_id();
                    for (pid, addr) in list {
                        // Tie-break: solo el peer con id menor dialea (evita colisión noise).
                        if local.to_bytes() < pid.to_bytes() {
                            let _ = swarm.dial(addr);
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    let applied = {
                        let mut s = store.lock().unwrap();
                        match s.merge_bytes(&message.data) {
                            Ok(n) if n > 0 => {
                                let _ = s.save();
                                n
                            }
                            _ => 0,
                        }
                    };
                    if applied > 0 {
                        events.doc_updated();
                    }
                }
                _ => {}
            }
        }
    }
}

fn publish(swarm: &mut Swarm<Behaviour>, topic: &gossipsub::IdentTopic, data: Vec<u8>) {
    match swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
        Ok(_) | Err(gossipsub::PublishError::InsufficientPeers) => {}
        Err(e) => eprintln!("publish error: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestEvents;
    impl Events for TestEvents {
        fn peers_changed(&self, _n: usize) {}
        fn doc_updated(&self) {}
        fn listen_addr(&self, _addr: String) {}
    }

    // Corre DOS swarms de producción en esta máquina: A agrega un record y B
    // debe recibirlo por mDNS + gossipsub + merge. Valida el código real de Fase 2.
    #[test]
    fn sincroniza_dos_peers_en_lan() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let dir = std::env::temp_dir().join(format!("scotia_p2p_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let store_a = Arc::new(Mutex::new(Store::load(dir.join("a.am")).unwrap()));
            let store_b = Arc::new(Mutex::new(Store::load(dir.join("b.am")).unwrap()));

            let (tx_a, rx_a) = mpsc::unbounded_channel();
            let (_tx_b, rx_b) = mpsc::unbounded_channel();

            let sa = store_a.clone();
            tokio::spawn(async move {
                let _ = run(Keypair::generate_ed25519(), sa, TestEvents, rx_a).await;
            });
            let sb = store_b.clone();
            tokio::spawn(async move {
                let _ = run(Keypair::generate_ed25519(), sb, TestEvents, rx_b).await;
            });

            // deja que se descubran y conecten
            tokio::time::sleep(Duration::from_secs(7)).await;

            // A agrega un record y notifica a su swarm para propagar
            {
                let mut s = store_a.lock().unwrap();
                s.add_ticket("a-1", "hola-p2p", "", "media", "", "ana", "A001", 1000)
                    .unwrap();
                s.save().unwrap();
            }
            tx_a.send(Cmd::Broadcast).unwrap();

            // espera propagación
            tokio::time::sleep(Duration::from_secs(6)).await;

            let recs_b = store_b.lock().unwrap().list_tickets();
            let _ = std::fs::remove_dir_all(&dir);

            assert!(
                recs_b.iter().any(|r| r.title == "hola-p2p"),
                "B debe recibir el record de A por P2P; B tiene: {recs_b:?}"
            );
        });
    }
}
