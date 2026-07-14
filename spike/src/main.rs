//! Spike Fase 0 — de-risk del core P2P + CRDT.
//!
//! Un solo binario que:
//!   1. Descubre otros peers en la LAN por mDNS (libp2p) — sin internet, sin servidor.
//!   2. Comparte un documento automerge (CRDT) por gossipsub.
//!   3. Al recibir el doc de otro peer, hace `merge` (convergencia sin conflictos).
//!
//! Prueba: corre 2+ instancias en la misma LAN, escribe texto en una y Enter;
//! debe aparecer en las otras. Apaga una, escribe en ambas por separado, reconecta:
//! convergen sin perder nada. Eso valida los pasos 1, 2 y 4 del plan.

use anyhow::Result;
use automerge::{transaction::Transactable, Automerge, ReadDoc, Value, ROOT};
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Swarm,
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

// ---------- capa CRDT (automerge) ----------

// GOTCHA automerge: NO crear un map contenedor con `put_object` de forma
// independiente en cada nodo — dos maps distintos pelean por la misma llave y el
// merge tira uno con todo su contenido. Guardamos los records DIRECTO en ROOT,
// que es el mismo objeto en todos los nodos. Llaves únicas por record → merge limpio.
// (En el producto real: sembrar un doc base idéntico compartido para tener estructura.)
fn add_record(doc: &mut Automerge, id: &str, text: &str) -> Result<()> {
    let mut tx = doc.transaction();
    tx.put(ROOT, id, text.to_string())?;
    tx.commit();
    Ok(())
}

fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::Scalar(s) => s.to_string(),
        other => format!("{other:?}"),
    }
}

fn print_state(doc: &Automerge) {
    let mut keys: Vec<String> = doc.keys(ROOT).collect();
    keys.sort();
    println!("   ── estado: {} records ──", keys.len());
    for k in keys {
        if let Ok(Some((v, _))) = doc.get(ROOT, &k) {
            println!("      {k}: {}", scalar_to_string(&v));
        }
    }
}

// ---------- red (libp2p) ----------

fn publish(swarm: &mut Swarm<Behaviour>, topic: &gossipsub::IdentTopic, doc: &mut Automerge) {
    let data = doc.save();
    match swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
        Ok(_) | Err(gossipsub::PublishError::InsufficientPeers) => {}
        Err(e) => eprintln!("publish error: {e}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
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

    let topic = gossipsub::IdentTopic::new("scotia-crdt");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let full = swarm.local_peer_id().to_string();
    let short = full[full.len().saturating_sub(6)..].to_string();
    println!("🚀 nodo {short} — escribe texto + Enter para agregar un record\n");

    let mut doc = Automerge::new();
    let mut counter = 0u64;
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut rebroadcast = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = rebroadcast.tick() => {
                publish(&mut swarm, &topic, &mut doc);
            }
            line = stdin.next_line() => {
                if let Ok(Some(raw)) = line {
                    let text = raw.trim().to_string();
                    if text.is_empty() { continue; }
                    counter += 1;
                    let id = format!("{short}-{counter}");
                    add_record(&mut doc, &id, &text)?;
                    println!("➕ agregado {id}: {text}");
                    print_state(&doc);
                    publish(&mut swarm, &topic, &mut doc);
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("👂 escuchando en {address}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("🤝 conectado a {peer_id}");
                    publish(&mut swarm, &topic, &mut doc); // sincroniza al conectar
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    println!("⚠️ error dial a {peer_id:?}: {error}");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    let local = *swarm.local_peer_id();
                    for (pid, addr) in list {
                        println!("🔍 descubierto {pid} @ {addr}");
                        // NO usamos add_explicit_peer: hace que gossipsub dialee por su
                        // cuenta y rompe el tie-break, causando dials cruzados simultáneos.
                        // Tie-break: solo el peer con id menor inicia el dial. Gossipsub
                        // descubre al peer sobre la conexión (ambos suscritos + flood_publish).
                        if local.to_bytes() < pid.to_bytes() {
                            if let Err(e) = swarm.dial(addr.clone()) {
                                println!("⚠️ no pude iniciar dial a {addr}: {e}");
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (pid, _addr) in list {
                        println!("👋 expiró {pid}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    match Automerge::load(&message.data) {
                        Ok(mut remote) => match doc.merge(&mut remote) {
                            Ok(changes) if !changes.is_empty() => {
                                println!("🔀 merge recibido ({} cambios nuevos)", changes.len());
                                print_state(&doc);
                            }
                            Ok(_) => {} // ya estábamos al día
                            Err(e) => eprintln!("merge error: {e}"),
                        },
                        Err(e) => eprintln!("load error: {e}"),
                    }
                }
                _ => {}
            }
        }
    }
}
