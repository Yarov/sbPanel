//! Capa CRDT: documento automerge persistido en disco (local-first).
//!
//! Modelo simple de TICKET. Diseño merge-safe (aprendido en el spike): cada ticket
//! vive como una llave ÚNICA directamente en ROOT. Como los ids son únicos por nodo,
//! dos nodos nunca crean la misma llave-objeto en concurrencia, así que el `merge`
//! nunca pisa datos. NUNCA crear un contenedor "tickets" compartido con put_object
//! en cada nodo (generaría dos objetos peleando por la misma llave y el merge tira uno).

use automerge::{
    transaction::Transactable, Automerge, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: String, // baja | media | alta
    pub assignee: String,
    pub status: String, // abierto | en_progreso | resuelto
    pub author: String,
    pub author_id: String, // ScotiaID de quien lo creó
    pub created_at: i64,
}

pub struct Store {
    doc: Automerge,
    path: PathBuf,
}

impl Store {
    /// Carga el doc desde disco, o crea uno nuevo si no existe.
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let doc = if path.exists() {
            Automerge::load(&std::fs::read(&path)?)?
        } else {
            Automerge::new()
        };
        Ok(Self { doc, path })
    }

    /// Persiste el doc completo en disco.
    pub fn save(&mut self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, self.doc.save())?;
        Ok(())
    }

    /// Serializa el doc completo para mandarlo a otros peers.
    pub fn snapshot(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Mergea el doc de otro peer. Devuelve cuántos cambios nuevos entraron.
    pub fn merge_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<usize> {
        let mut remote = Automerge::load(bytes)?;
        let new_changes = self.doc.merge(&mut remote)?;
        Ok(new_changes.len())
    }

    /// Crea un ticket. `id` debe ser único (p.ej. máquina + timestamp + contador).
    #[allow(clippy::too_many_arguments)]
    pub fn add_ticket(
        &mut self,
        id: &str,
        title: &str,
        description: &str,
        priority: &str,
        assignee: &str,
        author: &str,
        author_id: &str,
        created_at: i64,
    ) -> anyhow::Result<()> {
        let mut tx = self.doc.transaction();
        let obj = tx.put_object(ROOT, id, ObjType::Map)?;
        tx.put(&obj, "id", id.to_string())?;
        tx.put(&obj, "title", title.to_string())?;
        tx.put(&obj, "description", description.to_string())?;
        tx.put(&obj, "priority", priority.to_string())?;
        tx.put(&obj, "assignee", assignee.to_string())?;
        tx.put(&obj, "status", "abierto".to_string())?;
        tx.put(&obj, "author", author.to_string())?;
        tx.put(&obj, "author_id", author_id.to_string())?;
        tx.put(&obj, "created_at", created_at)?;
        tx.commit();
        Ok(())
    }

    /// Cambia un campo de texto de un ticket (status, priority, assignee, ...).
    /// Merge-safe: llave única por ticket; edición concurrente del MISMO campo se
    /// resuelve por LWW determinista (nadie crashea, ambos convergen).
    pub fn set_field(&mut self, id: &str, field: &str, value: &str) -> anyhow::Result<()> {
        if let Some(obj) = self.find_obj(id) {
            let mut tx = self.doc.transaction();
            tx.put(&obj, field, value.to_string())?;
            tx.commit();
        }
        Ok(())
    }

    /// Borra un ticket (elimina su llave en ROOT).
    pub fn delete_ticket(&mut self, id: &str) -> anyhow::Result<()> {
        if self.find_obj(id).is_some() {
            let mut tx = self.doc.transaction();
            tx.delete(ROOT, id)?;
            tx.commit();
        }
        Ok(())
    }

    pub fn list_tickets(&self) -> Vec<Ticket> {
        let mut out = Vec::new();
        for key in self.doc.keys(ROOT) {
            if let Ok(Some((Value::Object(ObjType::Map), obj))) = self.doc.get(ROOT, &key) {
                out.push(Ticket {
                    id: self.str_at(&obj, "id"),
                    title: self.str_at(&obj, "title"),
                    description: self.str_at(&obj, "description"),
                    priority: self.str_at(&obj, "priority"),
                    assignee: self.str_at(&obj, "assignee"),
                    status: self.str_at(&obj, "status"),
                    author: self.str_at(&obj, "author"),
                    author_id: self.str_at(&obj, "author_id"),
                    created_at: self.int_at(&obj, "created_at"),
                });
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at)); // más reciente primero
        out
    }

    /// Devuelve el ObjId de un ticket por su id (sin mantener el borrow del doc).
    fn find_obj(&self, id: &str) -> Option<ObjId> {
        match self.doc.get(ROOT, id) {
            Ok(Some((Value::Object(ObjType::Map), obj))) => Some(obj),
            _ => None,
        }
    }

    fn str_at(&self, obj: &ObjId, key: &str) -> String {
        match self.doc.get(obj, key) {
            Ok(Some((Value::Scalar(s), _))) => match s.as_ref() {
                ScalarValue::Str(v) => v.to_string(),
                other => other.to_string(),
            },
            _ => String::new(),
        }
    }

    fn int_at(&self, obj: &ObjId, key: &str) -> i64 {
        match self.doc.get(obj, key) {
            Ok(Some((Value::Scalar(s), _))) => match s.as_ref() {
                ScalarValue::Int(i) => *i,
                ScalarValue::Uint(u) => *u as i64,
                _ => 0,
            },
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("scotia_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("t.automerge");
        (Store::load(path).unwrap(), dir)
    }

    #[test]
    fn persiste_y_recarga_desde_disco() {
        let (mut s, dir) = tmp_store("persist");
        let path = s.path.clone();
        s.add_ticket("ana-1", "Error en login", "no deja entrar", "alta", "beto", "ana", "A001", 1000)
            .unwrap();
        s.add_ticket("ana-2", "Reporte lento", "", "media", "", "ana", "A001", 2000)
            .unwrap();
        s.save().unwrap();
        drop(s);

        let recs = Store::load(path).unwrap().list_tickets();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].id, "ana-2", "orden: más reciente primero");
        assert_eq!(recs[1].title, "Error en login");
        assert_eq!(recs[1].priority, "alta");
        assert_eq!(recs[1].assignee, "beto");
        assert_eq!(recs[1].status, "abierto");
    }

    #[test]
    fn cambia_estado_y_borra() {
        let (mut s, dir) = tmp_store("estado");
        s.add_ticket("r-1", "uno", "", "media", "", "ana", "A001", 1000).unwrap();
        s.add_ticket("r-2", "dos", "", "baja", "", "beto", "A002", 2000).unwrap();

        s.set_field("r-1", "status", "resuelto").unwrap();
        s.set_field("r-1", "priority", "alta").unwrap();
        s.delete_ticket("r-2").unwrap();

        let recs = s.list_tickets();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, "r-1");
        assert_eq!(recs[0].status, "resuelto");
        assert_eq!(recs[0].priority, "alta");
    }
}
