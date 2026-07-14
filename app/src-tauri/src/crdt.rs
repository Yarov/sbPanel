//! Capa CRDT: documento automerge persistido en disco (local-first).
//!
//! Diseño merge-safe (aprendido en el spike Fase 0): cada record vive como una
//! llave ÚNICA directamente en ROOT. Como los ids son únicos por nodo, dos nodos
//! nunca crean la misma llave-objeto en concurrencia, así que el `merge` de
//! automerge nunca pisa datos. NUNCA crear un contenedor "records" compartido con
//! put_object en cada nodo: eso genera dos objetos peleando por la misma llave y
//! el merge tira uno con todo su contenido.

use automerge::{
    transaction::Transactable, Automerge, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub title: String,
    pub author: String,
    pub status: String,
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

    /// Agrega un record. `id` debe ser único (p.ej. autor + timestamp/contador).
    pub fn add_record(
        &mut self,
        id: &str,
        title: &str,
        author: &str,
        created_at: i64,
    ) -> anyhow::Result<()> {
        let mut tx = self.doc.transaction();
        let obj = tx.put_object(ROOT, id, ObjType::Map)?;
        tx.put(&obj, "id", id.to_string())?;
        tx.put(&obj, "title", title.to_string())?;
        tx.put(&obj, "author", author.to_string())?;
        tx.put(&obj, "status", "open".to_string())?;
        tx.put(&obj, "created_at", created_at)?;
        tx.commit();
        Ok(())
    }

    /// Serializa el doc completo para mandarlo a otros peers.
    pub fn snapshot(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Mergea el doc de otro peer. Devuelve cuántos cambios nuevos entraron
    /// (0 = ya estábamos al día). automerge nunca pisa datos en el merge.
    pub fn merge_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<usize> {
        let mut remote = Automerge::load(bytes)?;
        let new_changes = self.doc.merge(&mut remote)?;
        Ok(new_changes.len())
    }

    pub fn list_records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        for key in self.doc.keys(ROOT) {
            if let Ok(Some((Value::Object(ObjType::Map), obj))) = self.doc.get(ROOT, &key) {
                out.push(Record {
                    id: self.str_at(&obj, "id"),
                    title: self.str_at(&obj, "title"),
                    author: self.str_at(&obj, "author"),
                    status: self.str_at(&obj, "status"),
                    created_at: self.int_at(&obj, "created_at"),
                });
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at)); // más reciente primero
        out
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

    #[test]
    fn persiste_y_recarga_desde_disco() {
        let dir = std::env::temp_dir().join(format!("scotia_test_{}", std::process::id()));
        let path = dir.join("t.automerge");
        let _ = std::fs::remove_dir_all(&dir);

        // escribe y guarda
        {
            let mut s = Store::load(path.clone()).unwrap();
            s.add_record("ana-1", "Llamar cliente X", "ana", 1000).unwrap();
            s.add_record("ana-2", "Revisar reporte", "ana", 2000).unwrap();
            s.save().unwrap();
        }

        // recarga en un Store nuevo (simula reinicio de la app)
        let recs = Store::load(path.clone()).unwrap().list_records();
        assert_eq!(recs.len(), 2, "deben persistir los 2 records");
        assert_eq!(recs[0].id, "ana-2", "orden: más reciente primero");
        assert_eq!(recs[0].title, "Revisar reporte");
        assert_eq!(recs[1].author, "ana");
        assert_eq!(recs[1].status, "open");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
