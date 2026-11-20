//! Session de boîte PST/OST (feature 002) : l'arborescence et les listes viennent des tables de
//! dossiers ; seuls les éléments ouverts par l'analyste sont lus et analysés (FR-006), une fois,
//! puis gardés pour la session. L'empreinte de la boîte se calcule par pas bornés (FR-002).

use crate::{Analyzed, expand_attached_messages};
use mf_core::{EngineError, Evidence, FolderInfo, Format, ItemSummary, StoreInfo};
use mf_pst::hash::{Digests, StreamHasher};
use mf_pst::{ByteSource, PstBox};
use mf_sig::Keyring;
use serde::Serialize;
use std::collections::HashMap;
use std::io;
use std::path::Path;

/// Avancement du calcul d'empreinte.
#[derive(Debug, Clone, Serialize)]
pub struct HashProgress {
    pub done: u64,
    pub total: u64,
    pub sha256: Option<String>,
    pub md5: Option<String>,
}

pub struct BoxSession {
    pst: PstBox,
    name: String,
    hash_source: Box<dyn ByteSource>,
    hasher: StreamHasher,
    digests: Option<Digests>,
    /// Dossier où chaque élément a été listé (provenance).
    item_folder: HashMap<u32, u32>,
    /// Classe MAPI de chaque élément listé (`IPM.Note`, `IPM.Contact`…).
    item_class: HashMap<u32, String>,
    analyzed: HashMap<u32, Analyzed>,
}

/// Élément de type courriel (message, accusé, invitation reçue par courriel) ; les autres
/// éléments d'une boîte (rendez-vous, contacts, tâches, notes, journaux) ne reçoivent pas de verdict.
pub fn is_mail(class: Option<&str>) -> bool {
    let Some(c) = class else { return true };
    let c = c.to_ascii_lowercase();
    ![
        "ipm.appointment",
        "ipm.contact",
        "ipm.distlist",
        "ipm.task",
        "ipm.stickynote",
        "ipm.activity",
        "ipm.journal",
    ]
    .iter()
    .any(|p| c == *p || c.starts_with(&format!("{p}.")))
}

fn pst_err(e: impl std::fmt::Display) -> EngineError {
    EngineError::Parse(e.to_string())
}

impl BoxSession {
    /// Ouvre une boîte : seule l'arborescence est lue. `make_source` rend une nouvelle source sur
    /// le même fichier à chaque appel (lecture de la boîte, empreinte).
    pub fn open_with(
        mut make_source: impl FnMut() -> io::Result<Box<dyn ByteSource>>,
        name: &str,
    ) -> Result<Self, EngineError> {
        let pst = PstBox::open_with(&mut make_source, name).map_err(pst_err)?;
        let hash_source = make_source().map_err(|source| EngineError::Io {
            path: name.to_string(),
            source,
        })?;
        let total = hash_source.len();
        Ok(Self {
            pst,
            name: name.to_string(),
            hash_source,
            hasher: StreamHasher::new(total),
            digests: None,
            item_folder: HashMap::new(),
            item_class: HashMap::new(),
            analyzed: HashMap::new(),
        })
    }

    /// Ouvre un fichier natif, en lecture seule.
    pub fn open_path(path: &Path) -> Result<Self, EngineError> {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let p = path.to_path_buf();
        Self::open_with(
            move || Ok(Box::new(mf_pst::FileSource::open(&p)?) as Box<dyn ByteSource>),
            &name,
        )
    }

    pub fn info(&self) -> &StoreInfo {
        self.pst.info()
    }

    pub fn folders(&self) -> &[FolderInfo] {
        self.pst.folders()
    }

    /// Lignes d'un dossier (table du dossier) ; adresse et verdict des éléments déjà ouverts.
    pub fn list(&mut self, folder: u32) -> Result<Vec<ItemSummary>, EngineError> {
        let mut rows = self.pst.list(folder).map_err(pst_err)?;
        for r in &mut rows {
            self.item_folder.insert(r.id, folder);
            if let Some(c) = &r.message_class {
                self.item_class.insert(r.id, c.clone());
            }
            self.decorate(r);
        }
        Ok(rows)
    }

    fn decorate(&self, r: &mut ItemSummary) {
        if let Some(a) = self.analyzed.get(&r.id) {
            r.from_address = a.message.from.first().and_then(|x| x.address.clone());
            r.verdict = a.message.verdict.as_ref().map(|v| v.level);
        }
    }

    /// Dossier d'un élément : celui où il a été listé, sinon recherché dans les tables (sans
    /// ouvrir d'élément).
    fn folder_of(&mut self, id: u32) -> Option<u32> {
        if let Some(f) = self.item_folder.get(&id) {
            return Some(*f);
        }
        let ids: Vec<u32> = self
            .pst
            .folders()
            .iter()
            .filter(|f| f.kind != "search")
            .map(|f| f.id)
            .collect();
        ids.into_iter().find(|f| {
            self.list(*f)
                .is_ok_and(|rows| rows.iter().any(|r| r.id == id))
        })
    }

    /// Ouvre et analyse un élément (analyse complète de la feature 001) ; le résultat est gardé.
    pub fn open_item(&mut self, id: u32, keys: &Keyring) -> Result<&Analyzed, EngineError> {
        if !self.analyzed.contains_key(&id) {
            let folder = self.folder_of(id);
            let sha = self
                .digests
                .as_ref()
                .map(|d| d.sha256.clone())
                .unwrap_or_default();
            let mut message = self.pst.open_item(id, folder, &sha).map_err(pst_err)?;
            expand_attached_messages(&mut message, 0);
            mf_analysis::analyze_with(&mut message, keys);
            if !is_mail(self.item_class.get(&id).map(String::as_str)) {
                // Rendez-vous, contact, tâche, note : pas de verdict de courriel (P021).
                message.verdict = None;
            }
            self.analyzed.insert(
                id,
                Analyzed {
                    evidence: self.evidence(),
                    message,
                },
            );
        }
        self.analyzed
            .get(&id)
            .ok_or_else(|| EngineError::Parse("élément introuvable".into()))
    }

    /// Classe MAPI d'un élément déjà listé.
    pub fn item_class(&self, id: u32) -> Option<&str> {
        self.item_class.get(&id).map(String::as_str)
    }

    /// Oublie les analyses (nouveau trousseau de clés) ; les éléments seront relus à la demande.
    pub fn forget_analyses(&mut self) {
        self.analyzed.clear();
    }

    /// Éléments déjà ouverts.
    pub fn analyzed(&self) -> impl Iterator<Item = (&u32, &Analyzed)> {
        self.analyzed.iter()
    }

    /// Preuve : la boîte elle-même (empreintes une fois calculées).
    pub fn evidence(&self) -> Evidence {
        Evidence {
            path: self.name.clone(),
            size: self.pst.info().size,
            sha256: self
                .digests
                .as_ref()
                .map(|d| d.sha256.clone())
                .unwrap_or_default(),
            md5: self
                .digests
                .as_ref()
                .map(|d| d.md5.clone())
                .unwrap_or_default(),
            format: Format::Pst,
            declared_extension: Path::new(&self.name)
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase()),
        }
    }

    /// Avance le calcul d'empreinte d'au plus `budget` octets.
    pub fn hash_step(&mut self, budget: u64) -> Result<HashProgress, EngineError> {
        if self.digests.is_none() {
            if let Some(d) = self
                .hasher
                .step(self.hash_source.as_mut(), budget)
                .map_err(|source| EngineError::Io {
                    path: self.name.clone(),
                    source,
                })?
            {
                // L'empreinte est reportée sur les éléments déjà ouverts.
                for a in self.analyzed.values_mut() {
                    a.evidence.sha256 = d.sha256.clone();
                    a.evidence.md5 = d.md5.clone();
                    if let Some(p) = a.message.provenance.as_mut() {
                        p.store_sha256 = d.sha256.clone();
                    }
                }
                self.digests = Some(d);
            }
        }
        let (done, total) = self.hasher.progress();
        Ok(HashProgress {
            done,
            total,
            sha256: self.digests.as_ref().map(|d| d.sha256.clone()),
            md5: self.digests.as_ref().map(|d| d.md5.clone()),
        })
    }

    /// Calcule l'empreinte jusqu'au bout.
    pub fn hash_all(&mut self) -> Result<HashProgress, EngineError> {
        loop {
            let p = self.hash_step(64 * 1024 * 1024)?;
            if p.sha256.is_some() {
                return Ok(p);
            }
        }
    }

    /// Éléments lus depuis l'ouverture (FR-006 : uniquement ceux ouverts par l'analyste).
    pub fn items_read(&self) -> u64 {
        self.pst.items_read()
    }

    /// Pages et octets lus pour la boîte (hors calcul d'empreinte).
    pub fn read_stats(&self) -> (u64, u64) {
        self.pst.read_stats()
    }
}
