//! Session de boîte PST/OST (feature 002) : l'arborescence et les listes viennent des tables de
//! dossiers ; seuls les éléments ouverts par l'analyste sont lus et analysés (FR-006), une fois,
//! puis gardés pour la session. L'empreinte de la boîte se calcule par pas bornés (FR-002).

use crate::filter::Compiled;
use crate::{Analyzed, expand_attached_messages};
use mf_core::{
    BoxFilter, EngineError, Evidence, FolderInfo, Format, Ioc, ItemSummary, StoreInfo,
    UnreadableItem,
};
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
    /// Lignes des tables de dossiers déjà lues (une seule lecture par dossier).
    rows: HashMap<u32, Vec<ItemSummary>>,
    /// Dossiers et éléments devenus illisibles pendant la session (boîte tronquée, nœud abîmé) :
    /// signalés, jamais ignorés en silence (FR-009).
    late_unreadable: Vec<UnreadableItem>,
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

/// Indicateurs d'un message puis de ses messages joints (« › PJ n »), ceux qui en ont.
fn walk_iocs(m: &mf_core::Message, label: String, out: &mut Vec<(String, Vec<Ioc>)>) {
    if !m.iocs.is_empty() {
        out.push((label.clone(), m.iocs.clone()));
    }
    for a in &m.attachments {
        if let Some(e) = &a.embedded {
            walk_iocs(e, format!("{label} › PJ {}", a.index), out);
        }
    }
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
            rows: HashMap::new(),
            late_unreadable: Vec::new(),
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
        self.load(folder)?;
        let mut rows = self.rows.get(&folder).cloned().unwrap_or_default();
        for r in &mut rows {
            self.decorate(r);
        }
        Ok(rows)
    }

    /// Lit la table d'un dossier une fois et la garde pour la session.
    fn load(&mut self, folder: u32) -> Result<(), EngineError> {
        if self.rows.contains_key(&folder) {
            return Ok(());
        }
        let rows = match self.pst.list(folder) {
            Ok(rows) => rows,
            Err(e) => {
                self.note_unreadable(folder, "folder", folder, &e.to_string());
                return Err(pst_err(e));
            }
        };
        // Table abîmée : des lignes peuvent manquer sans erreur. Le dossier annonce son nombre
        // d'éléments ; s'il en manque, le dossier est signalé comme partiellement lisible.
        let announced = self
            .pst
            .folders()
            .iter()
            .find(|f| f.id == folder)
            .map_or(0, |f| f.item_count as usize);
        if rows.len() < announced {
            let reason = format!(
                "table du dossier partiellement illisible : {} ligne(s) lue(s) sur {announced} annoncée(s)",
                rows.len()
            );
            self.note_unreadable(folder, "folder", folder, &reason);
        }
        for r in &rows {
            self.item_folder.insert(r.id, folder);
            if let Some(c) = &r.message_class {
                self.item_class.insert(r.id, c.clone());
            }
        }
        self.rows.insert(folder, rows);
        Ok(())
    }

    /// Filtre les lignes d'un dossier ou de toute la boîte (FR-007), dans l'ordre des dossiers
    /// puis des tables. Seules les tables sont lues ; un critère sur les éléments ouverts ne
    /// parcourt que les dossiers où des éléments ont été ouverts.
    pub fn filter(&mut self, f: &BoxFilter) -> Result<Vec<ItemSummary>, EngineError> {
        Ok(self.filter_report(f)?.0)
    }

    /// Comme [`Self::filter`], avec les dossiers illisibles qui n'ont pas pu être parcourus.
    pub fn filter_report(
        &mut self,
        f: &BoxFilter,
    ) -> Result<(Vec<ItemSummary>, Vec<UnreadableItem>), EngineError> {
        let folders: Vec<u32> = match f.folder {
            Some(id) => vec![id],
            None if f.needs_analysis() => {
                let opened: std::collections::HashSet<u32> = self
                    .analyzed
                    .keys()
                    .filter_map(|id| self.item_folder.get(id).copied())
                    .collect();
                self.searchable_folders()
                    .into_iter()
                    .filter(|id| opened.contains(id))
                    .collect()
            }
            None => self.searchable_folders(),
        };
        let compiled = Compiled::new(f);
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for folder in folders {
            // Un dossier illisible ne bloque pas la recherche dans les autres (FR-009) ; il est
            // rendu à l'appelant pour être signalé, comme un dossier lu en partie.
            skipped.push(folder);
            if self.load(folder).is_err() {
                continue;
            }
            for r in self
                .rows
                .get(&folder)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let mut r = r.clone();
                self.decorate(&mut r);
                if compiled.matches(&r, self.analyzed.contains_key(&r.id)) {
                    out.push(r);
                }
            }
        }
        let skipped = self.unreadable_folders_in(&skipped);
        Ok((out, skipped))
    }

    /// Dossiers parcourus par une recherche sur toute la boîte : tous sauf les dossiers de
    /// recherche, dont le contenu double celui des autres.
    fn searchable_folders(&self) -> Vec<u32> {
        self.pst
            .folders()
            .iter()
            .filter(|f| f.kind != "search")
            .map(|f| f.id)
            .collect()
    }

    fn note_unreadable(&mut self, node_id: u32, kind: &str, folder: u32, reason: &str) {
        if self
            .late_unreadable
            .iter()
            .any(|u| u.node_id == node_id && u.kind == kind)
        {
            return;
        }
        let folder_path = self
            .pst
            .folders()
            .iter()
            .find(|f| f.id == folder)
            .map(|f| f.path.clone())
            .unwrap_or_default();
        self.late_unreadable.push(UnreadableItem {
            node_id,
            folder_path,
            kind: kind.into(),
            reason: reason.into(),
        });
    }

    /// Tout ce qui est illisible : relevé à l'ouverture, puis en cours de session.
    pub fn unreadable(&self) -> Vec<UnreadableItem> {
        let mut all = self.pst.info().unreadable.clone();
        all.extend(self.late_unreadable.iter().cloned());
        all
    }

    /// Dossiers illisibles ou lus en partie parmi `folders`.
    pub fn unreadable_folders_in(&self, folders: &[u32]) -> Vec<UnreadableItem> {
        self.late_unreadable
            .iter()
            .filter(|u| u.kind == "folder" && folders.contains(&u.node_id))
            .cloned()
            .collect()
    }

    /// Identifiants des éléments ouverts, triés.
    pub fn analyzed_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.analyzed.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Indicateurs des éléments ouverts (tous, ou ceux de `ids` parmi eux), avec la provenance de
    /// chacun (FR-013) : `(boîte › dossier › élément #id, indicateurs)`, dans l'ordre des
    /// identifiants. Aucun élément n'est lu.
    pub fn iocs(&self, ids: Option<&[u32]>) -> Vec<(String, Vec<Ioc>)> {
        self.analyzed_ids()
            .into_iter()
            .filter(|id| ids.is_none_or(|want| want.contains(id)))
            .filter_map(|id| {
                let a = self.analyzed.get(&id)?;
                let label = a.message.provenance.as_ref().map_or_else(
                    || format!("{} › élément #{id}", self.name),
                    |p| format!("{} › élément #{id}", p.label()),
                );
                let mut out = Vec::new();
                walk_iocs(&a.message, label, &mut out);
                Some(out)
            })
            .flatten()
            .collect()
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
        let ids = self.searchable_folders();
        ids.into_iter().find(|f| {
            self.load(*f).is_ok()
                && self
                    .rows
                    .get(f)
                    .is_some_and(|rows| rows.iter().any(|r| r.id == id))
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
            let mut message = match self.pst.open_item(id, folder, &sha) {
                Ok(m) => m,
                Err(e) => {
                    self.note_unreadable(id, "item", folder.unwrap_or(0), &e.to_string());
                    return Err(pst_err(e));
                }
            };
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
                self.finish_hash(d);
            }
        }
        Ok(self.progress())
    }

    /// Avance l'empreinte avec des octets lus par l'appelant à partir de `offset` (flux du
    /// navigateur, sans allocation à chaque pas). Des octets mal placés sont ignorés : la
    /// progression retournée dit où reprendre.
    pub fn hash_feed(&mut self, offset: u64, data: &[u8]) -> HashProgress {
        if self.digests.is_none() {
            if let Some(d) = self.hasher.feed(offset, data) {
                self.finish_hash(d);
            }
        }
        self.progress()
    }

    fn progress(&self) -> HashProgress {
        let (done, total) = self.hasher.progress();
        HashProgress {
            done,
            total,
            sha256: self.digests.as_ref().map(|d| d.sha256.clone()),
            md5: self.digests.as_ref().map(|d| d.md5.clone()),
        }
    }

    /// L'empreinte est reportée sur les éléments déjà ouverts.
    fn finish_hash(&mut self, d: Digests) {
        for a in self.analyzed.values_mut() {
            a.evidence.sha256 = d.sha256.clone();
            a.evidence.md5 = d.md5.clone();
            if let Some(p) = a.message.provenance.as_mut() {
                p.store_sha256 = d.sha256.clone();
            }
        }
        self.digests = Some(d);
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
