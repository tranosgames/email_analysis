//! Ouverture d'une boîte, arborescence, listes de dossiers et ouverture d'éléments.
//!
//! Trois niveaux de lecture (R5) : l'ouverture ne lit que les tables de hiérarchie ; une liste ne
//! lit que la table de contenu du dossier ; seul [`PstBox::open_item`] lit un message.

use crate::item::{PstObj, table_rows};
use crate::source::{ByteSource, Paged, ReadStats};
use mf_core::{FolderInfo, ItemSummary, Message, Provenance, StoreInfo, UnreadableItem};
use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::messaging::folder::Folder;
use outlook_pst::messaging::store::{AnsiStore, EntryId, Store, UnicodeStore};
use outlook_pst::ndb::header::{Header, NdbCryptMethod, NdbVersion};
use outlook_pst::ndb::node_id::{NodeId, NodeIdType};
use outlook_pst::{AnsiPstFile, PstFile, UnicodePstFile};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

/// Racine de la hiérarchie des dossiers (`NID_ROOT_FOLDER`).
const NID_ROOT_FOLDER: u32 = 0x122;
/// Profondeur maximale parcourue (protection contre une hiérarchie piégée).
const MAX_DEPTH: u32 = 64;

const PR_DISPLAY_NAME: u16 = 0x3001;
const PR_CONTENT_COUNT: u16 = 0x3602;
const PR_CONTENT_UNREAD: u16 = 0x3603;
const PR_CONTAINER_CLASS: u16 = 0x3613;
const PR_PST_PASSWORD: u16 = 0x67FF;
const PR_IPM_SUBTREE: u16 = 0x35E0;
const PR_IPM_OUTBOX: u16 = 0x35E2;
const PR_IPM_WASTEBASKET: u16 = 0x35E3;
const PR_IPM_SENTMAIL: u16 = 0x35E4;
const PR_FINDER: u16 = 0x35E7;

/// Erreur d'ouverture d'une boîte.
#[derive(Debug)]
pub struct PstError(pub String);

impl std::fmt::Display for PstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PstError {}

impl From<io::Error> for PstError {
    fn from(e: io::Error) -> Self {
        Self(e.to_string())
    }
}

fn text(v: Option<&PropertyValue>) -> Option<String> {
    match v? {
        PropertyValue::Unicode(s) => Some(s.to_string()),
        PropertyValue::String8(s) => Some(mf_msg::decode_codepage(s.buffer(), None)),
        _ => None,
    }
    .map(|s| s.trim_end_matches('\0').to_string())
}

fn int(v: Option<&PropertyValue>) -> Option<u32> {
    match v? {
        PropertyValue::Integer32(i) => Some(*i as u32),
        _ => None,
    }
}

fn time(v: Option<&PropertyValue>) -> Option<String> {
    match v? {
        PropertyValue::Time(t) => mf_msg::filetime(*t as u64).map(|d| d.to_rfc3339()),
        _ => None,
    }
}

/// Type d'un dossier de l'utilisateur d'après son nom, quand la boîte ne le désigne pas
/// (la réception jamais, les autres dans les OST).
fn kind_by_name(name: &str) -> Option<&'static str> {
    let n = name.to_lowercase();
    let is = |list: &[&str]| list.contains(&n.as_str());
    if is(&[
        "inbox",
        "boîte de réception",
        "posteingang",
        "bandeja de entrada",
        "posta in arrivo",
        "postvak in",
        "caixa de entrada",
    ]) {
        Some("inbox")
    } else if is(&[
        "sent items",
        "sent",
        "éléments envoyés",
        "gesendete elemente",
        "elementos enviados",
        "posta inviata",
    ]) {
        Some("sent")
    } else if is(&[
        "deleted items",
        "éléments supprimés",
        "gelöschte elemente",
        "elementos eliminados",
        "posta eliminata",
    ]) {
        Some("deleted")
    } else if is(&["drafts", "brouillons", "entwürfe", "borradores", "bozze"]) {
        Some("drafts")
    } else if is(&[
        "outbox",
        "boîte d'envoi",
        "postausgang",
        "bandeja de salida",
        "posta in uscita",
    ]) {
        Some("outbox")
    } else if is(&[
        "junk email",
        "junk e-mail",
        "courrier indésirable",
        "junk-e-mail",
        "correo no deseado",
        "posta indesiderata",
    ]) {
        Some("junk")
    } else {
        None
    }
}

/// Une boîte PST/OST ouverte en lecture seule.
pub struct PstBox {
    store: Rc<dyn Store>,
    info: StoreInfo,
    folders: Vec<FolderInfo>,
    open_folders: RefCell<HashMap<u32, Rc<dyn Folder>>>,
    stats: Rc<ReadStats>,
    items_read: Cell<u64>,
}

impl PstBox {
    /// Ouvre une boîte : en-tête, propriétés de la boîte et arborescence des dossiers seulement.
    /// `make_source` fournit une nouvelle source sur le même fichier à chaque appel (deux essais
    /// au plus : format Unicode/OST, puis ANSI).
    pub fn open_with(
        mut make_source: impl FnMut() -> io::Result<Box<dyn ByteSource>>,
        name: &str,
    ) -> Result<Self, PstError> {
        let stats = Rc::new(ReadStats::default());
        let src = make_source()?;
        let size = src.len();
        match UnicodePstFile::read_from(Box::new(Paged::new(src, stats.clone()))) {
            Ok(f) => {
                let format = if f.header().version() == NdbVersion::Unicode4k {
                    "ost4k"
                } else {
                    "unicode"
                };
                let enc = f.header().crypt_method();
                let store: Rc<dyn Store> = UnicodeStore::read(Rc::new(f))?;
                Self::finish(store, format, enc, name, size, stats)
            }
            Err(unicode_err) => {
                let src = make_source()?;
                match AnsiPstFile::read_from(Box::new(Paged::new(src, stats.clone()))) {
                    Ok(f) => {
                        let enc = f.header().crypt_method();
                        let store: Rc<dyn Store> = AnsiStore::read(Rc::new(f))?;
                        Self::finish(store, "ansi", enc, name, size, stats)
                    }
                    Err(_) => Err(PstError(format!(
                        "{name} : n'est pas une boîte PST/OST lisible ({unicode_err})"
                    ))),
                }
            }
        }
    }

    fn finish(
        store: Rc<dyn Store>,
        format: &str,
        encoding: NdbCryptMethod,
        name: &str,
        size: u64,
        stats: Rc<ReadStats>,
    ) -> Result<Self, PstError> {
        let props = store.properties();
        // 0 = aucun mot de passe ; les OST portent 0xFFFFFFFF, valeur neutre.
        let password_protected =
            int(props.get(PR_PST_PASSWORD)).is_some_and(|p| p != 0 && p != u32::MAX);
        let mut info = StoreInfo {
            name: name.to_string(),
            size,
            format: format.into(),
            encoding: match encoding {
                NdbCryptMethod::None => "none",
                NdbCryptMethod::Permute => "permute",
                NdbCryptMethod::Cyclic => "cyclic",
            }
            .into(),
            password_protected,
            display_name: text(props.get(PR_DISPLAY_NAME)),
            ..Default::default()
        };
        let mut b = Self {
            store,
            info: StoreInfo::default(),
            folders: Vec::new(),
            open_folders: RefCell::new(HashMap::new()),
            stats,
            items_read: Cell::new(0),
        };
        let (folders, unreadable) = b.read_tree();
        info.folders = folders.len() as u32;
        // Les dossiers de recherche ne font que refléter des éléments rangés ailleurs.
        info.items = folders
            .iter()
            .filter(|f| f.kind != "search")
            .map(|f| u64::from(f.item_count))
            .sum();
        info.unreadable = unreadable;
        b.folders = folders;
        b.info = info;
        Ok(b)
    }

    /// Identifiant de nœud désigné par une propriété « entry id » de la boîte.
    fn special(&self, prop: u16) -> Option<u32> {
        match self.store.properties().get(prop)? {
            PropertyValue::Binary(b) => EntryId::try_from(b.buffer())
                .ok()
                .map(|e| u32::from(e.node_id())),
            _ => None,
        }
    }

    fn entry(&self, nid: u32) -> io::Result<EntryId> {
        self.store.properties().make_entry_id(NodeId::from(nid))
    }

    fn folder(&self, nid: u32) -> io::Result<Rc<dyn Folder>> {
        if let Some(f) = self.open_folders.borrow().get(&nid) {
            return Ok(f.clone());
        }
        let f = self.store.open_folder(&self.entry(nid)?)?;
        self.open_folders.borrow_mut().insert(nid, f.clone());
        Ok(f)
    }

    /// Arborescence complète depuis la racine, tables de hiérarchie seulement. Deux passes :
    /// relevé brut, puis sommet utilisateur (IPM), chemins et types de dossiers.
    fn read_tree(&self) -> (Vec<FolderInfo>, Vec<UnreadableItem>) {
        struct Raw {
            nid: u32,
            parent: Option<u32>,
            name: String,
            class: Option<String>,
            count: u32,
            unread: u32,
            depth: u32,
        }
        let mut raw: Vec<Raw> = Vec::new();
        let mut bad = Vec::new();
        let mut stack: Vec<(u32, Option<u32>, u32)> = vec![(NID_ROOT_FOLDER, None, 0)];
        let mut seen = std::collections::HashSet::new();
        while let Some((nid, parent, depth)) = stack.pop() {
            if !seen.insert(nid) || depth > MAX_DEPTH {
                continue;
            }
            let f = match self.folder(nid) {
                Ok(f) => f,
                Err(e) => {
                    bad.push(UnreadableItem {
                        node_id: nid,
                        folder_path: Vec::new(),
                        kind: "folder".into(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            let p = f.properties();
            raw.push(Raw {
                nid,
                parent,
                name: text(p.get(PR_DISPLAY_NAME)).unwrap_or_default(),
                class: text(p.get(PR_CONTAINER_CLASS)),
                count: int(p.get(PR_CONTENT_COUNT)).unwrap_or(0),
                unread: int(p.get(PR_CONTENT_UNREAD)).unwrap_or(0),
                depth,
            });
            if let Some(h) = f.hierarchy_table() {
                let mut kids: Vec<u32> = table_rows(h).into_iter().map(|(id, _)| id).collect();
                kids.reverse(); // pile : on garde l'ordre de la table
                for k in kids {
                    stack.push((k, Some(nid), depth + 1));
                }
            }
        }

        // Sommet des dossiers de l'utilisateur : désigné par la boîte (PST) ; à défaut (OST),
        // le parent du premier dossier de messages (classe IPF.Note) le moins profond.
        // Un OST peut désigner un sommet vide, les vrais dossiers étant ailleurs (IPM_SUBTREE).
        let by_id = |id: u32| raw.iter().find(|r| r.nid == id);
        let descends_from = |mut id: u32, top: u32| -> bool {
            for _ in 0..=MAX_DEPTH {
                match by_id(id).and_then(|r| r.parent) {
                    Some(p) if p == top => return true,
                    Some(p) => id = p,
                    None => return false,
                }
            }
            false
        };
        // Candidats : le sommet désigné par la boîte, tout dossier nommé IPM_SUBTREE (OST) et le
        // parent du premier dossier de messages. On retient celui qui contient le plus d'éléments
        // (hors dossiers de recherche), le plus profond à égalité.
        let is_search = |id: u32| {
            NodeId::from(id)
                .id_type()
                .is_ok_and(|t| t == NodeIdType::SearchFolder)
        };
        let items_under = |top: u32| -> u64 {
            raw.iter()
                .filter(|r| !is_search(r.nid) && descends_from(r.nid, top))
                .map(|r| u64::from(r.count))
                .sum()
        };
        let mut candidates: Vec<u32> = Vec::new();
        candidates.extend(
            self.special(PR_IPM_SUBTREE)
                .filter(|id| by_id(*id).is_some()),
        );
        candidates.extend(
            raw.iter()
                .filter(|r| r.name.eq_ignore_ascii_case("IPM_SUBTREE"))
                .map(|r| r.nid),
        );
        candidates.extend(
            raw.iter()
                .filter(|r| {
                    r.class
                        .as_deref()
                        .is_some_and(|c| c.eq_ignore_ascii_case("IPF.Note"))
                })
                .min_by_key(|r| r.depth)
                .and_then(|r| r.parent),
        );
        let ipm = candidates
            .iter()
            .copied()
            .filter(|id| *id != NID_ROOT_FOLDER)
            .max_by_key(|id| (items_under(*id), by_id(*id).map_or(0, |r| r.depth)));
        let under_ipm = |mut id: u32| -> bool {
            for _ in 0..=MAX_DEPTH {
                match by_id(id).and_then(|r| r.parent) {
                    Some(p) if Some(p) == ipm => return true,
                    Some(p) => id = p,
                    None => return false,
                }
            }
            false
        };
        let path_of = |id: u32| -> Vec<String> {
            let mut names = Vec::new();
            let mut cur = Some(id);
            let mut guard = 0;
            while let Some(c) = cur {
                if Some(c) == ipm || c == NID_ROOT_FOLDER || guard > MAX_DEPTH {
                    break;
                }
                if let Some(r) = by_id(c) {
                    names.push(r.name.clone());
                    cur = r.parent;
                } else {
                    break;
                }
                guard += 1;
            }
            names.reverse();
            names
        };
        let specials = [
            (self.special(PR_IPM_WASTEBASKET), "deleted"),
            (self.special(PR_IPM_SENTMAIL), "sent"),
            (self.special(PR_IPM_OUTBOX), "outbox"),
        ];
        let out = raw
            .iter()
            .map(|r| {
                let user = under_ipm(r.nid);
                let search = NodeId::from(r.nid)
                    .id_type()
                    .is_ok_and(|t| t == NodeIdType::SearchFolder)
                    || Some(r.nid) == self.special(PR_FINDER);
                let kind = if r.nid == NID_ROOT_FOLDER {
                    "root"
                } else if Some(r.nid) == ipm {
                    "ipm"
                } else if search {
                    "search"
                } else if let Some((_, k)) = specials.iter().find(|(id, _)| *id == Some(r.nid)) {
                    k
                } else if let (true, Some(k)) = (user, kind_by_name(&r.name)) {
                    k
                } else if user {
                    "other"
                } else {
                    "system"
                };
                let mut path = path_of(r.nid);
                if !user && Some(r.nid) != ipm && r.nid != NID_ROOT_FOLDER {
                    path.insert(0, "(système)".into());
                }
                FolderInfo {
                    id: r.nid,
                    parent: r.parent,
                    name: if r.name.is_empty() && Some(r.nid) == ipm {
                        "Boîte".into()
                    } else {
                        r.name.clone()
                    },
                    path,
                    kind: kind.into(),
                    container_class: r.class.clone(),
                    item_count: r.count,
                    unread_count: r.unread,
                    depth: r.depth,
                }
            })
            .collect();
        (out, bad)
    }

    /// Ouvre un fichier natif.
    pub fn open_path(path: &std::path::Path) -> Result<Self, PstError> {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        Self::open_with(
            || Ok(Box::new(crate::source::FileSource::open(path)?) as Box<dyn ByteSource>),
            &name,
        )
    }

    pub fn info(&self) -> &StoreInfo {
        &self.info
    }

    pub fn folders(&self) -> &[FolderInfo] {
        &self.folders
    }

    pub fn folder_info(&self, id: u32) -> Option<&FolderInfo> {
        self.folders.iter().find(|f| f.id == id)
    }

    /// Lignes d'un dossier, lues dans sa table de contenu, **sans ouvrir les éléments**.
    pub fn list(&self, folder: u32) -> Result<Vec<ItemSummary>, PstError> {
        let f = self.folder(folder)?;
        let Some(table) = f.contents_table() else {
            return Ok(Vec::new());
        };
        Ok(table_rows(table)
            .into_iter()
            .map(|(id, p)| {
                let flags = int(p.get(&0x0E07)).unwrap_or(0);
                ItemSummary {
                    id,
                    folder,
                    message_class: text(p.get(&0x001A)),
                    subject: text(p.get(&0x0037)).map(|s| strip_subject_prefix(&s)),
                    from_name: text(p.get(&0x0042)).or_else(|| text(p.get(&0x0C1A))),
                    to: text(p.get(&0x0E04)),
                    cc: text(p.get(&0x0E03)),
                    sent: time(p.get(&0x0039)),
                    received: time(p.get(&0x0E06)),
                    size: int(p.get(&0x0E08)),
                    has_attachments: flags & 0x10 != 0,
                    message_id: text(p.get(&0x1035)),
                    from_address: None,
                    verdict: None,
                }
            })
            .collect())
    }

    /// Lit et convertit un élément : le seul appel qui lit un message (FR-006). `folder` est le
    /// dossier dont la liste contenait l'élément (provenance).
    pub fn open_item(
        &self,
        id: u32,
        folder: Option<u32>,
        store_sha256: &str,
    ) -> Result<Message, PstError> {
        let m = self.store.open_message(&self.entry(id)?, None)?;
        self.items_read.set(self.items_read.get() + 1);
        let obj = PstObj::message(m);
        let mut msg = mf_msg::convert(&obj, 0);
        msg.issues.extend(obj.issues.borrow().iter().cloned());
        msg.provenance = Some(Provenance {
            store_name: self.info.name.clone(),
            store_sha256: store_sha256.to_string(),
            folder_path: folder
                .and_then(|f| self.folder_info(f))
                .map(|f| f.path.clone())
                .unwrap_or_default(),
            node_id: id,
            embedded_path: Vec::new(),
        });
        Ok(msg)
    }

    /// Nombre d'éléments lus depuis l'ouverture (preuve qu'aucun autre ne l'est).
    pub fn items_read(&self) -> u64 {
        self.items_read.get()
    }

    /// Pages lues et octets lus depuis l'ouverture.
    pub fn read_stats(&self) -> (u64, u64) {
        (self.stats.page_reads.get(), self.stats.bytes_read.get())
    }
}

/// `PR_SUBJECT` des tables commence parfois par deux caractères de contrôle (préfixe normalisé).
fn strip_subject_prefix(s: &str) -> String {
    let mut chars = s.chars();
    if s.starts_with('\u{1}') {
        chars.next();
        chars.next();
        return chars.as_str().to_string();
    }
    s.to_string()
}
