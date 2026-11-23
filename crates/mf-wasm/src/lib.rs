//! Liaison WebAssembly du moteur (contracts/wasm-api.md de la feature 003).
//! Exactement le même code que la CLI et l'application de bureau : seule l'origine des octets change.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use wasm_bindgen::prelude::*;

thread_local! {
    /// Trousseau de l'analyste (FR-049, FR-050) : réimporté par la page à chaque démarrage.
    static KEYS: RefCell<mf_engine::Keyring> = RefCell::new(mf_engine::Keyring::default());
}

fn open(file_name: &str, bytes: Vec<u8>) -> Result<mf_engine::Analyzed, JsError> {
    KEYS.with(|k| mf_engine::open_bytes_with(file_name, bytes, &k.borrow()))
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Importe une clé PGP ou un certificat ; retourne les entrées ajoutées (JSON).
#[wasm_bindgen]
pub fn import_key(name: &str, bytes: Vec<u8>) -> Result<String, JsError> {
    let added = KEYS
        .with(|k| k.borrow_mut().import(name, &bytes))
        .map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&added).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn remove_key(fingerprint: &str) {
    KEYS.with(|k| k.borrow_mut().remove(fingerprint));
}

/// Entrées du trousseau (JSON).
#[wasm_bindgen]
pub fn list_keys() -> String {
    KEYS.with(|k| serde_json::to_string(&k.borrow().entries).unwrap_or_else(|_| "[]".into()))
}

/// Analyse un fichier `.eml` / `.msg` déjà lu par le navigateur.
/// Retourne le JSON `{ evidence, message }` (mêmes types que `mf show --json`).
#[wasm_bindgen]
pub fn analyze(file_name: &str, bytes: Vec<u8>) -> Result<String, JsError> {
    let analyzed = open(file_name, bytes)?;
    serde_json::to_string(&analyzed).map_err(|e| JsError::new(&e.to_string()))
}

/// Version du moteur embarqué.
#[wasm_bindgen]
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Octets de la pièce jointe `index` du message désigné par `path` (FR-038), après
/// revérification de l'empreinte. Le navigateur ne fournit que les octets de la preuve :
/// le message est ré-analysé, ce qui garantit les mêmes indices que l'affichage.
#[wasm_bindgen]
pub fn extract_attachment(
    file_name: &str,
    bytes: Vec<u8>,
    path: Vec<u32>,
    index: u32,
) -> Result<Vec<u8>, JsError> {
    let analyzed = open(file_name, bytes)?;
    mf_engine::extract_attachment(&analyzed.message, &path, index)
        .map(|x| x.data)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Nom de fichier assaini proposé à l'enregistrement (même règle que le bureau et la CLI).
#[wasm_bindgen]
pub fn safe_file_name(name: &str) -> String {
    mf_engine::safe_file_name(name)
}

/// Rapport d'analyse du message désigné par `path` (FR-044) : `format` = « html » ou « json ».
/// `generated_utc` est fourni par le navigateur (pas d'horloge en WebAssembly).
#[wasm_bindgen]
pub fn report(
    file_name: &str,
    bytes: Vec<u8>,
    path: Vec<u32>,
    format: &str,
    generated_utc: &str,
) -> Result<String, JsError> {
    let a = open(file_name, bytes)?;
    let m = mf_engine::descend(&a.message, &path)
        .ok_or_else(|| JsError::new("message embarqué introuvable"))?;
    let provenance = path
        .iter()
        .map(|i| format!("PJ {i}"))
        .collect::<Vec<_>>()
        .join(" › ");
    let version = env!("CARGO_PKG_VERSION");
    match format {
        "html" => Ok(mf_report::report_html(
            &a.evidence,
            m,
            &provenance,
            generated_utc,
            version,
        )),
        "json" => Ok(mf_report::report_json(
            &a.evidence,
            m,
            &provenance,
            generated_utc,
            version,
        )),
        other => Err(JsError::new(&format!("format inconnu : {other}"))),
    }
}

/// Export des indicateurs de plusieurs messages (`[{source, iocs}]` en JSON) : « csv » ou « json ».
#[wasm_bindgen]
pub fn iocs_export(groups_json: &str, format: &str, defang: bool) -> Result<String, JsError> {
    let groups: Vec<mf_report::IocGroup> =
        serde_json::from_str(groups_json).map_err(|e| JsError::new(&e.to_string()))?;
    match format {
        "csv" => Ok(mf_report::iocs_csv(&groups, defang)),
        "json" => Ok(mf_report::iocs_json(&groups, defang)),
        other => Err(JsError::new(&format!("format inconnu : {other}"))),
    }
}

// ——— Boîtes PST / OST (feature 002, Phase 5) ———
//
// La boîte n'est jamais copiée en mémoire : le Worker fournit un lecteur qui lit des tranches du
// `File` (`FileReaderSync` sur `File.slice`). Seuls l'arborescence, les tables des dossiers
// ouverts et les éléments cliqués sont lus (FR-006), exactement comme sur le bureau.

#[wasm_bindgen]
extern "C" {
    /// Lecteur fourni par le Worker : `{ size, read(offset, buf) -> octets lus }`.
    #[derive(Clone)]
    pub type BlobReader;
    #[wasm_bindgen(method, getter)]
    fn size(this: &BlobReader) -> f64;
    #[wasm_bindgen(method, catch)]
    fn read(this: &BlobReader, offset: f64, buf: &mut [u8]) -> Result<u32, JsValue>;
}

struct BlobSource {
    reader: BlobReader,
    len: u64,
}

impl mf_pst::ByteSource for BlobSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        // Positions < 2^53 : exactes en f64 (boîtes jusqu'à 8 Po).
        self.reader
            .read(offset as f64, buf)
            .map(|n| (n as usize).min(buf.len()))
            .map_err(|e| std::io::Error::other(format!("lecture du fichier : {e:?}")))
    }
}

thread_local! {
    static BOXES: RefCell<std::collections::HashMap<u32, mf_engine::BoxSession>> =
        RefCell::new(std::collections::HashMap::new());
}

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn with_box<T>(
    id: u32,
    f: impl FnOnce(&mut mf_engine::BoxSession) -> Result<T, JsError>,
) -> Result<T, JsError> {
    BOXES.with(|b| {
        let mut boxes = b.borrow_mut();
        let s = boxes
            .get_mut(&id)
            .ok_or_else(|| JsError::new("boîte fermée"))?;
        f(s)
    })
}

/// Ouvre une boîte : seule l'arborescence est lue. Retourne `{ store, folders }` (JSON).
#[wasm_bindgen]
pub fn box_open(id: u32, name: &str, reader: BlobReader) -> Result<String, JsError> {
    let len = reader.size().max(0.0) as u64;
    let session = mf_engine::BoxSession::open_with(
        move || {
            Ok(Box::new(BlobSource {
                reader: reader.clone(),
                len,
            }) as Box<dyn mf_pst::ByteSource>)
        },
        name,
    )
    .map_err(js_err)?;
    let out = serde_json::json!({ "store": session.info(), "folders": session.folders() });
    BOXES.with(|b| b.borrow_mut().insert(id, session));
    serde_json::to_string(&out).map_err(js_err)
}

/// Lignes d'un dossier (table du dossier), sans ouvrir d'élément.
#[wasm_bindgen]
pub fn box_list(id: u32, folder: u32) -> Result<String, JsError> {
    with_box(id, |s| {
        let rows = s.list(folder).map_err(js_err)?;
        serde_json::to_string(&rows).map_err(js_err)
    })
}

/// Filtre (JSON `BoxFilter`) sur les tables de dossiers, sans lire d'élément (FR-007).
#[wasm_bindgen]
pub fn box_filter(id: u32, filter_json: &str) -> Result<String, JsError> {
    let filter: mf_core::BoxFilter = serde_json::from_str(filter_json).map_err(js_err)?;
    with_box(id, |s| {
        let (rows, unreadable) = s.filter_report(&filter).map_err(js_err)?;
        serde_json::to_string(&serde_json::json!({ "rows": rows, "unreadable": unreadable }))
            .map_err(js_err)
    })
}

/// Indicateurs des éléments ouverts, avec provenance : `[{ source, iocs }]` (JSON).
#[wasm_bindgen]
pub fn box_iocs(id: u32) -> Result<String, JsError> {
    with_box(id, |s| {
        let groups: Vec<mf_report::IocGroup> = s
            .iocs(None)
            .into_iter()
            .map(|(source, iocs)| mf_report::IocGroup { source, iocs })
            .collect();
        serde_json::to_string(&groups).map_err(js_err)
    })
}

/// Lit et analyse un élément : le seul appel qui lit un message. `{ evidence, message }`.
#[wasm_bindgen]
pub fn box_item(id: u32, item: u32) -> Result<String, JsError> {
    KEYS.with(|k| {
        let keys = k.borrow();
        with_box(id, |s| {
            let a = s.open_item(item, &keys).map_err(js_err)?;
            serde_json::to_string(a).map_err(js_err)
        })
    })
}

/// Avance l'empreinte de la boîte d'au plus `budget` octets : `{ done, total, sha256, md5 }`.
#[wasm_bindgen]
pub fn box_hash_step(id: u32, budget: f64) -> Result<String, JsError> {
    with_box(id, |s| {
        let p = s.hash_step(budget.max(1.0) as u64).map_err(js_err)?;
        serde_json::to_string(&p).map_err(js_err)
    })
}

/// Avance l'empreinte avec des octets lus en flux par le Worker à partir de `offset` (tampon
/// réutilisé : aucune allocation par pas). Retourne la progression ; si elle ne vaut pas
/// `offset + data.len()`, le Worker reprend la lecture à `done`.
#[wasm_bindgen]
pub fn box_hash_feed(id: u32, offset: f64, data: &[u8]) -> Result<String, JsError> {
    with_box(id, |s| {
        let p = s.hash_feed(offset.max(0.0) as u64, data);
        serde_json::to_string(&p).map_err(js_err)
    })
}

/// Rapport d'un élément ; l'empreinte de la boîte doit être calculée (le Worker s'en charge).
#[wasm_bindgen]
pub fn box_report(
    id: u32,
    item: u32,
    path: Vec<u32>,
    format: &str,
    generated_utc: &str,
) -> Result<String, JsError> {
    KEYS.with(|k| {
        let keys = k.borrow();
        with_box(id, |s| {
            s.hash_all().map_err(js_err)?;
            let a = s.open_item(item, &keys).map_err(js_err)?;
            let m = mf_engine::descend(&a.message, &path)
                .ok_or_else(|| JsError::new("message embarqué introuvable"))?;
            let mut provenance = a
                .message
                .provenance
                .as_ref()
                .map(|p| format!("{} › élément #{}", p.label(), p.node_id))
                .unwrap_or_default();
            for i in &path {
                provenance.push_str(&format!(" › PJ {i}"));
            }
            let version = env!("CARGO_PKG_VERSION");
            match format {
                "html" => Ok(mf_report::report_html(
                    &a.evidence,
                    m,
                    &provenance,
                    generated_utc,
                    version,
                )),
                "json" => Ok(mf_report::report_json(
                    &a.evidence,
                    m,
                    &provenance,
                    generated_utc,
                    version,
                )),
                other => Err(JsError::new(&format!("format inconnu : {other}"))),
            }
        })
    })
}

/// Octets d'une pièce jointe d'un élément (après revérification de son empreinte).
#[wasm_bindgen]
pub fn box_extract(id: u32, item: u32, path: Vec<u32>, index: u32) -> Result<Vec<u8>, JsError> {
    KEYS.with(|k| {
        let keys = k.borrow();
        with_box(id, |s| {
            let a = s.open_item(item, &keys).map_err(js_err)?;
            mf_engine::extract_attachment(&a.message, &path, index)
                .map(|x| x.data)
                .map_err(js_err)
        })
    })
}

/// Nouveau trousseau : les éléments seront ré-analysés à leur prochaine ouverture.
#[wasm_bindgen]
pub fn box_forget(id: u32) {
    BOXES.with(|b| {
        if let Some(s) = b.borrow_mut().get_mut(&id) {
            s.forget_analyses();
        }
    });
}

/// Taille de la mémoire WebAssembly du moteur, en octets (mesures, SC-004).
#[wasm_bindgen]
pub fn engine_memory_bytes() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        (core::arch::wasm32::memory_size(0) as f64) * 65536.0
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0.0
    }
}

/// Ferme une boîte et libère sa mémoire.
#[wasm_bindgen]
pub fn box_close(id: u32) {
    BOXES.with(|b| b.borrow_mut().remove(&id));
}
