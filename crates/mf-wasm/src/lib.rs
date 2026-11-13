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
