//! Application de bureau MailForensics : couche IPC mince au-dessus de `mf-engine`
//! (contracts/tauri-commands.md). Aucune logique d'analyse ici (Constitution III).
#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod mailbox;

use mf_core::{Evidence, FolderInfo, ItemSummary, Message, StoreInfo};
use mf_engine::{Analyzed, KeyEntry, Keyring};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Default)]
struct AppState {
    loaded: Mutex<Vec<Analyzed>>,
    /// Clés publiques et certificats importés par l'analyste (FR-049, FR-050).
    keys: Mutex<Keyring>,
    /// Boîtes PST/OST ouvertes (feature 002), chacune sur son thread.
    boxes: Mutex<Vec<mailbox::BoxHandle>>,
}

/// Ligne de la liste latérale (comme msg-reader : expéditeur, objet, date, badges).
#[derive(Serialize)]
struct Summary {
    id: usize,
    file_name: String,
    format: mf_core::Format,
    sha256: String,
    subject: Option<String>,
    from: Option<String>,
    date_utc: Option<String>,
    attachments: usize,
    urls: usize,
    issues: usize,
    verdict: Option<mf_core::VerdictLevel>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OpenResult {
    Ready {
        summary: Summary,
    },
    /// Boîte PST/OST : arborescence seulement, les éléments sont lus à la demande.
    Mailbox {
        box_id: usize,
        path: String,
        store: StoreInfo,
        folders: Vec<FolderInfo>,
    },
    Duplicate {
        path: String,
        of: usize,
    },
    Failed {
        path: String,
        error: String,
    },
}

#[derive(Serialize)]
struct MessageView<'a> {
    evidence: &'a Evidence,
    message: &'a Message,
}

fn summary(id: usize, a: &Analyzed) -> Summary {
    let m = &a.message;
    Summary {
        id,
        file_name: Path::new(&a.evidence.path).file_name().map_or_else(
            || a.evidence.path.clone(),
            |n| n.to_string_lossy().into_owned(),
        ),
        format: a.evidence.format,
        sha256: a.evidence.sha256.clone(),
        subject: m.subject.clone(),
        from: m
            .from
            .first()
            .and_then(|f| f.display_name.clone().or_else(|| f.address.clone())),
        date_utc: m.date_utc.clone(),
        attachments: m.attachments.len(),
        urls: m.urls.len(),
        issues: m.issues.len(),
        verdict: m.verdict.as_ref().map(|v| v.level),
    }
}

/// Dossiers : on ne retient que les `.eml` / `.msg` ; fichiers déposés : tous (détection par signature).
fn expand(paths: Vec<String>) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| {
                ["eml", "msg", "pst", "ost"]
                    .iter()
                    .any(|x| e.eq_ignore_ascii_case(x))
            }) {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for p in paths.into_iter().map(PathBuf::from) {
        if p.is_dir() {
            walk(&p, &mut out)
        } else {
            out.push(p)
        }
    }
    out
}

#[tauri::command]
fn open_paths(
    paths: Vec<String>,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Vec<OpenResult> {
    let files = expand(paths);
    let mut results = Vec::with_capacity(files.len());
    let keys = state.keys.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for f in files {
        let path = f.display().to_string();
        if is_mailbox(&f) {
            results.push(open_mailbox(f, path, &state, app.clone()));
            continue;
        }
        match mf_engine::open_with(&f, &keys) {
            Ok(a) => {
                let mut loaded = state.loaded.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(of) = loaded
                    .iter()
                    .position(|x| x.evidence.sha256 == a.evidence.sha256)
                {
                    results.push(OpenResult::Duplicate { path, of });
                } else {
                    let id = loaded.len();
                    results.push(OpenResult::Ready {
                        summary: summary(id, &a),
                    });
                    loaded.push(a);
                }
            }
            Err(e) => results.push(OpenResult::Failed {
                path,
                error: e.to_string(),
            }),
        }
    }
    results
}

/// Signature `!BDN` des boîtes PST/OST.
fn is_mailbox(p: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 4];
    std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && mf_pst_magic(&head)
}

fn mf_pst_magic(head: &[u8]) -> bool {
    head.starts_with(b"!BDN")
}

fn open_mailbox(
    f: PathBuf,
    path: String,
    state: &tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> OpenResult {
    let mut boxes = state.boxes.lock().unwrap_or_else(|e| e.into_inner());
    let canon = std::fs::canonicalize(&f).unwrap_or_else(|_| f.clone());
    if let Some(of) = boxes.iter().position(|b| b.path == canon) {
        return OpenResult::Duplicate { path, of };
    }
    let box_id = boxes.len();
    match mailbox::spawn(canon, box_id, app) {
        Ok((handle, store, folders)) => {
            boxes.push(handle);
            OpenResult::Mailbox {
                box_id,
                path,
                store,
                folders,
            }
        }
        Err(error) => OpenResult::Failed { path, error },
    }
}

fn with_box<T>(
    state: &tauri::State<'_, AppState>,
    box_id: usize,
    f: impl FnOnce(&mailbox::BoxHandle) -> Result<T, String>,
) -> Result<T, String> {
    let boxes = state.boxes.lock().unwrap_or_else(|e| e.into_inner());
    let h = boxes.get(box_id).ok_or("boîte inconnue")?;
    f(h)
}

/// Lignes d'un dossier, lues dans sa table, sans ouvrir les éléments (FR-006).
#[tauri::command]
fn box_list(
    box_id: usize,
    folder: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ItemSummary>, String> {
    with_box(&state, box_id, |h| {
        mailbox::ask(h, |reply| mailbox::Req::List { folder, reply })
    })
}

/// Filtre les lignes d'un dossier ou de toute la boîte (FR-007), sans ouvrir les éléments.
#[tauri::command]
fn box_filter(
    box_id: usize,
    filter: mf_core::BoxFilter,
    state: tauri::State<'_, AppState>,
) -> Result<mailbox::FilterResult, String> {
    with_box(&state, box_id, |h| {
        mailbox::ask(h, |reply| mailbox::Req::Filter { filter, reply })
    })
}

/// Indicateurs des éléments ouverts de la boîte, avec leur provenance.
#[tauri::command]
fn box_iocs(
    box_id: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<mf_report::IocGroup>, String> {
    with_box(&state, box_id, |h| {
        mailbox::ask(h, |reply| mailbox::Req::Iocs { reply })
    })
}

/// Ouvre et analyse un élément (le seul appel qui lit un message).
#[tauri::command]
fn box_item(
    box_id: usize,
    id: u32,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let keys = state.keys.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (evidence, message) = with_box(&state, box_id, |h| {
        mailbox::ask(h, |reply| mailbox::Req::Item { id, keys, reply })
    })?;
    serde_json::to_value(MessageView {
        evidence: &evidence,
        message: &message,
    })
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn box_report(
    box_id: usize,
    id: u32,
    path: Vec<u32>,
    format: String,
    generated: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let keys = state.keys.lock().unwrap_or_else(|e| e.into_inner()).clone();
    with_box(&state, box_id, |h| {
        mailbox::ask(h, |reply| mailbox::Req::Report {
            id,
            path,
            format,
            generated,
            keys,
            reply,
        })
    })
}

#[tauri::command]
fn box_save_attachment(
    box_id: usize,
    id: u32,
    path: Vec<u32>,
    index: u32,
    dest: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let keys = state.keys.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (box_path, (_, sha, data)) = with_box(&state, box_id, |h| {
        let x = mailbox::ask(h, |reply| mailbox::Req::Extract {
            id,
            path,
            index,
            keys,
            reply,
        })?;
        Ok((h.path.clone(), x))
    })?;
    let dest = PathBuf::from(dest);
    let dest_dir = dest.parent().and_then(|d| std::fs::canonicalize(d).ok());
    if dest_dir.is_some() && dest_dir == box_path.parent().map(PathBuf::from) {
        return Err(
            "Destination refusée : choisissez un autre dossier que celui de la preuve.".into(),
        );
    }
    std::fs::write(&dest, &data).map_err(|e| format!("{}: {e}", dest.display()))?;
    Ok(sha)
}

/// Message racine (`path` vide) ou embarqué (`path` = indices de PJ successifs).
#[tauri::command]
fn get_message(
    id: usize,
    path: Vec<u32>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let loaded = state.loaded.lock().unwrap_or_else(|e| e.into_inner());
    let a = loaded.get(id).ok_or("preuve inconnue")?;
    let message = mf_engine::descend(&a.message, &path).ok_or("message embarqué introuvable")?;
    serde_json::to_value(MessageView {
        evidence: &a.evidence,
        message,
    })
    .map_err(|e| e.to_string())
}

/// FR-038 : enregistre une pièce jointe à l'emplacement choisi dans le dialogue natif, après
/// confirmation côté interface. L'écriture est faite par le moteur, jamais par le frontend.
#[tauri::command]
fn save_attachment(
    id: usize,
    path: Vec<u32>,
    index: u32,
    dest: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let loaded = state.loaded.lock().unwrap_or_else(|e| e.into_inner());
    let a = loaded.get(id).ok_or("preuve inconnue")?;
    let x = mf_engine::extract_attachment(&a.message, &path, index).map_err(|e| e.to_string())?;
    let dest = PathBuf::from(dest);
    let dest_dir = dest.parent().and_then(|d| std::fs::canonicalize(d).ok());
    let evidence_dir = std::fs::canonicalize(&a.evidence.path)
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from));
    if dest_dir.is_some() && dest_dir == evidence_dir {
        return Err(
            "Destination refusée : choisissez un autre dossier que celui de la preuve.".into(),
        );
    }
    std::fs::write(&dest, &x.data).map_err(|e| format!("{}: {e}", dest.display()))?;
    Ok(x.sha256)
}

/// FR-044 : rapport d'analyse (HTML ou JSON) du message désigné.
#[tauri::command]
fn build_report(
    id: usize,
    path: Vec<u32>,
    format: String,
    generated: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let loaded = state.loaded.lock().unwrap_or_else(|e| e.into_inner());
    let a = loaded.get(id).ok_or("preuve inconnue")?;
    let m = mf_engine::descend(&a.message, &path).ok_or("message embarqué introuvable")?;
    let provenance = path
        .iter()
        .map(|i| format!("PJ {i}"))
        .collect::<Vec<_>>()
        .join(" › ");
    let version = env!("CARGO_PKG_VERSION");
    match format.as_str() {
        "html" => Ok(mf_report::report_html(
            &a.evidence,
            m,
            &provenance,
            &generated,
            version,
        )),
        "json" => Ok(mf_report::report_json(
            &a.evidence,
            m,
            &provenance,
            &generated,
            version,
        )),
        other => Err(format!("format inconnu : {other}")),
    }
}

/// FR-023 : export fusionné des indicateurs (`[{source, iocs}]`).
#[tauri::command]
fn export_iocs(
    groups: Vec<mf_report::IocGroup>,
    format: String,
    defang: bool,
) -> Result<String, String> {
    match format.as_str() {
        "csv" => Ok(mf_report::iocs_csv(&groups, defang)),
        "json" => Ok(mf_report::iocs_json(&groups, defang)),
        other => Err(format!("format inconnu : {other}")),
    }
}

/// Enregistre un export (rapport, indicateurs) à l'emplacement choisi dans le dialogue natif.
/// Refuse d'écraser une preuve chargée ou d'écrire dans son dossier (Constitution I).
#[tauri::command]
fn save_text(
    dest: String,
    content: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let dest = PathBuf::from(dest);
    let dest_dir = dest.parent().and_then(|d| std::fs::canonicalize(d).ok());
    let loaded = state.loaded.lock().unwrap_or_else(|e| e.into_inner());
    for a in loaded.iter() {
        let ev = std::fs::canonicalize(&a.evidence.path).ok();
        if ev.as_ref().and_then(|p| p.parent().map(PathBuf::from)) == dest_dir && dest_dir.is_some()
        {
            return Err(
                "Destination refusée : choisissez un autre dossier que celui d'une preuve.".into(),
            );
        }
    }
    std::fs::write(&dest, content).map_err(|e| format!("{}: {e}", dest.display()))
}

/// Fichiers passés au lancement (association `.eml` / `.msg`, double-clic).
#[tauri::command]
fn initial_paths() -> Vec<String> {
    std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect()
}

/// Importe une clé PGP ou un certificat (octets lus par l'interface).
#[tauri::command]
fn import_key(
    name: String,
    data: Vec<u8>,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<KeyEntry>, String> {
    state
        .keys
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .import(&name, &data)
}

#[tauri::command]
fn remove_key(fingerprint: String, state: tauri::State<'_, AppState>) {
    state
        .keys
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&fingerprint);
}

#[tauri::command]
fn list_keys(state: tauri::State<'_, AppState>) -> Vec<KeyEntry> {
    state
        .keys
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries
        .clone()
}

/// Ré-analyse toutes les preuves ouvertes avec le trousseau courant (relues sur disque :
/// l'empreinte est recalculée et doit rester identique).
#[tauri::command]
fn reanalyze_all(state: tauri::State<'_, AppState>) -> Result<Vec<Summary>, String> {
    let keys = state.keys.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for b in state.boxes.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        let _ = b.tx.send(mailbox::Req::Forget);
    }
    let mut loaded = state.loaded.lock().unwrap_or_else(|e| e.into_inner());
    for a in loaded.iter_mut() {
        let fresh =
            mf_engine::open_with(Path::new(&a.evidence.path), &keys).map_err(|e| e.to_string())?;
        if fresh.evidence.sha256 != a.evidence.sha256 {
            return Err(format!(
                "{} a changé sur le disque depuis son ouverture",
                a.evidence.path
            ));
        }
        *a = fresh;
    }
    Ok(loaded
        .iter()
        .enumerate()
        .map(|(i, a)| summary(i, a))
        .collect())
}

/// Ouvre un lien de vérification de clé dans le navigateur système (FR-051), après
/// confirmation de l'analyste côté interface. Seuls les services listés par `mf-sig` passent.
#[tauri::command]
fn open_verification_link(url: String, app: tauri::AppHandle) -> Result<(), String> {
    if !mf_engine::is_verification_link(&url) {
        return Err("lien non autorisé".into());
    }
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        // Utilisé uniquement depuis Rust (open_verification_link) : aucune permission JavaScript.
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            open_paths,
            get_message,
            initial_paths,
            save_attachment,
            build_report,
            export_iocs,
            save_text,
            import_key,
            remove_key,
            list_keys,
            reanalyze_all,
            open_verification_link,
            box_list,
            box_filter,
            box_iocs,
            box_item,
            box_report,
            box_save_attachment
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("MailForensics n'a pas pu démarrer : {e}");
            std::process::exit(1);
        });
}
