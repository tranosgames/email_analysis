//! Boîtes PST/OST (feature 002) : une session par boîte, sur un thread dédié (les objets de la
//! bibliothèque PST ne sont pas `Send`), pilotée par messages. Entre deux requêtes, le thread
//! avance le calcul d'empreinte et en publie la progression (`box-hash`).

use mf_core::{BoxFilter, Evidence, FolderInfo, ItemSummary, Message, StoreInfo};
use mf_engine::{BoxSession, Keyring};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

type Reply<T> = Sender<Result<T, String>>;

pub enum Req {
    List {
        folder: u32,
        reply: Reply<Vec<ItemSummary>>,
    },
    /// Filtre sur les tables de dossiers (FR-007) : aucun élément lu.
    Filter {
        filter: BoxFilter,
        reply: Reply<FilterResult>,
    },
    /// Indicateurs des éléments ouverts, avec leur provenance (FR-013).
    Iocs {
        reply: Reply<Vec<mf_report::IocGroup>>,
    },
    Item {
        id: u32,
        keys: Keyring,
        reply: Reply<(Evidence, Message)>,
    },
    /// Rapport d'un élément : l'empreinte de la boîte est d'abord calculée jusqu'au bout.
    Report {
        id: u32,
        path: Vec<u32>,
        format: String,
        generated: String,
        keys: Keyring,
        reply: Reply<String>,
    },
    Extract {
        id: u32,
        path: Vec<u32>,
        index: u32,
        keys: Keyring,
        reply: Reply<(String, String, Vec<u8>)>,
    },
    /// Export (FR-008) dans un dossier déjà vérifié (vide, hors du dossier de la preuve).
    Export {
        ids: Vec<u32>,
        format: mf_engine::export::ExportFormat,
        generated: String,
        keys: Keyring,
        dest: PathBuf,
        reply: Reply<mf_engine::export::Manifest>,
    },
    /// Nouveau trousseau : les analyses seront refaites à la prochaine ouverture.
    Forget,
}

/// Lignes trouvées et dossiers illisibles ignorés (FR-009).
#[derive(Serialize)]
pub struct FilterResult {
    rows: Vec<ItemSummary>,
    unreadable: Vec<mf_core::UnreadableItem>,
}

pub struct BoxHandle {
    pub tx: Sender<Req>,
    /// Chemin réel de la boîte (refus d'écrire dans son dossier).
    pub path: PathBuf,
}

#[derive(Serialize, Clone)]
struct HashEvent {
    box_id: usize,
    done: u64,
    total: u64,
    sha256: Option<String>,
    md5: Option<String>,
}

/// Ouvre la boîte sur un nouveau thread ; retourne son poignée, ses métadonnées et ses dossiers.
pub fn spawn(
    path: PathBuf,
    box_id: usize,
    app: AppHandle,
) -> Result<(BoxHandle, StoreInfo, Vec<FolderInfo>), String> {
    let (tx, rx) = mpsc::channel::<Req>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(StoreInfo, Vec<FolderInfo>), String>>();
    let p = path.clone();
    std::thread::Builder::new()
        .name(format!("boite-{box_id}"))
        .spawn(move || match BoxSession::open_path(&p) {
            Ok(session) => {
                let _ = ready_tx.send(Ok((session.info().clone(), session.folders().to_vec())));
                run(session, rx, box_id, app);
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
            }
        })
        .map_err(|e| e.to_string())?;
    let (info, folders) = ready_rx.recv().map_err(|e| e.to_string())??;
    Ok((BoxHandle { tx, path }, info, folders))
}

fn run(mut s: BoxSession, rx: Receiver<Req>, box_id: usize, app: AppHandle) {
    let mut hashed = false;
    let mut last_emit = Instant::now() - Duration::from_secs(1);
    loop {
        let req = if hashed {
            match rx.recv() {
                Ok(r) => r,
                Err(_) => return, // application fermée
            }
        } else {
            match rx.recv_timeout(Duration::ZERO) {
                Ok(r) => r,
                Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {
                    // Rien à faire : on avance l'empreinte de 16 Mo.
                    match s.hash_step(16 * 1024 * 1024) {
                        Ok(p) => {
                            hashed = p.sha256.is_some();
                            if hashed || last_emit.elapsed() >= Duration::from_millis(100) {
                                last_emit = Instant::now();
                                let _ = app.emit(
                                    "box-hash",
                                    HashEvent {
                                        box_id,
                                        done: p.done,
                                        total: p.total,
                                        sha256: p.sha256,
                                        md5: p.md5,
                                    },
                                );
                            }
                        }
                        Err(_) => hashed = true, // erreur d'E/S : signalée à l'export
                    }
                    continue;
                }
            }
        };
        match req {
            Req::List { folder, reply } => {
                let _ = reply.send(s.list(folder).map_err(|e| e.to_string()));
            }
            Req::Filter { filter, reply } => {
                let r = s
                    .filter_report(&filter)
                    .map(|(rows, unreadable)| FilterResult { rows, unreadable })
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            Req::Iocs { reply } => {
                let groups = s
                    .iocs(None)
                    .into_iter()
                    .map(|(source, iocs)| mf_report::IocGroup { source, iocs })
                    .collect();
                let _ = reply.send(Ok(groups));
            }
            Req::Item { id, keys, reply } => {
                let r = s
                    .open_item(id, &keys)
                    .map(|a| (a.evidence.clone(), a.message.clone()));
                let _ = reply.send(r.map_err(|e| e.to_string()));
            }
            Req::Report {
                id,
                path,
                format,
                generated,
                keys,
                reply,
            } => {
                let r = (|| -> Result<String, String> {
                    s.hash_all().map_err(|e| e.to_string())?;
                    hashed = true;
                    let a = s.open_item(id, &keys).map_err(|e| e.to_string())?;
                    let m = mf_engine::descend(&a.message, &path)
                        .ok_or("message embarqué introuvable")?;
                    let mut prov = a
                        .message
                        .provenance
                        .as_ref()
                        .map(|p| format!("{} › élément #{}", p.label(), p.node_id))
                        .unwrap_or_default();
                    for i in &path {
                        prov.push_str(&format!(" › PJ {i}"));
                    }
                    let version = env!("CARGO_PKG_VERSION");
                    match format.as_str() {
                        "html" => Ok(mf_report::report_html(
                            &a.evidence,
                            m,
                            &prov,
                            &generated,
                            version,
                        )),
                        "json" => Ok(mf_report::report_json(
                            &a.evidence,
                            m,
                            &prov,
                            &generated,
                            version,
                        )),
                        other => Err(format!("format {other} inconnu")),
                    }
                })();
                let _ = reply.send(r);
            }
            Req::Extract {
                id,
                path,
                index,
                keys,
                reply,
            } => {
                let r = s
                    .open_item(id, &keys)
                    .map_err(|e| e.to_string())
                    .and_then(|a| {
                        mf_engine::extract_attachment(&a.message, &path, index)
                            .map_err(|e| e.to_string())
                    })
                    .map(|x| (x.file_name, x.sha256, x.data));
                let _ = reply.send(r);
            }
            Req::Export {
                ids,
                format,
                generated,
                keys,
                dest,
                reply,
            } => {
                let r = s
                    .export(&ids, format, &generated, &keys, None, &mut |name, bytes| {
                        // Création exclusive : jamais d'écrasement.
                        let mut f = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(dest.join(name))?;
                        std::io::Write::write_all(&mut f, bytes)
                    })
                    .map_err(|e| e.to_string());
                if r.is_ok() {
                    hashed = true;
                }
                let _ = reply.send(r);
            }
            Req::Forget => s.forget_analyses(),
        }
    }
}

/// Envoie une requête et attend la réponse.
pub fn ask<T>(h: &BoxHandle, make: impl FnOnce(Reply<T>) -> Req) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    h.tx.send(make(tx))
        .map_err(|_| "boîte fermée".to_string())?;
    rx.recv().map_err(|_| "boîte fermée".to_string())?
}
