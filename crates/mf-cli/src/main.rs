//! `mf` — CLI MailForensics (contracts/cli.md). Couche mince au-dessus de `mf-engine`.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use mf_core::{Address, Message};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "mf",
    version,
    about = "Analyse forensic de courriels EML/MSG (lecture seule, hors-ligne)"
)]
struct Cli {
    /// Sortie JSON (un document par commande).
    #[arg(long, global = true)]
    json: bool,
    /// Clés publiques PGP et certificats (fichier ou dossier : .asc, .gpg, .pem, .cer, .crt)
    /// pour vérifier les signatures ; répétable.
    #[arg(long, global = true)]
    keys: Vec<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Boîtes Outlook PST / OST : seuls les éléments désignés par --id sont lus.
    Pst {
        #[command(subcommand)]
        cmd: PstCmd,
    },
    /// Constats automatiques (authentification, expéditeur, liens, pièces jointes).
    Findings { files: Vec<PathBuf> },
    /// Indicateurs de compromission de plusieurs messages, fusionnés (CSV ou JSON).
    Iocs {
        files: Vec<PathBuf>,
        /// csv ou json
        #[arg(long, default_value = "csv")]
        format: String,
        /// Valeurs non cliquables (hxxp[://]exemple[.]com).
        #[arg(long)]
        defang: bool,
    },
    /// Rapport d'analyse d'un message (HTML imprimable ou JSON).
    Report {
        file: PathBuf,
        /// Message embarqué, ex. « 2/1 ».
        #[arg(long)]
        path: Option<String>,
        /// html ou json
        #[arg(long, default_value = "html")]
        format: String,
        /// Fichier à créer (ne doit pas exister, ni être dans le dossier de la preuve).
        #[arg(long)]
        out: PathBuf,
    },
    /// SHA-256, MD5 et format détecté.
    Hash { files: Vec<PathBuf> },
    /// Résumé du message : en-tête lisible, fichiers contenus, URL (et en-têtes avec --headers).
    Show {
        file: PathBuf,
        /// Affiche aussi tous les en-têtes bruts.
        #[arg(long)]
        headers: bool,
        /// Message embarqué à afficher, ex. « 2/1 » = PJ 2 puis PJ 1.
        #[arg(long)]
        path: Option<String>,
    },
    /// Tous les en-têtes dans l'ordre d'origine.
    Headers {
        file: PathBuf,
        #[arg(long)]
        path: Option<String>,
    },
    /// Fichiers contenus (arborescence des messages embarqués).
    Attachments { file: PathBuf },
    /// Enregistre une pièce jointe (octets d'origine, nom assaini) dans un dossier.
    Extract {
        file: PathBuf,
        /// Numéro de la pièce jointe (colonne « n. » de `mf attachments`).
        #[arg(long)]
        index: u32,
        /// Message embarqué contenant la PJ, ex. « 1 ».
        #[arg(long)]
        path: Option<String>,
        /// Dossier de destination (ne doit pas être celui de la preuve).
        #[arg(long)]
        out: PathBuf,
    },
    /// URL uniques du message, avec emplacements.
    Urls {
        file: PathBuf,
        #[arg(long)]
        path: Option<String>,
        /// Affiche la forme non cliquable (hxxp[://]…).
        #[arg(long)]
        defang: bool,
    },
}

fn parse_path(p: &Option<String>) -> Result<Vec<u32>, String> {
    p.as_deref()
        .map(|s| {
            s.split('/')
                .filter(|x| !x.is_empty())
                .map(|x| x.parse::<u32>().map_err(|e| format!("--path : {e}")))
                .collect()
        })
        .unwrap_or(Ok(Vec::new()))
}

fn fmt_addr(a: &Address) -> String {
    match (&a.display_name, &a.address) {
        (Some(n), Some(e)) if n != e => format!("{n} <{e}>"),
        (_, Some(e)) => e.clone(),
        (Some(n), None) => a
            .x500_dn
            .as_ref()
            .map_or_else(|| n.clone(), |dn| format!("{n} [EX {dn}]")),
        (None, None) => a.x500_dn.clone().unwrap_or_default(),
    }
}

fn fmt_list(v: &[Address]) -> String {
    v.iter().map(fmt_addr).collect::<Vec<_>>().join(", ")
}

fn human(n: u64) -> String {
    match n {
        n if n >= 1 << 20 => format!("{:.1} Mo", n as f64 / f64::from(1 << 20)),
        n if n >= 1 << 10 => format!("{:.1} Ko", n as f64 / 1024.0),
        n => format!("{n} o"),
    }
}

fn print_headers(m: &Message) {
    println!("En-têtes ({})", m.headers.len());
    for h in &m.headers {
        println!("  {}", h.raw.replace('\n', "\n  "));
    }
}

fn print_attachments(m: &Message, indent: usize) {
    let pad = "  ".repeat(indent);
    if m.attachments.is_empty() && indent == 1 {
        println!("{pad}Aucun fichier");
    }
    for a in &m.attachments {
        println!(
            "{pad}{:>2}. {}  [{}] {}  {:?}  sha256 {}",
            a.index,
            a.filename,
            a.declared_mime.as_deref().unwrap_or("?"),
            human(a.size),
            a.disposition,
            a.sha256
        );
        if let Some(inner) = &a.embedded {
            println!(
                "{pad}    ↳ message embarqué : « {} » ({} fichier(s), {} URL)",
                inner.subject.as_deref().unwrap_or(""),
                inner.attachments.len(),
                inner.urls.len()
            );
            print_attachments(inner, indent + 2);
        }
    }
}

fn fmt_endpoint(e: &mf_core::Endpoint) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = &e.ip {
        let scope = match e.ip_scope {
            Some(mf_core::IpScope::Private) => " (privée)",
            Some(mf_core::IpScope::Loopback) => " (boucle locale)",
            Some(mf_core::IpScope::LinkLocal) => " (lien local)",
            Some(mf_core::IpScope::Shared) => " (CGNAT)",
            _ => "",
        };
        parts.push(format!("{ip}{scope}"));
    }
    if let Some(r) = &e.rdns {
        parts.push(format!("DNS inverse {r}"));
    }
    if let Some(n) = &e.name {
        parts.push(format!("annoncé {n}"));
    }
    let src = if e.hop > 0 {
        format!("saut {}", e.hop)
    } else {
        e.source.clone()
    };
    format!(
        "{}  [{src}]",
        if parts.is_empty() {
            "—".into()
        } else {
            parts.join(" · ")
        }
    )
}

/// FR-042 : IP et DNS d'envoi et de réception (noms tels qu'enregistrés dans les en-têtes).
fn print_route(m: &Message) {
    let Some(r) = &m.route else { return };
    println!(
        "Acheminement — {}",
        r.sender.as_deref().unwrap_or("expéditeur inconnu")
    );
    if m.hops.is_empty() {
        println!("  Aucun en-tête Received (message interne, brouillon ou en-têtes absents)");
    }
    let row = |label: &str, e: &Option<mf_core::Endpoint>| {
        if let Some(e) = e {
            println!("  {label:<22} {}", fmt_endpoint(e));
        }
    };
    row("Envoi", &r.origin);
    row("IP du client (en-tête)", &r.originating_ip_header);
    row("Première IP publique", &r.first_public);
    row("Remis par", &r.last_public);
    if let Some(rcv) = &r.receiver {
        let what = [rcv.name.clone(), rcv.ip.clone()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
        println!(
            "  {:<22} {}  {}",
            "Réception",
            if what.is_empty() { "—".into() } else { what },
            r.received_utc.as_deref().unwrap_or("")
        );
    }
    for h in &m.hops {
        println!(
            "  {:>2}. {} [{}] → {}  {}{}",
            h.index,
            h.from_rdns
                .clone()
                .or(h.from_name.clone())
                .unwrap_or_else(|| "—".into()),
            h.from_ip.as_deref().unwrap_or("—"),
            h.by_name.as_deref().unwrap_or("—"),
            h.date_utc.as_deref().unwrap_or(""),
            h.delay_seconds
                .map_or(String::new(), |d| format!("  (+{d} s)")),
        );
    }
}

fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap_or(0), 0)
        .map_or_else(String::new, |t| t.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// FR-013/014 : verdicts d'authentification (serveur de réception final) et DKIM.
fn print_auth(m: &Message) {
    if m.auth.is_empty() && m.dkim.is_empty() {
        return;
    }
    let v = |method: &str| {
        m.auth
            .iter()
            .filter(|a| a.method == method)
            .find(|a| a.most_recent)
            .or_else(|| m.auth.iter().find(|a| a.method == method))
            .map_or("—".to_string(), |a| a.result.clone())
    };
    println!(
        "Authentification  SPF {}  DKIM {}  DMARC {}",
        v("spf"),
        v("dkim"),
        v("dmarc")
    );
    for d in &m.dkim {
        let state = match d.body_hash_ok {
            Some(true) => "corps intact",
            Some(false) => "CORPS MODIFIÉ",
            None => "non vérifiable",
        };
        println!(
            "  DKIM d={} s={} : {state}",
            d.domain.as_deref().unwrap_or("?"),
            d.selector.as_deref().unwrap_or("?")
        );
    }
}

/// FR-015 : constats, du plus grave au moins grave.
fn print_findings(m: &Message) {
    if let Some(v) = &m.verdict {
        println!(
            "Verdict : {} (score {}) — {}",
            mf_report::verdict_label(v.level).1,
            v.score,
            v.summary
        );
        for r in &v.reasons {
            println!("  · {r}");
        }
    }
    println!("Constats ({})", m.findings.len());
    for f in &m.findings {
        let sev = match f.severity {
            mf_core::Severity::High => "ÉLEVÉ ",
            mf_core::Severity::Medium => "MOYEN ",
            mf_core::Severity::Low => "faible",
            mf_core::Severity::Info => "info  ",
        };
        println!("  {sev} {}\n         {}", f.title, f.detail);
    }
}

fn kind_label(k: mf_core::BlockedKind) -> &'static str {
    use mf_core::BlockedKind::*;
    match k {
        Image => "image",
        Background => "image de fond",
        Stylesheet => "feuille de style",
        Script => "script",
        Frame => "cadre",
        Media => "média",
        Object => "objet",
        Other => "autre",
    }
}

/// FR-039 : ressources que le HTML demandait à charger, bloquées et localisées.
fn print_blocked(m: &Message) {
    if m.blocked_resources.is_empty() {
        return;
    }
    println!(
        "Ressources distantes bloquées ({}) — jamais chargées",
        m.blocked_resources.len()
    );
    for b in &m.blocked_resources {
        println!(
            "  {:>2}. {:<16} <{} {}>  {}  {}",
            b.number,
            kind_label(b.kind),
            b.element,
            b.attribute,
            b.line
                .map_or_else(|| "ligne ?".to_string(), |l| format!("ligne {l} du HTML")),
            if b.marker.is_some() {
                "(visible au rendu)"
            } else {
                "(retiré du rendu)"
            },
        );
        println!("      {}", b.url);
    }
}

fn print_urls(m: &Message, defang: bool) {
    println!("URL ({})", m.urls.len());
    if m.urls.is_empty() {
        println!("  Aucune URL");
    }
    for u in &m.urls {
        let locs = u
            .locations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {}  ({locs}{})",
            if defang { &u.defanged } else { &u.url },
            if u.occurrences > 1 {
                format!(", ×{}", u.occurrences)
            } else {
                String::new()
            }
        );
    }
}

/// Trousseau construit à partir des fichiers et dossiers `--keys`.
fn load_keys(paths: &[PathBuf]) -> Result<mf_engine::Keyring, String> {
    let mut k = mf_engine::Keyring::default();
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| format!("{}: {e}", p.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|f| {
                    f.extension().and_then(|x| x.to_str()).is_some_and(|x| {
                        matches!(
                            x.to_ascii_lowercase().as_str(),
                            "asc" | "gpg" | "pgp" | "pem" | "cer" | "crt" | "der"
                        )
                    })
                })
                .collect();
            v.sort();
            files.extend(v);
        } else {
            files.push(p.clone());
        }
    }
    for f in files {
        let data = std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let name = f.file_name().map_or_else(
            || f.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        k.import(&name, &data)
            .map_err(|e| format!("{}: {e}", f.display()))?;
    }
    Ok(k)
}

fn print_signatures(m: &Message) {
    for c in &m.signatures {
        let scheme = match c.scheme {
            mf_core::SignatureScheme::Pgp => "PGP",
            mf_core::SignatureScheme::Smime => "S/MIME",
        };
        let st = match c.status {
            mf_core::SignatureStatus::Valid => "VALIDE",
            mf_core::SignatureStatus::Invalid => "INVALIDE",
            mf_core::SignatureStatus::UnknownKey => "clé inconnue",
            mf_core::SignatureStatus::Encrypted => "chiffré",
            mf_core::SignatureStatus::Unsupported => "non vérifiable",
        };
        println!(
            "Signature {scheme} ({}) : {st}{}",
            c.kind,
            c.signer_ids
                .first()
                .map(|s| format!(" — {s}"))
                .unwrap_or_default()
        );
        if let Some(fp) = c.fingerprint.as_deref() {
            println!("  empreinte {fp}");
        }
        if let Some(t) = c.signed_at.as_deref() {
            println!("  signée le {t}");
        }
        if let Some(x) = &c.cert {
            println!("  certificat émis par {} ({})", x.issuer, x.chain);
        }
        if let Some(n) = c.note.as_deref() {
            println!("  {n}");
        }
    }
}

/// Affichage lisible d'un message (`mf show`, `mf pst show`).
fn print_message(ev: &mf_core::Evidence, m: &Message, headers: bool) {
    println!(
        "Preuve   {} ({:?}, {})\n  sha256 {}\n  md5    {}",
        ev.path,
        ev.format,
        human(ev.size),
        if ev.sha256.is_empty() {
            "(non calculée : `mf pst info`)"
        } else {
            &ev.sha256
        },
        ev.md5
    );
    println!("De       {}", fmt_list(&m.from));
    if let Some(s) = &m.sender {
        println!("Envoyé par {}", fmt_addr(s));
    }
    if !m.reply_to.is_empty() {
        println!("Répondre à {}", fmt_list(&m.reply_to));
    }
    println!("À        {}", fmt_list(&m.to));
    if !m.cc.is_empty() {
        println!("Cc       {}", fmt_list(&m.cc));
    }
    if !m.bcc.is_empty() {
        println!("Cci      {}", fmt_list(&m.bcc));
    }
    println!("Objet    {}", m.subject.as_deref().unwrap_or(""));
    println!(
        "Date     {}  (UTC {})",
        m.date_raw.as_deref().unwrap_or("—"),
        m.date_utc.as_deref().unwrap_or("—")
    );
    for i in &m.issues {
        println!("⚠ {i}");
    }
    if headers {
        print_headers(m);
    } else {
        println!(
            "En-têtes ({}) — ajouter --headers pour les afficher",
            m.headers.len()
        );
    }
    println!("Fichiers contenus ({})", m.attachments.len());
    print_attachments(m, 1);
    print_auth(m);
    print_signatures(m);
    print_findings(m);
    print_route(m);
    print_urls(m, false);
    print_blocked(m);
}

fn run(cli: Cli) -> Result<(), String> {
    let keys = load_keys(&cli.keys)?;
    let out = |v: &dyn erased::Json| -> Result<(), String> {
        println!("{}", v.to_json().map_err(|e| e.to_string())?);
        Ok(())
    };
    match cli.cmd {
        Cmd::Pst { cmd } => return pst_cmd(cmd, cli.json, &keys),
        Cmd::Hash { files } => {
            let mut all = Vec::new();
            for f in files {
                let (ev, _) = mf_core::read_evidence(&f).map_err(|e| e.to_string())?;
                if !cli.json {
                    println!(
                        "{}  {:?}  {}\n  sha256 {}\n  md5    {}",
                        ev.path,
                        ev.format,
                        human(ev.size),
                        ev.sha256,
                        ev.md5
                    );
                }
                all.push(ev);
            }
            if cli.json {
                out(&all)?;
            }
        }
        Cmd::Show {
            file,
            headers,
            path,
        } => {
            let a = mf_engine::open_with(&file, &keys).map_err(|e| e.to_string())?;
            let m = mf_engine::descend(&a.message, &parse_path(&path)?)
                .ok_or("--path : message embarqué introuvable")?;
            if cli.json {
                return out(m);
            }
            print_message(&a.evidence, m, headers);
        }
        Cmd::Headers { file, path } => {
            let a = mf_engine::open_with(&file, &keys).map_err(|e| e.to_string())?;
            let m = mf_engine::descend(&a.message, &parse_path(&path)?)
                .ok_or("--path : message embarqué introuvable")?;
            if cli.json {
                return out(&m.headers);
            }
            print_headers(m);
        }
        Cmd::Attachments { file } => {
            let a = mf_engine::open_with(&file, &keys).map_err(|e| e.to_string())?;
            if cli.json {
                return out(&a.message.attachments);
            }
            println!("Fichiers contenus ({})", a.message.attachments.len());
            print_attachments(&a.message, 1);
        }
        Cmd::Extract {
            file,
            index,
            path,
            out: dir,
        } => {
            let evidence_dir = std::fs::canonicalize(&file)
                .ok()
                .and_then(|p| p.parent().map(PathBuf::from));
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if evidence_dir.is_some() && std::fs::canonicalize(&dir).ok() == evidence_dir {
                return Err(
                    "destination refusée : ne pas écrire dans le dossier de la preuve".into(),
                );
            }
            let a = mf_engine::open_with(&file, &keys).map_err(|e| e.to_string())?;
            let x = mf_engine::extract_attachment(&a.message, &parse_path(&path)?, index)
                .map_err(|e| e.to_string())?;
            let dest = dir.join(&x.file_name);
            if dest.exists() {
                return Err(format!("{} existe déjà", dest.display()));
            }
            std::fs::write(&dest, &x.data).map_err(|e| format!("{}: {e}", dest.display()))?;
            if cli.json {
                return out(
                    &serde_json::json!({ "written": dest.display().to_string(), "sha256": x.sha256, "size": x.data.len() }),
                );
            }
            println!(
                "{}  ({}, sha256 {})",
                dest.display(),
                human(x.data.len() as u64),
                x.sha256
            );
        }
        Cmd::Findings { files } => {
            let mut all = Vec::new();
            for f in files {
                let a =
                    mf_engine::open_with(&f, &keys).map_err(|e| format!("{}: {e}", f.display()))?;
                if !cli.json {
                    println!("== {}", f.display());
                    print_auth(&a.message);
                    print_signatures(&a.message);
                    print_findings(&a.message);
                }
                all.push(serde_json::json!({ "file": f.display().to_string(), "findings": a.message.findings }));
            }
            if cli.json {
                return out(&all);
            }
        }
        Cmd::Iocs {
            files,
            format,
            defang,
        } => {
            let mut groups = Vec::new();
            for f in files {
                let a =
                    mf_engine::open_with(&f, &keys).map_err(|e| format!("{}: {e}", f.display()))?;
                groups.push(mf_report::IocGroup {
                    source: f.display().to_string(),
                    iocs: a.message.iocs,
                });
            }
            match format.as_str() {
                "csv" => print!("{}", mf_report::iocs_csv(&groups, defang)),
                "json" => println!("{}", mf_report::iocs_json(&groups, defang)),
                other => return Err(format!("--format {other} : csv ou json attendu")),
            }
        }
        Cmd::Report {
            file,
            path,
            format,
            out: dest,
        } => {
            let evidence_dir = std::fs::canonicalize(&file)
                .ok()
                .and_then(|p| p.parent().map(PathBuf::from));
            let dest_dir = dest
                .parent()
                .map(|d| {
                    if d.as_os_str().is_empty() {
                        std::path::Path::new(".")
                    } else {
                        d
                    }
                })
                .and_then(|d| std::fs::canonicalize(d).ok());
            if evidence_dir.is_some() && dest_dir == evidence_dir {
                return Err(
                    "destination refusée : ne pas écrire dans le dossier de la preuve".into(),
                );
            }
            if dest.exists() {
                return Err(format!("{} existe déjà", dest.display()));
            }
            let a = mf_engine::open_with(&file, &keys).map_err(|e| e.to_string())?;
            let p = parse_path(&path)?;
            let m = mf_engine::descend(&a.message, &p)
                .ok_or("--path : message embarqué introuvable")?;
            let provenance = p
                .iter()
                .map(|i| format!("PJ {i}"))
                .collect::<Vec<_>>()
                .join(" › ");
            let now = now_utc();
            let version = env!("CARGO_PKG_VERSION");
            let content = match format.as_str() {
                "html" => mf_report::report_html(&a.evidence, m, &provenance, &now, version),
                "json" => mf_report::report_json(&a.evidence, m, &provenance, &now, version),
                other => return Err(format!("--format {other} : html ou json attendu")),
            };
            std::fs::write(&dest, content).map_err(|e| format!("{}: {e}", dest.display()))?;
            println!("{} ({} constat(s))", dest.display(), m.findings.len());
        }
        Cmd::Urls { file, path, defang } => {
            let a = mf_engine::open_with(&file, &keys).map_err(|e| e.to_string())?;
            let m = mf_engine::descend(&a.message, &parse_path(&path)?)
                .ok_or("--path : message embarqué introuvable")?;
            if cli.json {
                return out(&m.urls);
            }
            print_urls(m, defang);
        }
    }
    Ok(())
}

#[derive(Subcommand)]
enum PstCmd {
    /// Format, encodage, protection, empreintes, statistiques, éléments illisibles.
    Info {
        file: PathBuf,
        /// Ne pas calculer l'empreinte (qui lit tout le fichier).
        #[arg(long)]
        no_hash: bool,
    },
    /// Arborescence des dossiers avec leurs compteurs (tables de hiérarchie seulement).
    Tree { file: PathBuf },
    /// Lignes d'un dossier ou de toute la boîte, lues dans les tables, sans ouvrir les éléments ;
    /// filtres combinés en ET, sans tenir compte de la casse ni des accents.
    Ls {
        file: PathBuf,
        /// Identifiant ou chemin du dossier (« bailey-s/Inbox ») ; par défaut toute la boîte.
        #[arg(long)]
        folder: Option<String>,
        #[command(flatten)]
        filter: BoxFilterArgs,
    },
    /// Indicateurs d'éléments désignés (ouverts et analysés), fusionnés avec leur provenance.
    Iocs {
        file: PathBuf,
        /// Identifiants séparés par des virgules (voir `mf pst ls`).
        #[arg(long, value_delimiter = ',', required = true)]
        id: Vec<u32>,
        /// csv ou json
        #[arg(long, default_value = "csv")]
        format: String,
        #[arg(long)]
        defang: bool,
    },
    /// Élément complet, comme `mf show`, avec sa provenance.
    Show {
        file: PathBuf,
        #[arg(long)]
        id: u32,
        #[arg(long)]
        headers: bool,
    },
    /// Rapport d'un élément (HTML ou JSON), empreinte de la boîte calculée au préalable.
    Report {
        file: PathBuf,
        #[arg(long)]
        id: u32,
        #[arg(long, default_value = "html")]
        format: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Mesures : temps d'ouverture, de liste, d'ouverture d'élément, octets lus.
    Bench { file: PathBuf },
}

/// Filtres de `mf pst ls` (FR-007) : colonnes des tables de dossiers.
#[derive(clap::Args, Debug, Default)]
struct BoxFilterArgs {
    /// Mots cherchés dans l'objet, l'expéditeur et les destinataires.
    #[arg(long)]
    text: Option<String>,
    /// Nom affiché de l'expéditeur (l'adresse n'est pas dans les tables).
    #[arg(long)]
    from_name: Option<String>,
    /// Destinataire (À ou Cc).
    #[arg(long)]
    to: Option<String>,
    #[arg(long)]
    subject: Option<String>,
    #[arg(long)]
    message_id: Option<String>,
    /// Date de réception (sinon d'envoi) au plus tôt : AAAA-MM-JJ, UTC.
    #[arg(long)]
    after: Option<String>,
    /// Date au plus tard, journée incluse : AAAA-MM-JJ.
    #[arg(long)]
    before: Option<String>,
    /// Taille minimale en octets.
    #[arg(long)]
    min_size: Option<u32>,
    #[arg(long)]
    max_size: Option<u32>,
    /// Seulement les éléments avec pièces jointes.
    #[arg(long, conflicts_with = "no_attachments")]
    attachments: bool,
    /// Seulement les éléments sans pièce jointe.
    #[arg(long)]
    no_attachments: bool,
}

impl BoxFilterArgs {
    fn to_filter(&self, folder: Option<u32>) -> Result<mf_core::BoxFilter, String> {
        for (name, v) in [("--after", &self.after), ("--before", &self.before)] {
            if let Some(d) = v {
                let ok = d.len() >= 4 && d.chars().take(10).all(|c| c.is_ascii_digit() || c == '-');
                if !ok {
                    return Err(format!("{name} {d} : date AAAA-MM-JJ attendue"));
                }
            }
        }
        Ok(mf_core::BoxFilter {
            folder,
            text: self.text.clone(),
            from_name: self.from_name.clone(),
            to: self.to.clone(),
            subject: self.subject.clone(),
            message_id: self.message_id.clone(),
            after: self.after.clone(),
            before: self.before.clone(),
            min_size: self.min_size,
            max_size: self.max_size,
            has_attachments: match (self.attachments, self.no_attachments) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            },
            ..Default::default()
        })
    }
}

/// Dossiers désignés par `--folder` (identifiant ou chemin), ou tous les dossiers non virtuels.
fn pick_folders(s: &mf_engine::BoxSession, spec: &Option<String>) -> Result<Vec<u32>, String> {
    let all = s.folders();
    match spec {
        None => Ok(all
            .iter()
            .filter(|f| f.kind != "search")
            .map(|f| f.id)
            .collect()),
        Some(x) => {
            if let Ok(id) = x
                .trim_start_matches("0x")
                .parse::<u32>()
                .or_else(|_| u32::from_str_radix(x.trim_start_matches("0x"), 16))
            {
                if all.iter().any(|f| f.id == id) {
                    return Ok(vec![id]);
                }
            }
            let want = x.trim_matches('/').to_lowercase();
            all.iter()
                .find(|f| f.path.join("/").to_lowercase() == want)
                .map(|f| vec![f.id])
                .ok_or_else(|| format!("dossier introuvable : {x} (voir `mf pst tree`)"))
        }
    }
}

fn pst_cmd(cmd: PstCmd, json: bool, keys: &mf_engine::Keyring) -> Result<(), String> {
    use mf_engine::BoxSession;
    let open = |f: &PathBuf| BoxSession::open_path(f).map_err(|e| format!("{}: {e}", f.display()));
    let print = |v: &dyn erased::Json| -> Result<(), String> {
        println!("{}", v.to_json().map_err(|e| e.to_string())?);
        Ok(())
    };
    match cmd {
        PstCmd::Info { file, no_hash } => {
            let mut s = open(&file)?;
            let hash = if no_hash {
                None
            } else {
                Some(s.hash_all().map_err(|e| e.to_string())?)
            };
            let i = s.info();
            if json {
                return print(
                    &serde_json::json!({ "store": i, "hash": hash, "items_read": s.items_read() }),
                );
            }
            println!(
                "{} — {} {}, encodage {}, {}{}",
                i.name,
                if i.format == "ansi" {
                    "PST"
                } else if i.format == "ost4k" {
                    "OST"
                } else {
                    "PST"
                },
                match i.format.as_str() {
                    "ansi" => "ANSI (Outlook 97-2002)",
                    "ost4k" => "Outlook 2013+ (pages de 4 Ko)",
                    _ => "Unicode",
                },
                i.encoding,
                human(i.size),
                if i.password_protected {
                    ", protégé par mot de passe (le contenu reste lisible)"
                } else {
                    ""
                }
            );
            if let Some(n) = &i.display_name {
                println!("  nom de la boîte : {n}");
            }
            if let Some(h) = &hash {
                println!(
                    "  sha256 {}\n  md5    {}",
                    h.sha256.as_deref().unwrap_or(""),
                    h.md5.as_deref().unwrap_or("")
                );
            }
            println!(
                "  {} dossiers · {} éléments · {} illisible(s)",
                i.folders,
                i.items,
                i.unreadable.len()
            );
            for u in &i.unreadable {
                println!(
                    "  ⚠ {} {:#x} ({}) : {}",
                    u.kind,
                    u.node_id,
                    u.folder_path.join(" › "),
                    u.reason
                );
            }
        }
        PstCmd::Tree { file } => {
            let s = open(&file)?;
            if json {
                return print(&s.folders());
            }
            for f in s.folders() {
                if f.kind == "root" {
                    continue;
                }
                let label = if f.kind == "ipm" {
                    s.info()
                        .display_name
                        .clone()
                        .unwrap_or_else(|| "Boîte".into())
                } else {
                    f.name.clone()
                };
                let tag = match f.kind.as_str() {
                    "inbox" | "sent" | "deleted" | "drafts" | "outbox" | "junk" | "search"
                    | "system" => format!("  [{}]", f.kind),
                    _ => String::new(),
                };
                println!(
                    "{:indent$}{label}  ({}{}){tag}  #{}",
                    "",
                    f.item_count,
                    if f.unread_count > 0 {
                        format!(", {} non lus", f.unread_count)
                    } else {
                        String::new()
                    },
                    f.id,
                    indent = (f.depth.saturating_sub(1) * 2) as usize
                );
            }
        }
        PstCmd::Ls {
            file,
            folder,
            filter,
        } => {
            let mut s = open(&file)?;
            let folder = match folder {
                Some(_) => pick_folders(&s, &folder)?.first().copied(),
                None => None,
            };
            let rows = s
                .filter(&filter.to_filter(folder)?)
                .map_err(|e| e.to_string())?;
            if json {
                return print(&rows);
            }
            for r in &rows {
                println!(
                    "#{:<9} {}  {:24.24}  {}{}",
                    r.id,
                    r.received
                        .as_deref()
                        .or(r.sent.as_deref())
                        .map_or("—".to_string(), |d| d.chars().take(16).collect()),
                    r.from_name.as_deref().unwrap_or("—"),
                    r.subject.as_deref().unwrap_or("(sans objet)"),
                    if r.has_attachments { "  📎" } else { "" }
                );
            }
            eprintln!(
                "{} élément(s) ; éléments lus : {}",
                rows.len(),
                s.items_read()
            );
        }
        PstCmd::Show { file, id, headers } => {
            let mut s = open(&file)?;
            let a = s.open_item(id, keys).map_err(|e| e.to_string())?;
            if json {
                return print(a);
            }
            if let Some(p) = &a.message.provenance {
                println!("Provenance {} › élément #{}", p.label(), p.node_id);
            }
            print_message(&a.evidence, &a.message, headers);
        }
        PstCmd::Report {
            file,
            id,
            format,
            out: dest,
        } => {
            if dest.exists() {
                return Err(format!("{} existe déjà", dest.display()));
            }
            let evidence_dir = std::fs::canonicalize(&file)
                .ok()
                .and_then(|p| p.parent().map(PathBuf::from));
            let dest_dir = dest
                .parent()
                .map(|d| {
                    if d.as_os_str().is_empty() {
                        std::path::Path::new(".")
                    } else {
                        d
                    }
                })
                .and_then(|d| std::fs::canonicalize(d).ok());
            if evidence_dir.is_some() && dest_dir == evidence_dir {
                return Err(
                    "destination refusée : ne pas écrire dans le dossier de la preuve".into(),
                );
            }
            let mut s = open(&file)?;
            s.open_item(id, keys).map_err(|e| e.to_string())?;
            s.hash_all().map_err(|e| e.to_string())?;
            let a = s.open_item(id, keys).map_err(|e| e.to_string())?;
            let prov = a
                .message
                .provenance
                .as_ref()
                .map(|p| format!("{} › élément #{}", p.label(), p.node_id))
                .unwrap_or_default();
            let now = now_utc();
            let version = env!("CARGO_PKG_VERSION");
            let content = match format.as_str() {
                "html" => mf_report::report_html(&a.evidence, &a.message, &prov, &now, version),
                "json" => mf_report::report_json(&a.evidence, &a.message, &prov, &now, version),
                other => return Err(format!("--format {other} : html ou json attendu")),
            };
            std::fs::write(&dest, content).map_err(|e| format!("{}: {e}", dest.display()))?;
            println!(
                "{} ({} constat(s))",
                dest.display(),
                a.message.findings.len()
            );
        }
        PstCmd::Iocs {
            file,
            id,
            format,
            defang,
        } => {
            let mut s = open(&file)?;
            for i in &id {
                s.open_item(*i, keys)
                    .map_err(|e| format!("élément #{i} : {e}"))?;
            }
            let groups: Vec<mf_report::IocGroup> = s
                .iocs(Some(&id))
                .into_iter()
                .map(|(source, iocs)| mf_report::IocGroup { source, iocs })
                .collect();
            match format.as_str() {
                "csv" => print!("{}", mf_report::iocs_csv(&groups, defang)),
                "json" => println!("{}", mf_report::iocs_json(&groups, defang)),
                other => return Err(format!("--format {other} : csv ou json attendu")),
            }
            eprintln!("éléments lus : {}", s.items_read());
        }
        PstCmd::Bench { file } => {
            let t = std::time::Instant::now();
            let mut s = open(&file)?;
            let open_ms = t.elapsed().as_secs_f64() * 1e3;
            let (pages_open, bytes_open) = s.read_stats();
            let biggest = s
                .folders()
                .iter()
                .filter(|f| f.kind != "search")
                .max_by_key(|f| f.item_count)
                .map(|f| f.id);
            let t = std::time::Instant::now();
            let rows = match biggest {
                Some(f) => s.list(f).map_err(|e| e.to_string())?,
                None => Vec::new(),
            };
            let list_ms = t.elapsed().as_secs_f64() * 1e3;
            let t = std::time::Instant::now();
            let all: usize = pick_folders(&s, &None)?
                .into_iter()
                .map(|f| s.list(f).map(|r| r.len()).unwrap_or(0))
                .sum();
            let all_ms = t.elapsed().as_secs_f64() * 1e3;
            let t = std::time::Instant::now();
            if let Some(r) = rows.first() {
                s.open_item(r.id, keys).map_err(|e| e.to_string())?;
            }
            let item_ms = t.elapsed().as_secs_f64() * 1e3;
            // Filtre de toute la boîte (SC-005) : à froid (tables à lire) puis tables en mémoire.
            let probe = mf_core::BoxFilter {
                from_name: Some("a".into()),
                has_attachments: Some(true),
                ..Default::default()
            };
            let mut cold = open(&file)?;
            let t = std::time::Instant::now();
            let matched = cold.filter(&probe).map_err(|e| e.to_string())?.len();
            let filter_cold_ms = t.elapsed().as_secs_f64() * 1e3;
            let t = std::time::Instant::now();
            cold.filter(&probe).map_err(|e| e.to_string())?;
            let filter_warm_ms = t.elapsed().as_secs_f64() * 1e3;
            let filter_read = cold.items_read();
            let (pages, bytes) = s.read_stats();
            let t = std::time::Instant::now();
            s.hash_all().map_err(|e| e.to_string())?;
            let hash_ms = t.elapsed().as_secs_f64() * 1e3;
            let r = serde_json::json!({
                "file": s.info().name, "size": s.info().size, "folders": s.folders().len(), "items": all,
                "open_ms": open_ms, "open_bytes_read": bytes_open, "open_page_reads": pages_open,
                "list_largest_folder_ms": list_ms, "list_largest_folder_items": rows.len(),
                "list_whole_box_ms": all_ms, "open_one_item_ms": item_ms,
                "filter_whole_box_cold_ms": filter_cold_ms, "filter_whole_box_warm_ms": filter_warm_ms,
                "filter_matched": matched, "filter_items_read": filter_read,
                "page_reads": pages, "bytes_read": bytes, "items_read": s.items_read(), "hash_ms": hash_ms,
            });
            if json {
                return print(&r);
            }
            println!(
                "{} ({}) : ouverture {open_ms:.1} ms ({:.1} Mo lus) · plus gros dossier {} éléments en {list_ms:.1} ms · toute la boîte {all} lignes en {all_ms:.1} ms · un élément ouvert en {item_ms:.1} ms · {} lu(s) · empreinte {hash_ms:.0} ms",
                s.info().name,
                human(s.info().size),
                bytes_open as f64 / 1e6,
                rows.len(),
                s.items_read()
            );
            println!(
                "filtre de toute la boîte : {matched} résultat(s), {filter_cold_ms:.1} ms à froid, {filter_warm_ms:.1} ms ensuite, {filter_read} élément lu (SC-005 : < 1 000 ms, 0 lu)"
            );
        }
    }
    Ok(())
}

/// Petit adaptateur pour sérialiser des valeurs hétérogènes.
mod erased {
    pub trait Json {
        fn to_json(&self) -> serde_json::Result<String>;
    }
    impl<T: serde::Serialize + ?Sized> Json for T {
        fn to_json(&self) -> serde_json::Result<String> {
            serde_json::to_string_pretty(self)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mf: {e}");
            ExitCode::from(2)
        }
    }
}
