//! Rapport d'analyse (FR-026, FR-044) et export des indicateurs (FR-023).
//!
//! Même code pour la CLI, l'application de bureau et la version web (WebAssembly). Le rapport
//! est déterministe : pour une même preuve, seul `generated_utc` change (SC-005).
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]

use mf_core::{
    Address, BlockedKind, Evidence, Finding, Ioc, IocKind, Message, Severity, SourceRef,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write;

pub const TOOL: &str = "MailForensics";

#[derive(Serialize)]
struct Counts {
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

fn counts(f: &[Finding]) -> Counts {
    let n = |s: Severity| f.iter().filter(|x| x.severity == s).count();
    Counts {
        high: n(Severity::High),
        medium: n(Severity::Medium),
        low: n(Severity::Low),
        info: n(Severity::Info),
    }
}

/// Copie du message sans les corps (contenu potentiellement malveillant, souvent volumineux).
fn without_bodies(m: &Message) -> Message {
    let mut c = m.clone();
    c.body_text = None;
    c.body_html = None;
    c.body_html_safe = None;
    for a in &mut c.attachments {
        if let Some(inner) = a.embedded.as_deref() {
            a.embedded = Some(Box::new(without_bodies(inner)));
        }
    }
    c
}

/// Rapport JSON (schéma 1).
pub fn report_json(
    evidence: &Evidence,
    msg: &Message,
    provenance: &str,
    generated_utc: &str,
    version: &str,
) -> String {
    #[derive(Serialize)]
    struct Tool<'a> {
        name: &'a str,
        version: &'a str,
    }
    #[derive(Serialize)]
    struct Report<'a> {
        schema_version: u32,
        tool: Tool<'a>,
        generated_utc: &'a str,
        evidence: &'a Evidence,
        provenance: &'a str,
        findings_summary: Counts,
        verdict: Option<&'a mf_core::Verdict>,
        message: Message,
    }
    let r = Report {
        schema_version: 1,
        tool: Tool {
            name: TOOL,
            version,
        },
        generated_utc,
        evidence,
        provenance,
        findings_summary: counts(&msg.findings),
        verdict: msg.verdict.as_ref(),
        message: without_bodies(msg),
    };
    serde_json::to_string_pretty(&r).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Classe CSS et libellé d'un niveau de verdict.
pub fn verdict_label(level: mf_core::VerdictLevel) -> (&'static str, &'static str) {
    match level {
        mf_core::VerdictLevel::Malicious => ("malicious", "MALVEILLANT"),
        mf_core::VerdictLevel::Suspicious => ("suspicious", "À VÉRIFIER"),
        mf_core::VerdictLevel::Legitimate => ("legitimate", "LÉGITIME"),
    }
}

/// Les raisons reprennent des titres de constats ; aucun domaine n'y reste cliquable.
fn defang_text(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            if w.contains('.') && w.chars().any(|c| c.is_ascii_alphabetic()) && !w.ends_with('.') {
                w.replace('.', "[.]")
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {
                let _ = write!(o, "\\u{{{:04X}}}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

fn addr(a: &Address) -> String {
    match (&a.display_name, &a.address) {
        (Some(n), Some(e)) if n != e => format!("{n} <{e}>"),
        (_, Some(e)) => e.clone(),
        (Some(n), None) => n.clone(),
        _ => a.x500_dn.clone().unwrap_or_default(),
    }
}

fn addrs(v: &[Address]) -> String {
    v.iter().map(addr).collect::<Vec<_>>().join(", ")
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::High => "Élevée",
        Severity::Medium => "Moyenne",
        Severity::Low => "Faible",
        Severity::Info => "Info",
    }
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn ref_label(r: &SourceRef) -> String {
    match r {
        SourceRef::Header { index, name } => format!("en-tête {name} (n° {})", index + 1),
        SourceRef::Attachment { index, filename } => format!("PJ {index} {filename}"),
        SourceRef::Url { url } => format!("URL {}", mf_analysis::urls::defang(url)),
        SourceRef::Hop { index } => format!("saut {index}"),
    }
}

fn kind_label(k: IocKind) -> &'static str {
    match k {
        IocKind::Ipv4 => "IPv4",
        IocKind::Ipv6 => "IPv6",
        IocKind::Domain => "Domaine",
        IocKind::Url => "URL",
        IocKind::Email => "Adresse",
        IocKind::Sha256 => "SHA-256",
        IocKind::Md5 => "MD5",
    }
}

fn blocked_label(k: BlockedKind) -> &'static str {
    match k {
        BlockedKind::Image => "Image",
        BlockedKind::Background => "Image de fond",
        BlockedKind::Stylesheet => "Feuille de style",
        BlockedKind::Script => "Script",
        BlockedKind::Frame => "Cadre",
        BlockedKind::Media => "Média",
        BlockedKind::Object => "Objet",
        BlockedKind::Other => "Autre",
    }
}

const CSS: &str = "
:root{--ink:#1c2733;--soft:#5a6878;--rule:#d5dbe2;--seal:#f2c230;--data:#1f6f78}
*{box-sizing:border-box}body{font:14px/1.45 system-ui,-apple-system,'Segoe UI',sans-serif;color:var(--ink);margin:0;padding:32px;max-width:1100px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid var(--ink)}
h3{font-size:14px;margin:16px 0 6px}.meta{color:var(--soft);margin:0 0 16px}
.seal{background:var(--seal);border-radius:4px 14px 14px 4px;padding:10px 16px;margin:12px 0 0}
table{border-collapse:collapse;width:100%;margin:4px 0 8px}th,td{border-bottom:1px solid var(--rule);padding:5px 8px;text-align:left;vertical-align:top}
th{font-size:12px;color:var(--soft);font-weight:700}code,.mono{font-family:ui-monospace,'JetBrains Mono',Consolas,monospace;font-size:12px;overflow-wrap:anywhere}
.sev{display:inline-block;border-radius:4px;padding:0 6px;font-weight:700;font-size:12px}
.high{background:#b3261e;color:#fff}.medium{background:#e8a317;color:#2a1a00}.low{background:#dde8f0}.info{background:#eef1f4;color:var(--soft)}
.ok{color:#17733a;font-weight:700}.ko{color:#b3261e;font-weight:700}.summary{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.verdict{border:2px solid;border-radius:8px;padding:10px 14px;margin:12px 0}.verdict p,.verdict ul{margin:4px 0}.verdict-level{font-size:20px;font-weight:800}.verdict.malicious{border-color:#b3261e;background:#fbeaea}.verdict.malicious .verdict-level{color:#b3261e}.verdict.suspicious{border-color:#b8860b;background:#fdf6e3}.verdict.suspicious .verdict-level{color:#8a6100}.verdict.legitimate{border-color:#17733a;background:#e9f6ee}.verdict.legitimate .verdict-level{color:#17733a}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:11.5px/1.4 ui-monospace,Consolas,monospace;background:#f6f8fa;padding:8px;border:1px solid var(--rule)}
.note{color:var(--soft);font-size:12px}footer{margin-top:32px;color:var(--soft);font-size:12px;border-top:1px solid var(--rule);padding-top:8px}
@media print{body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}.no-print{display:none}}
";

/// Rapport HTML autonome (aucune ressource externe, aucun script), imprimable en PDF.
pub fn report_html(
    evidence: &Evidence,
    msg: &Message,
    provenance: &str,
    generated_utc: &str,
    version: &str,
) -> String {
    let mut h = String::new();
    let subject = msg.subject.as_deref().unwrap_or("(sans objet)");
    let file = evidence
        .path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&evidence.path);
    let _ = write!(
        h,
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <title>Rapport — {}</title><style>{CSS}</style></head><body>",
        esc(subject)
    );
    let _ = write!(
        h,
        "<h1>Rapport d'analyse de courriel</h1><p class=\"meta\">{} {} — généré le {} UTC</p>",
        TOOL,
        esc(version),
        esc(generated_utc)
    );

    // Verdict de synthèse (FR-045)
    if let Some(v) = &msg.verdict {
        let (class, label) = verdict_label(v.level);
        let _ = write!(
            h,
            "<div class=\"verdict {class}\"><div class=\"verdict-level\">Verdict : {label}</div><p>{}</p>",
            esc(&v.summary)
        );
        if !v.reasons.is_empty() {
            h.push_str("<ul>");
            for r in &v.reasons {
                let _ = write!(h, "<li>{}</li>", esc(&defang_text(r)));
            }
            h.push_str("</ul>");
        }
        let _ = write!(
            h,
            "<p class=\"meta\">Score {} — évaluation automatique fondée sur le seul contenu du fichier, à confirmer par l'analyste.</p></div>",
            v.score
        );
    }

    // Identification de la preuve
    h.push_str("<h2>Preuve</h2><table>");
    let row = |h: &mut String, k: &str, v: &str| {
        let _ = write!(h, "<tr><th>{}</th><td>{}</td></tr>", esc(k), v);
    };
    row(&mut h, "Fichier", &esc(file));
    row(
        &mut h,
        "Chemin",
        &format!("<code>{}</code>", esc(&evidence.path)),
    );
    if !provenance.is_empty() {
        row(&mut h, "Message analysé", &esc(provenance));
    }
    row(
        &mut h,
        "Format / taille",
        &format!("{:?} — {} octets", evidence.format, evidence.size),
    );
    row(
        &mut h,
        "SHA-256",
        &format!("<code>{}</code>", esc(&evidence.sha256)),
    );
    row(
        &mut h,
        "MD5",
        &format!("<code>{}</code>", esc(&evidence.md5)),
    );
    h.push_str("</table>");

    // Message
    h.push_str("<h2>Message</h2><table>");
    row(&mut h, "Objet", &esc(subject));
    row(&mut h, "De", &esc(&addrs(&msg.from)));
    if let Some(s) = &msg.sender {
        row(&mut h, "Envoyé par", &esc(&addr(s)));
    }
    if !msg.reply_to.is_empty() {
        row(&mut h, "Répondre à", &esc(&addrs(&msg.reply_to)));
    }
    row(&mut h, "À", &esc(&addrs(&msg.to)));
    if !msg.cc.is_empty() {
        row(&mut h, "Cc", &esc(&addrs(&msg.cc)));
    }
    row(
        &mut h,
        "Date",
        &format!(
            "{} <span class=\"note\">(UTC {})</span>",
            esc(msg.date_raw.as_deref().unwrap_or("—")),
            esc(msg.date_utc.as_deref().unwrap_or("—"))
        ),
    );
    row(
        &mut h,
        "Message-ID",
        &format!(
            "<code>{}</code>",
            esc(msg.message_id.as_deref().unwrap_or("—"))
        ),
    );
    h.push_str("</table>");

    // Constats
    let c = counts(&msg.findings);
    let _ = write!(
        h,
        "<h2>Constats</h2><div class=\"summary\"><span class=\"sev high\">{} élevée(s)</span><span class=\"sev medium\">{} moyenne(s)</span><span class=\"sev low\">{} faible(s)</span><span class=\"sev info\">{} info</span></div>",
        c.high, c.medium, c.low, c.info
    );
    if msg.findings.is_empty() {
        h.push_str("<p>Aucun constat automatique.</p>");
    } else {
        h.push_str(
            "<table><tr><th>Gravité</th><th>Constat</th><th>Détail</th><th>Source</th></tr>",
        );
        for f in &msg.findings {
            let _ = write!(
                h,
                "<tr><td><span class=\"sev {}\">{}</span></td><td><b>{}</b><br><span class=\"note mono\">{}</span></td><td>{}</td><td class=\"note\">{}</td></tr>",
                sev_class(f.severity),
                sev_label(f.severity),
                esc(&f.title),
                esc(&f.rule),
                esc(&f.detail),
                esc(&f.refs.iter().map(ref_label).collect::<Vec<_>>().join(" ; "))
            );
        }
        h.push_str("</table>");
    }

    // Authentification
    h.push_str("<h2>Authentification</h2>");
    if msg.auth.is_empty() {
        h.push_str("<p>Aucun en-tête Authentication-Results ou Received-SPF.</p>");
    } else {
        h.push_str("<table><tr><th>Méthode</th><th>Résultat</th><th>Serveur</th><th>Détails</th><th>En-tête</th></tr>");
        for a in &msg.auth {
            let cls = if a.result == "pass" {
                "ok"
            } else if matches!(a.result.as_str(), "fail" | "softfail" | "permerror") {
                "ko"
            } else {
                ""
            };
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"{cls}\">{}</td><td>{}{}</td><td class=\"mono\">{}</td><td class=\"note\">{} n° {}</td></tr>",
                esc(&a.method.to_uppercase()),
                esc(&a.result),
                esc(a.authserv_id.as_deref().unwrap_or("—")),
                if a.most_recent {
                    " <span class=\"note\">(réception finale)</span>"
                } else {
                    ""
                },
                esc(&a
                    .properties
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")),
                esc(&a.header_name),
                a.header_index + 1
            );
        }
        h.push_str("</table>");
    }
    for d in &msg.dkim {
        let state = match d.body_hash_ok {
            Some(true) => "<span class=\"ok\">corps intact depuis la signature</span>",
            Some(false) => "<span class=\"ko\">corps modifié depuis la signature</span>",
            None => "non vérifiable",
        };
        let _ = write!(
            h,
            "<h3>DKIM d={} s={}</h3><p>{state}. Algorithme {}, canonicalisation {}. Empreinte déclarée <code>{}</code>, recalculée <code>{}</code>. {}</p>",
            esc(d.domain.as_deref().unwrap_or("?")),
            esc(d.selector.as_deref().unwrap_or("?")),
            esc(d.algorithm.as_deref().unwrap_or("?")),
            esc(d.canonicalization.as_deref().unwrap_or("?")),
            esc(d.body_hash_declared.as_deref().unwrap_or("—")),
            esc(d.body_hash_computed.as_deref().unwrap_or("—")),
            esc(d.note.as_deref().unwrap_or(""))
        );
    }
    h.push_str("<p class=\"note\">La signature DKIM elle-même (b=) n'est pas vérifiée : il faudrait interroger le DNS du domaine signataire.</p>");

    // Acheminement
    h.push_str("<h2>Acheminement</h2>");
    if let Some(r) = &msg.route {
        h.push_str("<table>");
        let ep = |e: &mf_core::Endpoint| {
            format!(
                "<code>{}</code> {} {}",
                esc(e.ip.as_deref().unwrap_or("—")),
                e.rdns
                    .as_deref()
                    .map(|d| format!("DNS inverse <code>{}</code>", esc(d)))
                    .unwrap_or_default(),
                e.name
                    .as_deref()
                    .map(|d| format!("nom annoncé <code>{}</code>", esc(d)))
                    .unwrap_or_default()
            )
        };
        if let Some(e) = &r.origin {
            row(&mut h, "Envoi", &ep(e));
        }
        if let Some(e) = &r.originating_ip_header {
            row(&mut h, &format!("IP du client ({})", e.source), &ep(e));
        }
        if let Some(e) = &r.first_public {
            row(&mut h, "Première IP publique", &ep(e));
        }
        if let Some(e) = &r.last_public {
            row(&mut h, "Remis au destinataire par", &ep(e));
        }
        if let Some(e) = &r.receiver {
            row(
                &mut h,
                "Réception",
                &format!(
                    "{} {} — {}",
                    esc(e.name.as_deref().unwrap_or("—")),
                    esc(e.ip.as_deref().unwrap_or("")),
                    esc(r.received_utc.as_deref().unwrap_or(""))
                ),
            );
        }
        h.push_str("</table>");
    }
    if msg.hops.is_empty() {
        h.push_str("<p>Aucun en-tête Received.</p>");
    } else {
        h.push_str("<table><tr><th>#</th><th>De</th><th>IP</th><th>Par</th><th>Protocole</th><th>Horodatage (UTC)</th><th>Délai</th></tr>");
        for x in &msg.hops {
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                x.index,
                esc(x
                    .from_rdns
                    .as_deref()
                    .or(x.from_name.as_deref())
                    .unwrap_or("—")),
                esc(x.from_ip.as_deref().unwrap_or("—")),
                esc(x.by_name.as_deref().unwrap_or("—")),
                esc(x.with.as_deref().unwrap_or("")),
                esc(x.date_utc.as_deref().unwrap_or("—")),
                x.delay_seconds
                    .map(|d| format!("{d:+} s"))
                    .unwrap_or_default()
            );
        }
        h.push_str("</table><p class=\"note\">Noms DNS tels qu'enregistrés dans les en-têtes au moment du transit ; aucune requête DNS n'a été effectuée.</p>");
    }

    // Pièces jointes
    let _ = write!(h, "<h2>Pièces jointes ({})</h2>", msg.attachments.len());
    if !msg.attachments.is_empty() {
        h.push_str("<table><tr><th>#</th><th>Nom</th><th>Type déclaré / réel</th><th>Taille</th><th>Empreintes</th><th>Alertes</th></tr>");
        for a in &msg.attachments {
            let flags = a
                .flags
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}{}</td><td>{}<br><b>{}</b></td><td>{}</td><td class=\"mono\">SHA-256 {}<br>MD5 {}</td><td>{}</td></tr>",
                a.index,
                esc(&a.filename),
                a.embedded
                    .as_deref()
                    .map(|m| format!(
                        "<br><span class=\"note\">message joint : « {} »</span>",
                        esc(m.subject.as_deref().unwrap_or(""))
                    ))
                    .unwrap_or_default(),
                esc(a.declared_mime.as_deref().unwrap_or("—")),
                esc(a.detected_type.as_deref().unwrap_or("—")),
                a.size,
                esc(&a.sha256),
                esc(&a.md5),
                esc(&flags)
            );
        }
        h.push_str("</table>");
    }

    // URL
    let _ = write!(h, "<h2>URL ({})</h2>", msg.urls.len());
    if !msg.urls.is_empty() {
        h.push_str("<table><tr><th>URL (défangée)</th><th>Texte affiché</th><th>Alertes</th><th>Emplacement</th></tr>");
        for u in &msg.urls {
            let flags = u
                .flags
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                h,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}{}</td><td class=\"note\">{}</td></tr>",
                esc(&u.defanged),
                esc(&u.display_texts.join(" / ")),
                esc(&flags),
                u.lookalike_of
                    .as_deref()
                    .map(|b| format!(" (imite {})", esc(b)))
                    .unwrap_or_default(),
                esc(&u
                    .locations
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "))
            );
        }
        h.push_str("</table>");
    }
    if !msg.blocked_resources.is_empty() {
        let _ = write!(
            h,
            "<h3>Ressources distantes bloquées ({})</h3><table><tr><th>#</th><th>Type</th><th>Élément</th><th>Ligne</th><th>URL (défangée)</th></tr>",
            msg.blocked_resources.len()
        );
        for b in &msg.blocked_resources {
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td class=\"mono\">&lt;{} {}&gt;</td><td>{}</td><td class=\"mono\">{}</td></tr>",
                b.number,
                blocked_label(b.kind),
                esc(&b.element),
                esc(&b.attribute),
                b.line.map(|l| l.to_string()).unwrap_or_default(),
                esc(&mf_analysis::urls::defang(&b.url))
            );
        }
        h.push_str("</table>");
    }

    // Indicateurs
    let _ = write!(h, "<h2>Indicateurs ({})</h2>", msg.iocs.len());
    if !msg.iocs.is_empty() {
        h.push_str("<table><tr><th>Type</th><th>Valeur (défangée)</th><th>Trouvé dans</th></tr>");
        for i in &msg.iocs {
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"note\">{}</td></tr>",
                kind_label(i.kind),
                esc(&i.defanged),
                esc(&i.locations.join(" ; "))
            );
        }
        h.push_str("</table>");
    }

    // Annexe : en-têtes bruts
    let _ = write!(
        h,
        "<h2>Annexe — en-têtes bruts ({})</h2><pre>",
        msg.headers.len()
    );
    for hd in &msg.headers {
        h.push_str(&esc(&hd.raw));
        h.push('\n');
    }
    h.push_str("</pre>");
    if !msg.issues.is_empty() {
        h.push_str("<h3>Avertissements d'analyse</h3><ul>");
        for i in &msg.issues {
            let _ = write!(h, "<li>{}</li>", esc(i));
        }
        h.push_str("</ul>");
    }
    let _ = write!(
        h,
        "<footer>Analyse effectuée localement, en lecture seule ; aucune ressource du message n'a été chargée. Empreinte de la preuve : SHA-256 <code>{}</code>.</footer></body></html>",
        esc(&evidence.sha256)
    );
    h
}

/// Indicateurs de plusieurs messages, à fusionner.
#[derive(Deserialize, Serialize)]
pub struct IocGroup {
    /// Fichier (et provenance) d'où viennent ces indicateurs.
    pub source: String,
    pub iocs: Vec<Ioc>,
}

#[derive(Serialize)]
struct MergedIoc {
    kind: IocKind,
    value: String,
    defanged: String,
    sources: Vec<String>,
    locations: Vec<String>,
}

fn merge(groups: &[IocGroup]) -> Vec<MergedIoc> {
    let mut out: Vec<MergedIoc> = Vec::new();
    for g in groups {
        for i in &g.iocs {
            match out
                .iter_mut()
                .find(|m| m.kind == i.kind && m.value == i.value)
            {
                Some(m) => {
                    if !m.sources.contains(&g.source) {
                        m.sources.push(g.source.clone());
                    }
                    for l in &i.locations {
                        if !m.locations.contains(l) {
                            m.locations.push(l.clone());
                        }
                    }
                }
                None => out.push(MergedIoc {
                    kind: i.kind,
                    value: i.value.clone(),
                    defanged: i.defanged.clone(),
                    sources: vec![g.source.clone()],
                    locations: i.locations.clone(),
                }),
            }
        }
    }
    out.sort_by_key(|x| x.kind);
    out
}

fn csv_field(s: &str) -> String {
    // Protection contre l'injection de formules à l'ouverture dans un tableur.
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Export CSV (séparateur virgule, UTF-8 avec BOM pour Excel).
pub fn iocs_csv(groups: &[IocGroup], defang: bool) -> String {
    let mut s = String::from("\u{FEFF}type,valeur,sources,emplacements\r\n");
    for m in merge(groups) {
        let _ = write!(
            s,
            "{},{},{},{}\r\n",
            csv_field(kind_label(m.kind)),
            csv_field(if defang { &m.defanged } else { &m.value }),
            csv_field(&m.sources.join(" | ")),
            csv_field(&m.locations.join(" | "))
        );
    }
    s
}

/// Export JSON (fusionné, dédoublonné).
pub fn iocs_json(groups: &[IocGroup], defang: bool) -> String {
    let mut merged = merge(groups);
    if defang {
        for m in &mut merged {
            m.value = m.defanged.clone();
        }
    }
    serde_json::to_string_pretty(&merged).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_and_csv_injection() {
        assert_eq!(
            esc("<script>\"x\"&'"),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;"
        );
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        let g = vec![
            IocGroup {
                source: "a.eml".into(),
                iocs: vec![Ioc {
                    kind: IocKind::Domain,
                    value: "evil.example".into(),
                    defanged: "evil[.]example".into(),
                    locations: vec!["From".into()],
                }],
            },
            IocGroup {
                source: "b.eml".into(),
                iocs: vec![Ioc {
                    kind: IocKind::Domain,
                    value: "evil.example".into(),
                    defanged: "evil[.]example".into(),
                    locations: vec!["URL".into()],
                }],
            },
        ];
        let csv = iocs_csv(&g, true);
        assert!(
            csv.contains("\"Domaine\",\"evil[.]example\",\"a.eml | b.eml\",\"From | URL\""),
            "{csv}"
        );
        assert_eq!(csv.lines().count(), 2, "dédoublonné");
    }
}
