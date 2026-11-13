//! Constats automatiques (FR-015, FR-017, FR-022, FR-043). Chaque constat cite l'élément de la
//! preuve sur lequel il repose (Constitution II) ; les identifiants de règle sont stables.

use crate::auth::verdict;
use crate::links::{BRANDS, lookalike, registrable};
use mf_core::{AttachmentFlag, Finding, Message, Severity, SourceRef, UrlFlag};

fn header_ref(msg: &Message, name: &str) -> Vec<SourceRef> {
    msg.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| {
            vec![SourceRef::Header {
                index: h.index,
                name: h.name.clone(),
            }]
        })
        .unwrap_or_default()
}

fn domain_of(addr: &str) -> Option<String> {
    let a = addr.trim().trim_matches(['<', '>']);
    let a = a
        .rsplit_once('<')
        .map_or(a, |(_, r)| r.trim_end_matches('>'));
    a.rsplit_once('@')
        .map(|(_, d)| d.trim().trim_end_matches('>').to_ascii_lowercase())
}

struct Out(Vec<Finding>);

impl Out {
    fn push(
        &mut self,
        rule: &str,
        severity: Severity,
        title: String,
        detail: String,
        refs: Vec<SourceRef>,
    ) {
        self.0.push(Finding {
            rule: rule.into(),
            severity,
            title,
            detail,
            refs,
        });
    }
}

fn authentication(msg: &Message, out: &mut Out) {
    if msg.auth.is_empty() {
        if !msg.hops.is_empty() {
            out.push(
                "auth_results_missing",
                Severity::Info,
                "Aucun résultat SPF / DKIM / DMARC".into(),
                "Le serveur de réception n'a inscrit aucun en-tête Authentication-Results : l'authenticité de l'expéditeur n'a pas été évaluée ou le verdict n'a pas été conservé.".into(),
                Vec::new(),
            );
        }
        return;
    }
    for (method, label) in [("dmarc", "DMARC"), ("spf", "SPF"), ("dkim", "DKIM")] {
        let Some(r) = verdict(&msg.auth, method) else {
            out.push(
                &format!("auth_{method}_absent"),
                Severity::Low,
                format!("{label} non évalué"),
                format!("Aucun résultat {label} dans les en-têtes d'authentification."),
                Vec::new(),
            );
            continue;
        };
        let refs = vec![SourceRef::Header {
            index: r.header_index,
            name: r.header_name.clone(),
        }];
        let server = r
            .authserv_id
            .as_deref()
            .map(|s| format!(" (verdict de {s})"))
            .unwrap_or_default();
        let (severity, what) = match r.result.as_str() {
            "pass" | "bestguesspass" => continue,
            "fail" | "permerror" => (Severity::High, "en échec"),
            "softfail" => (Severity::Medium, "en échec partiel (softfail)"),
            "none" => (Severity::Low, "absent (aucune politique publiée)"),
            "neutral" | "policy" => (Severity::Low, "neutre"),
            "temperror" => (Severity::Low, "erreur temporaire"),
            _ => (Severity::Low, "résultat inhabituel"),
        };
        out.push(
            &format!("auth_{method}_{}", r.result),
            severity,
            format!("{label} {what}"),
            format!("Résultat {label} = « {} »{server}.", r.result),
            refs,
        );
    }
    for d in &msg.dkim {
        let refs = vec![SourceRef::Header {
            index: d.header_index,
            name: "DKIM-Signature".into(),
        }];
        let dom = d.domain.as_deref().unwrap_or("?");
        if d.body_hash_ok == Some(false) {
            out.push(
                "dkim_body_hash_mismatch",
                Severity::High,
                format!("Corps modifié depuis la signature DKIM de {dom}"),
                format!(
                    "Empreinte déclarée {} ≠ recalculée {}. Le contenu a été altéré après la signature (ou par un relais).",
                    d.body_hash_declared.as_deref().unwrap_or("?"),
                    d.body_hash_computed.as_deref().unwrap_or("?")
                ),
                refs.clone(),
            );
        }
        if let Some(l) = d.body_length_limit {
            out.push(
                "dkim_body_length_limit",
                Severity::Low,
                format!("Signature DKIM partielle (l={l})"),
                "Seuls les premiers octets du corps sont signés : du contenu a pu être ajouté après sans invalider la signature.".into(),
                refs,
            );
        }
    }
    let from_dom = msg
        .from
        .first()
        .and_then(|a| a.address.as_deref())
        .and_then(domain_of);
    if let Some(fd) = from_dom {
        let aligned = msg.dkim.iter().any(|d| {
            d.domain
                .as_deref()
                .is_some_and(|x| registrable(&x.to_ascii_lowercase()) == registrable(&fd))
        });
        if !msg.dkim.is_empty() && !aligned {
            let doms: Vec<&str> = msg
                .dkim
                .iter()
                .filter_map(|d| d.domain.as_deref())
                .collect();
            out.push(
                "dkim_not_aligned",
                Severity::Low,
                "Signature DKIM d'un autre domaine que l'expéditeur".into(),
                format!("Signé par {} alors que l'expéditeur est {fd} (courant pour les plateformes d'envoi, suspect sinon).", doms.join(", ")),
                msg.dkim.iter().map(|d| SourceRef::Header { index: d.header_index, name: "DKIM-Signature".into() }).collect(),
            );
        }
    }
}

fn sender(msg: &Message, out: &mut Out) {
    let Some(from) = msg.from.first() else {
        out.push(
            "from_missing",
            Severity::Medium,
            "Expéditeur (From) absent".into(),
            "Le message n'indique pas d'expéditeur.".into(),
            Vec::new(),
        );
        return;
    };
    let from_addr = from.address.clone().unwrap_or_default();
    let from_dom = domain_of(&from_addr);
    if let Some(fd) = &from_dom {
        if let Some(brand) = lookalike(fd) {
            out.push(
                "sender_lookalike_domain",
                Severity::High,
                format!("Domaine de l'expéditeur imitant « {brand} »"),
                format!("{fd} ressemble à {brand} par substitution de caractères ou en plaçant la marque dans un sous-domaine."),
                header_ref(msg, "From"),
            );
        }
        let cmp = |label: &str, rule: &str, sev: Severity, other: Option<String>, out: &mut Out| {
            if let Some(od) = other.as_deref().and_then(domain_of) {
                if registrable(&od) != registrable(fd) {
                    out.push(
                        rule,
                        sev,
                        format!("{label} d'un autre domaine que l'expéditeur"),
                        format!("From : {fd} — {label} : {}", other.unwrap_or_default()),
                        [header_ref(msg, "From"), header_ref(msg, label)].concat(),
                    );
                }
            }
        };
        cmp(
            "Reply-To",
            "reply_to_domain_mismatch",
            Severity::Medium,
            msg.reply_to.first().and_then(|a| a.address.clone()),
            out,
        );
        let rp = msg
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Return-Path"))
            .map(|h| h.value.trim().to_string());
        if rp.as_deref().is_some_and(|v| v != "<>") {
            cmp(
                "Return-Path",
                "return_path_domain_mismatch",
                Severity::Low,
                rp,
                out,
            );
        }
        if let Some(mid) = &msg.message_id {
            if let Some(md) = domain_of(mid) {
                if registrable(&md) != registrable(fd) && !md.ends_with("prod.outlook.com") {
                    out.push(
                        "message_id_foreign_domain",
                        Severity::Info,
                        "Message-ID d'un autre domaine".into(),
                        format!("Message-ID créé par {md}, expéditeur {fd} (normal via une plateforme d'envoi)."),
                        header_ref(msg, "Message-ID"),
                    );
                }
            }
        }
    }
    if let (Some(s), Some(fd)) = (&msg.sender, &from_dom) {
        if let Some(sd) = s.address.as_deref().and_then(domain_of) {
            if registrable(&sd) != registrable(fd) {
                out.push(
                    "sender_from_mismatch",
                    Severity::Low,
                    "Envoyé par un autre compte que l'expéditeur affiché".into(),
                    format!(
                        "From : {} — Sender : {}",
                        from_addr,
                        s.address.clone().unwrap_or_default()
                    ),
                    [header_ref(msg, "From"), header_ref(msg, "Sender")].concat(),
                );
            }
        }
    }
    if let Some(name) = &from.display_name {
        let lname = name.to_ascii_lowercase();
        // Nom affiché contenant une autre adresse : « service@banque.fr <x@autre.example> ».
        if let Some(shown) = lname
            .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | '\''))
            .find(|t| t.contains('@') && t.contains('.'))
        {
            if shown != from_addr.to_ascii_lowercase() {
                out.push(
                    "display_name_contains_address",
                    Severity::Medium,
                    "Le nom affiché contient une autre adresse".into(),
                    format!("Nom affiché « {name} », adresse réelle {from_addr}."),
                    header_ref(msg, "From"),
                );
            }
        }
        let compact: String = lname.chars().filter(|c| c.is_alphanumeric()).collect();
        if let Some(fd) = &from_dom {
            let fdc: String = fd.chars().filter(|c| c.is_alphanumeric()).collect();
            if let Some(brand) = BRANDS
                .iter()
                .find(|b| b.len() > 4 && compact.contains(*b) && !fdc.contains(*b))
            {
                out.push(
                    "display_name_brand",
                    Severity::Medium,
                    format!("Nom affiché « {name} » sans rapport avec le domaine"),
                    format!("Le nom évoque {brand} mais l'adresse est {from_addr}."),
                    header_ref(msg, "From"),
                );
            }
        }
    }
}

fn chronology(msg: &Message, out: &mut Out) {
    if msg.date_raw.is_none() && !msg.hops.is_empty() {
        out.push(
            "date_missing",
            Severity::Low,
            "En-tête Date absent".into(),
            "Le message ne porte pas de date d'envoi.".into(),
            Vec::new(),
        );
    }
    let parse = |s: &str| chrono::DateTime::parse_from_rfc3339(s).ok();
    if let (Some(date), Some(last)) = (
        msg.date_utc.as_deref().and_then(parse),
        msg.hops
            .last()
            .and_then(|h| h.date_utc.as_deref())
            .and_then(parse),
    ) {
        let ahead = (date - last).num_seconds();
        if ahead > 3600 {
            out.push(
                "date_in_future",
                Severity::Medium,
                "Date d'envoi postérieure à la réception".into(),
                format!("La date du message est {} h après la dernière réception : horloge faussée ou date forgée.", ahead / 3600),
                header_ref(msg, "Date"),
            );
        }
    }
    for h in &msg.hops {
        if let Some(d) = h.delay_seconds.filter(|d| *d < -60) {
            out.push(
                "hop_time_regression",
                Severity::Medium,
                format!("Horodatage incohérent au saut {}", h.index),
                format!("Ce relais date de {} s avant le précédent : horloge décalée ou en-tête Received falsifié.", -d),
                vec![SourceRef::Hop { index: h.index }, SourceRef::Header { index: h.header_index, name: "Received".into() }],
            );
        }
    }
}

fn links(msg: &Message, out: &mut Out) {
    let rules: [(UrlFlag, &str, Severity, &str, &str); 8] = [
        (
            UrlFlag::Lookalike,
            "url_lookalike_domain",
            Severity::High,
            "Lien vers un domaine imitant une marque",
            "imite",
        ),
        (
            UrlFlag::MixedScript,
            "url_mixed_script",
            Severity::High,
            "Lien vers un domaine mêlant plusieurs alphabets",
            "homoglyphes",
        ),
        (
            UrlFlag::Credentials,
            "url_credentials",
            Severity::High,
            "Lien qui masque sa vraie destination (user@hôte)",
            "masquage",
        ),
        (
            UrlFlag::TextTargetMismatch,
            "link_text_target_mismatch",
            Severity::Medium,
            "Texte du lien différent de sa destination",
            "texte",
        ),
        (
            UrlFlag::RawIp,
            "url_raw_ip",
            Severity::Medium,
            "Lien vers une adresse IP",
            "ip",
        ),
        (
            UrlFlag::Punycode,
            "url_punycode",
            Severity::Medium,
            "Lien vers un domaine internationalisé (punycode)",
            "idn",
        ),
        (
            UrlFlag::QrCode,
            "url_qr_code",
            Severity::Medium,
            "Lien caché dans un QR code",
            "qr",
        ),
        (
            UrlFlag::Redirector,
            "url_redirector_abuse",
            Severity::Medium,
            "Lien qui passe par un redirecteur détourné",
            "redirection",
        ),
    ];
    for (flag, rule, sev, title, _) in rules {
        let hits: Vec<_> = msg
            .urls
            .iter()
            .filter(|u| u.flags.contains(&flag))
            .collect();
        if hits.is_empty() {
            continue;
        }
        let detail = hits
            .iter()
            .map(|u| match flag {
                UrlFlag::TextTargetMismatch => {
                    format!("« {} » → {}", u.display_texts.join(" / "), u.url)
                }
                UrlFlag::Lookalike => format!(
                    "{} (imite {})",
                    u.host.as_deref().unwrap_or(&u.url),
                    u.lookalike_of.as_deref().unwrap_or("?")
                ),
                UrlFlag::Punycode | UrlFlag::MixedScript => format!(
                    "{} = {}",
                    u.host.as_deref().unwrap_or(""),
                    u.unicode_host
                        .as_deref()
                        .unwrap_or(u.host.as_deref().unwrap_or(""))
                ),
                UrlFlag::Redirector => format!(
                    "{} → {}",
                    u.redirect.as_ref().map_or("?", |r| r.service.as_str()),
                    crate::redirects::final_target(&msg.urls, &u.url)
                ),
                _ => u.url.clone(),
            })
            .fold(Vec::<String>::new(), |mut v, d| {
                if !v.contains(&d) {
                    v.push(d);
                }
                v
            })
            .join(" ; ");
        out.push(
            rule,
            sev,
            format!("{title} ({})", hits.len()),
            detail,
            hits.iter()
                .map(|u| SourceRef::Url { url: u.url.clone() })
                .collect(),
        );
    }
}

fn attachments(msg: &Message, out: &mut Out) {
    for a in &msg.attachments {
        let r = vec![SourceRef::Attachment {
            index: a.index,
            filename: a.filename.clone(),
        }];
        let det = a.detected_type.as_deref().unwrap_or("type inconnu");
        for f in &a.flags {
            let (rule, sev, title, detail) = match f {
                AttachmentFlag::Executable => (
                    "attachment_executable",
                    Severity::High,
                    "Pièce jointe exécutable",
                    format!("{} — contenu : {det}.", a.filename),
                ),
                AttachmentFlag::DoubleExtension => (
                    "attachment_double_extension",
                    Severity::High,
                    "Double extension",
                    format!("{} : une extension anodine masque la vraie.", a.filename),
                ),
                AttachmentFlag::TypeMismatch => (
                    "attachment_type_mismatch",
                    Severity::High,
                    "Extension trompeuse",
                    format!("{} est en réalité : {det}.", a.filename),
                ),
                AttachmentFlag::BidiOrControlChars => (
                    "attachment_bidi_name",
                    Severity::High,
                    "Nom de fichier maquillé",
                    format!(
                        "{:?} contient des caractères de contrôle ou d'inversion d'écriture.",
                        a.filename
                    ),
                ),
                AttachmentFlag::Macros => (
                    "attachment_macros",
                    Severity::High,
                    "Document Office avec macros",
                    format!("{} contient un projet VBA.", a.filename),
                ),
                AttachmentFlag::EncryptedArchive => (
                    "attachment_encrypted_archive",
                    Severity::Medium,
                    "Archive protégée par mot de passe",
                    format!(
                        "{} : contenu chiffré, invisible pour les antivirus.",
                        a.filename
                    ),
                ),
                AttachmentFlag::HtmlAttachment => (
                    "attachment_html",
                    Severity::Medium,
                    "Pièce jointe HTML",
                    format!(
                        "{} : page web locale (faux formulaire de connexion, contrebande HTML).",
                        a.filename
                    ),
                ),
                AttachmentFlag::RiskyExtension => (
                    "attachment_risky_extension",
                    Severity::Medium,
                    "Type de fichier à risque",
                    format!("{} ({det}).", a.filename),
                ),
                AttachmentFlag::Tnef => (
                    "attachment_tnef",
                    Severity::Info,
                    "Pièce jointe TNEF (winmail.dat)",
                    "Conteneur Outlook pouvant renfermer d'autres fichiers.".to_string(),
                ),
                AttachmentFlag::CredentialForm => (
                    "attachment_credential_form",
                    Severity::High,
                    "Faux formulaire de connexion",
                    html_detail(a, |r| {
                        let actions: Vec<String> = r
                            .forms
                            .iter()
                            .filter_map(|f| {
                                f.action
                                    .as_ref()
                                    .map(|x| format!("{} {x}", f.method.to_uppercase()))
                            })
                            .collect();
                        format!(
                            "{} champ(s) de mot de passe{}.",
                            r.password_fields,
                            if actions.is_empty() {
                                String::new()
                            } else {
                                format!(" ; envoi : {}", actions.join(", "))
                            }
                        )
                    }),
                ),
                AttachmentFlag::Exfiltration => (
                    "attachment_exfiltration",
                    Severity::High,
                    "Envoi des données vers un service tiers",
                    html_detail(a, |r| format!("{}.", r.exfiltration.join(", "))),
                ),
                AttachmentFlag::ObfuscatedScript => (
                    "attachment_obfuscated_script",
                    Severity::Medium,
                    "Script obfusqué",
                    html_detail(a, |r| {
                        format!(
                            "{}{}.",
                            r.obfuscation.join(", "),
                            if r.decoded_payloads > 0 {
                                format!(
                                    " ; {} charge(s) décodée(s) et analysée(s)",
                                    r.decoded_payloads
                                )
                            } else {
                                String::new()
                            }
                        )
                    }),
                ),
                AttachmentFlag::AutoRedirect => (
                    "attachment_auto_redirect",
                    Severity::Medium,
                    "Redirection automatique à l'ouverture",
                    html_detail(a, |r| r.redirects.join(" ; ")),
                ),
                AttachmentFlag::RecipientPrefill => (
                    "attachment_recipient_prefill",
                    Severity::Medium,
                    "Page personnalisée pour le destinataire",
                    html_detail(a, |r| {
                        format!(
                            "L'adresse {} est intégrée à la page (champ pré-rempli, ciblage).",
                            r.recipient_prefill.join(", ")
                        )
                    }),
                ),
                AttachmentFlag::QrCode => (
                    "attachment_qr_code",
                    Severity::Medium,
                    "Image contenant un QR code",
                    format!(
                        "{} : {}.",
                        a.filename,
                        a.qr_codes
                            .iter()
                            .map(|c| crate::urls::defang(c))
                            .collect::<Vec<_>>()
                            .join(" ; ")
                    ),
                ),
                AttachmentFlag::ZeroLength => (
                    "attachment_zero_length",
                    Severity::Info,
                    "Pièce jointe vide",
                    format!("{} ne contient aucun octet.", a.filename),
                ),
            };
            out.push(
                rule,
                sev,
                format!("{title} : {}", a.filename),
                detail,
                r.clone(),
            );
        }
    }
}

fn html_detail(
    a: &mf_core::Attachment,
    f: impl Fn(&mf_core::HtmlAttachmentReport) -> String,
) -> String {
    a.html_report.as_ref().map_or_else(String::new, f)
}

/// Tous les constats d'un message, du plus grave au moins grave.
pub fn evaluate(msg: &Message) -> Vec<Finding> {
    let mut out = Out(Vec::new());
    authentication(msg, &mut out);
    sender(msg, &mut out);
    chronology(msg, &mut out);
    links(msg, &mut out);
    attachments(msg, &mut out);
    let mut v = out.0;
    v.sort_by_key(|f| std::cmp::Reverse(f.severity));
    v
}
