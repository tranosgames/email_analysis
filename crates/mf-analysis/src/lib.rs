//! Analyse d'un message normalisé : HTML sûr, URL et liens trompeurs, acheminement,
//! authentification, pièces jointes, constats et indicateurs.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]

pub mod attachments;
pub mod auth;
pub mod dkim;
pub mod findings;
pub mod hops;
pub mod html;
pub mod htmlatt;
pub mod iocs;
pub mod links;
pub mod qr;
pub mod redirects;
pub mod urls;
pub mod verdict;

use mf_core::{Attachment, AttachmentFlag, Disposition, Message, UrlFlag, UrlLocation};
use std::collections::HashMap;

/// Enrichit le message et, récursivement, ses messages embarqués.
pub fn analyze(msg: &mut Message) {
    if let Some(raw_html) = &msg.body_html {
        let cids: HashMap<String, (String, Vec<u8>)> = msg
            .attachments
            .iter()
            .filter(|a| a.disposition == Disposition::Inline || a.content_id.is_some())
            .filter_map(|a| {
                let cid = a.content_id.as_ref()?;
                let mime = a
                    .declared_mime
                    .clone()
                    .filter(|m| m.starts_with("image/"))?;
                Some((cid.to_ascii_lowercase(), (mime, a.data.clone())))
            })
            .collect();
        let safe = html::sanitize(raw_html, &cids);
        msg.body_html_safe = Some(safe.html);
        msg.blocked_remote_resources = safe.blocked.len() as u32;
        msg.blocked_resources = safe.blocked;
    }
    // Pièces jointes d'abord : les URL d'une page HTML jointe ou d'un QR code rejoignent la liste.
    let recipients: Vec<String> = msg
        .to
        .iter()
        .chain(&msg.cc)
        .chain(&msg.bcc)
        .filter_map(|a| a.address.as_ref().map(|x| x.trim().to_ascii_lowercase()))
        .collect();
    let mut extra: Vec<(String, UrlLocation, bool)> = Vec::new();
    let mut images = 0usize;
    for a in &mut msg.attachments {
        attachments::inspect(a);
        if is_html_like(a) {
            let an = htmlatt::analyze(&a.data, &recipients);
            let r = &an.report;
            let mut add = |f: AttachmentFlag, on: bool| {
                if on && !a.flags.contains(&f) {
                    a.flags.push(f);
                }
            };
            add(AttachmentFlag::CredentialForm, r.password_fields > 0);
            add(AttachmentFlag::Exfiltration, !r.exfiltration.is_empty());
            add(AttachmentFlag::ObfuscatedScript, !r.obfuscation.is_empty());
            add(AttachmentFlag::AutoRedirect, !r.redirects.is_empty());
            add(
                AttachmentFlag::RecipientPrefill,
                !r.recipient_prefill.is_empty(),
            );
            for t in an.texts {
                extra.push((
                    t,
                    UrlLocation::Attachment {
                        filename: a.filename.clone(),
                    },
                    true,
                ));
            }
            a.html_report = Some(an.report);
        } else if is_image(a) && images < qr::MAX_IMAGES {
            images += 1;
            a.qr_codes = qr::decode(&a.data);
            if !a.qr_codes.is_empty() {
                a.flags.push(AttachmentFlag::QrCode);
            }
            for c in &a.qr_codes {
                if let Some(u) = qr::as_url(c) {
                    extra.push((
                        u,
                        UrlLocation::QrCode {
                            source: a.filename.clone(),
                        },
                        false,
                    ));
                }
            }
        }
        if let Some(inner) = a.embedded.as_deref_mut() {
            analyze(inner);
        }
    }
    if let Some(html) = &msg.body_html {
        for (i, img) in qr::inline_images(html).iter().enumerate() {
            if images >= qr::MAX_IMAGES {
                break;
            }
            images += 1;
            for c in qr::decode(img) {
                if let Some(u) = qr::as_url(&c) {
                    let source = format!("l'image n° {} intégrée au HTML", i + 1);
                    extra.push((u, UrlLocation::QrCode { source }, false));
                }
            }
        }
    }
    msg.urls = urls::extract(msg);
    urls::append(&mut msg.urls, extra);
    redirects::expand(msg);
    links::analyze(msg);
    for u in &mut msg.urls {
        if u.redirect.as_ref().is_some_and(|r| r.abused) {
            u.flags.push(UrlFlag::Redirector);
        }
        if u.locations
            .iter()
            .any(|l| matches!(l, UrlLocation::QrCode { .. }))
        {
            u.flags.push(UrlFlag::QrCode);
        }
    }
    let chain = hops::hops(msg);
    msg.route = Some(hops::route(msg, &chain));
    msg.hops = chain;
    msg.auth = auth::results(&msg.headers);
    msg.dkim = dkim::checks(&msg.headers, msg.raw_body.as_deref());
    msg.findings = findings::evaluate(msg);
    msg.iocs = iocs::extract(msg);
    msg.verdict = Some(verdict::evaluate(msg));
}

fn is_html_like(a: &Attachment) -> bool {
    let ext = a
        .filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    a.flags.contains(&AttachmentFlag::HtmlAttachment)
        || matches!(
            a.detected_mime.as_deref(),
            Some("text/html" | "image/svg+xml")
        )
        || matches!(
            ext.as_str(),
            "htm" | "html" | "shtml" | "xhtml" | "svg" | "hta"
        )
}

fn is_image(a: &Attachment) -> bool {
    a.detected_mime
        .as_deref()
        .is_some_and(|m| m.starts_with("image/") && m != "image/svg+xml")
}
