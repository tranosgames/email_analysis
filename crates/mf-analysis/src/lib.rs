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
pub mod iocs;
pub mod links;
pub mod urls;
pub mod verdict;

use mf_core::{Disposition, Message};
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
    msg.urls = urls::extract(msg);
    links::analyze(msg);
    let chain = hops::hops(msg);
    msg.route = Some(hops::route(msg, &chain));
    msg.hops = chain;
    msg.auth = auth::results(&msg.headers);
    msg.dkim = dkim::checks(&msg.headers, msg.raw_body.as_deref());
    for a in &mut msg.attachments {
        attachments::inspect(a);
        if let Some(inner) = a.embedded.as_deref_mut() {
            analyze(inner);
        }
    }
    msg.findings = findings::evaluate(msg);
    msg.iocs = iocs::extract(msg);
    msg.verdict = Some(verdict::evaluate(msg));
}
