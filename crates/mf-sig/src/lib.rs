//! Signatures OpenPGP et S/MIME vérifiées **hors-ligne** (FR-049, FR-050, FR-051).
//!
//! Les clés publiques et certificats d'autorité sont fournis par l'analyste ([`Keyring`]) ;
//! aucune requête n'est émise. Les liens externes de vérification sont seulement proposés.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]

pub mod keyring;
pub mod mime;
pub mod pgp;
pub mod smime;
pub mod wkd;

pub use keyring::{KeyEntry, Keyring};
use mf_core::{ExternalLink, SignatureCheck, SignatureScheme, SignatureStatus};

pub(crate) fn new_check(scheme: SignatureScheme, kind: &str) -> SignatureCheck {
    SignatureCheck {
        scheme,
        kind: kind.into(),
        status: SignatureStatus::Unsupported,
        fingerprint: None,
        key_id: None,
        signer_ids: Vec::new(),
        signer_emails: Vec::new(),
        matches_from: None,
        signed_at: None,
        hash_algorithm: None,
        key_algorithm: None,
        key_expired: None,
        key_revoked: None,
        cert: None,
        verified_with: None,
        note: None,
        links: Vec::new(),
    }
}

/// Adresses email d'une identité (`Nom <a@b>` ou adresse nue), en minuscules.
pub(crate) fn emails_in(s: &str) -> Vec<String> {
    let inner = s
        .rsplit_once('<')
        .map_or(s, |(_, r)| r.trim_end_matches('>'));
    let inner = inner.trim();
    if inner.contains('@') && !inner.contains(' ') {
        vec![inner.to_ascii_lowercase()]
    } else {
        Vec::new()
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Liens de vérification externes d'une clé PGP (FR-051). Aucun n'est ouvert automatiquement.
pub(crate) fn links_pgp(
    fingerprint: Option<&str>,
    key_id: Option<&str>,
    from: &[String],
) -> Vec<ExternalLink> {
    let mut out = Vec::new();
    let link = |label: &str, url: String| ExternalLink {
        label: label.into(),
        url,
    };
    if let Some(fp) = fingerprint.or(key_id) {
        out.push(link(
            "keys.openpgp.org (empreinte)",
            format!("https://keys.openpgp.org/search?q={fp}"),
        ));
        out.push(link(
            "keyserver.ubuntu.com",
            format!(
                "https://keyserver.ubuntu.com/pks/lookup?search=0x{fp}&fingerprint=on&op=index"
            ),
        ));
    }
    if let Some(fp) = fingerprint {
        out.push(link(
            "Keyoxide (preuves d'identité)",
            format!("https://keyoxide.org/{}", fp.to_ascii_lowercase()),
        ));
    }
    for addr in from.iter().take(1) {
        out.push(link(
            "keys.openpgp.org (adresse)",
            format!("https://keys.openpgp.org/search?q={}", enc(addr)),
        ));
        if let Some(u) = wkd::direct_url(addr) {
            out.push(link("WKD du domaine de l'expéditeur", u));
        }
        out.push(link(
            "Keyoxide via WKD",
            format!("https://keyoxide.org/wkd/{}", enc(addr)),
        ));
    }
    out
}

/// Le lien fait-il partie des services de vérification proposés (FR-051) ? Sert de liste
/// blanche à l'application de bureau, qui n'ouvre rien d'autre dans le navigateur système.
pub fn is_verification_link(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let path = &rest[host.len()..];
    matches!(
        host,
        "keys.openpgp.org" | "keyserver.ubuntu.com" | "keyoxide.org"
    ) || (path.starts_with("/.well-known/openpgpkey/")
        && !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
}

/// Vérifie les signatures d'un message.
/// `content_type` / `cte` / `body` : en-tête Content-Type, encodage et corps brut d'origine ;
/// `from` : adresses de l'expéditeur (minuscules) ; `msg_date` : date du message (secondes Unix).
pub fn check(
    content_type: Option<&str>,
    cte: Option<&str>,
    body: &[u8],
    from: &[String],
    msg_date: Option<i64>,
    keys: &Keyring,
) -> Vec<SignatureCheck> {
    let body = mime::to_crlf(body);
    let mut found = Vec::new();
    mime::walk(content_type, cte, &body, 0, &mut found);
    found
        .into_iter()
        .map(|f| match f {
            mime::Found::PgpMime { signed, signature } => {
                pgp::verify_detached(&signed, &signature, keys, from)
            }
            mime::Found::PgpInline { text } => pgp::verify_inline(&text, keys, from),
            mime::Found::SmimeDetached { signed, cms } => {
                smime::verify(&cms, Some(&signed), keys, from, msg_date)
            }
            mime::Found::SmimeOpaque { cms } => smime::verify(&cms, None, keys, from, msg_date),
            mime::Found::PgpEncrypted => {
                let mut c = new_check(SignatureScheme::Pgp, "pgp_encrypted");
                c.status = SignatureStatus::Encrypted;
                c.note = Some(
                    "Message chiffré en OpenPGP : illisible sans la clé privée du destinataire."
                        .into(),
                );
                c
            }
            mime::Found::SmimeEncrypted => {
                let mut c = new_check(SignatureScheme::Smime, "smime_encrypted");
                c.status = SignatureStatus::Encrypted;
                c.note = Some(
                    "Message chiffré en S/MIME : illisible sans la clé privée du destinataire."
                        .into(),
                );
                c
            }
        })
        .collect()
}

/// Entité MIME complète (en-têtes + corps), par exemple le `smime.p7m` d'un message Outlook.
pub fn check_entity(
    entity: &[u8],
    from: &[String],
    msg_date: Option<i64>,
    keys: &Keyring,
) -> Vec<SignatureCheck> {
    let e = mime::to_crlf(entity);
    let (h, body) = mime::split_entity(&e);
    if mime::header(&h, "content-type").is_none() {
        // Fichier .p7m brut (DER), sans en-têtes MIME.
        if smime::is_signed_data(entity) {
            return vec![smime::verify(entity, None, keys, from, msg_date)];
        }
        return Vec::new();
    }
    check(
        mime::header(&h, "content-type"),
        mime::header(&h, "content-transfer-encoding"),
        body,
        from,
        msg_date,
        keys,
    )
}
