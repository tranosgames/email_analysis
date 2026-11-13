//! Vérification OpenPGP (RFC 3156 PGP/MIME, RFC 9580) avec les clés importées (FR-049).

use crate::keyring::{Keyring, hex};
use crate::{emails_in, links_pgp, new_check};
use mf_core::{SignatureCheck, SignatureScheme, SignatureStatus};
use pgp::composed::{CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey};
use pgp::packet::Signature;
use pgp::types::KeyDetails;

fn ts(t: pgp::types::Timestamp) -> String {
    chrono::DateTime::from_timestamp(i64::from(t.as_secs()), 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// Expiration de la clé principale d'après ses auto-signatures (secondes Unix).
fn key_expiry(k: &SignedPublicKey) -> Option<i64> {
    let created = i64::from(k.primary_key.created_at().as_secs());
    k.details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter())
        .filter_map(|s| s.key_expiration_time())
        .map(|d| created + i64::from(d.as_secs()))
        .max()
}

fn describe(check: &mut SignatureCheck, sig: &Signature) {
    check.signed_at = sig.created().map(ts);
    check.hash_algorithm = sig.hash_alg().map(|h| format!("{h:?}"));
    check.key_algorithm = sig.config().map(|c| format!("{:?}", c.pub_alg));
    check.fingerprint = sig.issuer_fingerprint().first().map(|f| hex(f.as_bytes()));
    check.key_id = sig.issuer_key_id().first().map(|k| hex(k.as_ref()));
}

/// Clé principale ou sous-clé correspondant à l'émetteur de la signature.
enum Cand<'a> {
    Primary(&'a SignedPublicKey),
    Sub(&'a pgp::composed::SignedPublicSubKey),
}

fn candidate<'a>(sig: &Signature, keys: &'a Keyring) -> Option<(&'a SignedPublicKey, Cand<'a>)> {
    let fprs: Vec<Vec<u8>> = sig
        .issuer_fingerprint()
        .iter()
        .map(|f| f.as_bytes().to_vec())
        .collect();
    let ids: Vec<Vec<u8>> = sig
        .issuer_key_id()
        .iter()
        .map(|k| k.as_ref().to_vec())
        .collect();
    let matches =
        |fp: &[u8], id: &[u8]| fprs.iter().any(|f| f == fp) || ids.iter().any(|i| i == id);
    for k in &keys.pgp {
        if matches(
            k.primary_key.fingerprint().as_bytes(),
            k.primary_key.legacy_key_id().as_ref(),
        ) {
            return Some((k, Cand::Primary(k)));
        }
        for sk in &k.public_subkeys {
            if matches(
                sk.key.fingerprint().as_bytes(),
                sk.key.legacy_key_id().as_ref(),
            ) {
                return Some((k, Cand::Sub(sk)));
            }
        }
    }
    None
}

fn finish(check: &mut SignatureCheck, found: Option<(SignedPublicKey, bool)>, from: &[String]) {
    match found {
        None => {
            check.status = SignatureStatus::UnknownKey;
            check.note = Some(
                "Clé publique du signataire absente : importez-la (fichier .asc) pour vérifier la signature."
                    .into(),
            );
        }
        Some((k, ok)) => {
            check.status = if ok {
                SignatureStatus::Valid
            } else {
                SignatureStatus::Invalid
            };
            let fp = hex(k.primary_key.fingerprint().as_bytes());
            check.verified_with = Some(fp.clone());
            check.fingerprint = Some(fp);
            check.key_id = Some(hex(k.primary_key.legacy_key_id().as_ref()));
            check.signer_ids = k
                .details
                .users
                .iter()
                .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
                .collect();
            check.signer_emails = check.signer_ids.iter().flat_map(|u| emails_in(u)).collect();
            check.key_revoked = Some(!k.details.revocation_signatures.is_empty());
            let signed = check
                .signed_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.timestamp());
            check.key_expired = Some(match (key_expiry(&k), signed) {
                (Some(exp), Some(at)) => at > exp,
                _ => false,
            });
            if !ok {
                check.note = Some(
                    "Signature invalide : le contenu a été modifié après la signature, ou la signature est fausse."
                        .into(),
                );
            }
        }
    }
    check.matches_from = (!check.signer_emails.is_empty())
        .then(|| check.signer_emails.iter().any(|e| from.contains(e)));
    check.links = links_pgp(check.fingerprint.as_deref(), check.key_id.as_deref(), from);
}

/// PGP/MIME : `signed` = partie signée exacte (CRLF), `armored` = signature.
pub fn verify_detached(
    signed: &[u8],
    armored: &[u8],
    keys: &Keyring,
    from: &[String],
) -> SignatureCheck {
    let mut check = new_check(SignatureScheme::Pgp, "pgp_mime");
    let parsed = DetachedSignature::from_armor_single(std::io::Cursor::new(armored.to_vec()))
        .map(|(s, _)| s)
        .or_else(|_| DetachedSignature::from_bytes(std::io::Cursor::new(armored.to_vec())));
    let sig = match parsed {
        Ok(s) => s,
        Err(e) => {
            check.status = SignatureStatus::Unsupported;
            check.note = Some(format!("Signature OpenPGP illisible : {e}"));
            return check;
        }
    };
    describe(&mut check, &sig.signature);
    let found = candidate(&sig.signature, keys).map(|(k, c)| {
        let ok = match c {
            Cand::Primary(p) => sig.verify(p, signed).is_ok(),
            Cand::Sub(s) => sig.verify(s, signed).is_ok(),
        };
        (k.clone(), ok)
    });
    finish(&mut check, found, from);
    check
}

/// PGP inline (clearsign).
pub fn verify_inline(text: &str, keys: &Keyring, from: &[String]) -> SignatureCheck {
    let mut check = new_check(SignatureScheme::Pgp, "pgp_inline");
    let start = text.find("-----BEGIN PGP SIGNED MESSAGE-----").unwrap_or(0);
    let block = &text[start..];
    let msg = match CleartextSignedMessage::from_string(block) {
        Ok((m, _)) => m,
        Err(e) => {
            check.status = SignatureStatus::Unsupported;
            check.note = Some(format!("Bloc PGP signé illisible : {e}"));
            return check;
        }
    };
    let Some(sig) = msg.signatures().first().cloned() else {
        check.status = SignatureStatus::Unsupported;
        return check;
    };
    describe(&mut check, &sig);
    let found = candidate(&sig, keys).map(|(k, c)| {
        let ok = match c {
            Cand::Primary(p) => msg.verify(p).is_ok(),
            Cand::Sub(s) => msg.verify(s).is_ok(),
        };
        (k.clone(), ok)
    });
    finish(&mut check, found, from);
    if start > 0 {
        let extra = check
            .note
            .take()
            .map(|n| format!("{n} "))
            .unwrap_or_default();
        check.note = Some(format!(
            "{extra}Du texte précède le bloc signé : il n'est pas couvert par la signature."
        ));
    }
    check
}
