//! DKIM (RFC 6376) : lecture des signatures et recalcul **hors-ligne** de l'empreinte du corps
//! (`bh=`), qui prouve que le corps n'a pas été modifié depuis la signature (FR-014).
//!
//! La vérification de la signature elle-même (`b=`) exige la clé publique publiée dans le DNS
//! du domaine signataire : elle est hors périmètre (Constitution VI, aucune requête réseau).

use base64::Engine;
use mf_core::{DkimCheck, Header};
use sha1::Sha1;
use sha2::{Digest, Sha256};

fn unfold(s: &str) -> String {
    s.split(['\r', '\n'])
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Balises `nom=valeur` d'une signature.
fn tags(value: &str) -> Vec<(String, String)> {
    unfold(value)
        .split(';')
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// Normalise les fins de ligne en CRLF (un fichier enregistré sur disque peut n'avoir que des LF).
fn to_crlf(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + body.len() / 32);
    let mut prev = 0u8;
    for &b in body {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

/// Canonicalisation du corps (RFC 6376 §3.4.3 et §3.4.4).
pub fn canonical_body(body: &[u8], relaxed: bool) -> Vec<u8> {
    let crlf = to_crlf(body);
    let mut lines: Vec<Vec<u8>> = crlf
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec())
        .collect();
    // Le découpage laisse un dernier élément vide si le corps finit par CRLF.
    if lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    if relaxed {
        for line in &mut lines {
            let mut out = Vec::with_capacity(line.len());
            let mut in_wsp = false;
            for &b in line.iter() {
                if b == b' ' || b == b'\t' {
                    in_wsp = true;
                } else {
                    if in_wsp {
                        out.push(b' ');
                    }
                    in_wsp = false;
                    out.push(b);
                }
            }
            *line = out; // les blancs de fin de ligne disparaissent
        }
    }
    while lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    if lines.is_empty() {
        return if relaxed {
            Vec::new()
        } else {
            b"\r\n".to_vec()
        };
    }
    let mut out = Vec::with_capacity(crlf.len());
    for l in lines {
        out.extend_from_slice(&l);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Analyse des signatures `DKIM-Signature` ; `raw_body` = corps MIME brut (absent pour un MSG).
pub fn checks(headers: &[Header], raw_body: Option<&[u8]>) -> Vec<DkimCheck> {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("DKIM-Signature"))
        .map(|h| {
            let t = tags(&h.value);
            let get = |k: &str| t.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            let algorithm = get("a");
            let canonicalization = get("c").or_else(|| Some("simple/simple".into()));
            let body_relaxed = canonicalization.as_deref().is_some_and(|c| c.split('/').nth(1).unwrap_or("simple").trim() == "relaxed");
            let limit = get("l").and_then(|l| l.parse::<u64>().ok());
            let declared = get("bh").map(|b| b.split_whitespace().collect::<String>());
            let mut check = DkimCheck {
                header_index: h.index,
                domain: get("d"),
                selector: get("s"),
                algorithm: algorithm.clone(),
                canonicalization,
                signed_headers: get("h")
                    .map(|v| v.split(':').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
                    .unwrap_or_default(),
                body_length_limit: limit,
                body_hash_declared: declared.clone(),
                body_hash_computed: None,
                body_hash_ok: None,
                note: None,
            };
            let Some(body) = raw_body else {
                check.note = Some("Corps MIME d'origine indisponible (message Outlook .msg) : empreinte non vérifiable.".into());
                return check;
            };
            let mut canon = canonical_body(body, body_relaxed);
            if let Some(l) = limit {
                canon.truncate(usize::try_from(l).unwrap_or(usize::MAX));
            }
            let digest = match algorithm.as_deref().map(str::to_ascii_lowercase).as_deref() {
                Some("rsa-sha256" | "ed25519-sha256") => Sha256::digest(&canon).to_vec(),
                Some("rsa-sha1") => Sha1::digest(&canon).to_vec(),
                other => {
                    check.note = Some(format!("Algorithme {} non pris en charge.", other.unwrap_or("absent")));
                    return check;
                }
            };
            let computed = base64::engine::general_purpose::STANDARD.encode(digest);
            check.body_hash_ok = declared.as_ref().map(|d| *d == computed);
            if check.body_hash_ok == Some(false) {
                check.note = Some("Le corps a été modifié depuis la signature (ou par un relais : pied de page, antivirus, transfert).".into());
            }
            if limit.is_some() {
                check.note = Some(format!(
                    "{}Signature limitée à {} octets du corps (l=) : du contenu a pu être ajouté après.",
                    check.note.as_deref().map(|n| format!("{n} ")).unwrap_or_default(),
                    limit.unwrap_or(0)
                ));
            }
            check.body_hash_computed = Some(computed);
            check
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(v: &str) -> Header {
        Header {
            index: 0,
            name: "DKIM-Signature".into(),
            raw: String::new(),
            value: v.into(),
            offset: None,
        }
    }

    #[test]
    fn rfc6376_appendix_a() {
        let body = b"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n";
        let h = sig(
            "v=1; a=rsa-sha256; s=brisbane; d=example.com;\r\n c=simple/simple; q=dns/txt; i=joe@football.example.com;\r\n h=Received : From : To : Subject : Date : Message-ID;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\r\n 4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut",
        );
        let c = &checks(std::slice::from_ref(&h), Some(body))[0];
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert_eq!(c.selector.as_deref(), Some("brisbane"));
        assert_eq!(c.signed_headers.len(), 6);
        assert_eq!(c.body_hash_ok, Some(true), "{:?}", c.body_hash_computed);
        // Même corps avec des LF seuls (fichier converti) et des lignes vides finales : identique.
        assert_eq!(
            checks(
                std::slice::from_ref(&h),
                Some(b"Hi.\n\nWe lost the game. Are you hungry yet?\n\nJoe.\n\n\n")
            )[0]
            .body_hash_ok,
            Some(true)
        );
        // Un octet modifié : empreinte divergente.
        assert_eq!(
            checks(
                &[h],
                Some(b"Hi.\r\n\r\nWe won the game. Are you hungry yet?\r\n\r\nJoe.\r\n")
            )[0]
            .body_hash_ok,
            Some(false)
        );
    }

    #[test]
    fn canonicalization_edge_cases() {
        assert_eq!(canonical_body(b"", false), b"\r\n");
        assert_eq!(canonical_body(b"", true), b"");
        assert_eq!(canonical_body(b"  a \t b  \r\n\r\n", true), b" a b\r\n");
        let e = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(canonical_body(b"\r\n\r\n", true)));
        assert_eq!(e, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn msg_without_raw_body_is_not_verifiable() {
        let c = &checks(
            &[sig("v=1; a=rsa-sha256; d=x.example; s=s; bh=AAAA; b=BBBB")],
            None,
        )[0];
        assert_eq!(c.body_hash_ok, None);
        assert!(c.note.as_deref().is_some_and(|n| n.contains(".msg")));
    }
}
