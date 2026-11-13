//! Découpage MIME minimal **sur les octets d'origine** : une signature ne se vérifie que sur la
//! partie signée exacte (RFC 3156 §5, RFC 8551 §3.1.1), que les analyseurs MIME ordinaires
//! décodent et réécrivent. Toutes les fins de ligne sont normalisées en CRLF au préalable.

use base64::Engine;

/// Profondeur maximale d'imbrication parcourue.
const MAX_DEPTH: usize = 8;

/// Normalise les fins de ligne en CRLF.
pub fn to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    let mut prev = 0u8;
    for &b in data {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

/// En-têtes (dépliés) et corps d'une entité MIME.
pub fn split_entity(entity: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let (head, body) = match find(entity, b"\r\n\r\n") {
        Some(i) => (&entity[..i], &entity[i + 4..]),
        None if entity.starts_with(b"\r\n") => (&entity[..0], &entity[2..]),
        None => (entity, &entity[entity.len()..]),
    };
    let text = String::from_utf8_lossy(head);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in text.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((n, v)) = line.split_once(':') {
            headers.push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    (headers, body)
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Type (minuscules) et paramètres d'un `Content-Type`.
pub fn content_type(value: &str) -> (String, Vec<(String, String)>) {
    let mut it = split_params(value).into_iter();
    let main = it.next().unwrap_or_default().trim().to_ascii_lowercase();
    let params = it
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            ))
        })
        .collect();
    (main, params)
}

/// Découpe sur `;` hors guillemets.
fn split_params(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in v.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

pub fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parties d'un corps multipart : octets exacts entre deux délimiteurs (RFC 2046 §5.1.1 :
/// le CRLF qui précède un délimiteur appartient au délimiteur).
pub fn multipart_parts<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    // Positions des débuts de lignes délimiteurs.
    let mut starts = Vec::new();
    let mut i = 0;
    while let Some(p) = find(&body[i..], d) {
        let at = i + p;
        if at == 0 || body[..at].ends_with(b"\r\n") {
            starts.push(at);
        }
        i = at + d.len();
    }
    let mut parts = Vec::new();
    for w in starts.windows(2) {
        let (a, b) = (w[0], w[1]);
        let line_end = find(&body[a..b], b"\r\n").map_or(b, |e| a + e + 2);
        let end = b.saturating_sub(2).max(line_end);
        if body[a + d.len()..].starts_with(b"--") {
            break; // délimiteur de fin
        }
        parts.push(&body[line_end..end]);
    }
    parts
}

pub fn decode_transfer(cte: Option<&str>, body: &[u8]) -> Vec<u8> {
    match cte.map(|c| c.trim().to_ascii_lowercase()).as_deref() {
        Some("base64") => {
            let clean: Vec<u8> = body
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(&clean)
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(clean.strip_suffix(b"=").unwrap_or(&clean))
                })
                .unwrap_or_default()
        }
        Some("quoted-printable") => quoted_printable(body),
        _ => body.to_vec(),
    }
}

fn quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'=' {
            if body[i + 1..].starts_with(b"\r\n") {
                i += 3;
                continue;
            }
            if i + 2 < body.len() {
                if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&body[i + 1..i + 3]), 16)
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(body[i]);
        i += 1;
    }
    out
}

/// Élément cryptographique trouvé dans le message.
#[derive(Debug, Clone)]
pub enum Found {
    /// PGP/MIME : partie signée exacte + signature armurée.
    PgpMime {
        signed: Vec<u8>,
        signature: Vec<u8>,
    },
    /// PGP inline (`-----BEGIN PGP SIGNED MESSAGE-----`).
    PgpInline {
        text: String,
    },
    PgpEncrypted,
    /// S/MIME détaché : partie signée exacte + CMS DER.
    SmimeDetached {
        signed: Vec<u8>,
        cms: Vec<u8>,
    },
    /// S/MIME opaque : CMS DER contenant le contenu.
    SmimeOpaque {
        cms: Vec<u8>,
    },
    SmimeEncrypted,
}

/// Parcourt une entité MIME (`ctype` = Content-Type, `body` = corps en CRLF).
pub fn walk(
    ctype: Option<&str>,
    cte: Option<&str>,
    body: &[u8],
    depth: usize,
    out: &mut Vec<Found>,
) {
    if depth > MAX_DEPTH || out.len() > 16 {
        return;
    }
    let (main, params) = content_type(ctype.unwrap_or("text/plain"));
    match main.as_str() {
        "multipart/signed" => {
            let Some(b) = param(&params, "boundary") else {
                return;
            };
            let parts = multipart_parts(body, b);
            if parts.len() < 2 {
                return;
            }
            let protocol = param(&params, "protocol")
                .unwrap_or("")
                .to_ascii_lowercase();
            let (sh, sb) = split_entity(parts[1]);
            let sig = decode_transfer(header(&sh, "content-transfer-encoding"), sb);
            if protocol.contains("pgp-signature") {
                out.push(Found::PgpMime {
                    signed: parts[0].to_vec(),
                    signature: sig,
                });
            } else if protocol.contains("pkcs7-signature") {
                out.push(Found::SmimeDetached {
                    signed: parts[0].to_vec(),
                    cms: sig,
                });
            }
            // La partie signée peut elle-même contenir une signature imbriquée (transfert).
            let (h, b0) = split_entity(parts[0]);
            if content_type(header(&h, "content-type").unwrap_or(""))
                .0
                .starts_with("multipart/")
            {
                walk(
                    header(&h, "content-type"),
                    header(&h, "content-transfer-encoding"),
                    b0,
                    depth + 1,
                    out,
                );
            }
        }
        "multipart/encrypted" => {
            if param(&params, "protocol").is_some_and(|p| p.to_ascii_lowercase().contains("pgp")) {
                out.push(Found::PgpEncrypted);
            }
        }
        m if m.starts_with("multipart/") => {
            let Some(b) = param(&params, "boundary") else {
                return;
            };
            for p in multipart_parts(body, b) {
                let (h, b) = split_entity(p);
                walk(
                    header(&h, "content-type"),
                    header(&h, "content-transfer-encoding"),
                    b,
                    depth + 1,
                    out,
                );
            }
        }
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
            let der = decode_transfer(cte, body);
            let st = param(&params, "smime-type")
                .unwrap_or("")
                .to_ascii_lowercase();
            if st.contains("enveloped") || st.contains("authenveloped") {
                out.push(Found::SmimeEncrypted);
            } else if st.contains("signed") || crate::smime::is_signed_data(&der) {
                out.push(Found::SmimeOpaque { cms: der });
            } else if crate::smime::is_enveloped_data(&der) {
                out.push(Found::SmimeEncrypted);
            }
        }
        "text/plain" | "text/html" => {
            let text = String::from_utf8_lossy(&decode_transfer(cte, body)).into_owned();
            if text.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
                out.push(Found::PgpInline { text });
            } else if text.contains("-----BEGIN PGP MESSAGE-----") {
                out.push(Found::PgpEncrypted);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn exact_signed_part() {
        let body = to_crlf(b"preamble\n--B\nContent-Type: text/plain\n\nHello\n\n--B\nContent-Type: application/pgp-signature\n\nSIG\n--B--\n");
        let parts = multipart_parts(&body, "B");
        assert_eq!(parts.len(), 2);
        // Le CRLF final de « Hello » appartient à la partie ; celui avant « --B » non.
        assert_eq!(parts[0], b"Content-Type: text/plain\r\n\r\nHello\r\n");
        assert_eq!(split_entity(parts[1]).1, b"SIG");
    }

    #[test]
    fn content_type_params() {
        let (m, p) = content_type(
            "multipart/signed; micalg=pgp-sha256; protocol=\"application/pgp-signature\"; boundary=\"a;b\"",
        );
        assert_eq!(m, "multipart/signed");
        assert_eq!(param(&p, "boundary"), Some("a;b"));
        assert_eq!(param(&p, "protocol"), Some("application/pgp-signature"));
    }
}
