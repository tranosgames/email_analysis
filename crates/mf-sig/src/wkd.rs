//! Web Key Directory (draft-koch-openpgp-webkey-service) : adresse à laquelle un domaine publie
//! lui-même la clé d'une adresse. Calculée hors-ligne (SHA-1 + z-base-32 de la partie locale).

use sha1::{Digest, Sha1};

const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

pub fn zbase32(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZBASE32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// URL « méthode directe » : `https://domaine/.well-known/openpgpkey/hu/<hash>?l=<local>`.
pub fn direct_url(address: &str) -> Option<String> {
    let (local, domain) = address.trim().rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    let hash = zbase32(&Sha1::digest(local.to_ascii_lowercase().as_bytes()));
    Some(format!(
        "https://{}/.well-known/openpgpkey/hu/{hash}?l={local}",
        domain.to_ascii_lowercase()
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn spec_example() {
        // Exemple du draft WKD : « Joe.Doe@Example.ORG ».
        assert_eq!(
            direct_url("Joe.Doe@Example.ORG").unwrap(),
            "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
        );
    }
}
