//! Trousseau local : clés publiques OpenPGP et certificats X.509 (autorités, signataires)
//! importés par l'analyste. Rien n'est téléchargé : seul ce que l'analyste fournit est utilisé.

use base64::Engine;
use der::{Decode, Encode};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyDetails;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// Entrée du trousseau, telle qu'affichée à l'analyste et citée dans le rapport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEntry {
    /// `pgp` ou `x509`.
    pub kind: String,
    /// Empreinte complète (PGP) ou SHA-256 du certificat (hexadécimal).
    pub fingerprint: String,
    /// Identité principale (PGP) ou sujet du certificat.
    pub label: String,
    /// Nom du fichier importé.
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Keyring {
    pub(crate) pgp: Vec<SignedPublicKey>,
    pub(crate) certs: Vec<Certificate>,
    pub entries: Vec<KeyEntry>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn cert_sha256(c: &Certificate) -> String {
    hex(&Sha256::digest(c.to_der().unwrap_or_default()))
}

pub fn pgp_label(k: &SignedPublicKey) -> String {
    k.details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_else(|| "(sans identité)".into())
}

impl Keyring {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Importe un fichier : clé(s) PGP armurées ou binaires, certificat(s) PEM ou DER.
    pub fn import(&mut self, source: &str, data: &[u8]) -> Result<Vec<KeyEntry>, String> {
        let text = String::from_utf8_lossy(data);
        let mut added = Vec::new();
        if text.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
            let (keys, _) = SignedPublicKey::from_armor_many(std::io::Cursor::new(data.to_vec()))
                .map_err(|e| format!("clé PGP illisible : {e}"))?;
            for k in keys {
                let k = k.map_err(|e| format!("clé PGP illisible : {e}"))?;
                added.extend(self.add_pgp(k, source));
            }
        } else if text.contains("-----BEGIN CERTIFICATE-----") {
            for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
                let b64: String = block
                    .split("-----END CERTIFICATE-----")
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| format!("certificat PEM illisible : {e}"))?;
                let c = Certificate::from_der(&der)
                    .map_err(|e| format!("certificat illisible : {e}"))?;
                added.extend(self.add_cert(c, source));
            }
        } else if let Ok(c) = Certificate::from_der(data) {
            added.extend(self.add_cert(c, source));
        } else if let Ok(keys) =
            SignedPublicKey::from_bytes_many(std::io::Cursor::new(data.to_vec()))
        {
            for k in keys.flatten() {
                added.extend(self.add_pgp(k, source));
            }
        }
        if added.is_empty() && !self.entries.iter().any(|e| e.source == source) {
            return Err("aucune clé PGP ni certificat X.509 reconnu dans ce fichier".into());
        }
        Ok(added)
    }

    fn add_pgp(&mut self, k: SignedPublicKey, source: &str) -> Option<KeyEntry> {
        let fp = hex(k.primary_key.fingerprint().as_bytes());
        if self.entries.iter().any(|e| e.fingerprint == fp) {
            return None;
        }
        let e = KeyEntry {
            kind: "pgp".into(),
            fingerprint: fp,
            label: pgp_label(&k),
            source: source.to_string(),
        };
        self.pgp.push(k);
        self.entries.push(e.clone());
        Some(e)
    }

    fn add_cert(&mut self, c: Certificate, source: &str) -> Option<KeyEntry> {
        let fp = cert_sha256(&c);
        if self.entries.iter().any(|e| e.fingerprint == fp) {
            return None;
        }
        let e = KeyEntry {
            kind: "x509".into(),
            fingerprint: fp,
            label: c.tbs_certificate().subject().to_string(),
            source: source.to_string(),
        };
        self.certs.push(c);
        self.entries.push(e.clone());
        Some(e)
    }

    /// Retire une entrée (par empreinte).
    pub fn remove(&mut self, fingerprint: &str) {
        self.pgp
            .retain(|k| hex(k.primary_key.fingerprint().as_bytes()) != fingerprint);
        self.certs.retain(|c| cert_sha256(c) != fingerprint);
        self.entries.retain(|e| e.fingerprint != fingerprint);
    }
}
