//! Vérification S/MIME (CMS, RFC 5652 / RFC 8551) : signatures détachées et opaques (FR-050).
//! Le certificat du signataire est en général joint : l'intégrité se vérifie sans rien importer ;
//! la confiance (autorité) exige que l'analyste importe le certificat de l'autorité.

use crate::keyring::{Keyring, cert_sha256, hex};
use crate::new_check;
use base64::Engine;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier as Oid;
use der::{Decode, Encode};
use mf_core::{CertInfo, SignatureCheck, SignatureScheme, SignatureStatus};
use sha2::Digest;
use x509_cert::Certificate;

const SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
const ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.3");
const AUTH_ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.23");
const MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.5");
const EMAIL_ATTR: Oid = Oid::new_unwrap("1.2.840.113549.1.9.1");
const SAN: Oid = Oid::new_unwrap("2.5.29.17");
const RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const EC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const P256: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
const P384: Oid = Oid::new_unwrap("1.3.132.0.34");

fn content_info(der: &[u8]) -> Option<ContentInfo> {
    ContentInfo::from_der(der).ok()
}

pub fn is_signed_data(der: &[u8]) -> bool {
    content_info(der).is_some_and(|c| c.content_type == SIGNED_DATA)
}

pub fn is_enveloped_data(der: &[u8]) -> bool {
    content_info(der)
        .is_some_and(|c| c.content_type == ENVELOPED_DATA || c.content_type == AUTH_ENVELOPED_DATA)
}

/// Condensat selon l'OID d'algorithme de hachage (ou d'algorithme de signature qui l'implique).
fn digest(oid: &str, data: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    match oid {
        "1.3.14.3.2.26" | "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => {
            Some((sha1::Sha1::digest(data).to_vec(), "SHA-1"))
        }
        "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => {
            Some((sha2::Sha256::digest(data).to_vec(), "SHA-256"))
        }
        "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => {
            Some((sha2::Sha384::digest(data).to_vec(), "SHA-384"))
        }
        "2.16.840.1.101.3.4.2.3" | "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => {
            Some((sha2::Sha512::digest(data).to_vec(), "SHA-512"))
        }
        _ => None,
    }
}

/// Vérifie `signature` sur le condensat `hashed` (algorithme `hash_name`) avec la clé `cert`.
fn verify_hashed(
    cert: &Certificate,
    hash_name: &str,
    hashed: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let spki_der = spki.to_der().map_err(|e| e.to_string())?;
    let alg = spki.algorithm.oid;
    if alg == RSA {
        use rsa::pkcs8::DecodePublicKey;
        let key = rsa::PublicKey::from_public_key_der(&spki_der).map_err(|e| e.to_string())?;
        let scheme = match hash_name {
            "SHA-1" => rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>(),
            "SHA-256" => rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
            "SHA-384" => rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(),
            "SHA-512" => rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
            _ => return Err(format!("hachage {hash_name} non pris en charge")),
        };
        return Ok(key.verify(scheme, hashed, signature).is_ok());
    }
    if alg == EC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<Oid>().ok());
        use ecdsa::signature::hazmat::PrehashVerifier;
        use spki::DecodePublicKey;
        return match curve {
            Some(c) if c == P256 => {
                let k = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der)
                    .map_err(|e| e.to_string())?;
                let s = p256::ecdsa::Signature::from_der(signature).map_err(|e| e.to_string())?;
                Ok(k.verify_prehash(hashed, &s).is_ok())
            }
            Some(c) if c == P384 => {
                let k = p384::ecdsa::VerifyingKey::from_public_key_der(&spki_der)
                    .map_err(|e| e.to_string())?;
                let s = p384::ecdsa::Signature::from_der(signature).map_err(|e| e.to_string())?;
                Ok(k.verify_prehash(hashed, &s).is_ok())
            }
            _ => Err("courbe elliptique non prise en charge".into()),
        };
    }
    Err(format!("algorithme de clé {alg} non pris en charge"))
}

/// Le certificat `child` est-il signé par `issuer` ?
fn signed_by(child: &Certificate, issuer: &Certificate) -> bool {
    if child.tbs_certificate().issuer() != issuer.tbs_certificate().subject() {
        return false;
    }
    let Ok(tbs) = child.tbs_certificate().to_der() else {
        return false;
    };
    let alg = child.signature_algorithm().oid.to_string();
    let Some((hashed, name)) = digest(&alg, &tbs) else {
        return false;
    };
    let Some(sig) = child.signature().as_bytes() else {
        return false;
    };
    verify_hashed(issuer, name, &hashed, sig).unwrap_or(false)
}

fn unix(t: &x509_cert::time::Time) -> i64 {
    i64::try_from(t.to_unix_duration().as_secs()).unwrap_or(0)
}

fn iso(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn cert_emails(c: &Certificate) -> Vec<String> {
    let mut out = Vec::new();
    for atv in c.tbs_certificate().subject().iter() {
        if atv.oid == EMAIL_ATTR {
            if let Ok(s) = atv.value.decode_as::<der::asn1::Ia5String>() {
                out.push(s.to_string().to_ascii_lowercase());
            }
        }
    }
    if let Some(exts) = c.tbs_certificate().extensions() {
        for e in exts.iter().filter(|e| e.extn_id == SAN) {
            if let Ok(san) = x509_cert::ext::pkix::SubjectAltName::from_der(e.extn_value.as_bytes())
            {
                for n in san.0 {
                    if let x509_cert::ext::pkix::name::GeneralName::Rfc822Name(m) = n {
                        let m = m.to_string().to_ascii_lowercase();
                        if !out.contains(&m) {
                            out.push(m);
                        }
                    }
                }
            }
        }
    }
    out
}

fn pem(c: &Certificate) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(c.to_der().unwrap_or_default());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .filter_map(|l| std::str::from_utf8(l).ok())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// Chaîne de confiance : remonte via les certificats du message et ceux importés.
fn chain(leaf: &Certificate, bundled: &[Certificate], keys: &Keyring) -> (String, Option<String>) {
    let anchors = &keys.certs;
    let mut cur = leaf.clone();
    for _ in 0..6 {
        if let Some(a) = anchors.iter().find(|a| signed_by(&cur, a)) {
            return (
                "trusted".into(),
                Some(a.tbs_certificate().subject().to_string()),
            );
        }
        if cur.tbs_certificate().issuer() == cur.tbs_certificate().subject() {
            return (
                if signed_by(&cur, &cur) {
                    "self_signed"
                } else {
                    "invalid_chain"
                }
                .into(),
                None,
            );
        }
        match bundled
            .iter()
            .chain(anchors.iter())
            .find(|c| signed_by(&cur, c) && **c != cur)
        {
            Some(next) => cur = next.clone(),
            None => return ("unknown_ca".into(), None),
        }
    }
    ("unknown_ca".into(), None)
}

fn find_signer<'a>(si: &SignerInfo, certs: &'a [Certificate]) -> Option<&'a Certificate> {
    certs.iter().find(|c| match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            c.tbs_certificate().issuer() == &ias.issuer
                && c.tbs_certificate().serial_number() == &ias.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => c
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .filter(|e| e.extn_id == Oid::new_unwrap("2.5.29.14"))
            .any(|e| {
                x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(e.extn_value.as_bytes())
                    .is_ok_and(|k| k.0 == ski.0)
            }),
    })
}

/// Vérifie un CMS SignedData ; `detached` = contenu signé exact pour une signature détachée.
pub fn verify(
    cms_der: &[u8],
    detached: Option<&[u8]>,
    keys: &Keyring,
    from: &[String],
    msg_date: Option<i64>,
) -> SignatureCheck {
    let mut check = new_check(
        SignatureScheme::Smime,
        if detached.is_some() {
            "smime_detached"
        } else {
            "smime_opaque"
        },
    );
    let fail = |mut c: SignatureCheck, note: String| {
        c.status = SignatureStatus::Unsupported;
        c.note = Some(note);
        c
    };
    let Some(ci) = content_info(cms_der) else {
        return fail(check, "Signature S/MIME illisible (CMS invalide).".into());
    };
    if ci.content_type != SIGNED_DATA {
        return fail(check, "Structure CMS sans signature (SignedData).".into());
    }
    let Ok(sd) = ci.content.decode_as::<SignedData>() else {
        return fail(check, "SignedData illisible.".into());
    };
    let content: Vec<u8> = match detached {
        Some(d) => d.to_vec(),
        None => match sd.encap_content_info.econtent.as_ref() {
            Some(any) => any
                .decode_as::<der::asn1::OctetString>()
                .map(|o| o.as_bytes().to_vec())
                .unwrap_or_else(|_| any.value().to_vec()),
            None => return fail(check, "Signature opaque sans contenu encapsulé.".into()),
        },
    };
    let bundled: Vec<Certificate> = sd
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let Some(si) = sd.signer_infos.0.iter().next() else {
        return fail(check, "Aucun signataire dans la signature.".into());
    };
    let pool: Vec<Certificate> = bundled.iter().chain(keys.certs.iter()).cloned().collect();
    let digest_oid = si.digest_alg.oid.to_string();
    let Some((content_hash, hash_name)) = digest(&digest_oid, &content) else {
        return fail(
            check,
            format!("Algorithme de hachage {digest_oid} non pris en charge."),
        );
    };
    check.hash_algorithm = Some(hash_name.into());
    let mut signing_time: Option<i64> = None;
    // Données réellement signées : les attributs signés (SET OF, DER) s'ils existent.
    let (to_sign, attrs_ok) = match &si.signed_attrs {
        Some(attrs) => {
            let mut md_ok = false;
            for a in attrs.iter() {
                if a.oid == MESSAGE_DIGEST {
                    md_ok = a.values.iter().any(|v| {
                        v.decode_as::<der::asn1::OctetString>()
                            .is_ok_and(|o| o.as_bytes() == content_hash.as_slice())
                    });
                } else if a.oid == SIGNING_TIME {
                    signing_time = a
                        .values
                        .iter()
                        .next()
                        .and_then(|v| v.decode_as::<x509_cert::time::Time>().ok())
                        .map(|t| unix(&t));
                }
            }
            (attrs.to_der().unwrap_or_default(), md_ok)
        }
        None => (content.clone(), true),
    };
    check.signed_at = signing_time.map(iso);
    let Some(cert) = find_signer(si, &pool) else {
        check.status = SignatureStatus::UnknownKey;
        check.note = Some(
            "Certificat du signataire absent du message : importez-le (.pem / .cer) pour vérifier."
                .into(),
        );
        return check;
    };
    let (hashed, _) = digest(&digest_oid, &to_sign).unwrap_or_default();
    let sig_ok = verify_hashed(cert, hash_name, &hashed, si.signature.as_bytes());
    let spki_alg = cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid;
    check.key_algorithm = Some(if spki_alg == RSA {
        "RSA".into()
    } else if spki_alg == EC_KEY {
        "ECDSA".into()
    } else {
        spki_alg.to_string()
    });
    check.status = match sig_ok {
        Ok(true) if attrs_ok => SignatureStatus::Valid,
        Ok(_) => SignatureStatus::Invalid,
        Err(e) => return fail(check, format!("Vérification impossible : {e}.")),
    };
    if check.status == SignatureStatus::Invalid {
        check.note = Some(if attrs_ok {
            "Signature invalide : la signature ne correspond pas au certificat.".into()
        } else {
            "Signature invalide : le contenu a été modifié après la signature (empreinte différente).".into()
        });
    }
    let validity = cert.tbs_certificate().validity();
    let (nb, na) = (unix(&validity.not_before), unix(&validity.not_after));
    let at = signing_time.or(msg_date);
    let valid_at = at.is_none_or(|t| t >= nb && t <= na);
    let (chain_state, trusted_by) = chain(cert, &bundled, keys);
    let emails = cert_emails(cert);
    let fp = cert_sha256(cert);
    check.fingerprint = Some(fp.clone());
    check.signer_ids = vec![cert.tbs_certificate().subject().to_string()];
    check.signer_emails = emails.clone();
    check.matches_from = (!emails.is_empty()).then(|| emails.iter().any(|e| from.contains(e)));
    check.key_expired = Some(!valid_at);
    check.verified_with = trusted_by
        .clone()
        .or(Some(format!("certificat joint {fp}")));
    check.cert = Some(CertInfo {
        subject: cert.tbs_certificate().subject().to_string(),
        issuer: cert.tbs_certificate().issuer().to_string(),
        serial: hex(cert.tbs_certificate().serial_number().as_bytes()),
        not_before: Some(iso(nb)),
        not_after: Some(iso(na)),
        emails,
        sha256: fp,
        pem: pem(cert),
        valid_at_signing: valid_at,
        chain: chain_state,
        trusted_by,
    });
    check
}
