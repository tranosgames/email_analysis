//! Vérifications sur le corpus signé (`tests/corpus/tools/make_signed.py`), contre-vérifié
//! avec gpg et openssl lors de sa génération.
#![allow(clippy::unwrap_used)]

use mf_core::SignatureStatus::{self, *};
use mf_sig::Keyring;
use std::path::PathBuf;

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus")
        .join(rel)
}

fn keyring() -> Keyring {
    let mut k = Keyring::default();
    for f in ["keys/alice-pgp.asc", "keys/test-ca.pem"] {
        k.import(f, &std::fs::read(corpus(f)).unwrap()).unwrap();
    }
    k
}

fn run(file: &str, from: &str, keys: &Keyring) -> mf_core::SignatureCheck {
    let raw = std::fs::read(corpus(&format!("eml/{file}"))).unwrap();
    let v = mf_sig::check_entity(&raw, &[from.to_string()], Some(1_794_650_400), keys);
    assert_eq!(v.len(), 1, "{file} : {v:#?}");
    v.into_iter().next().unwrap()
}

#[test]
fn keyring_import() {
    let k = keyring();
    assert_eq!(k.entries.len(), 2);
    assert_eq!(k.entries[0].kind, "pgp");
    assert!(k.entries[0].label.contains("alice@signed.example"));
    assert_eq!(k.entries[0].fingerprint.len(), 40);
    assert!(k.entries[1].label.contains("MailForensics Test CA"));
}

#[test]
fn pgp_cases() {
    let k = keyring();
    let expect = |file: &str, from: &str, st: SignatureStatus, matches: Option<bool>| {
        let c = run(file, from, &k);
        assert_eq!(c.status, st, "{file} : {c:#?}");
        assert_eq!(c.matches_from, matches, "{file}");
        c
    };
    let v = expect(
        "pgp-signed-valid.eml",
        "alice@signed.example",
        Valid,
        Some(true),
    );
    assert_eq!(v.kind, "pgp_mime");
    assert_eq!(v.verified_with, Some(k.entries[0].fingerprint.clone()));
    assert!(v.signed_at.is_some());
    assert!(
        v.links
            .iter()
            .any(|l| l.url.starts_with("https://keys.openpgp.org/search?q="))
    );
    assert!(
        v.links
            .iter()
            .any(|l| l.url.contains("/.well-known/openpgpkey/hu/"))
    );
    expect(
        "pgp-signed-tampered.eml",
        "alice@signed.example",
        Invalid,
        Some(true),
    );
    expect(
        "pgp-signed-mismatch.eml",
        "bob@other.example",
        Valid,
        Some(false),
    );
    let u = expect(
        "pgp-signed-unknown-key.eml",
        "carol@unknown.example",
        UnknownKey,
        None,
    );
    assert_eq!(
        u.fingerprint.as_ref().map(String::len),
        Some(40),
        "empreinte de l'émetteur lue dans la signature"
    );
    let i = expect(
        "pgp-inline-valid.eml",
        "alice@signed.example",
        Valid,
        Some(true),
    );
    assert_eq!(i.kind, "pgp_inline");
    // Sans clé importée : clé inconnue, jamais « valide ».
    assert_eq!(
        run(
            "pgp-signed-valid.eml",
            "alice@signed.example",
            &Keyring::default()
        )
        .status,
        UnknownKey
    );
}

#[test]
fn smime_cases() {
    let k = keyring();
    let v = run("smime-signed-valid.eml", "dana@signed.example", &k);
    assert_eq!(v.status, Valid, "{v:#?}");
    let cert = v.cert.as_ref().unwrap();
    assert_eq!(cert.chain, "trusted");
    assert!(cert.valid_at_signing);
    assert_eq!(v.matches_from, Some(true));
    assert!(cert.pem.starts_with("-----BEGIN CERTIFICATE-----"));
    // Sans l'autorité importée : intégrité vérifiée, autorité inconnue.
    let n = run(
        "smime-signed-valid.eml",
        "dana@signed.example",
        &Keyring::default(),
    );
    assert_eq!(n.status, Valid);
    assert_eq!(n.cert.unwrap().chain, "unknown_ca");
    assert_eq!(
        run("smime-signed-tampered.eml", "dana@signed.example", &k).status,
        Invalid
    );
    let e = run("smime-signed-expired.eml", "erin@signed.example", &k);
    assert_eq!(e.status, Valid, "signature ECDSA intègre");
    assert_eq!(e.key_algorithm.as_deref(), Some("ECDSA"));
    assert_eq!(e.key_expired, Some(true));
    assert!(!e.cert.unwrap().valid_at_signing);
    let o = run("smime-opaque-valid.eml", "dana@signed.example", &k);
    assert_eq!((o.kind.as_str(), o.status), ("smime_opaque", Valid));
}

#[test]
fn unsigned_message_has_no_signature() {
    let raw = std::fs::read(corpus("eml/phishing-auth.eml")).unwrap();
    assert!(mf_sig::check_entity(&raw, &[], None, &keyring()).is_empty());
}

#[test]
fn verification_link_allowlist() {
    for ok in [
        "https://keys.openpgp.org/search?q=ABC",
        "https://keyserver.ubuntu.com/pks/lookup?search=0xABC&op=index",
        "https://keyoxide.org/abc",
        "https://signed.example/.well-known/openpgpkey/hu/iy9q119?l=a",
    ] {
        assert!(mf_sig::is_verification_link(ok), "{ok}");
    }
    for bad in [
        "http://keys.openpgp.org/",
        "https://evil.example/login",
        "https://keys.openpgp.org.evil.example/",
        "file:///etc/passwd",
        "https://evil.example/x/.well-known/openpgpkey/",
        "javascript:alert(1)",
    ] {
        assert!(!mf_sig::is_verification_link(bad), "{bad}");
    }
    // Chaque lien proposé par l'analyse passe la liste blanche.
    let raw = std::fs::read(corpus("eml/pgp-signed-valid.eml")).unwrap();
    let c = &mf_sig::check_entity(&raw, &["alice@signed.example".into()], None, &keyring())[0];
    assert!(c.links.len() >= 5);
    assert!(
        c.links.iter().all(|l| mf_sig::is_verification_link(&l.url)),
        "{:?}",
        c.links
    );
}
