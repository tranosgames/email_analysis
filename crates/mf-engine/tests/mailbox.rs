//! Feature 002 — session de boîte : éléments convertis conformes à libpff, provenance, empreinte,
//! intégrité de la preuve, et uniquement les éléments ouverts sont lus (FR-006).
#![allow(clippy::unwrap_used, clippy::panic)]

use mf_engine::{BoxSession, Keyring};
use std::path::PathBuf;

fn pst(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/pst")
        .join(rel)
}

fn sha256_file(p: &std::path::Path) -> String {
    mf_core::hashes(&std::fs::read(p).unwrap()).0
}

/// Références tirées de libpff (`pypff`) : identifiant, objet, expéditeur, tailles des pièces jointes.
const ENRON: [(u32, &str, &[u64]); 5] = [
    (2_097_220, "New Dominion LLC", &[29_184]),
    (2_097_252, "Enron Corp. Guaranty", &[34_816]),
    (2_097_316, "Enron Corp. Guaranty", &[35_840]),
    (2_097_188, "Cavell Energy Corporation", &[]),
    (2_097_284, "RE: ISDA Documents", &[]),
];

#[test]
fn enron_items_match_libpff() {
    let path = pst("large/enron-29.pst");
    if !path.exists() {
        eprintln!("ignoré : lancer tests/corpus/pst/fetch.sh");
        return;
    }
    let mut s = BoxSession::open_path(&path).unwrap();
    let sent = s
        .folders()
        .iter()
        .find(|f| f.path == ["bailey-s", "Sent Items"])
        .unwrap()
        .id;
    let rows = s.list(sent).unwrap();
    assert_eq!(rows.len(), 15);
    for (id, subject, att_sizes) in ENRON {
        let row = rows.iter().find(|r| r.id == id).unwrap();
        assert_eq!(row.subject.as_deref(), Some(subject), "ligne de liste {id}");
        assert_eq!(
            row.has_attachments,
            !att_sizes.is_empty(),
            "drapeau pièces jointes {id}"
        );
        let a = s.open_item(id, &Keyring::default()).unwrap();
        let m = &a.message;
        assert_eq!(m.subject.as_deref(), Some(subject));
        assert!(
            m.from
                .first()
                .and_then(|f| f.display_name.as_deref())
                .is_some_and(|n| n.contains("Bailey")),
            "{id} : {:?}",
            m.from
        );
        assert!(!m.headers.is_empty(), "{id} : en-têtes de transport");
        let sizes: Vec<u64> = m.attachments.iter().map(|x| x.size).collect();
        assert_eq!(sizes, att_sizes, "{id} : tailles des pièces jointes");
        for att in &m.attachments {
            assert_eq!(
                mf_core::hashes(&att.data).0,
                att.sha256,
                "{id} : empreinte de la pièce jointe"
            );
        }
        let p = m.provenance.as_ref().unwrap();
        assert_eq!(
            (p.node_id, p.folder_path.clone()),
            (id, vec!["bailey-s".to_string(), "Sent Items".to_string()])
        );
        assert!(
            m.verdict.is_some(),
            "{id} : analyse complète faite à l'ouverture"
        );
    }
    // FR-006 : seuls les 5 éléments ouverts ont été lus ; rouvrir ne relit pas.
    assert_eq!(s.items_read(), 5);
    s.open_item(ENRON[0].0, &Keyring::default()).unwrap();
    assert_eq!(s.items_read(), 5);
    let rows = s.list(sent).unwrap();
    let opened = rows.iter().filter(|r| r.verdict.is_some()).count();
    assert_eq!(
        opened, 5,
        "verdict reporté sur les lignes des éléments ouverts"
    );
}

#[test]
fn integrity_and_streamed_hash() {
    let path = pst("support.pst");
    let before = sha256_file(&path);
    let mut s = BoxSession::open_path(&path).unwrap();
    let f = s.folders().iter().find(|f| f.item_count > 0).unwrap().id;
    let first = s.list(f).unwrap()[0].id;
    let a = s.open_item(first, &Keyring::default()).unwrap();
    assert!(
        a.evidence.sha256.is_empty(),
        "empreinte pas encore calculée"
    );
    let mut steps = 0;
    let p = loop {
        steps += 1;
        let p = s.hash_step(200_000).unwrap();
        if p.sha256.is_some() {
            break p;
        }
    };
    assert!(steps > 3, "calcul par pas bornés");
    assert_eq!(p.sha256.as_deref(), Some(before.as_str()));
    // L'empreinte est reportée sur les éléments déjà ouverts et sur leur provenance.
    let (_, a) = s.analyzed().next().unwrap();
    assert_eq!(a.evidence.sha256, before);
    assert_eq!(a.message.provenance.as_ref().unwrap().store_sha256, before);
    drop(s);
    assert_eq!(sha256_file(&path), before, "la boîte n'est pas modifiée");
}

#[test]
fn every_item_of_small_boxes_converts() {
    for rel in [
        "32-bit.pst",
        "support.pst",
        "dist-list.pst",
        "passworded.pst",
    ] {
        let mut s = BoxSession::open_path(&pst(rel)).unwrap();
        let folders: Vec<u32> = s.folders().iter().map(|f| f.id).collect();
        let mut n = 0;
        for f in folders {
            for r in s.list(f).unwrap() {
                s.open_item(r.id, &Keyring::default())
                    .unwrap_or_else(|e| panic!("{rel} {} : {e}", r.id));
                n += 1;
            }
        }
        assert!(n > 0, "{rel}");
        assert_eq!(s.items_read(), n);
    }
}
