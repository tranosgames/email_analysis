//! SC-002 : par dossier, nombres d'éléments et de pièces jointes identiques à libpff
//! (`tests/corpus/pst/expected.json`, produit par `oracle.py`). Les gros fichiers de `large/`
//! sont vérifiés s'ils ont été téléchargés (`fetch.sh`).
#![allow(clippy::unwrap_used, clippy::panic)]

use mf_pst::PstBox;
use std::path::PathBuf;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/pst")
}

/// (nom du dossier, éléments, pièces jointes) pour chaque dossier non vide, triés.
fn ours(b: &PstBox) -> Vec<(String, u64, u64)> {
    let mut v = Vec::new();
    for f in b.folders() {
        let items = b.list(f.id).unwrap();
        if items.is_empty() {
            continue;
        }
        let mut atts = 0;
        for it in &items {
            atts += b
                .open_item(it.id, Some(it.folder), "")
                .unwrap()
                .attachments
                .len() as u64;
        }
        v.push((f.name.clone(), items.len() as u64, atts));
    }
    v.sort();
    v
}

#[test]
fn counts_match_libpff() {
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(corpus().join("expected.json")).unwrap())
            .unwrap();
    let mut checked = 0;
    for f in expected["files"].as_array().unwrap() {
        let rel = f["file"].as_str().unwrap();
        let path = corpus().join(rel);
        if !path.exists() {
            eprintln!("ignoré (absent, lancer fetch.sh) : {rel}");
            continue;
        }
        let b = PstBox::open_path(&path).unwrap_or_else(|e| panic!("{rel} : {e}"));
        let mut theirs: Vec<(String, u64, u64)> = f["folders_with_items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["name"].as_str().unwrap().to_string(),
                    d["items"].as_u64().unwrap(),
                    d["attachments"].as_u64().unwrap(),
                )
            })
            .collect();
        theirs.sort();
        let mine = ours(&b);
        assert_eq!(
            mine, theirs,
            "{rel} : dossiers (nom, éléments, pièces jointes)"
        );
        assert_eq!(
            b.info().encoding,
            f["encoding"].as_str().unwrap(),
            "{rel} : encodage"
        );
        checked += 1;
    }
    assert!(checked >= 4, "au moins les 4 PST versionnés");
}

#[test]
fn formats_and_metadata() {
    let b = PstBox::open_path(&corpus().join("32-bit.pst")).unwrap();
    assert_eq!(b.info().format, "ansi");
    let b = PstBox::open_path(&corpus().join("support.pst")).unwrap();
    assert_eq!(b.info().format, "unicode");
    assert!(!b.info().password_protected);
    assert!(
        PstBox::open_path(&corpus().join("passworded.pst"))
            .unwrap()
            .info()
            .password_protected
    );
    let ost = corpus().join("large/example-2013.ost");
    if ost.exists() {
        let b = PstBox::open_path(&ost).unwrap();
        assert_eq!(b.info().format, "ost4k");
        assert!(
            !b.info().password_protected,
            "0xFFFFFFFF n'est pas un mot de passe"
        );
    }
}

/// Arborescence : sommet utilisateur retrouvé (y compris dans un OST), dossiers spéciaux typés,
/// dossiers de recherche exclus du total, aucun élément lu à l'ouverture ni au listage.
#[test]
fn tree_kinds_and_totals() {
    for (rel, inbox_path) in [
        ("support.pst", vec!["Posta in arrivo"]),
        ("large/enron-29.pst", vec!["bailey-s", "Inbox"]),
        ("large/outlook-com-a.ost", vec!["Inbox"]),
        ("large/example-2013.ost", vec!["Inbox"]),
    ] {
        let path = corpus().join(rel);
        if !path.exists() {
            continue;
        }
        let b = PstBox::open_path(&path).unwrap();
        assert!(
            b.folders()
                .iter()
                .any(|f| f.kind == "inbox" && f.path == inbox_path),
            "{rel} : boîte de réception {inbox_path:?} : {:?}",
            b.folders()
                .iter()
                .map(|f| (&f.kind, &f.path))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            b.folders().iter().filter(|f| f.kind == "ipm").count(),
            1,
            "{rel}"
        );
        let rows: u64 = b
            .folders()
            .iter()
            .map(|f| b.list(f.id).unwrap().len() as u64)
            .sum();
        assert_eq!(
            b.info().items,
            rows,
            "{rel} : total hors dossiers de recherche"
        );
        assert_eq!(b.items_read(), 0, "{rel} : aucun élément lu sans ouverture");
    }
}
