//! Feature 002, P036 (FR-009) : boîte tronquée, endommagée ou qui n'est pas une boîte Outlook.
//! Message explicite quand rien ne se lit ; sinon ouverture partielle, la coupure et chaque dossier
//! ou élément illisible étant signalés, jamais ignorés en silence. Aucune panique.
#![allow(clippy::unwrap_used, clippy::panic)]

use mf_core::BoxFilter;
use mf_engine::{BoxSession, Keyring};
use mf_pst::{ByteSource, MemSource};
use std::path::PathBuf;

fn pst(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/pst")
        .join(rel)
}

fn open_bytes(bytes: Vec<u8>, name: &str) -> Result<BoxSession, String> {
    BoxSession::open_with(
        move || Ok(Box::new(MemSource(bytes.clone())) as Box<dyn ByteSource>),
        name,
    )
    .map_err(|e| e.to_string())
}

fn cut(rel: &str, n: usize) -> Vec<u8> {
    let mut b = std::fs::read(pst(rel)).unwrap();
    b.truncate(n);
    b
}

#[test]
fn explicit_reasons_when_nothing_is_readable() {
    let e = open_bytes(cut("support.pst", 1_033_216 * 30 / 100), "coupe.pst")
        .err()
        .unwrap();
    assert!(
        e.contains("tronquée") && e.contains("30 %") && e.contains("arborescence"),
        "{e}"
    );
    let e = open_bytes(b"hello".to_vec(), "x.pst").err().unwrap();
    assert!(e.contains("trop court"), "{e}");
    let e = open_bytes(vec![0x41; 4096], "faux.ost").err().unwrap();
    assert!(
        e.contains("!BDN") && e.contains("pas une boîte Outlook"),
        "{e}"
    );
    // En-tête valide d'une version inconnue.
    let mut v = std::fs::read(pst("support.pst")).unwrap();
    v[0x0A] = 99;
    let e = open_bytes(v, "futur.pst").err().unwrap();
    assert!(
        e.contains("non pris en charge") && e.contains("version 99"),
        "{e}"
    );
}

/// Ouvre ce qui se lit, puis parcourt tout : dossiers, éléments, filtre sur toute la boîte.
fn walk_partial(mut s: BoxSession, label: &str) -> (usize, usize) {
    let info = s.info().clone();
    assert_eq!(
        info.unreadable[0].kind, "store",
        "{label} : la coupure est signalée en premier"
    );
    assert!(info.unreadable[0].reason.contains("tronquée"));
    let folders: Vec<u32> = s
        .folders()
        .iter()
        .filter(|f| f.kind != "search")
        .map(|f| f.id)
        .collect();
    let (mut ok, mut bad) = (0, 0);
    let mut bad_folders = Vec::new();
    for f in &folders {
        match s.list(*f) {
            Ok(rows) => {
                for r in rows {
                    match s.open_item(r.id, &Keyring::default()) {
                        Ok(_) => ok += 1,
                        Err(_) => bad += 1,
                    }
                }
            }
            Err(_) => bad_folders.push(*f),
        }
    }
    let late = s.unreadable();
    // Chaque échec est consigné (dossier ou élément), avec sa raison.
    let partial: Vec<u32> = late
        .iter()
        .filter(|u| u.kind == "folder" && !bad_folders.contains(&u.node_id))
        .map(|u| u.node_id)
        .collect();
    assert_eq!(
        late.iter().filter(|u| u.kind == "folder").count(),
        bad_folders.len() + partial.len(),
        "{label}"
    );
    assert_eq!(
        late.iter().filter(|u| u.kind == "item").count(),
        bad,
        "{label}"
    );
    assert!(late.iter().all(|u| !u.reason.is_empty()));
    // Le filtre sur toute la boîte rend les dossiers qu'il n'a pas pu parcourir.
    let (_, skipped) = s.filter_report(&BoxFilter::default()).unwrap();
    let mut got: Vec<u32> = skipped.iter().map(|u| u.node_id).collect();
    got.sort_unstable();
    bad_folders.extend(partial);
    bad_folders.sort_unstable();
    assert_eq!(
        got, bad_folders,
        "{label} : dossiers illisibles ou partiels signalés"
    );
    eprintln!(
        "{label} : {ok} élément(s) lus, {bad} illisible(s), {} dossier(s) illisible(s)",
        bad_folders.len()
    );
    (ok, bad + bad_folders.len())
}

#[test]
fn partial_ansi_box() {
    let s = open_bytes(cut("32-bit.pst", 40_000), "32-bit-coupe.pst").unwrap();
    walk_partial(s, "32-bit.pst à 61 %");
}

#[test]
fn ost_cut_in_free_space_stays_readable() {
    let p = pst("large/outlook-com-a.ost");
    if !p.exists() {
        eprintln!("ignoré : outlook-com-a.ost absent (fetch.sh)");
        return;
    }
    // La seconde moitié de cet OST est de l'espace libre : coupé à 48 %, tout se lit encore, mais
    // la coupure reste signalée.
    let s = open_bytes(cut("large/outlook-com-a.ost", 8_000_000), "ost-coupe.ost").unwrap();
    let (ok, bad) = walk_partial(s, "outlook-com-a.ost à 48 %");
    assert_eq!((ok, bad), (214, 0));
}

#[test]
fn damaged_middle_of_enron() {
    let p = pst("large/enron-29.pst");
    if !p.exists() {
        eprintln!("ignoré : enron-29.pst absent (fetch.sh)");
        return;
    }
    // Disque abîmé : 3 Mo remis à zéro au milieu de la boîte (taille inchangée).
    let mut b = std::fs::read(&p).unwrap();
    b[10_000_000..13_000_000].fill(0);
    let mut s = open_bytes(b, "enron-abime.pst").unwrap();
    assert!(
        s.info().unreadable.iter().all(|u| u.kind != "store"),
        "pas de coupure"
    );
    let folders: Vec<u32> = s
        .folders()
        .iter()
        .filter(|f| f.kind != "search")
        .map(|f| f.id)
        .collect();
    let (mut ok, mut bad) = (0, 0);
    for f in folders {
        let Ok(rows) = s.list(f) else { continue };
        for r in rows {
            match s.open_item(r.id, &Keyring::default()) {
                Ok(_) => ok += 1,
                Err(_) => bad += 1,
            }
        }
    }
    let late = s.unreadable();
    // Les lignes perdues dans les tables sont signalées : chaque élément annoncé est soit lu, soit
    // illisible, soit compté dans un dossier signalé comme partiellement lisible.
    let missing: usize = late
        .iter()
        .filter(|u| u.kind == "folder")
        .map(|u| {
            let n: Vec<usize> = u
                .reason
                .split(|c: char| !c.is_ascii_digit())
                .filter_map(|x| x.parse().ok())
                .collect();
            n[1] - n[0]
        })
        .sum();
    assert_eq!(
        ok + bad + missing,
        s.info().items as usize,
        "rien ne disparaît en silence"
    );
    eprintln!(
        "enron abîmée : {ok} élément(s) lus, {bad} illisible(s), {} signalement(s)",
        late.len()
    );
    assert!(
        ok > 1000 && bad > 0,
        "une partie se lit, une partie non ({ok}/{bad})"
    );
    assert_eq!(late.iter().filter(|u| u.kind == "item").count(), bad);
    assert!(
        late.iter()
            .filter(|u| u.kind == "item")
            .all(|u| !u.folder_path.is_empty()),
        "provenance de chaque élément illisible"
    );
}
