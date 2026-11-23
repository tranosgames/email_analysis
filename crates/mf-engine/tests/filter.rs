//! Feature 002, Phase 4 (P022, P023) : filtres sur les tables de dossiers, sans lire un seul
//! élément ; critères sur les éléments ouverts ; indicateurs des seuls éléments analysés.
#![allow(clippy::unwrap_used, clippy::panic)]

use mf_core::{BoxFilter, ItemSummary, VerdictLevel};
use mf_engine::{BoxSession, Keyring};
use std::path::PathBuf;
use std::time::Instant;

fn pst(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/pst")
        .join(rel)
}

fn oracle_total(file: &str) -> u64 {
    let raw = std::fs::read_to_string(pst("expected.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["file"] == file)
        .unwrap_or_else(|| panic!("{file} absent de expected.json"))["total_items"]
        .as_u64()
        .unwrap()
}

/// Toutes les lignes de la boîte, par une autre voie que `filter` (liste dossier par dossier).
fn all_rows(s: &mut BoxSession) -> Vec<ItemSummary> {
    let ids: Vec<u32> = s
        .folders()
        .iter()
        .filter(|f| f.kind != "search")
        .map(|f| f.id)
        .collect();
    ids.into_iter().flat_map(|f| s.list(f).unwrap()).collect()
}

fn ids(rows: &[ItemSummary]) -> Vec<u32> {
    let mut v: Vec<u32> = rows.iter().map(|r| r.id).collect();
    v.sort_unstable();
    v
}

/// Critères des tables, vérifiés contre un filtrage écrit indépendamment dans le test.
fn check_table_filters(file: &str, name_word: &str, after: &str, before: &str) {
    let path = pst(file);
    if !path.exists() {
        eprintln!("ignoré : {file} absent (tests/corpus/pst/fetch.sh)");
        return;
    }
    let mut s = BoxSession::open_path(&path).unwrap();
    let rows = all_rows(&mut s);

    // Sans critère : toute la boîte, autant d'éléments que libpff.
    let t = Instant::now();
    let everything = s.filter(&BoxFilter::default()).unwrap();
    eprintln!(
        "{file} : {} lignes filtrées en {:?}",
        everything.len(),
        t.elapsed()
    );
    assert_eq!(everything.len() as u64, oracle_total(file), "{file}");
    assert_eq!(ids(&everything), ids(&rows));

    let lower = |o: &Option<String>| o.as_deref().unwrap_or("").to_lowercase();
    let date = |r: &ItemSummary| r.received.clone().or(r.sent.clone()).unwrap_or_default();

    // Nom d'expéditeur + période : exactement les lignes attendues.
    let f = BoxFilter {
        from_name: Some(name_word.to_uppercase()),
        after: Some(after.into()),
        before: Some(before.into()),
        ..Default::default()
    };
    let got = s.filter(&f).unwrap();
    let want: Vec<&ItemSummary> = rows
        .iter()
        .filter(|r| lower(&r.from_name).contains(name_word))
        .filter(|r| {
            let d = date(r);
            !d.is_empty() && &d[..10] >= after && &d[..10] <= before
        })
        .collect();
    assert!(!want.is_empty(), "{file} : jeu de test vide");
    assert_eq!(
        ids(&got),
        ids(&want.into_iter().cloned().collect::<Vec<_>>()),
        "{file} : expéditeur + période"
    );

    // Pièces jointes, taille, objet, destinataire, Message-ID, dossier.
    let with_att = s
        .filter(&BoxFilter {
            has_attachments: Some(true),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        with_att.len(),
        rows.iter().filter(|r| r.has_attachments).count()
    );
    let big = s
        .filter(&BoxFilter {
            min_size: Some(20_000),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        big.len(),
        rows.iter()
            .filter(|r| r.size.unwrap_or(0) >= 20_000)
            .count()
    );
    let sample = rows
        .iter()
        .find(|r| r.message_id.is_some() && r.subject.as_deref().is_some_and(|x| x.len() > 3))
        .unwrap();
    let by_mid = s
        .filter(&BoxFilter {
            message_id: sample.message_id.clone(),
            ..Default::default()
        })
        .unwrap();
    assert!(
        by_mid.iter().any(|r| r.id == sample.id),
        "{file} : Message-ID"
    );
    let by_subject = s
        .filter(&BoxFilter {
            subject: sample.subject.clone(),
            folder: Some(sample.folder),
            ..Default::default()
        })
        .unwrap();
    assert!(by_subject.iter().any(|r| r.id == sample.id));
    assert!(
        by_subject.iter().all(|r| r.folder == sample.folder),
        "{file} : dossier"
    );
    if let Some(to) = rows.iter().find_map(|r| r.to.clone()) {
        let word = to.split_whitespace().next().unwrap().to_string();
        let got = s
            .filter(&BoxFilter {
                to: Some(word.clone()),
                ..Default::default()
            })
            .unwrap();
        let lw = word.to_lowercase();
        let want = rows
            .iter()
            .filter(|r| lower(&r.to).contains(&lw) || lower(&r.cc).contains(&lw))
            .count();
        assert_eq!(got.len(), want, "{file} : destinataire « {word} »");
    }

    // FR-006 : filtrer toute la boîte n'a lu aucun élément.
    assert_eq!(s.items_read(), 0, "{file} : aucun élément lu");
}

#[test]
fn table_filters_support() {
    check_table_filters("support.pst", "support", "2015-01-01", "2015-12-31");
}

#[test]
fn table_filters_enron() {
    check_table_filters("large/enron-29.pst", "bailey", "2001-01-01", "2001-12-31");
}

#[test]
fn opened_items_only() {
    let path = pst("large/enron-29.pst");
    if !path.exists() {
        eprintln!("ignoré : enron-29.pst absent");
        return;
    }
    let mut s = BoxSession::open_path(&path).unwrap();
    let keys = Keyring::default();
    let opened = [2_097_220, 2_097_252, 2_097_188];
    for id in opened {
        s.open_item(id, &keys).unwrap();
    }
    assert_eq!(s.items_read(), 3);
    s.open_item(2_097_220, &keys).unwrap();
    assert_eq!(s.items_read(), 3, "rouvrir un élément ne le relit pas");

    // « Analysés seulement » : exactement ces trois, avec verdict et adresse.
    let mine = s
        .filter(&BoxFilter {
            analyzed_only: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ids(&mine), {
        let mut v = opened.to_vec();
        v.sort_unstable();
        v
    });
    assert!(
        mine.iter()
            .all(|r| r.verdict.is_some() && r.from_address.is_some())
    );

    // Verdict et domaine : seulement parmi les éléments ouverts.
    let all_levels = s
        .filter(&BoxFilter {
            verdict: vec![
                VerdictLevel::Legitimate,
                VerdictLevel::Suspicious,
                VerdictLevel::Malicious,
            ],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(all_levels.len(), 3);
    let domain = mine[0]
        .from_address
        .as_deref()
        .unwrap()
        .rsplit('@')
        .next()
        .unwrap()
        .to_string();
    let by_domain = s
        .filter(&BoxFilter {
            from_domain: Some(domain.to_uppercase()),
            ..Default::default()
        })
        .unwrap();
    assert!(!by_domain.is_empty() && by_domain.iter().all(|r| opened.contains(&r.id)));

    // Indicateurs : ceux des seuls éléments ouverts, avec leur provenance.
    let groups = s.iocs(None);
    // Un groupe par élément ouvert qui a des indicateurs (et par message joint qui en a).
    assert!(!groups.is_empty() && groups.len() >= 2, "{groups:?}");
    assert!(
        groups
            .iter()
            .all(|(label, _)| label.contains("enron-29.pst") && label.contains("élément #"))
    );
    assert!(groups.iter().all(|(_, iocs)| !iocs.is_empty()));
    let one = s.iocs(Some(&[2_097_252, 42]));
    assert!(!one.is_empty() && one.iter().all(|(l, _)| l.contains("#2097252")));
    assert_eq!(s.items_read(), 3, "filtres et indicateurs ne lisent rien");
}
