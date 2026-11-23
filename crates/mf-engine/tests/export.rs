//! Feature 002, Phase 7 (P037, P038) : export `.msg` fidèle et `.eml` reconstruit, manifeste,
//! refus. Aller-retour : chaque `.msg` exporté est rouvert par notre lecteur `.msg` et comparé à
//! l'élément lu dans la boîte (SC-006).
#![allow(clippy::unwrap_used, clippy::panic)]

use mf_core::Message;
use mf_engine::export::{ExportFormat, Manifest, prepare_export_dir};
use mf_engine::{BoxSession, Keyring};
use mf_pst::{ByteSource, MemSource};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

fn pst(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/pst")
        .join(rel)
}

type Files = BTreeMap<String, Vec<u8>>;

fn export(s: &mut BoxSession, ids: &[u32], format: ExportFormat) -> (Files, Manifest) {
    let mut files = Files::new();
    let m = s
        .export(
            ids,
            format,
            "2026-11-23T00:00:00Z",
            &Keyring::default(),
            None,
            &mut |n, b| {
                files.insert(n.to_string(), b.to_vec());
                Ok(())
            },
        )
        .unwrap();
    (files, m)
}

fn addrs(v: &[mf_core::Address]) -> Vec<(Option<String>, Option<String>)> {
    v.iter()
        .map(|a| (a.display_name.clone(), a.address.clone()))
        .collect()
}

fn atts(m: &Message) -> Vec<(String, String, bool)> {
    m.attachments
        .iter()
        .map(|a| (a.filename.clone(), a.sha256.clone(), a.embedded.is_some()))
        .collect()
}

/// Champs clés identiques entre l'élément de la boîte et le fichier rouvert (SC-006).
fn same_message(orig: &Message, back: &Message, label: &str, eml: bool) {
    assert_eq!(orig.subject, back.subject, "{label} : objet");
    // Même valeur ; le lecteur .eml retire les chevrons, le lecteur .msg les garde.
    let mid = |m: &Message| {
        m.message_id
            .as_deref()
            .map(|x| x.trim_matches(['<', '>']).to_string())
    };
    assert_eq!(mid(orig), mid(back), "{label} : Message-ID");
    // Date : à la seconde pour un .eml (RFC 2822 ne porte pas les fractions).
    let date = |m: &Message| {
        m.date_utc.as_deref().map(|d| {
            if eml {
                d.get(..19).unwrap_or(d).to_string()
            } else {
                d.to_string()
            }
        })
    };
    assert_eq!(date(orig), date(back), "{label} : date");
    if !eml {
        // .msg : en-têtes de transport repris octet pour octet, destinataires identiques.
        let h = |m: &Message| {
            m.headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(h(orig), h(back), "{label} : en-têtes de transport");
        assert_eq!(addrs(&orig.from), addrs(&back.from), "{label} : expéditeur");
        assert_eq!(addrs(&orig.to), addrs(&back.to), "{label} : À");
        assert_eq!(addrs(&orig.cc), addrs(&back.cc), "{label} : Cc");
        assert_eq!(orig.body_text, back.body_text, "{label} : corps texte");
    }
    assert_eq!(
        atts(orig),
        atts(back),
        "{label} : pièces jointes et leurs empreintes"
    );
}

fn round_trip(rel: &str, pick: usize) {
    let path = pst(rel);
    if !path.exists() {
        eprintln!("ignoré : {rel} absent (tests/corpus/pst/fetch.sh)");
        return;
    }
    let mut s = BoxSession::open_path(&path).unwrap();
    // Éléments avec pièces jointes d'abord (les plus exigeants), puis les autres.
    let mut rows: Vec<_> = s
        .folders()
        .iter()
        .filter(|f| f.kind != "search")
        .map(|f| f.id)
        .collect::<Vec<_>>()
        .into_iter()
        .flat_map(|f| s.list(f).unwrap())
        .filter(|r| mf_engine::is_mail(r.message_class.as_deref()))
        .collect();
    rows.sort_by_key(|r| (!r.has_attachments, r.id));
    let ids: Vec<u32> = rows.iter().take(pick).map(|r| r.id).collect();

    for format in [ExportFormat::Msg, ExportFormat::Eml] {
        let (files, manifest) = export(&mut s, &ids, format);
        let label = format!("{rel} .{}", format.ext());
        // Manifeste complet : chaque fichier, son empreinte, la boîte revérifiée.
        assert!(
            manifest.errors.is_empty(),
            "{label} : {:?}",
            manifest.errors
        );
        assert_eq!(manifest.items.len(), ids.len(), "{label}");
        assert!(manifest.store.verified);
        let whole = mf_pst::hash::digests(&mut mf_pst::FileSource::open(&path).unwrap()).unwrap();
        assert_eq!(
            manifest.store.sha256, whole.sha256,
            "{label} : empreinte de la boîte"
        );
        assert!(files.contains_key("manifest.json") && files.contains_key("manifest.csv"));
        let parsed: Manifest = serde_json::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(parsed, manifest);
        assert_eq!(manifest.to_csv().lines().count(), ids.len() + 1);

        for it in &manifest.items {
            let bytes = &files[&it.file];
            assert_eq!(
                mf_core::hashes(bytes).0,
                it.sha256,
                "{label} : empreinte du fichier"
            );
            assert_eq!(it.item_sha256.len(), 64);
            assert_eq!(
                it.named_properties_skipped, 0,
                "{label} : propriétés nommées reprises avec la table des noms"
            );
            let orig = s
                .open_item(it.id, &Keyring::default())
                .unwrap()
                .message
                .clone();
            let back = mf_engine::open_bytes(&it.file, bytes.clone())
                .unwrap_or_else(|e| panic!("{label} #{} : réouverture : {e}", it.id))
                .message;
            same_message(
                &orig,
                &back,
                &format!("{label} #{}", it.id),
                format == ExportFormat::Eml,
            );
            if format == ExportFormat::Msg {
                // Lecteur indépendant : objet, destinataires, pièces jointes et leurs octets.
                let o = msg_parser::Outlook::from_slice(bytes)
                    .unwrap_or_else(|e| panic!("{label} #{} : msg_parser : {e:?}", it.id));
                assert_eq!(
                    o.subject,
                    orig.subject.clone().unwrap_or_default(),
                    "{label} #{} : objet (msg_parser)",
                    it.id
                );
                assert_eq!(
                    o.to.len(),
                    orig.to.len(),
                    "{label} #{} : À (msg_parser)",
                    it.id
                );
                assert_eq!(
                    o.attachments.len(),
                    orig.attachments.len(),
                    "{label} #{} : PJ (msg_parser)",
                    it.id
                );
                for (a, r) in orig.attachments.iter().zip(&o.attachments) {
                    if a.embedded.is_none() {
                        assert_eq!(
                            mf_core::hashes(&r.payload_bytes).0,
                            a.sha256,
                            "{label} #{} : octets de {} (msg_parser)",
                            it.id,
                            a.filename
                        );
                    }
                }
            }
            if format == ExportFormat::Eml {
                assert!(
                    back.headers
                        .iter()
                        .any(|h| h.name == "X-MailForensics-Reconstructed" && h.value == "pst"),
                    "{label} : marqué comme reconstruit"
                );
                assert!(it.reconstructed);
            }
        }
        // Même sélection, mêmes fichiers : l'export est reproductible (empreintes stables).
        let (again, _) = export(&mut s, &ids, format);
        for it in &manifest.items {
            assert_eq!(
                files[&it.file], again[&it.file],
                "{label} : export reproductible"
            );
        }
        eprintln!(
            "{label} : {} élément(s) exportés, rouverts et identiques",
            ids.len()
        );
    }
}

#[test]
fn round_trip_support() {
    round_trip("support.pst", 17);
}

#[test]
fn round_trip_enron() {
    round_trip("large/enron-29.pst", 10);
}

#[test]
fn round_trip_ost() {
    round_trip("large/outlook-com-c.ost", 10);
}

#[test]
fn refusals() {
    let tmp = std::env::temp_dir().join(format!("mf-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("preuve")).unwrap();
    let evidence = tmp.join("preuve/boite.pst");
    std::fs::copy(pst("support.pst"), &evidence).unwrap();
    // Dossier de la preuve et ses sous-dossiers.
    let e = prepare_export_dir(&tmp.join("preuve"), &evidence)
        .err()
        .unwrap();
    assert!(e.contains("dossier de la preuve"), "{e}");
    let e = prepare_export_dir(&tmp.join("preuve/export"), &evidence)
        .err()
        .unwrap();
    assert!(e.contains("dossier de la preuve"), "{e}");
    // Dossier non vide.
    std::fs::create_dir_all(tmp.join("plein")).unwrap();
    std::fs::write(tmp.join("plein/autre.txt"), b"x").unwrap();
    let e = prepare_export_dir(&tmp.join("plein"), &evidence)
        .err()
        .unwrap();
    assert!(e.contains("n'est pas vide"), "{e}");
    // Dossier neuf : créé et accepté.
    assert!(prepare_export_dir(&tmp.join("export"), &evidence).is_ok());
    std::fs::remove_dir_all(&tmp).unwrap();

    // Boîte modifiée après l'ouverture : rien n'est exporté.
    let bytes = Rc::new(RefCell::new(std::fs::read(pst("support.pst")).unwrap()));
    let shared = bytes.clone();
    let mut s = BoxSession::open_with(
        move || Ok(Box::new(MemSource(shared.borrow().clone())) as Box<dyn ByteSource>),
        "support.pst",
    )
    .unwrap();
    s.hash_all().unwrap();
    let id = s.filter(&Default::default()).unwrap()[0].id;
    let last = bytes.borrow().len() - 1;
    bytes.borrow_mut()[last] ^= 0xFF;
    let mut written = 0;
    let e = s
        .export(
            &[id],
            ExportFormat::Msg,
            "t",
            &Keyring::default(),
            None,
            &mut |_, _| {
                written += 1;
                Ok(())
            },
        )
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("a changé depuis son ouverture"), "{e}");
    assert_eq!(written, 0, "aucun fichier écrit");
}

#[test]
fn appointments_export_as_msg() {
    let path = pst("large/outlook-com-c.ost");
    if !path.exists() {
        eprintln!("ignoré : outlook-com-c.ost absent");
        return;
    }
    let mut s = BoxSession::open_path(&path).unwrap();
    let ids: Vec<u32> = s
        .filter(&Default::default())
        .unwrap()
        .into_iter()
        .filter(|r| r.message_class.as_deref() == Some("IPM.Appointment"))
        .take(20)
        .map(|r| r.id)
        .collect();
    assert_eq!(ids.len(), 20);
    let (files, manifest) = export(&mut s, &ids, ExportFormat::Msg);
    assert!(manifest.errors.is_empty(), "{:?}", manifest.errors);
    for it in &manifest.items {
        let orig = s
            .open_item(it.id, &Keyring::default())
            .unwrap()
            .message
            .clone();
        let back = mf_engine::open_bytes(&it.file, files[&it.file].clone())
            .unwrap()
            .message;
        assert_eq!(orig.subject, back.subject, "rendez-vous #{}", it.id);
        assert_eq!(atts(&orig), atts(&back), "rendez-vous #{}", it.id);
    }
}
