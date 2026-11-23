//! Cible de fuzzing `pst_open` (feature 002, P042) : des octets quelconques ouverts comme une
//! boîte, puis tout ce qu'une session parcourt — arborescence, tables de dossiers, filtre sur
//! toute la boîte, ouverture et analyse de quelques éléments, export `.msg`. Aucune entrée ne doit
//! faire paniquer, boucler sans fin ni épuiser la mémoire.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mf_engine::{BoxSession, Keyring};
use mf_pst::{ByteSource, MemSource};

fuzz_target!(|data: &[u8]| {
    let bytes = data.to_vec();
    let Ok(mut s) = BoxSession::open_with(
        move || Ok(Box::new(MemSource(bytes.clone())) as Box<dyn ByteSource>),
        "fuzz.pst",
    ) else {
        return;
    };
    let folders: Vec<u32> = s.folders().iter().map(|f| f.id).collect();
    let mut items = Vec::new();
    for f in folders.iter().take(64) {
        if let Ok(rows) = s.list(*f) {
            items.extend(rows.into_iter().take(8).map(|r| r.id));
        }
    }
    let _ = s.filter(&mf_core::BoxFilter {
        text: Some("a".into()),
        ..Default::default()
    });
    let keys = Keyring::default();
    for id in items.iter().take(8) {
        let _ = s.open_item(*id, &keys);
    }
    let _ = s.export(
        &items[..items.len().min(4)],
        mf_engine::export::ExportFormat::Msg,
        "fuzz",
        &keys,
        None,
        &mut |_, _| Ok(()),
    );
    let _ = s.hash_all();
});
