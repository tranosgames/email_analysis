//! Constitution IV : un PST tronqué ou altéré produit des erreurs, jamais de panique ni de
//! consommation mémoire démesurée. Variantes déterministes de `support.pst`.
#![allow(clippy::unwrap_used, clippy::panic)]

use mf_pst::{MemSource, PstBox};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn exercise(data: Vec<u8>) {
    let shared = std::rc::Rc::new(data);
    let Ok(b) = PstBox::open_with(
        || Ok(Box::new(MemSource((*shared).clone())) as Box<dyn mf_pst::ByteSource>),
        "variante.pst",
    ) else {
        return;
    };
    for f in b.folders().to_vec() {
        if let Ok(items) = b.list(f.id) {
            for it in items.iter().take(5) {
                let _ = b.open_item(it.id, Some(it.folder), "");
            }
        }
    }
}

/// Générateur pseudo-aléatoire reproductible (xorshift).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn truncated_and_corrupted_never_panic() {
    let original = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/pst/support.pst"),
    )
    .unwrap();
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let mut variants: Vec<(String, Vec<u8>)> = Vec::new();
    for cut in [
        0,
        1,
        100,
        511,
        512,
        4096,
        20_000,
        100_000,
        400_000,
        original.len() - 1,
    ] {
        variants.push((
            format!("tronqué à {cut}"),
            original[..cut.min(original.len())].to_vec(),
        ));
    }
    for i in 0..150 {
        let mut v = original.clone();
        let flips = 1 + (rng.next() % 16) as usize;
        for _ in 0..flips {
            let pos = (rng.next() % v.len() as u64) as usize;
            v[pos] = (rng.next() & 0xFF) as u8;
        }
        variants.push((format!("altération {i}"), v));
    }
    let mut panics = Vec::new();
    for (name, data) in variants {
        if catch_unwind(AssertUnwindSafe(|| exercise(data))).is_err() {
            panics.push(name);
        }
    }
    assert!(
        panics.is_empty(),
        "{} variantes paniquent : {:?}",
        panics.len(),
        &panics[..panics.len().min(10)]
    );
}
