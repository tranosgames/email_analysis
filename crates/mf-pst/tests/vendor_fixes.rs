//! Correctifs de la copie embarquée d'`outlook-pst` (voir `vendor/outlook-pst/NOTICE.md`).
#![allow(clippy::unwrap_used)]

use outlook_pst::UnicodePstFile;
use outlook_pst::messaging::store::{Store, UnicodeStore};
use std::rc::Rc;

/// Correctif officiel d0f9f00 (« deadlock in root_hierarchy_table », repris en amont) : sans lui,
/// cet appel ne revient jamais.
#[test]
fn root_hierarchy_table_returns() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/pst/support.pst");
    let pst = UnicodePstFile::open(&path).unwrap();
    let store = UnicodeStore::read(Rc::new(pst)).unwrap();
    assert!(store.root_hierarchy_table().is_ok());
}
