//! Lecture forensic des boîtes Outlook `.pst` / `.ost` (feature 002), en lecture seule.
//!
//! Seuls sont lus : l'arborescence à l'ouverture, la table d'un dossier quand on le liste, et un
//! message quand on l'ouvre ([`PstBox::open_item`]). Le reste de la boîte n'est jamais parcouru,
//! sauf par le calcul d'empreinte, qui lit les octets sans les interpréter ([`hash`]).
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]

pub mod hash;
mod item;
mod msg_writer;
pub use msg_writer::MsgReport;
pub mod source;
mod store;

pub use source::{ByteSource, FileSource, MemSource};
pub use store::{PstBox, PstError};

/// Le fichier ressemble-t-il à une boîte PST/OST (signature `!BDN`) ?
pub fn looks_like_pst(head: &[u8]) -> bool {
    head.starts_with(b"!BDN")
}
