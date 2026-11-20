//! Accès générique aux propriétés MAPI d'un objet (message, destinataire, pièce jointe), quel que
//! soit le conteneur : fichier `.msg` (fichier composé) ou boîte `.pst` / `.ost` (feature 002).
//! La conversion vers le modèle unifié ([`crate::convert`]) ne dépend que de ce trait.

use chrono::{DateTime, Utc};
use std::borrow::Cow;

pub trait PropertySource: Sized {
    /// Propriété texte (PT_UNICODE, ou PT_STRING8 décodée selon la page de code de l'objet).
    fn string(&self, id: u16) -> Option<String>;
    /// Propriété binaire (PT_BINARY).
    fn binary(&self, id: u16) -> Option<Cow<'_, [u8]>>;
    /// Décode un corps binaire (PR_HTML) selon la page de code Internet de l'objet.
    fn decode_internet(&self, bytes: &[u8]) -> String;
    fn u32(&self, id: u16) -> Option<u32>;
    fn bool(&self, id: u16) -> Option<bool>;
    /// PT_SYSTIME en UTC.
    fn time(&self, id: u16) -> Option<DateTime<Utc>>;
    /// Destinataires du message, dans l'ordre.
    fn recipients(&self) -> Vec<Self>;
    /// Pièces jointes du message, dans l'ordre.
    fn attachments(&self) -> Vec<Self>;
    /// Message embarqué d'une pièce jointe (méthode 5).
    fn embedded(&self) -> Option<Self>;
    /// Taille totale des données de l'objet (pour un message embarqué).
    fn total_len(&self) -> u64;
    /// Représentation canonique d'un message embarqué, base de son empreinte.
    fn canonical_bytes(&self) -> Vec<u8>;
}

/// FILETIME (intervalles de 100 ns depuis 1601-01-01) → UTC.
pub fn filetime(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let unix_100ns = i128::from(ft) - 116_444_736_000_000_000;
    let secs = i64::try_from(unix_100ns.div_euclid(10_000_000)).ok()?;
    let nanos = u32::try_from(unix_100ns.rem_euclid(10_000_000) * 100).ok()?;
    DateTime::from_timestamp(secs, nanos)
}

/// Décodage d'un texte ANSI selon une page de code Windows (défaut : 1252).
pub fn decode_codepage(bytes: &[u8], codepage: Option<u32>) -> String {
    let label = match codepage.unwrap_or(1252) {
        65001 => "utf-8".to_string(),
        20127 | 1252 => "windows-1252".to_string(),
        932 => "shift_jis".to_string(),
        936 => "gbk".to_string(),
        949 => "euc-kr".to_string(),
        950 => "big5".to_string(),
        cp @ 28591..=28606 => format!("iso-8859-{}", cp - 28590),
        cp => format!("windows-{cp}"),
    };
    let enc =
        encoding_rs::Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::WINDOWS_1252);
    enc.decode(bytes).0.into_owned()
}
