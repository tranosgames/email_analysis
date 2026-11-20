//! Accès aux propriétés MAPI d'un objet (message, destinataire, pièce jointe) dans un MSG.

use crate::Streams;
use crate::source::{PropertySource, decode_codepage, filetime};
use chrono::{DateTime, Utc};
use std::borrow::Cow;
use std::collections::HashMap;

const PT_LONG: u16 = 0x0003;
const PT_BOOLEAN: u16 = 0x000B;
const PT_OBJECT: u16 = 0x000D;
const PT_STRING8: u16 = 0x001E;
const PT_UNICODE: u16 = 0x001F;
const PT_SYSTIME: u16 = 0x0040;
const PT_BINARY: u16 = 0x0102;

const PR_INTERNET_CPID: u16 = 0x3FDE;
const PR_MESSAGE_CODEPAGE: u16 = 0x3FFD;

/// Un objet MAPI : un préfixe de chemin dans le fichier composé + ses propriétés fixes.
pub(crate) struct Node<'s> {
    streams: &'s Streams,
    base: String,
    fixed: HashMap<u32, [u8; 8]>,
}

impl<'s> Node<'s> {
    pub fn root(streams: &'s Streams) -> Self {
        Self::new(streams, String::new(), 32)
    }

    /// `header_len` : 32 (message racine), 24 (message embarqué), 8 (destinataire / PJ).
    fn new(streams: &'s Streams, base: String, header_len: usize) -> Self {
        let mut fixed = HashMap::new();
        if let Some(buf) = streams.get(&format!("{base}/__properties_version1.0")) {
            for e in buf.get(header_len..).unwrap_or_default().chunks_exact(16) {
                let tag = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                let mut v = [0u8; 8];
                v.copy_from_slice(&e[8..16]);
                fixed.insert(tag, v);
            }
        }
        Self {
            streams,
            base,
            fixed,
        }
    }

    fn stream(&self, id: u16, ptype: u16) -> Option<&'s [u8]> {
        self.streams
            .get(&format!("{}/__substg1.0_{id:04X}{ptype:04X}", self.base))
            .map(Vec::as_slice)
    }

    fn codepage(&self) -> Option<u32> {
        self.fixed_u32(PR_INTERNET_CPID)
            .or_else(|| self.fixed_u32(PR_MESSAGE_CODEPAGE))
    }

    /// Propriété texte : UTF-16LE (PT_UNICODE) ou ANSI selon la page de code (PT_STRING8).
    pub fn string(&self, id: u16) -> Option<String> {
        if let Some(b) = self.stream(id, PT_UNICODE) {
            let u: Vec<u16> = b
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Some(
                String::from_utf16_lossy(&u)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
        self.stream(id, PT_STRING8).map(|b| {
            decode(b, self.codepage())
                .trim_end_matches('\0')
                .to_string()
        })
    }

    pub fn binary(&self, id: u16) -> Option<&'s [u8]> {
        self.stream(id, PT_BINARY)
    }

    /// Décode un corps binaire (PR_HTML) selon PR_INTERNET_CPID.
    pub fn decode_internet(&self, b: &[u8]) -> String {
        decode(b, self.codepage().or(Some(65001)))
    }

    fn fixed(&self, id: u16, ptype: u16) -> Option<&[u8; 8]> {
        self.fixed.get(&((u32::from(id) << 16) | u32::from(ptype)))
    }

    pub fn fixed_u32(&self, id: u16) -> Option<u32> {
        self.fixed(id, PT_LONG)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn fixed_bool(&self, id: u16) -> Option<bool> {
        self.fixed(id, PT_BOOLEAN).map(|v| v[0] != 0)
    }

    /// PT_SYSTIME (FILETIME, intervalles de 100 ns depuis 1601-01-01) → UTC.
    pub fn fixed_time(&self, id: u16) -> Option<DateTime<Utc>> {
        filetime(u64::from_le_bytes(*self.fixed(id, PT_SYSTIME)?))
    }

    /// Sous-objets (`__recip_version1.0_#…`, `__attach_version1.0_#…`) dans l'ordre.
    pub fn children(&self, prefix: &str) -> Vec<Node<'s>> {
        let start = format!("{}/{prefix}", self.base);
        let mut names: Vec<String> = self
            .streams
            .range(start.clone()..)
            .take_while(|(k, _)| k.starts_with(&start))
            .filter_map(|(k, _)| {
                let rest = &k[self.base.len() + 1..];
                rest.split('/').next().map(str::to_string)
            })
            .collect();
        names.dedup();
        names
            .into_iter()
            .map(|n| Node::new(self.streams, format!("{}/{n}", self.base), 8))
            .collect()
    }

    /// Objet embarqué (PT_OBJECT), ex. message joint dans `__substg1.0_3701000D`.
    pub fn object(&self, id: u16) -> Option<Node<'s>> {
        let base = format!("{}/__substg1.0_{id:04X}{PT_OBJECT:04X}", self.base);
        let probe = format!("{base}/");
        self.streams
            .range(probe.clone()..)
            .next()
            .filter(|(k, _)| k.starts_with(&probe))
            .map(|_| Node::new(self.streams, base, 24))
    }

    fn own_streams(&self) -> impl Iterator<Item = (&'s String, &'s Vec<u8>)> + '_ {
        let probe = format!("{}/", self.base);
        self.streams
            .range(probe.clone()..)
            .take_while(move |(k, _)| k.starts_with(&probe))
    }

    pub fn total_len(&self) -> u64 {
        self.own_streams().map(|(_, v)| v.len() as u64).sum()
    }

    /// Représentation canonique d'un objet embarqué pour son empreinte.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in self.own_streams() {
            out.extend_from_slice(&k.as_bytes()[self.base.len()..]);
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(v);
        }
        out
    }
}

fn decode(bytes: &[u8], codepage: Option<u32>) -> String {
    decode_codepage(bytes, codepage)
}

impl PropertySource for Node<'_> {
    fn string(&self, id: u16) -> Option<String> {
        Node::string(self, id)
    }
    fn binary(&self, id: u16) -> Option<Cow<'_, [u8]>> {
        Node::binary(self, id).map(Cow::Borrowed)
    }
    fn decode_internet(&self, bytes: &[u8]) -> String {
        Node::decode_internet(self, bytes)
    }
    fn u32(&self, id: u16) -> Option<u32> {
        self.fixed_u32(id)
    }
    fn bool(&self, id: u16) -> Option<bool> {
        self.fixed_bool(id)
    }
    fn time(&self, id: u16) -> Option<DateTime<Utc>> {
        self.fixed_time(id)
    }
    fn recipients(&self) -> Vec<Self> {
        self.children("__recip_version1.0_#")
    }
    fn attachments(&self) -> Vec<Self> {
        self.children("__attach_version1.0_#")
    }
    fn embedded(&self) -> Option<Self> {
        self.object(0x3701)
    }
    fn total_len(&self) -> u64 {
        Node::total_len(self)
    }
    fn canonical_bytes(&self) -> Vec<u8> {
        Node::canonical_bytes(self)
    }
}
