//! Export d'éléments d'une boîte (feature 002, FR-008) : `.msg` fidèle ou `.eml` reconstruit,
//! manifeste JSON et CSV (provenance, empreintes), archive ZIP pour le navigateur.

use base64::Engine as _;
use mf_core::{Address, Message};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

/// Format des fichiers exportés.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// Propriétés MAPI reprises telles quelles (fidèle).
    Msg,
    /// MIME reconstruit à partir des en-têtes de transport, des corps et des pièces jointes.
    Eml,
}

impl ExportFormat {
    pub fn ext(self) -> &'static str {
        match self {
            Self::Msg => "msg",
            Self::Eml => "eml",
        }
    }
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "msg" => Ok(Self::Msg),
            "eml" => Ok(Self::Eml),
            other => Err(format!("format d'export {other} : msg ou eml attendu")),
        }
    }
}

/// Manifeste d'un export : ce qui a été produit, d'où, avec quelles empreintes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub tool: String,
    pub version: String,
    pub generated_utc: String,
    pub store: ManifestStore,
    pub format: ExportFormat,
    pub items: Vec<ExportedItem>,
    /// Éléments demandés mais illisibles : listés, jamais omis en silence (FR-009).
    pub errors: Vec<ExportError>,
    /// Ce qu'il faut savoir pour lire les fichiers produits.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestStore {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    /// Empreinte recalculée juste avant l'export et identique à celle de l'ouverture.
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportedItem {
    pub id: u32,
    pub folder_path: Vec<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub from: Option<String>,
    pub date_utc: Option<String>,
    /// Nom du fichier produit (dans le dossier ou l'archive).
    pub file: String,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    /// Empreinte du contenu de l'élément dans la boîte (voir `Provenance::item_sha256`).
    pub item_sha256: String,
    pub attachments: Vec<ExportedAttachment>,
    /// `.msg` : propriétés nommées non reprises (table de noms propre à la boîte).
    pub named_properties_skipped: u32,
    /// `.eml` : fichier reconstruit, pas l'original.
    pub reconstructed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportedAttachment {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportError {
    pub id: u32,
    pub reason: String,
}

impl Manifest {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Une ligne par fichier produit ; champs entre guillemets, formules neutralisées.
    pub fn to_csv(&self) -> String {
        let q = |s: &str| {
            let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
                format!("'{s}")
            } else {
                s.to_string()
            };
            format!("\"{}\"", s.replace('"', "\"\""))
        };
        let mut out = String::from(
            "id,dossier,objet,message_id,expediteur,date_utc,fichier,taille,sha256,md5,empreinte_element,pieces_jointes\r\n",
        );
        for i in &self.items {
            let atts: Vec<String> = i
                .attachments
                .iter()
                .map(|a| format!("{} ({})", a.name, a.sha256))
                .collect();
            out.push_str(
                &[
                    i.id.to_string(),
                    q(&i.folder_path.join(" › ")),
                    q(i.subject.as_deref().unwrap_or("")),
                    q(i.message_id.as_deref().unwrap_or("")),
                    q(i.from.as_deref().unwrap_or("")),
                    q(i.date_utc.as_deref().unwrap_or("")),
                    q(&i.file),
                    i.size.to_string(),
                    i.sha256.clone(),
                    i.md5.clone(),
                    i.item_sha256.clone(),
                    q(&atts.join(" ; ")),
                ]
                .join(","),
            );
            out.push_str("\r\n");
        }
        out
    }
}

/// Nom du fichier exporté : `<id>_<objet>.<ext>`, sûr sur tous les systèmes.
pub fn export_file_name(id: u32, subject: Option<&str>, format: ExportFormat) -> String {
    let subject: String = subject
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let subject: String = subject.split_whitespace().collect::<Vec<_>>().join("_");
    let subject: String = subject.chars().take(60).collect();
    let base = if subject.is_empty() {
        format!("{id}")
    } else {
        format!("{id}_{subject}")
    };
    mf_core::safe_file_name(&format!("{base}.{}", format.ext()))
}

/// Destination d'un export sur disque (FR-008, P038) : hors du dossier de la preuve, et vide
/// (elle est créée si elle n'existe pas). Retourne le chemin canonique.
pub fn prepare_export_dir(dest: &Path, evidence: &Path) -> Result<std::path::PathBuf, String> {
    let evidence_dir = std::fs::canonicalize(evidence)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    // Chemin réel de la destination, même si elle n'existe pas encore : on remonte jusqu'au
    // premier parent existant. Le refus a lieu avant toute création.
    let mut existing = dest.to_path_buf();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(n), Some(p)) => {
                rest.push(n.to_os_string());
                existing = p.to_path_buf();
            }
            _ => break,
        }
        if existing.as_os_str().is_empty() {
            existing = std::path::PathBuf::from(".");
        }
    }
    let mut real =
        std::fs::canonicalize(&existing).map_err(|e| format!("{} : {e}", dest.display()))?;
    for n in rest.iter().rev() {
        real.push(n);
    }
    if let Some(ev) = evidence_dir {
        if real.starts_with(&ev) {
            return Err(
                "destination refusée : ne pas écrire dans le dossier de la preuve (ni dans un de ses sous-dossiers)"
                    .into(),
            );
        }
    }
    if real.exists() {
        let mut entries =
            std::fs::read_dir(&real).map_err(|e| format!("{} : {e}", dest.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "destination refusée : le dossier {} n'est pas vide (un export ne mélange pas ses fichiers à d'autres)",
                dest.display()
            ));
        }
    } else {
        std::fs::create_dir_all(&real).map_err(|e| format!("{} : {e}", dest.display()))?;
    }
    Ok(real)
}

// ——— `.eml` reconstruit ———

/// Message MIME reconstruit depuis un élément de boîte. Les en-têtes de transport d'origine sont
/// repris s'ils existent (sauf ceux qui décrivent la structure MIME, refaite) ; sinon les champs
/// principaux sont recréés. Le fichier n'est pas l'original : il porte
/// `X-MailForensics-Reconstructed: pst`, et une signature DKIM d'origine n'y est plus vérifiable.
pub fn reconstruct_eml(m: &Message, source_label: &str) -> Vec<u8> {
    let seed = m
        .provenance
        .as_ref()
        .map(|p| p.item_sha256.chars().take(16).collect::<String>())
        .unwrap_or_default();
    let mut w = Mime {
        out: Vec::new(),
        seed,
        n: 0,
    };
    w.message(m, source_label, 0);
    w.out
}

struct Mime {
    out: Vec<u8>,
    /// Graine des délimiteurs : un même élément donne toujours le même fichier.
    seed: String,
    n: u32,
}

const MAX_NESTING: usize = 16;

impl Mime {
    fn line(&mut self, s: &str) {
        self.out.extend_from_slice(s.as_bytes());
        self.out.extend_from_slice(b"\r\n");
    }

    fn boundary(&mut self) -> String {
        self.n += 1;
        format!("=_mf_{}_{}", self.seed, self.n)
    }

    fn message(&mut self, m: &Message, source_label: &str, depth: usize) {
        let transport = !m.headers.is_empty();
        if transport {
            for h in &m.headers {
                let lower = h.name.to_ascii_lowercase();
                if lower.starts_with("content-") || lower == "mime-version" {
                    continue;
                }
                // Ligne brute, repliée comme à l'origine ; retours à la ligne normalisés. Selon la
                // source, la ligne brute porte déjà le nom de l'en-tête ou seulement sa valeur.
                let raw = h.raw.replace("\r\n", "\n").replace('\r', "\n");
                let has_name = raw
                    .split_once(':')
                    .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(&h.name));
                let raw = if has_name {
                    raw
                } else {
                    format!("{}: {}", h.name, raw.trim_start())
                };
                let mut lines = raw.split('\n');
                let first = lines.next().unwrap_or("");
                self.line(first);
                for l in lines {
                    if l.trim().is_empty() {
                        continue;
                    }
                    let l = if l.starts_with([' ', '\t']) {
                        l.to_string()
                    } else {
                        format!(" {l}")
                    };
                    self.line(&l);
                }
            }
        }
        // Champs principaux absents des en-têtes de transport (ou pas d'en-têtes du tout) :
        // recréés depuis les propriétés de l'élément.
        let present: std::collections::HashSet<String> = m
            .headers
            .iter()
            .map(|h| h.name.to_ascii_lowercase())
            .collect();
        self.synth_headers(m, &present);
        if depth == 0 {
            self.line("X-MailForensics-Reconstructed: pst");
            self.line(&format!(
                "X-MailForensics-Source: {}",
                encode_word(source_label)
            ));
            if let Some(h) = m.provenance.as_ref().map(|p| p.item_sha256.as_str()) {
                if !h.is_empty() {
                    self.line(&format!("X-MailForensics-Item-SHA256: {h}"));
                }
            }
        }
        self.line("MIME-Version: 1.0");
        self.body(m, depth);
    }

    fn synth_headers(&mut self, m: &Message, present: &std::collections::HashSet<String>) {
        let addr = |a: &Address| match (&a.display_name, &a.address) {
            (Some(n), Some(e)) if !n.is_empty() && n != e => format!("{} <{e}>", encode_word(n)),
            (_, Some(e)) => format!("<{e}>"),
            (Some(n), None) => encode_word(n),
            _ => String::new(),
        };
        let list = |v: &[Address]| {
            v.iter()
                .map(addr)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let missing = |n: &str| !present.contains(n);
        if missing("from") && !m.from.is_empty() {
            self.line(&format!("From: {}", list(&m.from)));
        }
        if missing("to") && !m.to.is_empty() {
            self.line(&format!("To: {}", list(&m.to)));
        }
        if missing("cc") && !m.cc.is_empty() {
            self.line(&format!("Cc: {}", list(&m.cc)));
        }
        if let (true, Some(s)) = (missing("subject"), &m.subject) {
            self.line(&format!("Subject: {}", encode_word(s)));
        }
        if !missing("date") {
        } else if let Some(d) = m
            .date_utc
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.to_rfc2822())
        {
            // Date recréée depuis la date UTC de l'élément (le champ « brut » d'un élément sans
            // en-têtes décrit sa source, ce n'est pas une date RFC 2822).
            self.line(&format!("Date: {d}"));
        }
        if let (true, Some(id)) = (missing("message-id"), &m.message_id) {
            self.line(&format!("Message-ID: {id}"));
        }
    }

    fn body(&mut self, m: &Message, depth: usize) {
        let has_text = m.body_text.as_deref().is_some_and(|t| !t.is_empty());
        let has_html = m.body_html.as_deref().is_some_and(|t| !t.is_empty());
        let atts: Vec<&mf_core::Attachment> = m.attachments.iter().collect();
        let mixed = if atts.is_empty() {
            None
        } else {
            let b = self.boundary();
            self.line(&format!("Content-Type: multipart/mixed; boundary=\"{b}\""));
            self.line("");
            self.line(&format!("--{b}"));
            Some(b)
        };
        match (has_text, has_html) {
            (true, true) => {
                let b = self.boundary();
                self.line(&format!(
                    "Content-Type: multipart/alternative; boundary=\"{b}\""
                ));
                self.line("");
                self.line(&format!("--{b}"));
                self.text_part("plain", m.body_text.as_deref().unwrap_or(""));
                self.line(&format!("--{b}"));
                self.text_part("html", m.body_html.as_deref().unwrap_or(""));
                self.line(&format!("--{b}--"));
            }
            (false, true) => self.text_part("html", m.body_html.as_deref().unwrap_or("")),
            _ => self.text_part("plain", m.body_text.as_deref().unwrap_or("")),
        }
        if let Some(b) = mixed {
            for a in atts {
                self.line(&format!("--{b}"));
                self.attachment(a, depth);
            }
            self.line(&format!("--{b}--"));
        }
    }

    fn text_part(&mut self, sub: &str, text: &str) {
        self.line(&format!("Content-Type: text/{sub}; charset=utf-8"));
        self.line("Content-Transfer-Encoding: base64");
        self.line("");
        self.base64(text.as_bytes());
    }

    fn attachment(&mut self, a: &mf_core::Attachment, depth: usize) {
        let inline =
            a.content_id.is_some() && matches!(a.disposition, mf_core::Disposition::Inline);
        if let (Some(e), true) = (&a.embedded, depth < MAX_NESTING) {
            self.line("Content-Type: message/rfc822");
            self.line(&format!(
                "Content-Disposition: attachment; {}",
                filename_param(&format!("{}.eml", a.filename.trim_end_matches(".msg")))
            ));
            self.line("");
            self.message(e, "", depth + 1);
            return;
        }
        let mime = a
            .declared_mime
            .clone()
            .filter(|m| m.contains('/') && !m.contains(['\r', '\n', '"']))
            .unwrap_or_else(|| "application/octet-stream".into());
        self.line(&format!(
            "Content-Type: {mime}; {}",
            name_param(&a.filename)
        ));
        self.line(&format!(
            "Content-Disposition: {}; {}",
            if inline { "inline" } else { "attachment" },
            filename_param(&a.filename)
        ));
        if let Some(cid) = &a.content_id {
            let cid = cid.trim_matches(['<', '>']);
            if !cid.contains(['\r', '\n', '>']) {
                self.line(&format!("Content-ID: <{cid}>"));
            }
        }
        self.line("Content-Transfer-Encoding: base64");
        self.line("");
        self.base64(&a.data);
    }

    fn base64(&mut self, data: &[u8]) {
        let enc = base64::engine::general_purpose::STANDARD.encode(data);
        for chunk in enc.as_bytes().chunks(76) {
            self.out.extend_from_slice(chunk);
            self.out.extend_from_slice(b"\r\n");
        }
    }
}

/// Mot encodé RFC 2047 si le texte n'est pas en ASCII imprimable.
fn encode_word(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).collect();
    if s.is_ascii() {
        return s;
    }
    format!(
        "=?utf-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    )
}

/// `filename=` (ASCII) ou `filename*=utf-8''…` (RFC 2231).
fn filename_param(name: &str) -> String {
    param("filename", name)
}

fn name_param(name: &str) -> String {
    param("name", name)
}

fn param(key: &str, value: &str) -> String {
    let value: String = value.chars().filter(|c| !c.is_control()).collect();
    if value.is_ascii() && !value.contains(['"', '\\']) {
        return format!("{key}=\"{value}\"");
    }
    let enc: String = value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("{key}*=utf-8''{enc}")
}

// ——— Archive ZIP (version web) ———

/// Archive ZIP sans compression, écrite au fil de l'eau. Les noms sont en UTF-8. Limitée à
/// 4 Go et 65 535 fichiers (pas de ZIP64) : au-delà, l'export s'arrête avec une erreur claire.
pub struct ZipWriter {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u16,
}

impl Default for ZipWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ZipWriter {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            central: Vec::new(),
            count: 0,
        }
    }

    pub fn add(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        let too_big = || {
            io::Error::other(
                "archive trop volumineuse pour le navigateur (4 Go ou 65 535 fichiers) : exporter moins d'éléments à la fois",
            )
        };
        let offset = u32::try_from(self.out.len()).map_err(|_| too_big())?;
        let size = u32::try_from(data.len()).map_err(|_| too_big())?;
        self.count = self.count.checked_add(1).ok_or_else(too_big)?;
        let crc = crc32(data);
        let name_b = name.as_bytes();
        let name_len = u16::try_from(name_b.len()).map_err(|_| too_big())?;
        // Date DOS fixe (1980-01-01) : une même sélection donne la même archive.
        let (time, date) = (0u16, 0x0021u16);
        let mut local = Vec::with_capacity(30 + name_b.len());
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes()); // version nécessaire
        local.extend_from_slice(&0x0800u16.to_le_bytes()); // noms en UTF-8
        local.extend_from_slice(&0u16.to_le_bytes()); // stocké
        local.extend_from_slice(&time.to_le_bytes());
        local.extend_from_slice(&date.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&name_len.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name_b);
        self.out.extend_from_slice(&local);
        self.out.extend_from_slice(data);
        u32::try_from(self.out.len()).map_err(|_| too_big())?;

        let c = &mut self.central;
        c.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes()); // version de l'outil
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&0x0800u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(&time.to_le_bytes());
        c.extend_from_slice(&date.to_le_bytes());
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&name_len.to_le_bytes());
        c.extend_from_slice(&[0u8; 6]); // longueurs extra et commentaire, disque de départ
        c.extend_from_slice(&[0u8; 6]); // attributs internes (2) et externes (4)
        c.extend_from_slice(&offset.to_le_bytes());
        c.extend_from_slice(name_b);
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<Vec<u8>> {
        let too_big = || io::Error::other("archive trop volumineuse pour le navigateur");
        let cd_offset = u32::try_from(self.out.len()).map_err(|_| too_big())?;
        let cd_size = u32::try_from(self.central.len()).map_err(|_| too_big())?;
        self.out.extend_from_slice(&self.central);
        self.out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        self.out.extend_from_slice(&[0u8; 4]);
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&cd_size.to_le_bytes());
        self.out.extend_from_slice(&cd_offset.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        Ok(self.out)
    }
}

/// CRC-32 (IEEE), table calculée une fois.
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    let mut c = !0u32;
    for b in data {
        c = TABLE[((c ^ u32::from(*b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn crc_and_names() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            export_file_name(42, Some("Re: Réunion / budget <2001>"), ExportFormat::Msg),
            "42_Re__Réunion___budget__2001_.msg"
        );
        assert_eq!(export_file_name(7, None, ExportFormat::Eml), "7.eml");
        assert_eq!(param("filename", "a\"b.pdf"), "filename*=utf-8''a%22b.pdf");
        assert_eq!(
            param("filename", "été.pdf"),
            "filename*=utf-8''%C3%A9t%C3%A9.pdf"
        );
        assert_eq!(encode_word("Réunion"), "=?utf-8?B?UsOpdW5pb24=?=");
    }

    #[test]
    fn zip_is_readable() {
        let mut z = ZipWriter::new();
        z.add("a.txt", b"bonjour").unwrap();
        z.add("dossier/é.bin", &[0u8, 1, 2]).unwrap();
        let bytes = z.finish().unwrap();
        let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as usize;
        let u32_at =
            |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        // Fin d'archive : deux entrées, puis chaque entrée du répertoire central relue jusqu'à
        // son en-tête local et ses données.
        let end = &bytes[bytes.len() - 22..];
        assert_eq!(u32_at(end, 0), 0x0605_4b50);
        assert_eq!(u16_at(end, 10), 2);
        let mut at = u32_at(end, 16);
        let mut seen = Vec::new();
        for _ in 0..2 {
            assert_eq!(
                u32_at(&bytes, at),
                0x0201_4b50,
                "signature d'entrée centrale"
            );
            let size = u32_at(&bytes, at + 20);
            let crc = u32_at(&bytes, at + 16) as u32;
            let name_len = u16_at(&bytes, at + 28);
            let extra = u16_at(&bytes, at + 30) + u16_at(&bytes, at + 32);
            let local = u32_at(&bytes, at + 42);
            let name = std::str::from_utf8(&bytes[at + 46..at + 46 + name_len]).unwrap();
            assert_eq!(u32_at(&bytes, local), 0x0403_4b50, "en-tête local");
            let data_at = local + 30 + u16_at(&bytes, local + 26) + u16_at(&bytes, local + 28);
            let data = &bytes[data_at..data_at + size];
            assert_eq!(crc32(data), crc);
            seen.push((name.to_string(), data.to_vec()));
            at += 46 + name_len + extra;
        }
        assert_eq!(
            seen,
            vec![
                ("a.txt".to_string(), b"bonjour".to_vec()),
                ("dossier/é.bin".to_string(), vec![0, 1, 2])
            ]
        );
    }
}
