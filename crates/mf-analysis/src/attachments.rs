//! Pièces jointes dangereuses (FR-016, FR-017) : type réel d'après le contenu et alertes.
//! Aucune pièce jointe n'est ouverte ni exécutée : seuls les octets sont inspectés.

use mf_core::{Attachment, AttachmentFlag};

/// Extensions exécutables ou interprétées par Windows / Office au double-clic.
const EXECUTABLE_EXT: [&str; 26] = [
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "msi",
    "msp",
    "jar",
    "dll",
    "cpl",
    "reg",
    "lnk",
    "scf",
    "appx",
    "msix",
    "application",
];
/// Extensions à risque sans être directement exécutables (conteneurs, macros, raccourcis).
const RISKY_EXT: [&str; 20] = [
    "iso",
    "img",
    "vhd",
    "vhdx",
    "docm",
    "xlsm",
    "pptm",
    "dotm",
    "xltm",
    "xlam",
    "ppam",
    "one",
    "chm",
    "url",
    "website",
    "library-ms",
    "settingcontent-ms",
    "svg",
    "xll",
    "iqy",
];
const HTML_EXT: [&str; 5] = ["htm", "html", "shtml", "xhtml", "mht"];
/// Extensions « anodines » utilisées comme leurre devant une vraie extension.
const DECOY_EXT: [&str; 18] = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "zip",
    "rtf", "csv", "odt", "mp3", "mp4",
];

/// Type détecté : (libellé, type MIME, famille).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub label: &'static str,
    pub mime: &'static str,
    pub family: Family,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Executable,
    Document,
    Archive,
    Image,
    Html,
    Text,
    Mail,
    DiskImage,
    Other,
}

fn zip_names(data: &[u8]) -> Vec<String> {
    // Répertoire central : signature PK\x01\x02, nom à l'offset 46, longueur à l'offset 28.
    let mut names = Vec::new();
    let mut i = 0;
    while let Some(pos) = data
        .get(i..)
        .and_then(|d| d.windows(4).position(|w| w == b"PK\x01\x02"))
    {
        let at = i + pos;
        let len = data
            .get(at + 28..at + 30)
            .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])));
        if let Some(n) = data.get(at + 46..at + 46 + len) {
            names.push(String::from_utf8_lossy(n).into_owned());
        }
        i = at + 4;
        if names.len() > 10_000 {
            break;
        }
    }
    names
}

/// Au moins une entrée ZIP chiffrée (bit 0 des drapeaux d'un en-tête local).
fn zip_encrypted(data: &[u8]) -> bool {
    let mut i = 0;
    while let Some(pos) = data
        .get(i..)
        .and_then(|d| d.windows(4).position(|w| w == b"PK\x03\x04"))
    {
        let at = i + pos;
        if data.get(at + 6).is_some_and(|f| f & 1 == 1) {
            return true;
        }
        i = at + 4;
    }
    false
}

fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

/// Contient un projet VBA (OLE `_VBA_PROJECT`, OOXML `vbaProject.bin`).
fn has_macros(data: &[u8], d: Option<&Detected>) -> bool {
    match d.map(|x| x.mime) {
        Some(m) if m.contains("openxmlformats") || m == "application/zip" => zip_names(data)
            .iter()
            .any(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin")),
        Some(
            "application/x-ole-storage"
            | "application/msword"
            | "application/vnd.ms-excel"
            | "application/vnd.ms-powerpoint",
        ) => {
            // Noms de flux OLE en UTF-16LE.
            let utf16 = |s: &str| {
                s.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<u8>>()
            };
            contains(data, &utf16("_VBA_PROJECT")) || contains(data, &utf16("VBA"))
        }
        _ => false,
    }
}

/// Type réel d'après les premiers octets.
pub fn detect(data: &[u8]) -> Option<Detected> {
    use Family::*;
    let d = |label, mime, family| {
        Some(Detected {
            label,
            mime,
            family,
        })
    };
    let head = &data[..data.len().min(512)];
    let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
    let trimmed = lower
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(&lower[..0], |i| &lower[i..]);
    if data.starts_with(b"MZ") {
        return d(
            "Exécutable Windows (PE)",
            "application/vnd.microsoft.portable-executable",
            Executable,
        );
    }
    if data.starts_with(b"\x7fELF") {
        return d("Exécutable Linux (ELF)", "application/x-elf", Executable);
    }
    if data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
    {
        return d(
            "Exécutable macOS (Mach-O) ou classe Java",
            "application/x-mach-binary",
            Executable,
        );
    }
    if data.starts_with(&[0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0]) {
        return d(
            "Raccourci Windows (LNK)",
            "application/x-ms-shortcut",
            Executable,
        );
    }
    if data.starts_with(b"%PDF") {
        return d("Document PDF", "application/pdf", Document);
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        let names = zip_names(data);
        let has = |p: &str| names.iter().any(|n| n.starts_with(p));
        if names.iter().any(|n| n == "[Content_Types].xml") {
            if has("word/") {
                return d(
                    "Document Word (OOXML)",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    Document,
                );
            }
            if has("xl/") {
                return d(
                    "Classeur Excel (OOXML)",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    Document,
                );
            }
            if has("ppt/") {
                return d(
                    "Présentation PowerPoint (OOXML)",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    Document,
                );
            }
        }
        if names.iter().any(|n| n == "META-INF/MANIFEST.MF") {
            return d("Archive Java (JAR)", "application/java-archive", Executable);
        }
        if names.iter().any(|n| n == "mimetype") && has("content.xml") {
            return d(
                "Document OpenDocument",
                "application/vnd.oasis.opendocument",
                Document,
            );
        }
        return d("Archive ZIP", "application/zip", Archive);
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        let utf16 = |s: &str| {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        };
        if contains(data, &utf16("__properties_version1.0")) {
            return d("Message Outlook (MSG)", "application/vnd.ms-outlook", Mail);
        }
        if contains(data, &utf16("WordDocument")) {
            return d("Document Word 97-2003", "application/msword", Document);
        }
        if contains(data, &utf16("Workbook")) || contains(data, &utf16("Book")) {
            return d(
                "Classeur Excel 97-2003",
                "application/vnd.ms-excel",
                Document,
            );
        }
        if contains(data, &utf16("PowerPoint Document")) {
            return d(
                "Présentation PowerPoint 97-2003",
                "application/vnd.ms-powerpoint",
                Document,
            );
        }
        if contains(data, &utf16("Installer")) || contains(data, b"Windows Installer") {
            return d("Installeur Windows (MSI)", "application/x-msi", Executable);
        }
        return d(
            "Conteneur OLE (Office 97-2003)",
            "application/x-ole-storage",
            Document,
        );
    }
    if data.starts_with(b"Rar!\x1a\x07") {
        return d("Archive RAR", "application/vnd.rar", Archive);
    }
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return d("Archive 7-Zip", "application/x-7z-compressed", Archive);
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return d("Archive GZIP", "application/gzip", Archive);
    }
    if data.get(0x8001..0x8006) == Some(b"CD001") {
        return d("Image disque ISO", "application/x-iso9660-image", DiskImage);
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return d("Image PNG", "image/png", Image);
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return d("Image JPEG", "image/jpeg", Image);
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return d("Image GIF", "image/gif", Image);
    }
    if data.starts_with(b"II*\0") || data.starts_with(b"MM\0*") {
        return d("Image TIFF", "image/tiff", Image);
    }
    if data.starts_with(b"{\\rtf") {
        return d("Document RTF", "application/rtf", Document);
    }
    if data.starts_with(&[0x78, 0x9F, 0x3E, 0x22]) {
        return d(
            "Pièce jointe TNEF (winmail.dat)",
            "application/ms-tnef",
            Other,
        );
    }
    if trimmed.starts_with(b"<!doctype html")
        || trimmed.starts_with(b"<html")
        || contains(&lower, b"<script")
    {
        return d("Page HTML", "text/html", Html);
    }
    if trimmed.starts_with(b"<svg") || (trimmed.starts_with(b"<?xml") && contains(&lower, b"<svg"))
    {
        return d("Image SVG (peut contenir du script)", "image/svg+xml", Html);
    }
    if lower.starts_with(b"from:")
        || lower.starts_with(b"received:")
        || lower.starts_with(b"return-path:")
    {
        return d("Courriel (EML)", "message/rfc822", Mail);
    }
    if !head.is_empty()
        && head.iter().all(|&b| {
            b == b'\t' || b == b'\n' || b == b'\r' || (0x20..0x7f).contains(&b) || b >= 0x80
        })
    {
        return d("Texte", "text/plain", Text);
    }
    None
}

fn extensions(name: &str) -> Vec<String> {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_end_matches('.');
    base.split('.')
        .skip(1)
        .map(|e| e.trim().to_ascii_lowercase())
        .collect()
}

fn ext_family(ext: &str) -> Option<Family> {
    use Family::*;
    Some(match ext {
        "pdf" | "doc" | "docx" | "docm" | "xls" | "xlsx" | "xlsm" | "ppt" | "pptx" | "pptm"
        | "rtf" | "odt" | "ods" => Document,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tif" | "tiff" => Image,
        "zip" | "rar" | "7z" | "gz" | "tgz" => Archive,
        "txt" | "csv" | "log" => Text,
        "htm" | "html" | "svg" => Html,
        "eml" | "msg" => Mail,
        "iso" | "img" => DiskImage,
        e if EXECUTABLE_EXT.contains(&e) => Executable,
        _ => return None,
    })
}

/// Renseigne `detected_*` et `flags` de chaque pièce jointe.
pub fn inspect(att: &mut Attachment) {
    let detected = (!att.data.is_empty()).then(|| detect(&att.data)).flatten();
    let exts = extensions(&att.filename);
    let last = exts.last().cloned().unwrap_or_default();
    let mut flags = Vec::new();
    let mime = att
        .declared_mime
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    if att.size == 0 && att.embedded.is_none() {
        flags.push(AttachmentFlag::ZeroLength);
    }
    if EXECUTABLE_EXT.contains(&last.as_str())
        || detected
            .as_ref()
            .is_some_and(|d| d.family == Family::Executable)
    {
        flags.push(AttachmentFlag::Executable);
    }
    if RISKY_EXT.contains(&last.as_str())
        || detected
            .as_ref()
            .is_some_and(|d| d.family == Family::DiskImage)
    {
        flags.push(AttachmentFlag::RiskyExtension);
    }
    if exts.len() >= 2
        && DECOY_EXT.contains(&exts[exts.len() - 2].as_str())
        && (EXECUTABLE_EXT.contains(&last.as_str())
            || RISKY_EXT.contains(&last.as_str())
            || HTML_EXT.contains(&last.as_str()))
    {
        flags.push(AttachmentFlag::DoubleExtension);
    }
    if let (Some(d), Some(fam)) = (&detected, ext_family(&last)) {
        let compatible = d.family == fam
            || (fam == Family::Archive && d.family == Family::Document) // OOXML = ZIP
            || (fam == Family::Document && d.family == Family::Archive && last.ends_with('x'))
            || (fam == Family::Text && d.family == Family::Html);
        if !compatible {
            flags.push(AttachmentFlag::TypeMismatch);
        }
    }
    if att.filename.chars().any(|c| c.is_control() || matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')) {
        flags.push(AttachmentFlag::BidiOrControlChars);
    }
    if detected
        .as_ref()
        .is_some_and(|d| d.mime == "application/zip" || d.family == Family::Document)
        && zip_encrypted(&att.data)
    {
        flags.push(AttachmentFlag::EncryptedArchive);
    }
    if has_macros(&att.data, detected.as_ref())
        || matches!(
            last.as_str(),
            "docm" | "xlsm" | "pptm" | "dotm" | "xltm" | "xlam" | "ppam"
        )
    {
        flags.push(AttachmentFlag::Macros);
    }
    if HTML_EXT.contains(&last.as_str())
        || detected.as_ref().is_some_and(|d| d.family == Family::Html)
    {
        flags.push(AttachmentFlag::HtmlAttachment);
    }
    if mime == "application/ms-tnef"
        || att.filename.eq_ignore_ascii_case("winmail.dat")
        || detected
            .as_ref()
            .is_some_and(|d| d.mime == "application/ms-tnef")
    {
        flags.push(AttachmentFlag::Tnef);
    }
    flags.dedup();
    att.detected_type = detected.as_ref().map(|d| d.label.to_string());
    att.detected_mime = detected.map(|d| d.mime.to_string());
    att.flags = flags;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mf_core::Disposition;

    fn att(name: &str, mime: &str, data: &[u8]) -> Attachment {
        let mut a = Attachment {
            index: 1,
            filename: name.into(),
            declared_mime: Some(mime.into()),
            size: data.len() as u64,
            sha256: String::new(),
            md5: String::new(),
            disposition: Disposition::Attachment,
            content_id: None,
            embedded: None,
            extractable: true,
            detected_type: None,
            detected_mime: None,
            flags: Vec::new(),
            data: data.to_vec(),
        };
        inspect(&mut a);
        a
    }

    /// ZIP minimal : un en-tête local + une entrée de répertoire central nommée `name`.
    fn zip(name: &str, encrypted: bool) -> Vec<u8> {
        let mut z = b"PK\x03\x04\x14\x00".to_vec();
        z.extend_from_slice(&[u8::from(encrypted), 0]);
        z.extend_from_slice(&[0; 22]);
        let mut cd = b"PK\x01\x02".to_vec();
        cd.extend_from_slice(&[0; 24]);
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0; 16]);
        cd.extend_from_slice(name.as_bytes());
        z.extend_from_slice(&cd);
        z
    }

    #[test]
    fn executable_disguised_as_pdf() {
        let a = att("facture.pdf.exe", "application/pdf", b"MZ\x90\x00rest");
        assert_eq!(a.detected_type.as_deref(), Some("Exécutable Windows (PE)"));
        assert!(a.flags.contains(&AttachmentFlag::Executable));
        assert!(a.flags.contains(&AttachmentFlag::DoubleExtension));
        let b = att("facture.pdf", "application/pdf", b"MZ\x90\x00rest");
        assert!(
            b.flags.contains(&AttachmentFlag::TypeMismatch),
            "{:?}",
            b.flags
        );
        assert!(b.flags.contains(&AttachmentFlag::Executable));
    }

    #[test]
    fn office_macros_and_encrypted_zip() {
        let mut docm = zip("[Content_Types].xml", false);
        docm.extend_from_slice(&zip("word/document.xml", false));
        docm.extend_from_slice(&zip("word/vbaProject.bin", false));
        let a = att("contrat.docx", "application/octet-stream", &docm);
        assert_eq!(a.detected_type.as_deref(), Some("Document Word (OOXML)"));
        assert!(a.flags.contains(&AttachmentFlag::Macros), "{:?}", a.flags);
        assert!(!a.flags.contains(&AttachmentFlag::TypeMismatch));
        let z = att("photos.zip", "application/zip", &zip("photo.exe", true));
        assert!(z.flags.contains(&AttachmentFlag::EncryptedArchive));
    }

    #[test]
    fn bidi_html_and_benign() {
        let a = att("facture\u{202E}fdp.exe", "application/octet-stream", b"MZ");
        assert!(a.flags.contains(&AttachmentFlag::BidiOrControlChars));
        let h = att(
            "Facture.html",
            "text/html",
            b"<!DOCTYPE html><form action=x>",
        );
        assert!(h.flags.contains(&AttachmentFlag::HtmlAttachment));
        let p = att("logo.png", "image/png", b"\x89PNG\r\n\x1a\n....");
        assert!(p.flags.is_empty(), "{:?}", p.flags);
        let pdf = att("rapport.pdf", "application/pdf", b"%PDF-1.7");
        assert!(pdf.flags.is_empty());
    }
}
