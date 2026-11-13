//! QR codes dans les images (FR-046) : le « quishing » cache l'URL de phishing dans une image,
//! invisible pour les filtres de liens. Décodage local, mémoire bornée.

use base64::Engine;
use image::{ImageReader, Limits};
use std::io::Cursor;
use std::sync::LazyLock;

/// Images plus grosses ignorées (octets compressés).
const MAX_BYTES: usize = 8 * 1024 * 1024;
/// Dimensions maximales acceptées par le décodeur.
const MAX_SIDE: u32 = 8000;
/// Mémoire maximale allouée pour une image décodée.
const MAX_ALLOC: u64 = 96 * 1024 * 1024;
/// Côté maximal analysé : au-delà, l'image est réduite (le QR reste lisible).
const WORK_SIDE: u32 = 1600;
/// Nombre maximal d'images analysées par message.
pub const MAX_IMAGES: usize = 40;

/// Contenus des QR codes d'une image (vide si aucun ou image illisible).
pub fn decode(data: &[u8]) -> Vec<String> {
    if data.len() > MAX_BYTES || data.len() < 32 {
        return Vec::new();
    }
    let Ok(mut reader) = ImageReader::new(Cursor::new(data)).with_guessed_format() else {
        return Vec::new();
    };
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    let Ok(img) = reader.decode() else {
        return Vec::new();
    };
    let mut gray = img.to_luma8();
    drop(img);
    if gray.width().max(gray.height()) > WORK_SIDE {
        // Réduction proportionnelle (le côté le plus long passe à WORK_SIDE).
        let (w, h) = (u64::from(gray.width()), u64::from(gray.height()));
        let side = u64::from(WORK_SIDE);
        let (nw, nh) = if w >= h {
            (side, (h * side / w).max(1))
        } else {
            ((w * side / h).max(1), side)
        };
        gray = image::imageops::thumbnail(
            &gray,
            u32::try_from(nw).unwrap_or(WORK_SIDE),
            u32::try_from(nh).unwrap_or(WORK_SIDE),
        );
    }
    let (w, h) = (gray.width() as usize, gray.height() as usize);
    let raw = gray.into_raw();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| raw[y * w + x]);
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_, content)) = grid.decode() {
            let content = content.trim().to_string();
            if !content.is_empty() && !out.contains(&content) {
                out.push(content);
            }
        }
    }
    out
}

static DATA_IMG: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)data:image/(?:png|jpe?g|gif|bmp|webp);base64,([A-Za-z0-9+/=\s]{200,})")
        .ok()
});

/// Images `data:` intégrées directement au HTML (sans pièce jointe).
pub fn inline_images(html: &str) -> Vec<Vec<u8>> {
    let Some(re) = DATA_IMG.as_ref() else {
        return Vec::new();
    };
    re.captures_iter(html)
        .take(MAX_IMAGES)
        .filter_map(|c| {
            let b64: String = c.get(1)?.as_str().split_whitespace().collect();
            base64::engine::general_purpose::STANDARD.decode(b64).ok()
        })
        .collect()
}

/// Le contenu ressemble-t-il à une URL web ?
pub fn as_url(content: &str) -> Option<String> {
    let c = content.trim();
    let l = c.to_ascii_lowercase();
    if l.starts_with("http://") || l.starts_with("https://") {
        return Some(c.to_string());
    }
    // QR « URLTO: » ou domaine nu.
    if let Some(rest) = l.strip_prefix("urlto:") {
        return Some(format!("https://{}", &c[c.len() - rest.len()..]));
    }
    if l.starts_with("www.") && !c.contains(char::is_whitespace) {
        return Some(c.to_string());
    }
    None
}
