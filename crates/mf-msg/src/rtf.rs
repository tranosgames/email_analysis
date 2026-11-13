//! Corps RTF des messages Outlook (FR-041, tâche T030/T114).
//!
//! - Décompression `PR_RTF_COMPRESSED` (MS-OXRTFCP) via `compressed-rtf`, protégée par des
//!   contrôles préalables : la bibliothèque indexe et alloue d'après l'en-tête sans vérifier.
//! - Dé-encapsulation (MS-OXRTFEX) : un RTF marqué `\fromhtml1` contient le HTML d'origine,
//!   restitué ici ; sinon (`\fromtext`, RTF natif) on en extrait le texte.

/// Taille maximale du RTF décompressé (data-model.md › Limites).
const MAX_RTF: usize = 64 * 1024 * 1024;
const LZFU: u32 = 0x7546_5A4C;
const MELA: u32 = 0x414C_454D;

/// Corps obtenu à partir du RTF.
#[derive(Debug, PartialEq, Eq)]
pub enum RtfBody {
    /// HTML d'origine encapsulé (`\fromhtml1`).
    Html(String),
    /// Texte extrait d'un RTF natif ou `\fromtext`.
    Text(String),
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

/// Décompresse `PR_RTF_COMPRESSED`. Retourne le RTF (un caractère par octet).
pub fn decompress(data: &[u8]) -> Result<String, String> {
    let comp_size = le_u32(data, 0).ok_or("RTF compressé tronqué (en-tête)")? as usize;
    let raw_size = le_u32(data, 4).ok_or("RTF compressé tronqué (en-tête)")? as usize;
    let kind = le_u32(data, 8).ok_or("RTF compressé tronqué (en-tête)")?;
    if data.len() < 16 || comp_size.checked_add(4) != Some(data.len()) {
        return Err(format!(
            "RTF compressé : taille déclarée {comp_size} incohérente"
        ));
    }
    if raw_size > MAX_RTF {
        return Err(format!("RTF décompressé trop volumineux ({raw_size} o)"));
    }
    if kind == MELA {
        // RTF stocké sans compression. Certains producteurs déclarent une taille supérieure aux
        // données présentes : on lit ce qui existe, sans dépasser, jusqu'au premier octet nul.
        let body = data.get(16..).unwrap_or_default();
        let body = &body[..raw_size.min(body.len())];
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        return Ok(body[..end].iter().map(|&b| char::from(b)).collect());
    }
    if kind != LZFU {
        return Err(format!("RTF compressé : type inconnu 0x{kind:08X}"));
    }
    compressed_rtf::decompress_rtf(data).map_err(|e| format!("RTF compressé illisible : {e}"))
}

/// Destinations RTF sans texte affichable.
const SKIP_DESTINATIONS: [&str; 24] = [
    "fonttbl",
    "colortbl",
    "stylesheet",
    "info",
    "pict",
    "object",
    "header",
    "footer",
    "headerl",
    "headerr",
    "footerl",
    "footerr",
    "generator",
    "listtable",
    "listoverridetable",
    "rsidtbl",
    "themedata",
    "colorschememapping",
    "datastore",
    "latentstyles",
    "xmlnstbl",
    "filetbl",
    "revtbl",
    "userprops",
];

#[derive(Clone, Copy)]
struct State {
    skip: bool,
    htmlrtf: bool,
    uc: u32,
    /// Début de groupe : le premier mot de contrôle peut désigner une destination.
    at_group_start: bool,
    star: bool,
}

struct Out {
    text: String,
    pending: Vec<u8>,
    encoding: &'static encoding_rs::Encoding,
}

impl Out {
    fn flush(&mut self) {
        if !self.pending.is_empty() {
            self.text
                .push_str(&self.encoding.decode_without_bom_handling(&self.pending).0);
            self.pending.clear();
        }
    }
    fn byte(&mut self, b: u8) {
        self.pending.push(b);
    }
    fn ch(&mut self, c: char) {
        self.flush();
        self.text.push(c);
    }
    fn str(&mut self, s: &str) {
        self.flush();
        self.text.push_str(s);
    }
}

fn codepage_encoding(cp: i64) -> &'static encoding_rs::Encoding {
    let label = match cp {
        65001 => "utf-8".to_string(),
        932 => "shift_jis".into(),
        936 => "gbk".into(),
        949 => "euc-kr".into(),
        950 => "big5".into(),
        cp => format!("windows-{cp}"),
    };
    encoding_rs::Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::WINDOWS_1252)
}

/// Convertit un RTF : HTML d'origine s'il est encapsulé, sinon texte.
pub fn convert(rtf: &str) -> RtfBody {
    let head: String = rtf.chars().take(2048).collect();
    let html_mode = head.contains("\\fromhtml1");
    let chars: Vec<char> = rtf.chars().collect();
    let mut out = Out {
        text: String::new(),
        pending: Vec::new(),
        encoding: encoding_rs::WINDOWS_1252,
    };
    let mut st = State {
        skip: false,
        htmlrtf: false,
        uc: 1,
        at_group_start: false,
        star: false,
    };
    let mut stack: Vec<State> = Vec::new();
    let mut skip_fallback = 0u32;
    // Dans un groupe {\*\htmltag…}, le contenu est du HTML même si \htmlrtf est actif autour.
    let emit_ok = |s: &State| !s.skip && !(html_mode && s.htmlrtf);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '{' => {
                stack.push(st);
                st.at_group_start = true;
                st.star = false;
                i += 1;
            }
            '}' => {
                if let Some(prev) = stack.pop() {
                    st = prev;
                }
                i += 1;
            }
            '\\' => {
                let next = chars.get(i + 1).copied().unwrap_or(' ');
                if next.is_ascii_alphabetic() {
                    let mut j = i + 1;
                    while j < chars.len() && chars[j].is_ascii_alphabetic() {
                        j += 1;
                    }
                    let word: String = chars[i + 1..j].iter().collect();
                    let num_start = j;
                    if j < chars.len() && chars[j] == '-' {
                        j += 1;
                    }
                    while j < chars.len() && chars[j].is_ascii_digit() && j - num_start < 10 {
                        j += 1;
                    }
                    let param: Option<i64> = (j > num_start)
                        .then(|| chars[num_start..j].iter().collect::<String>().parse().ok())
                        .flatten();
                    if j < chars.len() && chars[j] == ' ' {
                        j += 1;
                    }
                    i = j;

                    let destination = st.at_group_start;
                    st.at_group_start = false;
                    if destination {
                        if word == "htmltag" && st.star {
                            st.skip = stack.last().is_some_and(|p| p.skip);
                            st.htmlrtf = false; // contenu HTML à restituer
                            continue;
                        }
                        if st.star || SKIP_DESTINATIONS.contains(&word.as_str()) {
                            st.skip = true;
                            continue;
                        }
                    }
                    match word.as_str() {
                        "ansicpg" => out.encoding = codepage_encoding(param.unwrap_or(1252)),
                        "htmlrtf" => st.htmlrtf = param != Some(0),
                        "uc" => st.uc = u32::try_from(param.unwrap_or(1)).unwrap_or(1).min(8),
                        "bin" => i += usize::try_from(param.unwrap_or(0)).unwrap_or(0),
                        "u" if emit_ok(&st) => {
                            let n = param.unwrap_or(63);
                            let code = if n < 0 { n + 65536 } else { n };
                            out.ch(u32::try_from(code)
                                .ok()
                                .and_then(char::from_u32)
                                .unwrap_or('\u{FFFD}'));
                            skip_fallback = st.uc;
                        }
                        "par" | "line" if emit_ok(&st) => {
                            out.str(if html_mode { "\r\n" } else { "\n" })
                        }
                        "tab" if emit_ok(&st) => out.ch('\t'),
                        "emdash" if emit_ok(&st) => out.ch('—'),
                        "endash" if emit_ok(&st) => out.ch('–'),
                        "bullet" if emit_ok(&st) => out.ch('•'),
                        "lquote" if emit_ok(&st) => out.ch('‘'),
                        "rquote" if emit_ok(&st) => out.ch('’'),
                        "ldblquote" if emit_ok(&st) => out.ch('“'),
                        "rdblquote" if emit_ok(&st) => out.ch('”'),
                        _ => {}
                    }
                } else {
                    i += 2;
                    let first = st.at_group_start;
                    st.at_group_start = false;
                    match next {
                        '*' if first => {
                            st.star = true;
                            st.at_group_start = true; // le mot suivant nomme la destination
                        }
                        '\'' => {
                            let hex: String = chars
                                .get(i..i + 2)
                                .map(|h| h.iter().collect())
                                .unwrap_or_default();
                            i += 2;
                            if skip_fallback > 0 {
                                skip_fallback -= 1;
                            } else if emit_ok(&st) {
                                if let Ok(b) = u8::from_str_radix(&hex, 16) {
                                    out.byte(b);
                                }
                            }
                        }
                        '\\' | '{' | '}' if emit_ok(&st) => out.ch(next),
                        '~' if emit_ok(&st) => out.ch('\u{a0}'),
                        '_' if emit_ok(&st) => out.ch('-'),
                        '\r' | '\n' if emit_ok(&st) => {
                            out.str(if html_mode { "\r\n" } else { "\n" })
                        }
                        _ => {}
                    }
                }
            }
            '\r' | '\n' => i += 1,
            _ => {
                st.at_group_start = false;
                if skip_fallback > 0 {
                    skip_fallback -= 1;
                } else if emit_ok(&st) {
                    match u8::try_from(u32::from(c)) {
                        Ok(b) if b >= 0x80 => out.byte(b),
                        _ => out.ch(c),
                    }
                }
                i += 1;
            }
        }
    }
    out.flush();
    if html_mode {
        RtfBody::Html(out.text)
    } else {
        RtfBody::Text(out.text.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html_of(b: RtfBody) -> String {
        match b {
            RtfBody::Html(h) => h,
            RtfBody::Text(t) => format!("(texte au lieu de HTML) {t}"),
        }
    }

    #[test]
    fn decompresses_roundtrip() {
        let rtf = "{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n";
        let data = compressed_rtf::compress_rtf(rtf).expect("compression");
        assert_eq!(&data[8..12], b"LZFu");
        let back = decompress(&data).expect("décompression");
        assert_eq!(back, rtf);
        assert_eq!(convert(&back), RtfBody::Text("hello world".into()));
    }

    #[test]
    fn rejects_hostile_headers_without_panicking() {
        assert!(decompress(&[]).is_err());
        assert!(decompress(&[1, 2, 3]).is_err());
        // Taille déclarée de 4 Gio : refusée avant toute allocation.
        let mut big = vec![0u8; 16];
        big[0] = 12;
        big[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        big[8..12].copy_from_slice(&LZFU.to_le_bytes());
        assert!(decompress(&big).is_err());
        // Non compressé, taille annoncée (1000) supérieure aux données (2 octets) : lu sans dépasser.
        let mut mela = vec![0u8; 16];
        mela[0] = 14;
        mela[4..8].copy_from_slice(&1000u32.to_le_bytes());
        mela[8..12].copy_from_slice(&MELA.to_le_bytes());
        mela.extend_from_slice(b"{}");
        assert_eq!(decompress(&mela).as_deref(), Ok("{}"));
    }

    #[test]
    fn deencapsulates_html() {
        // Extrait typique produit par Outlook (MS-OXRTFEX §4).
        let rtf = r#"{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl{\f0\fswiss Arial;}}
{\*\htmltag19 <html>}{\*\htmltag34 <head>}{\*\htmltag161 <title>}Rapport{\*\htmltag169 </title>}
{\*\htmltag41 </head>}{\*\htmltag50 <body>}\htmlrtf {\htmlrtf0
{\*\htmltag64 <p>}Fr\'e9d\'e9ric \u8364? 1 & 2 \{ok\}{\*\htmltag244 <a href="http://x.example/?a=1&amp;b=2">}lien{\*\htmltag252 </a>}\htmlrtf\par\htmlrtf0
{\*\htmltag72 </p>}
\htmlrtf }\htmlrtf0 {\*\htmltag58 </body>}{\*\htmltag27 </html>}}"#;
        let html = html_of(convert(rtf));
        assert!(html.contains("<title>Rapport</title>"), "{html}");
        assert!(
            html.contains(
                "<p>Frédéric € 1 & 2 {ok}<a href=\"http://x.example/?a=1&amp;b=2\">lien</a>"
            ),
            "{html}"
        );
        assert!(html.contains("</body></html>"), "{html}");
        assert!(!html.contains("Arial"), "table des polices exclue");
        assert!(!html.contains("\\"), "aucun mot de contrôle restant");
    }

    #[test]
    fn extracts_text_from_native_rtf() {
        let rtf = r"{\rtf1\ansi{\fonttbl{\f0 Calibri;}}{\*\generator Riched20}\pard Bonjour\par {\b le} monde\tab !\par}";
        assert_eq!(convert(rtf), RtfBody::Text("Bonjour\nle monde\t!".into()));
    }
}
