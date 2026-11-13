//! Liens trompeurs et domaines sosies (FR-022, FR-043).

use crate::urls::{decode_entities, host};
use mf_core::{Message, UrlFlag};
use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;

/// Marques fréquemment imitées dans l'hameçonnage (liste volontairement courte et explicable).
pub const BRANDS: [&str; 40] = [
    "microsoft",
    "office365",
    "outlook",
    "onedrive",
    "sharepoint",
    "google",
    "gmail",
    "apple",
    "icloud",
    "paypal",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "docusign",
    "adobe",
    "wetransfer",
    "dhl",
    "fedex",
    "laposte",
    "chronopost",
    "colissimo",
    "ameli",
    "impots",
    "orange",
    "bouygues",
    "creditagricole",
    "bnpparibas",
    "societegenerale",
    "labanquepostale",
    "boursorama",
    "caisseepargne",
    "creditmutuel",
    "sncf",
    "binance",
    "coinbase",
    "whatsapp",
    "yahoo",
];

static ANCHOR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)<a\b([^>]*)>(.*?)</a\s*>").ok());
static HREF: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).ok());
static TAG: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"(?s)<[^>]*>").ok());
static DOMAIN_LIKE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?$").ok()
});

// ——— Punycode (RFC 3492) ———

fn adapt(mut delta: u32, num_points: u32, first: bool) -> u32 {
    delta /= if first { 700 } else { 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > 455 {
        delta /= 35;
        k += 36;
    }
    k + (36 * delta) / (delta + 38)
}

/// Décode un label `xn--…` ; `None` s'il est invalide.
pub fn punycode_decode(label: &str) -> Option<String> {
    let input = label.strip_prefix("xn--")?;
    let (basic, encoded) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    let mut output: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let mut chars = encoded.chars().peekable();
    while chars.peek().is_some() {
        let old_i = i;
        let mut w = 1u32;
        let mut k = 36u32;
        loop {
            let c = chars.next()?;
            let digit = match c {
                'a'..='z' => c as u32 - 'a' as u32,
                'A'..='Z' => c as u32 - 'A' as u32,
                '0'..='9' => c as u32 - '0' as u32 + 26,
                _ => return None,
            };
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                1
            } else if k >= bias + 26 {
                26
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(36 - t)?;
            k += 36;
        }
        let len = output.len() as u32 + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        n = n.checked_add(i / len)?;
        i %= len;
        output.insert(usize::try_from(i).ok()?, char::from_u32(n)?);
        i += 1;
    }
    Some(output.into_iter().collect())
}

/// Hôte en Unicode (labels punycode décodés), si au moins un label était encodé.
pub fn unicode_host(h: &str) -> Option<String> {
    if !h.split('.').any(|l| l.starts_with("xn--")) {
        return None;
    }
    Some(
        h.split('.')
            .map(|l| punycode_decode(l).unwrap_or_else(|| l.to_string()))
            .collect::<Vec<_>>()
            .join("."),
    )
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

fn script(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    Some(match c as u32 {
        0x41..=0x5A | 0x61..=0x7A | 0xC0..=0x24F => Script::Latin,
        0x370..=0x3FF => Script::Greek,
        0x400..=0x52F => Script::Cyrillic,
        _ => Script::Other,
    })
}

/// Un label mêle plusieurs écritures (ex. « pаypal » avec un « а » cyrillique).
pub fn mixed_script(h: &str) -> bool {
    h.split('.').any(|label| {
        let mut seen: Vec<Script> = label.chars().filter_map(script).collect();
        seen.dedup();
        seen.sort_by_key(|s| *s as u8);
        seen.dedup();
        seen.len() > 1
    })
}

/// Remplace les caractères de substitution courants (chiffres, homoglyphes cyrilliques…).
fn deconfuse(label: &str) -> String {
    let mapped: String = label
        .to_lowercase()
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            '0' | 'о' | 'ο' => 'o',
            '1' | 'ӏ' | 'і' | 'ı' => 'l',
            '3' | 'е' | 'ε' => 'e',
            '4' | '@' | 'а' | 'α' => 'a',
            '5' | 'ѕ' => 's',
            '7' => 't',
            '8' => 'b',
            'р' | 'ρ' => 'p',
            'с' => 'c',
            'х' => 'x',
            'у' => 'y',
            'ԁ' => 'd',
            'ј' => 'j',
            'ν' => 'v',
            c => c,
        })
        .collect();
    mapped.replace("rn", "m").replace("vv", "w")
}

/// Domaine enregistrable (approximation : deux derniers labels, trois pour `co.uk`, `gouv.fr`…).
pub fn registrable(h: &str) -> String {
    let labels: Vec<&str> = h.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return h.to_ascii_lowercase();
    }
    let second = labels[n - 2];
    let take = if labels[n - 1].len() == 2
        && matches!(
            second,
            "co" | "com" | "org" | "net" | "gov" | "gouv" | "ac" | "edu"
        ) {
        3
    } else {
        2
    };
    labels[n - take.min(n)..].join(".").to_ascii_lowercase()
}

/// Marque imitée par un domaine, s'il y en a une.
pub fn lookalike(h: &str) -> Option<&'static str> {
    let host = unicode_host(h)
        .unwrap_or_else(|| h.to_string())
        .to_lowercase();
    let reg = registrable(&host);
    let reg_label = reg.split('.').next().unwrap_or("");
    for brand in BRANDS {
        let plain: String = reg_label.chars().filter(|c| *c != '-').collect();
        // Substitution de caractères dans le domaine enregistrable : micros0ft, paypa1, rnicrosoft…
        // Marques courtes (dhl, sncf…) : segment entier seulement, pour éviter les faux positifs.
        let substituted = if brand.len() <= 4 {
            reg_label
                .split('-')
                .any(|seg| seg != brand && deconfuse(seg) == brand)
        } else {
            !plain.contains(brand) && deconfuse(reg_label).contains(brand)
        };
        if substituted {
            return Some(brand);
        }
        // Marque placée en sous-domaine d'un domaine qui ne lui appartient pas : paypal.com.secure-x.top
        let subs = &host[..host.len().saturating_sub(reg.len())];
        if !plain.contains(brand) && subs.split(['.', '-']).any(|l| l == brand) {
            return Some(brand);
        }
    }
    None
}

/// Alertes sur les URL d'un message, et textes affichés des liens.
pub fn analyze(msg: &mut Message) {
    let mut anchors: Vec<(String, String)> = Vec::new();
    if let (Some(html), Some(a_re), Some(href_re), Some(tag_re)) =
        (&msg.body_html, ANCHOR.as_ref(), HREF.as_ref(), TAG.as_ref())
    {
        for cap in a_re.captures_iter(html) {
            let attrs = cap.get(1).map_or("", |m| m.as_str());
            let Some(h) = href_re.captures(attrs) else {
                continue;
            };
            let href = decode_entities(
                h.get(1)
                    .or(h.get(2))
                    .or(h.get(3))
                    .map_or("", |m| m.as_str()),
            )
            .trim()
            .to_string();
            let text =
                decode_entities(&tag_re.replace_all(cap.get(2).map_or("", |m| m.as_str()), " "));
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if !href.is_empty() && !text.is_empty() {
                anchors.push((href, text));
            }
        }
    }
    for u in &mut msg.urls {
        for (href, text) in &anchors {
            if (href == &u.url || href.starts_with(&u.url))
                && !u.display_texts.contains(text)
                && u.display_texts.len() < 10
            {
                u.display_texts.push(text.clone());
            }
        }
        let Some(h) = u.host.clone() else { continue };
        let mut flags = Vec::new();
        let target_reg = registrable(&h);
        if u.display_texts.iter().any(|t| {
            DOMAIN_LIKE.as_ref().is_some_and(|r| r.is_match(t))
                && host(t).is_some_and(|th| registrable(&th) != target_reg)
        }) {
            flags.push(UrlFlag::TextTargetMismatch);
        }
        if h.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
            flags.push(UrlFlag::RawIp);
        }
        u.unicode_host = unicode_host(&h);
        if u.unicode_host.is_some() {
            flags.push(UrlFlag::Punycode);
        }
        if mixed_script(u.unicode_host.as_deref().unwrap_or(&h)) {
            flags.push(UrlFlag::MixedScript);
        }
        u.lookalike_of = lookalike(&h).map(str::to_string);
        if u.lookalike_of.is_some() {
            flags.push(UrlFlag::Lookalike);
        }
        let authority = u
            .url
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("");
        if authority.contains('@') && u.url.contains("://") {
            flags.push(UrlFlag::Credentials);
        }
        u.flags = flags;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punycode_rfc3492() {
        assert_eq!(
            punycode_decode("xn--mnchen-3ya").as_deref(),
            Some("münchen")
        );
        assert_eq!(punycode_decode("xn--pypal-4ve").as_deref(), Some("pаypal"));
        assert_eq!(
            unicode_host("www.xn--pypal-4ve.com").as_deref(),
            Some("www.pаypal.com")
        );
        assert!(punycode_decode("xn--!!").is_none());
    }

    #[test]
    fn lookalikes() {
        assert_eq!(lookalike("micros0ft-help.example"), Some("microsoft"));
        assert_eq!(lookalike("paypa1.com"), Some("paypal"));
        assert_eq!(lookalike("rnicrosoft.com"), Some("microsoft"));
        assert_eq!(lookalike("xn--pypal-4ve.com"), Some("paypal"));
        assert_eq!(lookalike("paypal.com.secure-login.top"), Some("paypal"));
        assert_eq!(lookalike("www.paypal.com"), None);
        assert_eq!(lookalike("login.microsoftonline.com"), None);
        assert_eq!(lookalike("example.org"), None);
        assert!(mixed_script("pаypal.com"));
        assert!(!mixed_script("münchen.de"));
        assert_eq!(registrable("a.b.example.co.uk"), "example.co.uk");
    }
}
