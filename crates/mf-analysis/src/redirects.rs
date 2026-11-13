//! Liens de redirection (FR-048) : la vraie destination est souvent encodée dans le lien lui-même
//! (Safe Links, Proofpoint, Google, Bing…). On la décode **sans suivre le lien** (aucune requête),
//! puis elle est ajoutée à la liste des URL pour être analysée comme les autres.

use crate::urls::host;
use base64::Engine;
use mf_core::{Message, Redirect, UrlEntry, UrlLocation};
use percent_encoding::percent_decode_str;

/// Profondeur maximale d'imbrication (Safe Links → Google → Bing → cible).
const MAX_DEPTH: usize = 5;

fn decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " "))
        .decode_utf8_lossy()
        .trim()
        .to_string()
}

fn query_params(url: &str) -> Vec<(String, String)> {
    let Some((_, q)) = url.split_once('?') else {
        return Vec::new();
    };
    let q = q.split('#').next().unwrap_or(q);
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect()
}

fn param(url: &str, names: &[&str]) -> Option<String> {
    let params = query_params(url);
    names
        .iter()
        .find_map(|n| params.iter().find(|(k, _)| k == n).map(|(_, v)| decode(v)))
}

fn is_web(u: &str) -> bool {
    let l = u.to_ascii_lowercase();
    (l.starts_with("http://") || l.starts_with("https://")) && u.len() > 10
}

fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.find('/').map_or("", |i| &rest[i..])
}

/// Bing `ck/a` : `u=a1` + base64url de la cible.
fn bing(url: &str) -> Option<String> {
    let u = param(url, &["u"])?;
    let b64 = u.strip_prefix("a1")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Proofpoint URL Defense v2 (`u=` avec `-`→`%` et `_`→`/`) et v3 (`/v3/__URL__;…`).
fn proofpoint(url: &str) -> Option<String> {
    if let Some(i) = url.find("/v3/__") {
        let rest = &url[i + 6..];
        let end = rest.find("__;").unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    let u = param(url, &["u"])?;
    let u = u.replace('-', "%").replace('_', "/");
    Some(percent_decode_str(&u).decode_utf8_lossy().into_owned())
}

/// Décode un lien de redirection connu : (service, destination, redirecteur détourné).
pub fn unwrap(url: &str) -> Option<Redirect> {
    let h = host(url)?;
    let path = path_of(url).to_ascii_lowercase();
    let found = |service: &str, target: Option<String>, abused: bool| {
        target.filter(|t| is_web(t)).map(|target| Redirect {
            service: service.to_string(),
            target,
            abused,
        })
    };
    let google = h == "google.com"
        || h.starts_with("www.google.")
        || h.starts_with("google.")
        || h.ends_with(".google.com");
    if h.ends_with("safelinks.protection.outlook.com") {
        return found("Microsoft Safe Links", param(url, &["url"]), false);
    }
    if h.ends_with("urldefense.proofpoint.com") || h == "urldefense.com" {
        return found("Proofpoint URL Defense", proofpoint(url), false);
    }
    if google && path.starts_with("/url") {
        return found("Google", param(url, &["q", "url"]), true);
    }
    if google && path.starts_with("/amp/s/") {
        let rest = &path_of(url)["/amp/s/".len()..];
        return found("Google AMP", Some(format!("https://{rest}")), true);
    }
    if (h == "bing.com" || h == "www.bing.com") && path.starts_with("/ck/a") {
        return found("Bing", bing(url), true);
    }
    if matches!(
        h.as_str(),
        "l.facebook.com" | "lm.facebook.com" | "l.instagram.com" | "l.messenger.com"
    ) {
        return found("Facebook / Instagram", param(url, &["u"]), true);
    }
    if (h == "www.youtube.com" || h == "youtube.com") && path.starts_with("/redirect") {
        return found("YouTube", param(url, &["q"]), true);
    }
    if h.ends_with("linkedin.com") && path.contains("redir") {
        return found("LinkedIn", param(url, &["url"]), true);
    }
    if h == "slack-redir.net" {
        return found("Slack", param(url, &["url"]), false);
    }
    // Paramètre générique qui contient une URL complète (suivi d'emailing, redirecteurs maison).
    let generic = param(
        url,
        &[
            "url",
            "u",
            "target",
            "dest",
            "destination",
            "redirect",
            "redirect_url",
            "goto",
            "link",
            "r",
            "to",
            "next",
            "out",
        ],
    )?;
    let target_host = host(&generic)?;
    (target_host != h)
        .then_some(())
        .and(found("paramètre de redirection", Some(generic), false))
}

/// Décode les redirections et ajoute les destinations à la liste des URL.
pub fn expand(msg: &mut Message) {
    let mut i = 0;
    let mut depth: Vec<usize> = vec![0; msg.urls.len()];
    while i < msg.urls.len() {
        let d = depth[i];
        if d < MAX_DEPTH {
            if let Some(r) = unwrap(&msg.urls[i].url) {
                let from = msg.urls[i].host.clone().unwrap_or_default();
                let target = r.target.clone();
                msg.urls[i].redirect = Some(r);
                let loc = UrlLocation::Redirect { from };
                if let Some(e) = msg.urls.iter_mut().find(|e| e.url == target) {
                    if !e.locations.contains(&loc) {
                        e.locations.push(loc);
                    }
                } else {
                    msg.urls.push(UrlEntry {
                        defanged: crate::urls::defang(&target),
                        host: host(&target),
                        url: target,
                        locations: vec![loc],
                        occurrences: 1,
                        display_texts: Vec::new(),
                        unicode_host: None,
                        lookalike_of: None,
                        flags: Vec::new(),
                        redirect: None,
                    });
                    depth.push(d + 1);
                }
            }
        }
        i += 1;
    }
}

/// Destination finale d'une URL, en suivant les redirections décodées.
pub fn final_target<'a>(urls: &'a [UrlEntry], url: &'a str) -> &'a str {
    let mut cur = url;
    for _ in 0..MAX_DEPTH {
        match urls
            .iter()
            .find(|u| u.url == cur)
            .and_then(|u| u.redirect.as_ref())
        {
            Some(r) => cur = &r.target,
            None => break,
        }
    }
    cur
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn known_redirectors() {
        let r = unwrap("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&data=05%7C01").unwrap();
        assert_eq!(
            (r.service.as_str(), r.target.as_str(), r.abused),
            ("Microsoft Safe Links", "https://evil.example/login", false)
        );
        let r = unwrap("https://www.google.com/url?sa=t&q=https://evil.example/x&usg=AOv").unwrap();
        assert_eq!(
            (r.target.as_str(), r.abused),
            ("https://evil.example/x", true)
        );
        let r = unwrap(
            "https://www.bing.com/ck/a?!&&p=abc&u=a1aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcGF0aA&ntb=1",
        )
        .unwrap();
        assert_eq!(r.target, "https://evil.example/path");
        let r =
            unwrap("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_a_b&d=DwMF")
                .unwrap();
        assert_eq!(r.target, "https://evil.example/a/b");
        let r = unwrap("https://urldefense.com/v3/__https://evil.example/p?x=1__;!!abc$").unwrap();
        assert_eq!(r.target, "https://evil.example/p?x=1");
        let r = unwrap("https://www.google.com/amp/s/evil.example/a").unwrap();
        assert_eq!(r.target, "https://evil.example/a");
        let r = unwrap("https://click.news.example/track?id=1&url=https%3A%2F%2Fshop.example%2F")
            .unwrap();
        assert_eq!(
            (r.service.as_str(), r.abused),
            ("paramètre de redirection", false)
        );
        assert!(unwrap("https://www.google.com/search?q=https://x.example").is_none());
        assert!(unwrap("https://shop.example/?next=/account").is_none());
    }

    #[test]
    fn nested_chain_is_expanded() {
        let inner = "https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fz";
        let outer = format!(
            "https://nam02.safelinks.protection.outlook.com/?url={}",
            percent_encoding::utf8_percent_encode(inner, percent_encoding::NON_ALPHANUMERIC)
        );
        let mut m = Message::default();
        m.urls = crate::urls::extract(&Message {
            body_text: Some(outer.clone()),
            ..Message::default()
        });
        expand(&mut m);
        let all: Vec<&str> = m.urls.iter().map(|u| u.url.as_str()).collect();
        assert_eq!(all, vec![outer.as_str(), inner, "https://evil.example/z"]);
        assert_eq!(final_target(&m.urls, &outer), "https://evil.example/z");
    }
}
