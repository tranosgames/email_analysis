//! Résultats d'authentification déclarés (FR-013) : `Authentication-Results` (RFC 8601),
//! `ARC-Authentication-Results` (RFC 8617) et `Received-SPF` (RFC 7208).
//!
//! Ce sont les verdicts **écrits par les serveurs** au moment de la réception. Le plus récent
//! (premier dans la liste des en-têtes) est celui du serveur de réception final : c'est lui qui
//! fait foi, les autres peuvent avoir été ajoutés en amont, y compris par l'expéditeur.

use mf_core::{AuthResult, Header};

/// Retire les commentaires `( … )`, imbriqués compris, hors guillemets.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let (mut depth, mut quoted, mut escaped) = (0u32, false, false);
    for c in s.chars() {
        if escaped {
            escaped = false;
            if depth == 0 {
                out.push(c);
            }
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                if depth == 0 {
                    out.push(c);
                }
            }
            '"' if depth == 0 => {
                quoted = !quoted;
                out.push(c);
            }
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn unfold(s: &str) -> String {
    s.split(['\r', '\n'])
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Découpe `méthode=résultat prop=valeur …` en un résultat.
fn parse_resinfo(part: &str, authserv: Option<&str>, h: &Header) -> Option<AuthResult> {
    let mut tokens = part.split_whitespace();
    let (method, result) = tokens.next()?.split_once('=')?;
    let method = method
        .split('/')
        .next()
        .unwrap_or(method)
        .to_ascii_lowercase();
    if method.is_empty() || result.is_empty() {
        return None;
    }
    let properties = tokens
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.to_ascii_lowercase(), unquote(v)))
        .collect();
    Some(AuthResult {
        method,
        result: result.to_ascii_lowercase(),
        authserv_id: authserv.map(str::to_string),
        properties,
        header_name: h.name.clone(),
        header_index: h.index,
        most_recent: false,
    })
}

fn parse_authentication_results(h: &Header) -> Vec<AuthResult> {
    let value = strip_comments(&unfold(&h.value));
    let mut parts = value.split(';').map(str::trim).filter(|p| !p.is_empty());
    let mut first = parts.next().unwrap_or("");
    // ARC-Authentication-Results commence par « i=N ; ».
    let is_arc = h.name.eq_ignore_ascii_case("ARC-Authentication-Results");
    if is_arc && first.starts_with("i=") {
        first = parts.next().unwrap_or("");
    }
    // authserv-id [version] — ou directement un résultat si l'en-tête est mal formé.
    let (authserv, inline) = if first.contains('=') {
        (None, Some(first))
    } else {
        (first.split_whitespace().next(), None)
    };
    inline
        .into_iter()
        .chain(parts)
        .filter(|p| !p.eq_ignore_ascii_case("none"))
        .filter_map(|p| parse_resinfo(p, authserv, h))
        .collect()
}

fn parse_received_spf(h: &Header) -> Option<AuthResult> {
    let value = unfold(&h.value);
    let result = value.split_whitespace().next()?.to_ascii_lowercase();
    let after = strip_comments(&value);
    let properties = after
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .map(|(k, v)| {
            (
                k.trim()
                    .rsplit(' ')
                    .next()
                    .unwrap_or(k)
                    .to_ascii_lowercase(),
                unquote(v),
            )
        })
        .collect();
    Some(AuthResult {
        method: "spf".into(),
        result,
        authserv_id: after
            .split(';')
            .filter_map(|kv| kv.trim().split_once('='))
            .find(|(k, _)| k.trim().ends_with("receiver"))
            .map(|(_, v)| unquote(v)),
        properties,
        header_name: h.name.clone(),
        header_index: h.index,
        most_recent: false,
    })
}

/// Tous les résultats, dans l'ordre des en-têtes (le plus récent d'abord).
pub fn results(headers: &[Header]) -> Vec<AuthResult> {
    let mut out = Vec::new();
    for h in headers {
        if h.name.eq_ignore_ascii_case("Authentication-Results")
            || h.name.eq_ignore_ascii_case("ARC-Authentication-Results")
        {
            out.extend(parse_authentication_results(h));
        } else if h.name.eq_ignore_ascii_case("Received-SPF") {
            out.extend(parse_received_spf(h));
        }
    }
    // Le premier `Authentication-Results` rencontré est celui du serveur final.
    if let Some(first) = out
        .iter()
        .find(|r| r.header_name.eq_ignore_ascii_case("Authentication-Results"))
        .map(|r| r.header_index)
    {
        for r in out.iter_mut().filter(|r| r.header_index == first) {
            r.most_recent = true;
        }
    }
    out
}

/// Verdict faisant foi pour une méthode : celui du serveur final, sinon le plus récent connu.
pub fn verdict<'a>(results: &'a [AuthResult], method: &str) -> Option<&'a AuthResult> {
    results
        .iter()
        .filter(|r| r.method == method)
        .find(|r| r.most_recent)
        .or_else(|| {
            results
                .iter()
                .find(|r| r.method == method && !r.header_name.starts_with("ARC"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u32, name: &str, v: &str) -> Header {
        Header {
            index: i,
            name: name.into(),
            raw: format!("{name}: {v}"),
            value: v.into(),
            offset: None,
        }
    }

    #[test]
    fn rfc8601_and_real_world() {
        let headers = [
            h(
                0,
                "Authentication-Results",
                "mx.google.com;\r\n       dkim=pass header.i=@example.com header.s=s1 header.b=AbCd;\r\n       spf=softfail (google.com: domain of transitioning x@example.com does not designate 1.2.3.4 as permitted sender) smtp.mailfrom=x@example.com;\r\n       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=example.com",
            ),
            h(
                1,
                "ARC-Authentication-Results",
                "i=1; relay.example.net; spf=pass smtp.mailfrom=example.com",
            ),
            h(
                2,
                "Received-SPF",
                "Pass (mailfrom) identity=mailfrom; client-ip=192.0.2.1; helo=mail.example.org; envelope-from=a@example.org; receiver=mx.example.net",
            ),
            h(3, "Authentication-Results", "upstream.example; none"),
        ];
        let r = results(&headers);
        let spf = verdict(&r, "spf").expect("spf");
        assert_eq!(
            (
                spf.result.as_str(),
                spf.authserv_id.as_deref(),
                spf.most_recent
            ),
            ("softfail", Some("mx.google.com"), true)
        );
        assert!(
            spf.properties
                .contains(&("smtp.mailfrom".into(), "x@example.com".into()))
        );
        assert_eq!(
            verdict(&r, "dmarc").map(|d| d.result.as_str()),
            Some("fail")
        );
        assert_eq!(verdict(&r, "dkim").map(|d| d.result.as_str()), Some("pass"));
        let arc = r
            .iter()
            .find(|x| x.header_name.starts_with("ARC"))
            .expect("arc");
        assert_eq!(
            (
                arc.result.as_str(),
                arc.authserv_id.as_deref(),
                arc.most_recent
            ),
            ("pass", Some("relay.example.net"), false)
        );
        let rspf = r
            .iter()
            .find(|x| x.header_name == "Received-SPF")
            .expect("received-spf");
        assert_eq!(
            (rspf.result.as_str(), rspf.authserv_id.as_deref()),
            ("pass", Some("mx.example.net"))
        );
        assert!(
            rspf.properties
                .contains(&("client-ip".into(), "192.0.2.1".into()))
        );
        assert_eq!(
            r.iter().filter(|x| x.header_index == 3).count(),
            0,
            "« none » n'est pas un résultat"
        );
    }
}
