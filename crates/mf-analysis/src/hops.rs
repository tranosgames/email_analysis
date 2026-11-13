//! Chaîne `Received` et résumé d'acheminement (FR-012, FR-042).
//!
//! Les noms DNS affichés sont ceux **enregistrés dans les en-têtes** par les serveurs au moment
//! du transit (DNS inverse, HELO). Aucune résolution DNS n'est effectuée : l'outil reste
//! hors-ligne (Constitution VI) et la valeur affichée est celle de la preuve, pas celle
//! d'aujourd'hui.

use mail_parser::{HeaderValue, Host, MessageParser};
use mf_core::{Endpoint, Header, Hop, IpScope, MailRoute, Message};
use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;

static BRACKET_IP: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{3,45})\]").ok());
static BY_PAREN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)\bby\s+\S+\s+\(([^)]*)\)").ok());
static WITH: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)\bwith\s+([A-Za-z0-9-]+)").ok());
static BY: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"(?i)\bby\s+([^\s;()]+)").ok());
static FROM: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*from\s+([^\s;()]+)").ok());

/// En-têtes où les clients de messagerie / webmails inscrivent l'IP de l'utilisateur.
const ORIGINATING_HEADERS: [&str; 4] = [
    "X-Originating-IP",
    "X-Sender-IP",
    "X-Source-IP",
    "X-MS-Exchange-Organization-OriginalClientIPAddress",
];

/// Portée d'une IP.
pub fn ip_scope(ip: &IpAddr) -> IpScope {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                IpScope::Loopback
            } else if v4.is_private() {
                IpScope::Private
            } else if v4.is_link_local() {
                IpScope::LinkLocal
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                IpScope::Shared
            } else if matches!(
                (o[0], o[1], o[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            ) {
                IpScope::Documentation
            } else {
                IpScope::Public
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if v6.is_loopback() {
                IpScope::Loopback
            } else if seg[0] & 0xfe00 == 0xfc00 {
                IpScope::Private
            } else if seg[0] & 0xffc0 == 0xfe80 {
                IpScope::LinkLocal
            } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                IpScope::Documentation
            } else if let Some(v4) = v6.to_ipv4_mapped() {
                ip_scope(&IpAddr::V4(v4))
            } else {
                IpScope::Public
            }
        }
    }
}

/// Publique au sens de l'analyse (routable sur Internet ; la documentation compte comme publique).
fn is_public(scope: Option<IpScope>) -> bool {
    matches!(scope, Some(IpScope::Public | IpScope::Documentation))
}

fn host_str(h: &Host<'_>) -> String {
    match h {
        Host::Name(n) => n.trim_end_matches('.').to_string(),
        Host::IpAddr(ip) => ip.to_string(),
    }
}

fn clean_name(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').trim_matches(['[', ']']);
    let lower = s.to_ascii_lowercase();
    (!s.is_empty() && lower != "unknown" && lower != "localhost.localdomain").then(|| s.to_string())
}

fn unfold(s: &str) -> String {
    s.split(['\r', '\n'])
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Analyse un en-tête `Received` (repli par expressions régulières si `mail-parser` échoue).
fn parse_received(h: &Header) -> Hop {
    let value = unfold(&h.value);
    let buf = format!("Received: {value}\r\n\r\n");
    let mut hop = Hop {
        header_index: h.index,
        ..Default::default()
    };

    let parsed = MessageParser::default().parse(buf.as_bytes());
    let received = parsed
        .as_ref()
        .and_then(|m| match m.headers().first().map(|x| x.value()) {
            Some(HeaderValue::Received(r)) => Some(r.as_ref().clone()),
            _ => None,
        });
    if let Some(r) = received {
        hop.from_name = r.from.as_ref().map(host_str).and_then(|s| clean_name(&s));
        hop.from_helo = r.helo.as_ref().map(host_str).and_then(|s| clean_name(&s));
        hop.from_rdns = r.from_iprev.as_deref().and_then(clean_name);
        hop.from_ip = r
            .from_ip
            .map(|ip| ip.to_string())
            .or_else(|| match &r.from {
                Some(Host::IpAddr(ip)) => Some(ip.to_string()),
                _ => None,
            });
        hop.by_name = r.by.as_ref().map(host_str).and_then(|s| clean_name(&s));
        if let Some(Host::IpAddr(ip)) = &r.by {
            hop.by_ip = Some(ip.to_string());
        }
        hop.with = r.with.as_ref().map(|w| w.to_string());
        hop.id = r.id.as_deref().map(str::to_string);
        hop.for_addr = r
            .for_
            .as_deref()
            .map(|f| f.trim_matches(['<', '>']).to_string());
        if let Some(d) = &r.date {
            hop.date_utc =
                chrono::DateTime::from_timestamp(d.to_timestamp(), 0).map(|t| t.to_rfc3339());
        }
    } else {
        // Repli : en-tête non conforme, on récupère ce qui est identifiable.
        hop.from_name = FROM
            .as_ref()
            .and_then(|r| r.captures(&value))
            .and_then(|c| clean_name(&c[1]));
        hop.by_name = BY
            .as_ref()
            .and_then(|r| r.captures(&value))
            .and_then(|c| clean_name(&c[1]));
        let from_part = value.split(" by ").next().unwrap_or(&value);
        hop.from_ip = BRACKET_IP
            .as_ref()
            .and_then(|r| r.captures(from_part))
            .map(|c| c[1].to_string())
            .filter(|ip| ip.parse::<IpAddr>().is_ok());
    }
    if hop.with.is_none() {
        hop.with = WITH
            .as_ref()
            .and_then(|r| r.captures(&value))
            .map(|c| c[1].to_string());
    }
    // `by NOM (IP)` (Exchange) : IP du serveur récepteur.
    if hop.by_ip.is_none() {
        hop.by_ip = BY_PAREN
            .as_ref()
            .and_then(|r| r.captures(&value))
            .and_then(|c| {
                c[1].split([' ', ',', '[', ']'])
                    .find(|t| t.parse::<IpAddr>().is_ok())
                    .map(str::to_string)
            });
    }
    hop.from_ip_scope = hop
        .from_ip
        .as_deref()
        .and_then(|ip| ip.parse().ok())
        .map(|ip| ip_scope(&ip));
    hop.date_raw = value
        .rsplit_once(';')
        .map(|(_, d)| d.trim().to_string())
        .filter(|d| !d.is_empty());
    hop
}

/// Chaîne `Received` du plus ancien au plus récent, avec délais entre sauts.
pub fn hops(msg: &Message) -> Vec<Hop> {
    let mut out: Vec<Hop> = msg
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Received"))
        .map(parse_received)
        .collect();
    out.reverse(); // le premier en-tête est le plus récent
    let mut prev: Option<chrono::DateTime<chrono::FixedOffset>> = None;
    for (i, hop) in out.iter_mut().enumerate() {
        hop.index = i as u32 + 1;
        let t = hop
            .date_utc
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok());
        if let (Some(a), Some(b)) = (prev, t) {
            hop.delay_seconds = Some((b - a).num_seconds());
        }
        if t.is_some() {
            prev = t;
        }
    }
    out
}

fn endpoint_from(hop: &Hop) -> Endpoint {
    Endpoint {
        ip: hop.from_ip.clone(),
        ip_scope: hop.from_ip_scope,
        rdns: hop.from_rdns.clone(),
        name: hop.from_helo.clone().or_else(|| hop.from_name.clone()),
        hop: hop.index,
        source: "Received".into(),
    }
}

/// Résumé d'acheminement (FR-042).
pub fn route(msg: &Message, hops: &[Hop]) -> MailRoute {
    let origin = hops
        .iter()
        .find(|h| h.from_ip.is_some() || h.from_name.is_some())
        .map(endpoint_from);
    let first_public = hops
        .iter()
        .find(|h| is_public(h.from_ip_scope))
        .map(endpoint_from);
    let last_public = hops
        .iter()
        .rev()
        .find(|h| is_public(h.from_ip_scope))
        .map(endpoint_from);
    let receiver = hops.last().map(|h| Endpoint {
        ip: h.by_ip.clone(),
        ip_scope: h
            .by_ip
            .as_deref()
            .and_then(|ip| ip.parse().ok())
            .map(|ip| ip_scope(&ip)),
        rdns: None,
        name: h.by_name.clone(),
        hop: h.index,
        source: "Received".into(),
    });
    let originating_ip_header = ORIGINATING_HEADERS.iter().find_map(|name| {
        let h = msg
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))?;
        let raw = h.value.trim().trim_matches(['[', ']']);
        let ip: IpAddr = raw.parse().ok()?;
        Some(Endpoint {
            ip: Some(ip.to_string()),
            ip_scope: Some(ip_scope(&ip)),
            rdns: None,
            name: None,
            hop: 0,
            source: h.name.clone(),
        })
    });
    let times: Vec<_> = hops
        .iter()
        .filter_map(|h| {
            h.date_utc
                .as_deref()
                .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
        })
        .collect();
    MailRoute {
        sender: msg
            .from
            .first()
            .and_then(|a| a.address.clone().or_else(|| a.x500_dn.clone())),
        // Afficher la première IP publique seulement si elle apporte une information de plus.
        first_public: first_public.filter(|f| origin.as_ref().is_none_or(|o| o.hop != f.hop)),
        last_public: last_public.filter(|l| origin.as_ref().is_none_or(|o| o.hop != l.hop)),
        origin,
        originating_ip_header,
        received_utc: hops.last().and_then(|h| h.date_utc.clone()),
        transit_seconds: match (times.first(), times.last()) {
            (Some(a), Some(b)) if times.len() > 1 => Some((*b - *a).num_seconds()),
            _ => None,
        },
        receiver,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(i: u32, name: &str, value: &str) -> Header {
        Header {
            index: i,
            name: name.into(),
            raw: format!("{name}: {value}"),
            value: value.into(),
            offset: None,
        }
    }

    fn msg(received: &[&str], extra: &[(&str, &str)]) -> Message {
        let mut headers: Vec<Header> = received
            .iter()
            .enumerate()
            .map(|(i, v)| header(i as u32, "Received", v))
            .collect();
        for (n, v) in extra {
            headers.push(header(headers.len() as u32, n, v));
        }
        Message {
            headers,
            ..Default::default()
        }
    }

    #[test]
    fn chain_with_private_origin() {
        let m = msg(
            &[
                "from mx.attacker.example (mx.attacker.example [203.0.113.7]) by mx.victim.example with ESMTPS id abc123; Tue, 13 Oct 2026 09:12:03 +0000",
                "from [192.168.1.20] (unknown [198.51.100.4]) by mx.attacker.example with ESMTPSA; Tue, 13 Oct 2026 09:12:01 +0000",
            ],
            &[("X-Originating-IP", "[198.51.100.4]")],
        );
        let h = hops(&m);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].index, 1);
        assert_eq!(h[0].from_ip.as_deref(), Some("198.51.100.4"));
        assert_eq!(h[0].from_name.as_deref(), Some("192.168.1.20"));
        assert_eq!(h[0].from_rdns, None, "« unknown » n'est pas un nom");
        assert_eq!(h[1].from_rdns.as_deref(), Some("mx.attacker.example"));
        assert_eq!(h[1].by_name.as_deref(), Some("mx.victim.example"));
        assert_eq!(h[1].delay_seconds, Some(2));
        let r = route(&m, &h);
        let o = r.origin.as_ref().expect("origine");
        assert_eq!((o.ip.as_deref(), o.hop), (Some("198.51.100.4"), 1));
        let last = r.last_public.as_ref().expect("dernière IP publique");
        assert_eq!(
            (last.ip.as_deref(), last.rdns.as_deref()),
            (Some("203.0.113.7"), Some("mx.attacker.example"))
        );
        assert!(r.first_public.is_none(), "l'origine est déjà publique");
        assert_eq!(
            r.receiver.as_ref().and_then(|e| e.name.as_deref()),
            Some("mx.victim.example")
        );
        assert_eq!(
            r.originating_ip_header
                .as_ref()
                .and_then(|e| e.ip.as_deref()),
            Some("198.51.100.4")
        );
        assert_eq!(r.transit_seconds, Some(2));
    }

    #[test]
    fn real_world_formats() {
        let m = msg(
            &[
                "from AM0PR02MB5555.eurprd02.prod.outlook.com (2603:10a6:208:12c::14) by DB9PR02MB6666.eurprd02.prod.outlook.com (2603:10a6:10:1d1::9) with HTTPS; Mon, 14 Oct 2024 08:02:05 +0000",
                "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id a64; Mon, 14 Oct 2024 01:02:03 -0700 (PDT)",
                "from smtp.example.org (HELO relay.example.org) (198.51.100.20) by mail.example.net with SMTP; 14 Oct 2024 08:00:00 -0000",
                "from localhost (localhost [127.0.0.1]) by relay.example.org (Postfix) with ESMTP id 4F1; Mon, 14 Oct 2024 09:59:59 +0200",
            ],
            &[],
        );
        let h = hops(&m);
        assert_eq!(h[0].from_ip_scope, Some(IpScope::Loopback));
        assert_eq!(h[1].from_helo.as_deref(), Some("relay.example.org"));
        assert_eq!(
            h[2].from_rdns.as_deref(),
            Some("mail-sor-f41.google.com"),
            "point final retiré"
        );
        assert_eq!(h[2].with.as_deref(), Some("SMTPS"));
        assert_eq!(h[3].by_ip.as_deref(), Some("2603:10a6:10:1d1::9"));
        assert_eq!(h[3].from_ip_scope, Some(IpScope::Public));
        let r = route(&m, &h);
        assert_eq!(
            r.origin.as_ref().and_then(|o| o.ip.as_deref()),
            Some("127.0.0.1")
        );
        assert_eq!(
            r.first_public.as_ref().and_then(|o| o.ip.as_deref()),
            Some("198.51.100.20")
        );
        assert_eq!(
            r.receiver.as_ref().and_then(|o| o.ip.as_deref()),
            Some("2603:10a6:10:1d1::9")
        );
    }

    #[test]
    fn scopes() {
        let s = |x: &str| ip_scope(&x.parse().expect("ip"));
        assert_eq!(s("10.1.2.3"), IpScope::Private);
        assert_eq!(s("100.72.0.1"), IpScope::Shared);
        assert_eq!(s("8.8.8.8"), IpScope::Public);
        assert_eq!(s("fd00::1"), IpScope::Private);
        assert_eq!(s("fe80::1"), IpScope::LinkLocal);
        assert_eq!(s("::ffff:192.168.0.1"), IpScope::Private);
    }
}
