//! Indicateurs de compromission d'un message (FR-021, FR-023) : ce qui peut être recherché ou
//! bloqué ailleurs (SOC, EDR, passerelle). Les destinataires et les IP privées sont exclus.

use crate::urls::defang;
use mf_core::{Ioc, IocKind, IpScope, Message, UrlFlag, UrlLocation};
use std::net::IpAddr;

/// Forme non cliquable d'un indicateur.
pub fn defang_value(kind: IocKind, value: &str) -> String {
    match kind {
        IocKind::Url => defang(value),
        IocKind::Domain | IocKind::Ipv4 => value.replace('.', "[.]"),
        IocKind::Ipv6 => value.replace(':', "[:]"),
        IocKind::Email => value.replace('@', "[@]").replace('.', "[.]"),
        IocKind::Sha256 | IocKind::Md5 => value.to_string(),
    }
}

#[derive(Default)]
struct Builder {
    items: Vec<Ioc>,
}

impl Builder {
    fn add(&mut self, kind: IocKind, value: &str, location: String) {
        let value = value.trim().trim_end_matches('.');
        if value.is_empty() {
            return;
        }
        let value = match kind {
            IocKind::Domain | IocKind::Email | IocKind::Sha256 | IocKind::Md5 => {
                value.to_ascii_lowercase()
            }
            _ => value.to_string(),
        };
        if let Some(i) = self
            .items
            .iter_mut()
            .find(|i| i.kind == kind && i.value == value)
        {
            if !i.locations.contains(&location) {
                i.locations.push(location);
            }
            return;
        }
        self.items.push(Ioc {
            kind,
            defanged: defang_value(kind, &value),
            value,
            locations: vec![location],
        });
    }

    fn host(&mut self, host: &str, location: String) {
        let h = host.trim_matches(['[', ']']);
        match h.parse::<IpAddr>() {
            Ok(ip) => self.ip(&ip, location),
            Err(_) if h.contains('.') => self.add(IocKind::Domain, h, location),
            Err(_) => {}
        }
    }

    fn ip(&mut self, ip: &IpAddr, location: String) {
        if !matches!(
            crate::hops::ip_scope(ip),
            IpScope::Public | IpScope::Documentation
        ) {
            return;
        }
        let kind = if ip.is_ipv4() {
            IocKind::Ipv4
        } else {
            IocKind::Ipv6
        };
        self.add(kind, &ip.to_string(), location);
    }
}

fn address_of(s: &str) -> Option<&str> {
    let s = s.trim();
    let inner = s
        .rsplit_once('<')
        .map_or(s, |(_, r)| r.trim_end_matches('>'));
    inner.contains('@').then_some(inner.trim())
}

pub fn extract(msg: &Message) -> Vec<Ioc> {
    let mut b = Builder::default();
    fn sender(label: &str, addr: &str, b: &mut Builder) {
        b.add(IocKind::Email, addr, label.to_string());
        if let Some((_, domain)) = addr.rsplit_once('@') {
            b.add(IocKind::Domain, domain, format!("{label} (domaine)"));
        }
    }
    for a in &msg.from {
        if let Some(addr) = &a.address {
            sender("From", addr, &mut b);
        }
    }
    if let Some(addr) = msg.sender.as_ref().and_then(|a| a.address.clone()) {
        sender("Sender", &addr, &mut b);
    }
    for a in &msg.reply_to {
        if let Some(addr) = a.address.as_deref().and_then(address_of) {
            sender("Reply-To", addr, &mut b);
        }
    }
    if let Some(rp) = msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Return-Path"))
    {
        if let Some(addr) = address_of(&rp.value) {
            sender("Return-Path", addr, &mut b);
        }
    }
    for h in &msg.hops {
        if let Some(ip) = h
            .from_ip
            .as_deref()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        {
            b.ip(&ip, format!("Received saut {}", h.index));
        }
    }
    if let Some(e) = msg
        .route
        .as_ref()
        .and_then(|r| r.originating_ip_header.as_ref())
    {
        if let Some(ip) = e.ip.as_deref().and_then(|ip| ip.parse::<IpAddr>().ok()) {
            b.ip(&ip, e.source.clone());
        }
    }
    // Adresse légitime affichée comme leurre devant un lien trompeur : ce n'est pas un indicateur.
    let decoys: Vec<&str> = msg
        .urls
        .iter()
        .filter(|u| u.flags.contains(&UrlFlag::TextTargetMismatch))
        .flat_map(|u| u.display_texts.iter().map(String::as_str))
        .collect();
    for u in &msg.urls {
        let only_text = u
            .locations
            .iter()
            .all(|l| matches!(l, UrlLocation::HtmlText | UrlLocation::BodyText));
        if only_text
            && decoys
                .iter()
                .any(|d| d.trim_end_matches('/') == u.url.trim_end_matches('/'))
        {
            continue;
        }
        let loc = u
            .locations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if u.url.to_ascii_lowercase().starts_with("mailto:") {
            if let Some(addr) = u.url.get(7..).map(|a| a.split('?').next().unwrap_or(a)) {
                b.add(IocKind::Email, addr, format!("URL ({loc})"));
            }
            continue;
        }
        b.add(IocKind::Url, &u.url, format!("URL ({loc})"));
        if let Some(h) = &u.host {
            b.host(h, format!("URL ({loc})"));
        }
    }
    for a in &msg.attachments {
        let loc = format!("PJ {} {}", a.index, a.filename);
        if a.extractable && !a.sha256.is_empty() {
            b.add(IocKind::Sha256, &a.sha256, loc.clone());
            b.add(IocKind::Md5, &a.md5, loc);
        }
    }
    let mut items = b.items;
    items.sort_by_key(|x| x.kind);
    items
}
