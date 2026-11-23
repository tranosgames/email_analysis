//! Filtre des lignes d'une boîte (feature 002, FR-007) : uniquement sur ce que contiennent les
//! tables de dossiers, plus le verdict et l'adresse des éléments déjà ouverts. Aucun élément n'est
//! lu ici.

use mf_core::{BoxFilter, ItemSummary};

/// Minuscules sans accents (latin) : « Éléonore » et « eleonore » se rejoignent.
pub fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        match c {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => out.push('a'),
            'ç' | 'ć' | 'č' => out.push('c'),
            'ď' | 'đ' => out.push('d'),
            'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' | 'ě' => out.push('e'),
            'ì' | 'í' | 'î' | 'ï' | 'ī' | 'į' | 'ı' => out.push('i'),
            'ł' | 'ľ' | 'ĺ' => out.push('l'),
            'ñ' | 'ń' | 'ň' => out.push('n'),
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => out.push('o'),
            'ŕ' | 'ř' => out.push('r'),
            'ś' | 'š' | 'ş' => out.push('s'),
            'ť' | 'ţ' => out.push('t'),
            'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' => out.push('u'),
            'ý' | 'ÿ' => out.push('y'),
            'ź' | 'ż' | 'ž' => out.push('z'),
            'æ' => out.push_str("ae"),
            'œ' => out.push_str("oe"),
            'ß' => out.push_str("ss"),
            c => out.push(c),
        }
    }
    out
}

/// Critère texte déjà normalisé, découpé en mots : chacun doit figurer dans l'un des champs
/// (« reunion comite » trouve « Réunion du Comité »). Un critère vide ne filtre rien.
struct Needle(Vec<String>);

impl Needle {
    fn new(v: &Option<String>) -> Self {
        Self(
            v.as_deref()
                .map(|s| fold(s).split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
        )
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn hits(&self, fields: &[Option<&str>]) -> bool {
        if self.0.is_empty() {
            return true;
        }
        let folded: Vec<String> = fields.iter().flatten().map(|f| fold(f)).collect();
        self.0
            .iter()
            .all(|w| folded.iter().any(|f| f.contains(w.as_str())))
    }
}

/// Filtre compilé : les textes sont normalisés une seule fois.
pub struct Compiled<'a> {
    f: &'a BoxFilter,
    text: Needle,
    from_name: Needle,
    to: Needle,
    subject: Needle,
    message_id: Needle,
    from_address: Needle,
    from_domain: Option<String>,
}

impl<'a> Compiled<'a> {
    pub fn new(f: &'a BoxFilter) -> Self {
        Self {
            f,
            text: Needle::new(&f.text),
            from_name: Needle::new(&f.from_name),
            to: Needle::new(&f.to),
            subject: Needle::new(&f.subject),
            message_id: Needle::new(&f.message_id),
            from_address: Needle::new(&f.from_address),
            from_domain: f
                .from_domain
                .as_deref()
                .map(|d| fold(d.trim().trim_start_matches('@')))
                .filter(|d| !d.is_empty()),
        }
    }

    /// `analyzed` : l'élément a été ouvert pendant la session.
    pub fn matches(&self, r: &ItemSummary, analyzed: bool) -> bool {
        let f = self.f;
        let date = r.received.as_deref().or(r.sent.as_deref());
        let in_range = |bound: &Option<String>, after: bool| match bound.as_deref().map(str::trim) {
            None | Some("") => true,
            Some(b) => date.is_some_and(|d| {
                let d = &d[..d.len().min(b.len())];
                if after { d >= b } else { d <= b }
            }),
        };
        let size = r.size.unwrap_or(0);
        self.text.hits(&[
            r.subject.as_deref(),
            r.from_name.as_deref(),
            r.from_address.as_deref(),
            r.to.as_deref(),
            r.cc.as_deref(),
        ]) && self.from_name.hits(&[r.from_name.as_deref()])
            && self.to.hits(&[r.to.as_deref(), r.cc.as_deref()])
            && self.subject.hits(&[r.subject.as_deref()])
            && self.message_id.hits(&[r.message_id.as_deref()])
            && in_range(&f.after, true)
            && in_range(&f.before, false)
            && f.min_size.is_none_or(|m| size >= m)
            && f.max_size.is_none_or(|m| size <= m)
            && f.has_attachments.is_none_or(|a| r.has_attachments == a)
            && (!f.analyzed_only || analyzed)
            && (f.verdict.is_empty() || r.verdict.is_some_and(|v| f.verdict.contains(&v)))
            && (self.from_address.is_empty()
                || (analyzed && self.from_address.hits(&[r.from_address.as_deref()])))
            && self.from_domain.as_deref().is_none_or(|d| {
                r.from_address.as_deref().is_some_and(|a| {
                    let host = fold(a.rsplit('@').next().unwrap_or(""));
                    host == d || host.ends_with(&format!(".{d}"))
                })
            })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mf_core::VerdictLevel;

    fn row() -> ItemSummary {
        ItemSummary {
            id: 1,
            folder: 2,
            message_class: Some("IPM.Note".into()),
            subject: Some("Réunion du Comité".into()),
            from_name: Some("Éléonore Martin".into()),
            to: Some("Bailey, Susan".into()),
            cc: Some("Paul".into()),
            sent: Some("2001-05-30T23:10:00+00:00".into()),
            received: Some("2001-05-31T08:00:00+00:00".into()),
            size: Some(30_000),
            has_attachments: true,
            message_id: Some("<abc@enron.com>".into()),
            from_address: None,
            verdict: None,
        }
    }

    fn ok(f: BoxFilter, r: &ItemSummary, analyzed: bool) -> bool {
        Compiled::new(&f).matches(r, analyzed)
    }

    #[test]
    fn table_criteria() {
        let r = row();
        assert!(ok(BoxFilter::default(), &r, false));
        let t = |s: &str| Some(s.to_string());
        assert!(ok(
            BoxFilter {
                from_name: t("eleonore"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(ok(
            BoxFilter {
                subject: t("REUNION comite"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(!ok(
            BoxFilter {
                subject: t("budget"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(
            ok(
                BoxFilter {
                    to: t("paul"),
                    ..Default::default()
                },
                &r,
                false
            ),
            "Cc compte"
        );
        assert!(ok(
            BoxFilter {
                text: t("susan"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(ok(
            BoxFilter {
                message_id: t("ABC@"),
                ..Default::default()
            },
            &r,
            false
        ));
        // Période : la date de réception prime ; une borne au jour inclut la journée.
        assert!(ok(
            BoxFilter {
                after: t("2001-05-31"),
                before: t("2001-05-31"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(!ok(
            BoxFilter {
                before: t("2001-05-30"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(!ok(
            BoxFilter {
                after: t("2001-06"),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(ok(
            BoxFilter {
                min_size: Some(29_000),
                max_size: Some(30_000),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(!ok(
            BoxFilter {
                min_size: Some(30_001),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(ok(
            BoxFilter {
                has_attachments: Some(true),
                ..Default::default()
            },
            &r,
            false
        ));
        assert!(!ok(
            BoxFilter {
                has_attachments: Some(false),
                ..Default::default()
            },
            &r,
            false
        ));
    }

    #[test]
    fn opened_criteria() {
        let mut r = row();
        let f = BoxFilter {
            analyzed_only: true,
            ..Default::default()
        };
        assert!(!ok(f.clone(), &r, false));
        assert!(ok(f, &r, true));
        let by_domain = BoxFilter {
            from_domain: Some("@Enron.com".into()),
            ..Default::default()
        };
        assert!(
            !ok(by_domain.clone(), &r, false),
            "adresse inconnue tant que l'élément n'est pas ouvert"
        );
        r.from_address = Some("susan.bailey@mail.enron.com".into());
        r.verdict = Some(VerdictLevel::Suspicious);
        assert!(ok(by_domain, &r, true), "sous-domaine accepté");
        assert!(!ok(
            BoxFilter {
                from_domain: Some("ron.com".into()),
                ..Default::default()
            },
            &r,
            true
        ));
        assert!(ok(
            BoxFilter {
                verdict: vec![VerdictLevel::Suspicious, VerdictLevel::Malicious],
                ..Default::default()
            },
            &r,
            true
        ));
        assert!(!ok(
            BoxFilter {
                verdict: vec![VerdictLevel::Legitimate],
                ..Default::default()
            },
            &r,
            true
        ));
        assert!(ok(
            BoxFilter {
                from_address: Some("SUSAN.bailey".into()),
                ..Default::default()
            },
            &r,
            true
        ));
    }
}
