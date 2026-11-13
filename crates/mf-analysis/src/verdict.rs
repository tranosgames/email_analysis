//! Verdict de synthèse (FR-045) : **malveillant**, **à vérifier** ou **légitime**, calculé à partir
//! des constats et de l'authentification, avec ses raisons. C'est une aide au tri : il ne remplace
//! pas l'analyste et ne repose que sur ce que contient le fichier (aucune réputation externe).
//!
//! Principe :
//! - chaque constat pèse un poids selon sa règle ; la somme forme le score ;
//! - **malveillant** exige un score élevé **et** au moins un signe de tromperie délibérée
//!   (domaine sosie, exécutable déguisé, destination masquée…) : une simple mauvaise
//!   configuration SPF/DMARC d'un expéditeur légitime ne suffit pas ;
//! - **légitime** exige un score faible **et** une authentification réussie (DMARC pass, ou
//!   SPF et DKIM pass) : sans preuve d'authenticité, le message reste « à vérifier ».

use crate::auth;
use mf_core::{Message, Verdict, VerdictLevel};

/// Poids d'une règle et indication qu'elle traduit une tromperie délibérée.
fn weight(rule: &str) -> (u32, bool) {
    match rule {
        "sender_lookalike_domain"
        | "url_lookalike_domain"
        | "url_mixed_script"
        | "url_credentials"
        | "attachment_executable"
        | "attachment_double_extension"
        | "attachment_bidi_name"
        | "attachment_credential_form"
        | "attachment_exfiltration"
        | "signature_invalid"
        | "signature_signer_mismatch" => (40, true),
        "signature_key_revoked" => (30, false),
        "signature_key_expired" => (20, false),
        "smime_untrusted_ca" | "signature_unsupported" => (5, false),
        "signature_unknown_key" | "message_encrypted" => (0, false),
        "attachment_type_mismatch" | "attachment_macros" => (30, true),
        "auth_dmarc_fail" | "auth_dmarc_permerror" | "attachment_encrypted_archive" => (30, false),
        "link_text_target_mismatch" | "display_name_brand" => (20, true),
        "attachment_html" | "url_raw_ip" => (20, true),
        "attachment_obfuscated_script"
        | "attachment_auto_redirect"
        | "attachment_recipient_prefill"
        | "url_redirector_abuse"
        | "url_qr_code" => (20, true),
        "attachment_qr_code" => (10, true),
        "auth_spf_fail"
        | "auth_spf_permerror"
        | "auth_dkim_fail"
        | "auth_dkim_permerror"
        | "dkim_body_hash_mismatch"
        | "reply_to_domain_mismatch"
        | "date_in_future" => (20, false),
        "display_name_contains_address" | "url_punycode" => (10, true),
        "auth_spf_softfail"
        | "return_path_domain_mismatch"
        | "hop_time_regression"
        | "dkim_body_length_limit"
        | "message_id_foreign_domain"
        | "attachment_risky_extension"
        | "dkim_not_aligned"
        | "sender_from_mismatch"
        | "from_missing" => (10, false),
        r if r.starts_with("auth_") && r.ends_with("_absent") => (5, false),
        "auth_results_missing" | "date_missing" | "attachment_tnef" | "attachment_zero_length" => {
            (0, false)
        }
        _ => (5, false),
    }
}

const MALICIOUS: u32 = 70;
const SUSPICIOUS: u32 = 20;

fn passed(msg: &Message, method: &str) -> bool {
    auth::verdict(&msg.auth, method).is_some_and(|r| r.result == "pass")
}

pub fn evaluate(msg: &Message) -> Verdict {
    let mut score = 0u32;
    let mut deception = false;
    let mut weighted: Vec<(u32, &str)> = Vec::new();
    for f in &msg.findings {
        let (w, d) = weight(&f.rule);
        score += w;
        deception |= d && w > 0;
        if w > 0 {
            weighted.push((w, f.title.as_str()));
        }
    }
    // Message joint (ex. phishing transféré pour analyse) : il compte, sans contaminer le parent.
    let mut embedded_malicious = Vec::new();
    for a in &msg.attachments {
        if let Some(inner) = a.embedded.as_deref() {
            if inner
                .verdict
                .as_ref()
                .is_some_and(|v| v.level == VerdictLevel::Malicious)
            {
                embedded_malicious.push(format!(
                    "Le message joint « {} » est jugé malveillant",
                    a.filename
                ));
            }
        }
    }
    let signed_ok = signed_by_sender(msg);
    let authenticated =
        passed(msg, "dmarc") || (passed(msg, "spf") && passed(msg, "dkim")) || signed_ok.is_some();
    let level = if score >= MALICIOUS && deception {
        VerdictLevel::Malicious
    } else if score >= SUSPICIOUS || !authenticated || !embedded_malicious.is_empty() {
        VerdictLevel::Suspicious
    } else {
        VerdictLevel::Legitimate
    };

    weighted.sort_by_key(|(w, _)| std::cmp::Reverse(*w));
    let mut reasons: Vec<String> = embedded_malicious;
    reasons.extend(weighted.iter().take(5).map(|(_, t)| (*t).to_string()));
    let summary = match level {
        VerdictLevel::Malicious => {
            "Plusieurs signes graves, dont au moins une tromperie délibérée : à traiter comme malveillant.".to_string()
        }
        VerdictLevel::Suspicious if msg.auth.is_empty() && score < SUSPICIOUS => {
            "Aucun résultat d'authentification dans les en-têtes : l'expéditeur ne peut pas être confirmé.".to_string()
        }
        VerdictLevel::Suspicious if score < SUSPICIOUS && embedded_malicious_only(msg) => {
            "Le message lui-même est sain, mais il transporte un message malveillant.".to_string()
        }
        VerdictLevel::Suspicious if score < SUSPICIOUS => {
            "Peu de signaux, mais l'authentification de l'expéditeur n'a pas réussi : à vérifier.".to_string()
        }
        VerdictLevel::Suspicious => "Des signaux d'alerte demandent une vérification par l'analyste.".to_string(),
        VerdictLevel::Legitimate => {
            "Expéditeur authentifié et aucun signal notable dans le fichier.".to_string()
        }
    };
    if level == VerdictLevel::Legitimate {
        // La preuve d'authenticité qui a réellement fondé le verdict.
        let how = if let Some(sig) = &signed_ok {
            sig.clone()
        } else if passed(msg, "dmarc") {
            "DMARC réussi".to_string()
        } else {
            "SPF et DKIM réussis".to_string()
        };
        reasons.insert(0, how);
    }
    Verdict {
        level,
        score,
        summary,
        reasons,
    }
}

/// Signature valide d'une clé ou d'un certificat de confiance au nom de l'expéditeur.
fn signed_by_sender(msg: &Message) -> Option<String> {
    use mf_core::{SignatureScheme, SignatureStatus};
    msg.signatures.iter().find_map(|c| {
        let ok = c.status == SignatureStatus::Valid
            && c.matches_from == Some(true)
            && c.key_expired != Some(true)
            && c.key_revoked != Some(true);
        match c.scheme {
            SignatureScheme::Pgp if ok => {
                Some("Signature PGP valide d'une clé importée au nom de l'expéditeur".to_string())
            }
            SignatureScheme::Smime
                if ok && c.cert.as_ref().is_some_and(|x| x.chain == "trusted") =>
            {
                Some("Signature S/MIME valide, certificat d'une autorité importée".to_string())
            }
            _ => None,
        }
    })
}

fn embedded_malicious_only(msg: &Message) -> bool {
    msg.attachments.iter().any(|a| {
        a.embedded
            .as_deref()
            .and_then(|m| m.verdict.as_ref())
            .is_some_and(|v| v.level == VerdictLevel::Malicious)
    })
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use mf_core::{AuthResult, Finding, Severity};

    fn finding(rule: &str) -> Finding {
        Finding {
            rule: rule.into(),
            severity: Severity::High,
            title: rule.into(),
            detail: String::new(),
            refs: Vec::new(),
        }
    }

    fn auth(method: &str, result: &str) -> AuthResult {
        AuthResult {
            method: method.into(),
            result: result.into(),
            authserv_id: None,
            properties: Vec::new(),
            header_name: "Authentication-Results".into(),
            header_index: 0,
            most_recent: true,
        }
    }

    #[test]
    fn authenticated_and_clean_is_legitimate() {
        let mut m = Message::default();
        m.auth = vec![auth("dmarc", "pass")];
        assert_eq!(evaluate(&m).level, VerdictLevel::Legitimate);
        m.auth = vec![auth("spf", "pass"), auth("dkim", "pass")];
        assert_eq!(evaluate(&m).level, VerdictLevel::Legitimate);
    }

    #[test]
    fn no_authentication_is_never_legitimate() {
        let m = Message::default();
        let v = evaluate(&m);
        assert_eq!(v.level, VerdictLevel::Suspicious);
        assert!(v.summary.contains("authentification"));
    }

    #[test]
    fn misconfiguration_alone_is_not_malicious() {
        let mut m = Message::default();
        m.findings = [
            "auth_dmarc_fail",
            "auth_spf_fail",
            "auth_dkim_fail",
            "reply_to_domain_mismatch",
        ]
        .map(finding)
        .to_vec();
        let v = evaluate(&m);
        assert!(v.score >= MALICIOUS);
        assert_eq!(v.level, VerdictLevel::Suspicious);
    }

    #[test]
    fn deception_plus_failures_is_malicious() {
        let mut m = Message::default();
        m.auth = vec![auth("dmarc", "pass")];
        m.findings = ["sender_lookalike_domain", "auth_dmarc_fail"]
            .map(finding)
            .to_vec();
        let v = evaluate(&m);
        assert_eq!(v.level, VerdictLevel::Malicious);
        assert_eq!(v.reasons[0], "sender_lookalike_domain");
    }
}
