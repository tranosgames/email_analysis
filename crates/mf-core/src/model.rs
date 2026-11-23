//! Modèle unifié, indépendant du format source (data-model.md).

use serde::{Deserialize, Serialize};

/// Format détecté par signature (FR-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Eml,
    Msg,
    Pst,
    Unknown,
}

/// Fichier de preuve ingéré (lecture seule, empreintes calculées avant parsing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub format: Format,
    pub declared_extension: Option<String>,
}

/// Une adresse, telle qu'elle figure dans la preuve.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Address {
    pub display_name: Option<String>,
    /// Adresse SMTP (pour un MSG : adresse SMTP résolue).
    pub address: Option<String>,
    /// Adresse Exchange X.500 d'origine (MSG), le cas échéant.
    pub x500_dn: Option<String>,
}

/// Un en-tête dans l'ordre d'origine (FR-011, FR-035).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub index: u32,
    pub name: String,
    /// Valeur brute telle qu'écrite (lignes repliées conservées).
    pub raw: String,
    /// Valeur dépliée (sans retours à la ligne de repli).
    pub value: String,
    /// Plage d'octets dans la source : la preuve (EML) ou la propriété 0x007D (MSG).
    pub offset: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Inline,
    Attachment,
    Unknown,
}

/// Fichier contenu dans le message (FR-016, FR-036).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub index: u32,
    pub filename: String,
    pub declared_mime: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub disposition: Disposition,
    pub content_id: Option<String>,
    /// Message embarqué (message/rfc822 ou MSG imbriqué), analysé récursivement.
    pub embedded: Option<Box<Message>>,
    /// Faux pour un message Outlook embarqué en objet MAPI : il n'a pas de fichier d'origine (FR-038).
    pub extractable: bool,
    /// Type réel d'après le contenu (signature), ex. « Exécutable Windows (PE) » (FR-017).
    pub detected_type: Option<String>,
    pub detected_mime: Option<String>,
    /// Alertes sur ce fichier (FR-017).
    pub flags: Vec<AttachmentFlag>,
    /// Contenu des QR codes de l'image (FR-046).
    #[serde(default)]
    pub qr_codes: Vec<String>,
    /// Analyse statique d'une pièce HTML/SVG (FR-047).
    #[serde(default)]
    pub html_report: Option<HtmlAttachmentReport>,
    /// Contenu décodé ; jamais sérialisé (export à la demande uniquement).
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Où une URL a été trouvée.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UrlLocation {
    Header {
        name: String,
    },
    BodyText,
    HtmlAttribute {
        attribute: String,
    },
    HtmlText,
    HtmlCss,
    /// Contenu d'une pièce jointe HTML/SVG (FR-047).
    Attachment {
        filename: String,
    },
    /// Charge utile d'un QR code trouvé dans une image (FR-046).
    QrCode {
        source: String,
    },
    /// Vraie destination décodée d'un lien de redirection (FR-048).
    Redirect {
        from: String,
    },
}

impl std::fmt::Display for UrlLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlLocation::Header { name } => write!(f, "en-tête {name}"),
            UrlLocation::BodyText => write!(f, "corps texte"),
            UrlLocation::HtmlAttribute { attribute } => write!(f, "HTML @{attribute}"),
            UrlLocation::HtmlText => write!(f, "HTML texte"),
            UrlLocation::HtmlCss => write!(f, "HTML css"),
            UrlLocation::Attachment { filename } => write!(f, "pièce jointe {filename}"),
            UrlLocation::QrCode { source } => write!(f, "QR code dans {source}"),
            UrlLocation::Redirect { from } => write!(f, "redirection depuis {from}"),
        }
    }
}

/// URL unique d'un message (FR-037).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlEntry {
    pub url: String,
    pub defanged: String,
    pub host: Option<String>,
    pub locations: Vec<UrlLocation>,
    pub occurrences: u32,
    /// Textes affichés des liens `<a>` qui pointent vers cette URL (FR-022).
    pub display_texts: Vec<String>,
    /// Hôte décodé quand il est en punycode (`xn--`).
    pub unicode_host: Option<String>,
    /// Marque imitée, si le domaine en est un sosie (FR-043).
    pub lookalike_of: Option<String>,
    pub flags: Vec<UrlFlag>,
    /// Lien de redirection : service et vraie destination décodée sans requête (FR-048).
    #[serde(default)]
    pub redirect: Option<Redirect>,
}

/// Redirection décodée hors-ligne.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redirect {
    /// Service qui redirige (« Google », « Microsoft Safe Links »…).
    pub service: String,
    /// Destination finale encodée dans le lien.
    pub target: String,
    /// Redirecteur ouvert détourné (Google, Bing…) plutôt que réécriture de sécurité.
    pub abused: bool,
}

/// Analyse statique d'une pièce jointe HTML ou SVG (FR-047).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HtmlAttachmentReport {
    /// Champs de saisie de mot de passe.
    pub password_fields: u32,
    /// Formulaires : (méthode, action).
    pub forms: Vec<FormInfo>,
    /// Points d'exfiltration reconnus (bot Telegram, webhook…).
    pub exfiltration: Vec<String>,
    /// Procédés d'obfuscation relevés (`atob`, `eval`, longues chaînes base64…).
    pub obfuscation: Vec<String>,
    /// Redirections automatiques (meta refresh, `window.location`…).
    pub redirects: Vec<String>,
    /// Adresse du destinataire présente dans la page (page personnalisée).
    pub recipient_prefill: Vec<String>,
    /// Une charge base64 décodée (`atob`) a été analysée elle aussi.
    pub decoded_payloads: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormInfo {
    pub method: String,
    pub action: Option<String>,
}

/// Alerte sur une URL (FR-022, FR-043).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlFlag {
    /// Le texte du lien est une autre adresse que la cible.
    TextTargetMismatch,
    /// Cible = adresse IP littérale.
    RawIp,
    /// Domaine encodé en punycode (IDN).
    Punycode,
    /// Domaine mêlant plusieurs écritures (latin + cyrillique…).
    MixedScript,
    /// Domaine qui imite une marque connue.
    Lookalike,
    /// Identifiants dans l'URL (`user@host`), procédé de masquage de la vraie cible.
    Credentials,
    /// Redirecteur ouvert détourné (Google, Bing…) qui cache la vraie destination.
    Redirector,
    /// URL lue dans un QR code.
    QrCode,
}

/// Alerte sur une pièce jointe (FR-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentFlag {
    Executable,
    RiskyExtension,
    DoubleExtension,
    /// Extension ou type déclaré incohérent avec le contenu réel.
    TypeMismatch,
    BidiOrControlChars,
    EncryptedArchive,
    Macros,
    /// Pièce jointe HTML (contrebande HTML, faux formulaire de connexion).
    HtmlAttachment,
    Tnef,
    ZeroLength,
    /// Pièce HTML avec champ de mot de passe (FR-047).
    CredentialForm,
    /// Envoi des données vers un service d'exfiltration connu.
    Exfiltration,
    /// Script obfusqué.
    ObfuscatedScript,
    /// Redirection automatique à l'ouverture.
    AutoRedirect,
    /// Adresse du destinataire intégrée à la page.
    RecipientPrefill,
    /// Image contenant un QR code (FR-046).
    QrCode,
}

/// Résultat d'authentification déclaré par un serveur (FR-013).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// `spf`, `dkim`, `dmarc`, `arc`, `compauth`…
    pub method: String,
    /// `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`…
    pub result: String,
    /// Serveur qui a rendu le verdict.
    pub authserv_id: Option<String>,
    /// Propriétés (`smtp.mailfrom`, `header.d`, `header.from`…) et motif.
    pub properties: Vec<(String, String)>,
    /// En-tête source (`Authentication-Results`, `ARC-Authentication-Results`, `Received-SPF`).
    pub header_name: String,
    pub header_index: u32,
    /// Vrai pour le verdict du serveur de réception final (le plus récent), celui qui fait foi.
    pub most_recent: bool,
}

/// Signature DKIM et vérification hors-ligne de l'empreinte du corps (FR-014).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimCheck {
    pub header_index: u32,
    pub domain: Option<String>,
    pub selector: Option<String>,
    pub algorithm: Option<String>,
    pub canonicalization: Option<String>,
    pub signed_headers: Vec<String>,
    pub body_length_limit: Option<u64>,
    pub body_hash_declared: Option<String>,
    pub body_hash_computed: Option<String>,
    /// `Some(true)` : corps intact depuis la signature ; `None` : non vérifiable (voir `note`).
    pub body_hash_ok: Option<bool>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

/// Élément de la preuve sur lequel repose un constat (Constitution II).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRef {
    Header { index: u32, name: String },
    Attachment { index: u32, filename: String },
    Url { url: String },
    Hop { index: u32 },
}

/// Constat automatique (FR-015).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Identifiant stable de la règle (data-model.md).
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub refs: Vec<SourceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
    Sha256,
    Md5,
}

// ——— Boîtes PST / OST (feature 002) ———

/// Emplacement d'un élément dans une boîte (FR-005).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub store_name: String,
    /// Vide tant que l'empreinte de la boîte est en cours de calcul.
    pub store_sha256: String,
    /// Du sommet de la boîte jusqu'au dossier de l'élément.
    pub folder_path: Vec<String>,
    /// Identifiant de nœud (NID) de l'élément.
    pub node_id: u32,
    /// Chemin dans les messages embarqués (indices de pièces jointes), vide pour l'élément lui-même.
    #[serde(default)]
    pub embedded_path: Vec<u32>,
}

impl Provenance {
    /// `boite.pst › Boîte de réception › Fournisseurs`.
    pub fn label(&self) -> String {
        std::iter::once(self.store_name.as_str())
            .chain(self.folder_path.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" › ")
    }
}

/// Métadonnées d'une boîte (FR-001, FR-012).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreInfo {
    pub name: String,
    pub size: u64,
    /// `unicode`, `ansi`, `ost4k`.
    pub format: String,
    /// `none`, `permute`, `cyclic`.
    pub encoding: String,
    pub password_protected: bool,
    pub display_name: Option<String>,
    pub folders: u32,
    /// Somme des compteurs d'éléments des dossiers (sans ouvrir les éléments).
    pub items: u64,
    pub unreadable: Vec<UnreadableItem>,
}

/// Dossier d'une boîte, lu dans les tables de hiérarchie (FR-003).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderInfo {
    pub id: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub path: Vec<String>,
    /// `inbox`, `sent`, `deleted`, `drafts`, `outbox`, `junk`, `root`, `system`, `other`.
    pub kind: String,
    pub container_class: Option<String>,
    pub item_count: u32,
    pub unread_count: u32,
    pub depth: u32,
}

/// Ligne de liste d'un élément, lue dans la table du dossier, sans ouvrir l'élément (FR-006).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: u32,
    pub folder: u32,
    pub message_class: Option<String>,
    pub subject: Option<String>,
    /// Nom affiché de l'expéditeur : l'adresse n'est pas dans la table.
    pub from_name: Option<String>,
    pub to: Option<String>,
    pub cc: Option<String>,
    pub sent: Option<String>,
    pub received: Option<String>,
    pub size: Option<u32>,
    pub has_attachments: bool,
    pub message_id: Option<String>,
    /// Renseignés une fois l'élément ouvert.
    pub from_address: Option<String>,
    pub verdict: Option<VerdictLevel>,
}

/// Filtre d'une boîte (FR-007). Tous les critères se combinent en ET ; le texte est comparé sans
/// tenir compte de la casse ni des accents. Les critères « tables » ne lisent que les tables des
/// dossiers ; les critères « ouverts » ne portent que sur les éléments déjà analysés.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BoxFilter {
    /// Dossier ; `None` = toute la boîte (hors dossiers de recherche).
    pub folder: Option<u32>,
    /// Texte cherché dans l'objet, le nom de l'expéditeur et les destinataires.
    pub text: Option<String>,
    pub from_name: Option<String>,
    /// Destinataires : champs À et Cc de la table.
    pub to: Option<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    /// Date (réception, sinon envoi) ≥ `after` ; `AAAA-MM-JJ` ou RFC 3339, UTC.
    pub after: Option<String>,
    /// Date ≤ `before`, à la précision donnée (`2001-05-31` inclut tout le 31 mai).
    pub before: Option<String>,
    pub min_size: Option<u32>,
    pub max_size: Option<u32>,
    pub has_attachments: Option<bool>,
    /// Éléments déjà ouverts seulement.
    pub analyzed_only: bool,
    /// Verdicts acceptés (éléments ouverts) ; vide = tous.
    pub verdict: Vec<VerdictLevel>,
    /// Adresse ou domaine de l'expéditeur (éléments ouverts : absents des tables).
    pub from_address: Option<String>,
    pub from_domain: Option<String>,
}

impl BoxFilter {
    /// Vrai si un critère ne peut être évalué que sur un élément ouvert.
    pub fn needs_analysis(&self) -> bool {
        self.analyzed_only
            || !self.verdict.is_empty()
            || self.from_address.is_some()
            || self.from_domain.is_some()
    }
}

/// Élément ou dossier illisible, listé plutôt que masqué (FR-009).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnreadableItem {
    pub node_id: u32,
    pub folder_path: Vec<String>,
    /// `folder`, `item`, `attachment`.
    pub kind: String,
    pub reason: String,
}

/// Signature cryptographique d'un message (FR-049, FR-050).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    Pgp,
    Smime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Signature mathématiquement valide : contenu intact depuis la signature.
    Valid,
    /// Signature fausse : contenu modifié après signature (ou signature forgée).
    Invalid,
    /// Clé publique absente : importer la clé du signataire pour vérifier.
    UnknownKey,
    /// Message chiffré : illisible sans la clé privée du destinataire.
    Encrypted,
    /// Format ou algorithme non pris en charge, signature illisible.
    Unsupported,
}

/// Certificat X.509 du signataire S/MIME.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub emails: Vec<String>,
    /// SHA-256 du certificat (DER), en hexadécimal.
    pub sha256: String,
    /// Certificat au format PEM, pour l'exporter.
    pub pem: String,
    /// Valide à la date de signature (ou à la date du message).
    pub valid_at_signing: bool,
    /// `trusted` (autorité importée), `unknown_ca`, `self_signed`, `invalid_chain`.
    pub chain: String,
    /// Autorité importée qui a validé la chaîne.
    pub trusted_by: Option<String>,
}

/// Lien externe de vérification de la clé, ouvert uniquement sur action de l'analyste (FR-051).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalLink {
    pub label: String,
    pub url: String,
}

/// Résultat de vérification d'une signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCheck {
    pub scheme: SignatureScheme,
    /// `pgp_mime`, `pgp_inline`, `smime_detached`, `smime_opaque`, `pgp_encrypted`, `smime_encrypted`.
    pub kind: String,
    pub status: SignatureStatus,
    /// Empreinte complète de la clé (PGP) ou SHA-256 du certificat (S/MIME), en hexadécimal.
    pub fingerprint: Option<String>,
    /// Identifiant court de la clé PGP (16 hex).
    pub key_id: Option<String>,
    /// Identités de la clé (PGP) ou noms du certificat.
    pub signer_ids: Vec<String>,
    pub signer_emails: Vec<String>,
    /// L'email de la clé ou du certificat est celui de l'expéditeur (From).
    pub matches_from: Option<bool>,
    pub signed_at: Option<String>,
    pub hash_algorithm: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_expired: Option<bool>,
    pub key_revoked: Option<bool>,
    pub cert: Option<CertInfo>,
    /// Clé ou autorité importée utilisée pour vérifier (traçabilité).
    pub verified_with: Option<String>,
    pub note: Option<String>,
    pub links: Vec<ExternalLink>,
}

/// Verdict de synthèse (FR-045).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictLevel {
    Legitimate,
    Suspicious,
    Malicious,
}

/// Évaluation automatique d'un message : aide au tri, à confirmer par l'analyste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub level: VerdictLevel,
    /// Somme des poids des constats (plus c'est haut, plus c'est grave).
    pub score: u32,
    /// Une phrase qui justifie le verdict.
    pub summary: String,
    /// Principales raisons, de la plus lourde à la plus légère.
    pub reasons: Vec<String>,
}

/// Indicateur de compromission (FR-021, FR-023).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub defanged: String,
    /// Où il a été trouvé (« From », « Received saut 2 », « PJ 1 facture.pdf.exe »…).
    pub locations: Vec<String>,
}

/// Portée d'une adresse IP (pour distinguer l'origine réelle d'un relais interne).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpScope {
    Public,
    /// RFC 1918 / IPv6 ULA (fc00::/7).
    Private,
    Loopback,
    LinkLocal,
    /// 100.64.0.0/10 (CGNAT).
    Shared,
    /// Plages de documentation (RFC 5737 / RFC 3849), traitées comme publiques pour l'analyse.
    Documentation,
}

/// Un saut de la chaîne `Received`, du plus ancien (1) au plus récent (FR-012, FR-042).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hop {
    pub index: u32,
    /// Position de l'en-tête `Received` dans la liste des en-têtes.
    pub header_index: u32,
    /// Nom annoncé par la machine émettrice (après `from`, ou HELO/EHLO).
    pub from_name: Option<String>,
    /// HELO explicite quand il diffère du nom annoncé.
    pub from_helo: Option<String>,
    /// DNS inverse de l'IP émettrice, tel qu'enregistré par le serveur récepteur.
    pub from_rdns: Option<String>,
    pub from_ip: Option<String>,
    pub from_ip_scope: Option<IpScope>,
    /// Serveur qui a reçu le message à ce saut.
    pub by_name: Option<String>,
    pub by_ip: Option<String>,
    pub with: Option<String>,
    pub id: Option<String>,
    pub for_addr: Option<String>,
    pub date_raw: Option<String>,
    pub date_utc: Option<String>,
    /// Délai depuis le saut précédent (négatif = incohérence d'horloge ou falsification).
    pub delay_seconds: Option<i64>,
}

/// Extrémité d'acheminement mise en évidence (FR-042).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: Option<String>,
    pub ip_scope: Option<IpScope>,
    /// DNS inverse enregistré dans l'en-tête (aucune résolution n'est faite).
    pub rdns: Option<String>,
    /// Nom annoncé (HELO/EHLO) ou nom du serveur récepteur.
    pub name: Option<String>,
    /// Numéro du saut d'où provient l'information (0 = autre en-tête).
    pub hop: u32,
    /// En-tête source, ex. `Received` ou `X-Originating-IP`.
    pub source: String,
}

/// Résumé d'acheminement : d'où part le message et où il arrive (FR-042).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailRoute {
    /// Adresse de l'expéditeur (`From`), titre du panneau.
    pub sender: Option<String>,
    /// Machine d'envoi : côté `from` du saut le plus ancien.
    pub origin: Option<Endpoint>,
    /// IP déclarée par le client de messagerie (`X-Originating-IP`, `X-Sender-IP`…).
    pub originating_ip_header: Option<Endpoint>,
    /// Première IP publique de la chaîne, si l'origine est privée, absente ou différente.
    pub first_public: Option<Endpoint>,
    /// Dernière IP publique : celle qui a remis le message à l'infrastructure du destinataire.
    pub last_public: Option<Endpoint>,
    /// Serveur de réception finale : côté `by` du saut le plus récent.
    pub receiver: Option<Endpoint>,
    pub received_utc: Option<String>,
    /// Durée totale d'acheminement (premier → dernier horodatage).
    pub transit_seconds: Option<i64>,
}

/// Nature d'une ressource distante que le HTML demandait à charger (FR-039).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedKind {
    /// `<img src>`, `<img srcset>`, `<input type=image>` — dont les pixels de suivi.
    Image,
    /// `style="background: url(…)"`, attribut `background`.
    Background,
    /// `<link rel=stylesheet>`, `@import`, `url()` dans un bloc `<style>`.
    Stylesheet,
    Script,
    /// `<iframe>`, `<frame>`.
    Frame,
    /// `<video>`, `<audio>`, `<source>`, `<track>`, attribut `poster`.
    Media,
    /// `<object>`, `<embed>`.
    Object,
    Other,
}

/// Ressource distante bloquée : jamais chargée, mais localisée (FR-039).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedResource {
    /// Numéro affiché (1, 2, …) dans l'ordre du HTML.
    pub number: u32,
    pub url: String,
    pub kind: BlockedKind,
    /// Élément HTML d'origine (`img`, `td`, `link`…).
    pub element: String,
    /// Attribut ou construction d'origine (`src`, `style`, `href`, `@import`…).
    pub attribute: String,
    /// Ligne (1 = première) dans le corps HTML brut, si retrouvée.
    pub line: Option<u32>,
    /// Repère interne présent dans le HTML rendu ; `None` si l'élément a été supprimé
    /// par la sanitisation (script, feuille de style, cadre…) et n'apparaît pas au rendu.
    pub marker: Option<u32>,
}

/// Courriel normalisé.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    pub subject: Option<String>,
    pub from: Vec<Address>,
    pub sender: Option<Address>,
    pub reply_to: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    /// Valeur brute de la date (en-tête `Date:` ou propriété MAPI).
    pub date_raw: Option<String>,
    /// Date normalisée en UTC (RFC 3339).
    pub date_utc: Option<String>,
    pub message_id: Option<String>,
    pub headers: Vec<Header>,
    pub body_text: Option<String>,
    /// HTML brut, tel que dans la preuve (jamais rendu tel quel).
    pub body_html: Option<String>,
    /// HTML sanitisé, prêt pour une iframe sandbox (rempli par l'analyse).
    pub body_html_safe: Option<String>,
    /// Nombre de ressources distantes bloquées (= `blocked_resources.len()`).
    pub blocked_remote_resources: u32,
    /// Chaîne `Received`, du plus ancien au plus récent (FR-012, FR-042).
    pub hops: Vec<Hop>,
    /// Résumé IP/DNS d'envoi et de réception (FR-042).
    pub route: Option<MailRoute>,
    /// Résultats SPF/DKIM/DMARC/ARC déclarés (FR-013).
    pub auth: Vec<AuthResult>,
    /// Signatures DKIM et empreinte du corps (FR-014).
    pub dkim: Vec<DkimCheck>,
    /// Constats automatiques, du plus grave au moins grave (FR-015).
    pub findings: Vec<Finding>,
    /// Indicateurs de compromission dédoublonnés (FR-021).
    pub iocs: Vec<Ioc>,
    /// Verdict de synthèse (FR-045).
    pub verdict: Option<Verdict>,
    /// Signatures PGP / S/MIME vérifiées hors-ligne (FR-049, FR-050).
    #[serde(default)]
    pub signatures: Vec<SignatureCheck>,
    /// Emplacement d'un élément issu d'une boîte PST/OST (feature 002, FR-005).
    #[serde(default)]
    pub provenance: Option<Provenance>,
    /// Corps MIME brut tel que transmis (EML), pour la vérification DKIM ; jamais sérialisé.
    #[serde(skip)]
    pub raw_body: Option<Vec<u8>>,
    /// Provenance du corps HTML affiché (FR-041) : `html` (d'origine) ou `rtf` (reconstitué).
    pub html_source: Option<String>,
    /// Détail de chaque ressource distante bloquée, dans l'ordre du HTML (FR-039).
    pub blocked_resources: Vec<BlockedResource>,
    pub attachments: Vec<Attachment>,
    pub urls: Vec<UrlEntry>,
    /// Avertissements de parsing non bloquants.
    pub issues: Vec<String>,
}
