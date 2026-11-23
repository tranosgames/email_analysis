// Accès au moteur : commandes Tauri (contracts/tauri-commands.md) dans l'application de bureau,
// module WebAssembly dans un Web Worker dans la version web (specs/003-web-version).

export type Format = "eml" | "msg" | "pst" | "unknown";

export interface Address {
  display_name: string | null;
  address: string | null;
  x500_dn: string | null;
}

export interface Header {
  index: number;
  name: string;
  raw: string;
  value: string;
  offset: [number, number] | null;
}

export interface Attachment {
  index: number;
  filename: string;
  declared_mime: string | null;
  size: number;
  sha256: string;
  md5: string;
  disposition: "inline" | "attachment" | "unknown";
  content_id: string | null;
  embedded: Message | null;
  /** Faux pour un message Outlook embarqué (objet MAPI) : pas de fichier d'origine. */
  extractable: boolean;
  detected_type: string | null;
  detected_mime: string | null;
  flags: string[];
  /** Contenu des QR codes de l'image (FR-046). */
  qr_codes: string[];
  /** Analyse statique d'une pièce HTML/SVG (FR-047). */
  html_report: HtmlAttachmentReport | null;
}

export interface HtmlAttachmentReport {
  password_fields: number;
  forms: { method: string; action: string | null }[];
  exfiltration: string[];
  obfuscation: string[];
  redirects: string[];
  recipient_prefill: string[];
  decoded_payloads: number;
}

/** Redirection décodée sans suivre le lien (FR-048). */
export interface Redirect {
  service: string;
  target: string;
  abused: boolean;
}

export type UrlLocation =
  | { kind: "header"; name: string }
  | { kind: "body_text" }
  | { kind: "html_attribute"; attribute: string }
  | { kind: "html_text" }
  | { kind: "html_css" }
  | { kind: "attachment"; filename: string }
  | { kind: "qr_code"; source: string }
  | { kind: "redirect"; from: string };

export interface UrlEntry {
  url: string;
  defanged: string;
  host: string | null;
  locations: UrlLocation[];
  occurrences: number;
  display_texts: string[];
  unicode_host: string | null;
  lookalike_of: string | null;
  flags: string[];
  redirect: Redirect | null;
}

export type BlockedKind = "image" | "background" | "stylesheet" | "script" | "frame" | "media" | "object" | "other";

/** Ressource distante bloquée et localisée (FR-039). */
export interface BlockedResource {
  number: number;
  url: string;
  kind: BlockedKind;
  element: string;
  attribute: string;
  line: number | null;
  marker: number | null;
}

export type Severity = "high" | "medium" | "low" | "info";

export type SourceRef =
  | { kind: "header"; index: number; name: string }
  | { kind: "attachment"; index: number; filename: string }
  | { kind: "url"; url: string }
  | { kind: "hop"; index: number };

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  refs: SourceRef[];
}

export interface AuthResult {
  method: string;
  result: string;
  authserv_id: string | null;
  properties: [string, string][];
  header_name: string;
  header_index: number;
  most_recent: boolean;
}

export interface DkimCheck {
  header_index: number;
  domain: string | null;
  selector: string | null;
  algorithm: string | null;
  canonicalization: string | null;
  signed_headers: string[];
  body_length_limit: number | null;
  body_hash_declared: string | null;
  body_hash_computed: string | null;
  body_hash_ok: boolean | null;
  note: string | null;
}

export type IocKind = "ipv4" | "ipv6" | "domain" | "url" | "email" | "sha256" | "md5";

export type SignatureStatus = "valid" | "invalid" | "unknown_key" | "encrypted" | "unsupported";

export interface CertInfo {
  subject: string;
  issuer: string;
  serial: string;
  not_before: string | null;
  not_after: string | null;
  emails: string[];
  sha256: string;
  pem: string;
  valid_at_signing: boolean;
  chain: "trusted" | "unknown_ca" | "self_signed" | "invalid_chain";
  trusted_by: string | null;
}

export interface ExternalLink {
  label: string;
  url: string;
}

/** Signature PGP / S/MIME vérifiée hors-ligne (FR-049, FR-050). */
export interface SignatureCheck {
  scheme: "pgp" | "smime";
  kind: string;
  status: SignatureStatus;
  fingerprint: string | null;
  key_id: string | null;
  signer_ids: string[];
  signer_emails: string[];
  matches_from: boolean | null;
  signed_at: string | null;
  hash_algorithm: string | null;
  key_algorithm: string | null;
  key_expired: boolean | null;
  key_revoked: boolean | null;
  cert: CertInfo | null;
  verified_with: string | null;
  note: string | null;
  links: ExternalLink[];
}

/** Entrée du trousseau local de l'analyste. */
export interface KeyEntry {
  kind: "pgp" | "x509";
  fingerprint: string;
  label: string;
  source: string;
}

export type VerdictLevel = "legitimate" | "suspicious" | "malicious";

export interface Verdict {
  level: VerdictLevel;
  score: number;
  summary: string;
  reasons: string[];
}

export const VERDICT_LABEL: Record<VerdictLevel, string> = {
  malicious: "Malveillant",
  suspicious: "À vérifier",
  legitimate: "Légitime",
};

export interface Ioc {
  kind: IocKind;
  value: string;
  defanged: string;
  locations: string[];
}

export type IpScope = "public" | "private" | "loopback" | "link_local" | "shared" | "documentation";

/** Saut de la chaîne Received, du plus ancien (1) au plus récent (FR-042). */
export interface Hop {
  index: number;
  header_index: number;
  from_name: string | null;
  from_helo: string | null;
  from_rdns: string | null;
  from_ip: string | null;
  from_ip_scope: IpScope | null;
  by_name: string | null;
  by_ip: string | null;
  with: string | null;
  id: string | null;
  for_addr: string | null;
  date_raw: string | null;
  date_utc: string | null;
  delay_seconds: number | null;
}

export interface Endpoint {
  ip: string | null;
  ip_scope: IpScope | null;
  rdns: string | null;
  name: string | null;
  hop: number;
  source: string;
}

export interface MailRoute {
  sender: string | null;
  origin: Endpoint | null;
  originating_ip_header: Endpoint | null;
  first_public: Endpoint | null;
  last_public: Endpoint | null;
  receiver: Endpoint | null;
  received_utc: string | null;
  transit_seconds: number | null;
}

export interface Message {
  subject: string | null;
  from: Address[];
  sender: Address | null;
  reply_to: Address[];
  to: Address[];
  cc: Address[];
  bcc: Address[];
  date_raw: string | null;
  date_utc: string | null;
  message_id: string | null;
  headers: Header[];
  body_text: string | null;
  /** HTML brut tel que dans la preuve (affiché comme texte dans la vue « Source HTML »). */
  body_html: string | null;
  body_html_safe: string | null;
  blocked_remote_resources: number;
  blocked_resources: BlockedResource[];
  hops: Hop[];
  route: MailRoute | null;
  auth: AuthResult[];
  dkim: DkimCheck[];
  findings: Finding[];
  iocs: Ioc[];
  /** Verdict de synthèse (FR-045). */
  verdict: Verdict | null;
  /** Signatures PGP / S/MIME (FR-049, FR-050). */
  signatures: SignatureCheck[];
  /** Emplacement dans une boîte PST/OST (feature 002). */
  provenance: Provenance | null;
  /** « html » : corps HTML d'origine ; « rtf » : HTML reconstitué depuis le RTF Outlook (FR-041). */
  html_source: "html" | "rtf" | null;
  attachments: Attachment[];
  urls: UrlEntry[];
  issues: string[];
}

export interface Evidence {
  path: string;
  size: number;
  sha256: string;
  md5: string;
  format: Format;
}

export interface Summary {
  id: number;
  file_name: string;
  format: Format;
  sha256: string;
  subject: string | null;
  from: string | null;
  date_utc: string | null;
  attachments: number;
  urls: number;
  issues: number;
  verdict: VerdictLevel | null;
}

// ——— Boîtes PST / OST (feature 002) ———

export interface StoreInfo {
  name: string;
  size: number;
  format: "unicode" | "ansi" | "ost4k";
  encoding: string;
  password_protected: boolean;
  display_name: string | null;
  folders: number;
  items: number;
  unreadable: { node_id: number; folder_path: string[]; kind: string; reason: string }[];
}

export interface FolderInfo {
  id: number;
  parent: number | null;
  name: string;
  path: string[];
  kind: "inbox" | "sent" | "deleted" | "drafts" | "outbox" | "junk" | "root" | "ipm" | "search" | "system" | "other";
  container_class: string | null;
  item_count: number;
  unread_count: number;
  depth: number;
}

/** Ligne de liste lue dans la table du dossier, sans ouvrir l'élément. */
export interface ItemSummary {
  id: number;
  folder: number;
  message_class: string | null;
  subject: string | null;
  from_name: string | null;
  to: string | null;
  cc: string | null;
  sent: string | null;
  received: string | null;
  size: number | null;
  has_attachments: boolean;
  message_id: string | null;
  from_address: string | null;
  verdict: VerdictLevel | null;
}

export interface Provenance {
  store_name: string;
  store_sha256: string;
  folder_path: string[];
  node_id: number;
  embedded_path: number[];
}

export interface BoxHash {
  box_id: number;
  done: number;
  total: number;
  sha256: string | null;
  md5: string | null;
}

export type OpenResult =
  | { kind: "ready"; summary: Summary }
  | { kind: "mailbox"; box_id: number; path: string; store: StoreInfo; folders: FolderInfo[] }
  | { kind: "duplicate"; path: string; of: number }
  | { kind: "failed"; path: string; error: string };

export interface MessageView {
  evidence: Evidence;
  message: Message;
}

import { createEngineWorker } from "./web-engine";

export const inTauri = "__TAURI_INTERNALS__" in window;

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

// ——— Backend web (feature 003) : moteur WebAssembly dans un Web Worker ———

/** Fichier fourni par le navigateur, avec son chemin relatif (dossier déposé). */
export interface WebFile {
  path: string;
  file: File;
}

/** FR-W07 : au-delà, l'onglet risque de manquer de mémoire ; l'application de bureau s'impose. */
export const WEB_MAX_SIZE = 500 * 1024 * 1024;

const webViews: MessageView[] = [];
/** Boîtes ouvertes dans le Worker (signature nom|taille|date, indice = identifiant). */
const webBoxes: string[] = [];
const boxHashListeners: ((h: BoxHash) => void)[] = [];
/** Clé des octets de chaque preuve dans le worker (même indice que webViews). */
const webKeys: number[] = [];
let worker: Worker | null = null;
let nextJob = 0;
interface WorkerReply {
  ok: boolean;
  text?: string;
  view?: MessageView;
  key?: number;
  data?: ArrayBuffer;
  name?: string;
  error?: string;
  json?: unknown;
}
const pending = new Map<number, (r: WorkerReply) => void>();

function ask(job: Record<string, unknown>, transfer: Transferable[] = []): Promise<WorkerReply> {
  const id = nextJob++;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    engine().postMessage({ ...job, id }, transfer);
  });
}

function engine(): Worker {
  if (!worker) {
    worker = createEngineWorker();
    worker.onmessage = (e: MessageEvent) => {
      const d = e.data as WorkerReply & { id?: number; event?: string; hash?: BoxHash };
      if (d.event === "box-hash" && d.hash) {
        boxHashListeners.forEach((fn) => fn(d.hash as BoxHash));
        return;
      }
      if (d.event) return;
      if (d.id === undefined) {
        // Module prêt : plus aucune ressource ne sera demandée au serveur (FR-W02).
        document.documentElement.dataset.engine = (e.data as { version?: string }).version ?? "ready";
        return;
      }
      pending.get(d.id)?.(d);
      pending.delete(d.id);
    };
  }
  return worker;
}

/** Version web : charge le moteur dès l'ouverture de la page, pour que toute requête réseau
 *  ait lieu avant que l'analyste ne dépose une preuve. */
export function warmUp(): void {
  if (!inTauri) engine();
}

async function analyzeInWorker(name: string, file: File): Promise<WorkerReply> {
  const bytes = await file.arrayBuffer();
  return ask({ kind: "analyze", name, bytes }, [bytes]); // transfert sans copie
}

/** Même résumé que le backend Tauri (src-tauri/src/main.rs › summary). */
function summarize(id: number, v: MessageView): Summary {
  const m = v.message;
  const first = m.from[0];
  return {
    id,
    file_name: v.evidence.path.split("/").pop() ?? v.evidence.path,
    format: v.evidence.format,
    sha256: v.evidence.sha256,
    subject: m.subject,
    from: first ? (first.display_name ?? first.address) : null,
    date_utc: m.date_utc,
    attachments: m.attachments.length,
    urls: m.urls.length,
    issues: m.issues.length,
    verdict: m.verdict?.level ?? null,
  };
}

async function openWebFiles(files: WebFile[]): Promise<OpenResult[]> {
  const results: OpenResult[] = [];
  for (const { path, file } of files) {
    if (/\.(pst|ost)$/i.test(path)) {
      // Doublon : même nom, même taille, même date (l'empreinte n'est connue qu'après coup).
      const sig = `${file.name}|${file.size}|${file.lastModified}`;
      const of = webBoxes.indexOf(sig);
      if (of >= 0) {
        results.push({ kind: "failed", path, error: "cette boîte est déjà ouverte" });
        continue;
      }
      const boxId = webBoxes.length;
      // Le File est cloné vers le Worker sans copier son contenu ; seules des tranches seront lues.
      const r = await ask({ kind: "box-open", box: boxId, name: file.name, file });
      if (!r.ok || !r.json) {
        results.push({ kind: "failed", path, error: r.error ?? "boîte illisible" });
        continue;
      }
      webBoxes.push(sig);
      const { store, folders } = r.json as { store: StoreInfo; folders: FolderInfo[] };
      results.push({ kind: "mailbox", box_id: boxId, path, store, folders });
      continue;
    }
    if (file.size > WEB_MAX_SIZE) {
      results.push({
        kind: "failed",
        path,
        error: `fichier de ${Math.round(file.size / 1048576)} Mo : au-delà de 500 Mo, utilisez l'application de bureau`,
      });
      continue;
    }
    const r = await analyzeInWorker(path, file);
    if (!r.ok || !r.view) {
      results.push({ kind: "failed", path, error: r.error ?? "erreur inconnue" });
      continue;
    }
    const view = r.view;
    const of = webViews.findIndex((v) => v.evidence.sha256 === view.evidence.sha256);
    if (of >= 0) {
      results.push({ kind: "duplicate", path, of });
      void ask({ kind: "release", key: r.key });
    } else {
      webViews.push(view);
      webKeys.push(r.key ?? -1);
      results.push({ kind: "ready", summary: summarize(webViews.length - 1, view) });
    }
  }
  return results;
}

// ——— API commune aux deux cibles ———

export async function openSources(sources: string[] | WebFile[]): Promise<OpenResult[]> {
  if (inTauri) return invoke<OpenResult[]>("open_paths", { paths: sources as string[] });
  return openWebFiles(sources as WebFile[]);
}

export async function getMessage(id: number, path: number[]): Promise<MessageView> {
  if (inTauri) return invoke<MessageView>("get_message", { id, path });
  const view = webViews[id];
  if (!view) throw new Error("preuve inconnue");
  return view; // l'interface descend elle-même dans les messages embarqués
}

export async function initialPaths(): Promise<string[]> {
  return inTauri ? invoke<string[]>("initial_paths") : [];
}

// ——— Rapport et indicateurs (FR-026, FR-044) ———

/** Horodatage UTC « AAAA-MM-JJ HH:MM:SS » (le moteur WebAssembly n'a pas d'horloge). */
function nowUtc(): string {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

/** Rapport d'analyse du message `path` de la preuve `id`. */
export async function buildReport(id: number, path: number[], format: "html" | "json"): Promise<string> {
  if (inTauri) return invoke<string>("build_report", { id, path, format, generated: nowUtc() });
  const r = await ask({ kind: "report", key: webKeys[id], path, format, generated: nowUtc() });
  if (!r.ok || r.text === undefined) throw new Error(r.error ?? "rapport impossible");
  return r.text;
}

export interface IocGroup {
  source: string;
  iocs: Ioc[];
}

/** Indicateurs fusionnés et dédoublonnés, en CSV ou JSON. */
export async function exportIocs(groups: IocGroup[], format: "csv" | "json", defang: boolean): Promise<string> {
  if (inTauri) return invoke<string>("export_iocs", { groups, format, defang });
  const r = await ask({ kind: "iocs", json: JSON.stringify(groups), format, defang });
  if (!r.ok || r.text === undefined) throw new Error(r.error ?? "export impossible");
  return r.text;
}

/** Bureau : dialogue d'enregistrement natif ; web : téléchargement (aucune requête réseau). */
export async function saveText(content: string, filename: string, mime: string): Promise<string | null> {
  if (inTauri) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const dest = await save({ defaultPath: filename, title: "Enregistrer" });
    if (!dest) return null;
    await invoke("save_text", { dest, content });
    return dest;
  }
  const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return filename;
}

/** Boîte de confirmation système : `ask` natif (bureau) ou `window.confirm` (web). */
export async function confirmBox(message: string, title: string, okLabel = "Télécharger"): Promise<boolean> {
  if (!inTauri) return window.confirm(`${title}\n\n${message}`);
  const { ask: nativeAsk } = await import("@tauri-apps/plugin-dialog");
  return nativeAsk(message, { title, kind: "warning", okLabel, cancelLabel: "Annuler" });
}

/**
 * FR-038 : enregistre la pièce jointe `index` du message `path` de la preuve `id`.
 * Bureau : dialogue d'enregistrement natif puis écriture par le moteur.
 * Web : octets extraits par le worker, téléchargement via Blob (aucune requête réseau).
 * Retourne le nom enregistré, ou null si l'analyste a annulé le choix d'emplacement.
 */
export async function saveAttachment(id: number, path: number[], att: Attachment): Promise<string | null> {
  if (inTauri) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const dest = await save({ defaultPath: att.filename.replace(/[\\/]/g, "_"), title: "Enregistrer la pièce jointe" });
    if (!dest) return null;
    await invoke<string>("save_attachment", { id, path, index: att.index, dest });
    return dest;
  }
  const r = await ask({ kind: "extract", key: webKeys[id], path, index: att.index, filename: att.filename });
  if (!r.ok || !r.data) throw new Error(r.error ?? "extraction impossible");
  return downloadBytes(r.data, r.name ?? "piece-jointe");
}

/** Téléchargement local d'octets (Blob) : aucune requête réseau. */
function downloadBytes(data: ArrayBuffer, name: string): string {
  // application/octet-stream : le navigateur enregistre sans tenter d'ouvrir ni d'afficher.
  const url = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return link.download;
}

/** Dialogue natif (bureau) ; côté web, FileHandler utilise un <input type="file">. */
export async function pickPaths(directory: boolean): Promise<string[]> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const picked = await open({
    multiple: true,
    directory,
    filters: directory ? undefined : [{ name: "Courriels et boîtes Outlook", extensions: ["eml", "msg", "pst", "ost"] }],
  });
  if (!picked) return [];
  return Array.isArray(picked) ? picked : [picked];
}

// ——— Trousseau de l'analyste : clés PGP et certificats (FR-049 à FR-051) ———

/** Fichiers de clés importés, mémorisés sur ce poste (navigateur ou application) et réimportés au
 *  démarrage. Les clés publiques ne sont pas secrètes ; rien n'est envoyé sur le réseau. */
const KEY_STORE = "mf.keyring.v1";

interface StoredKeys {
  files: { name: string; b64: string }[];
  removed: string[];
}

function loadStore(): StoredKeys {
  try {
    const v = JSON.parse(localStorage.getItem(KEY_STORE) ?? "null") as StoredKeys | null;
    if (v && Array.isArray(v.files) && Array.isArray(v.removed)) return v;
  } catch {
    /* stockage indisponible ou illisible */
  }
  return { files: [], removed: [] };
}

function saveStore(v: StoredKeys): void {
  try {
    localStorage.setItem(KEY_STORE, JSON.stringify(v));
  } catch {
    /* navigation privée : le trousseau ne vit que pour la session */
  }
}

function toB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function backendImport(name: string, bytes: Uint8Array): Promise<KeyEntry[]> {
  if (inTauri) return invoke<KeyEntry[]>("import_key", { name, data: Array.from(bytes) });
  const buf = bytes.slice().buffer as ArrayBuffer;
  const r = await ask({ kind: "key-import", name, bytes: buf }, [buf]);
  if (!r.ok || r.text === undefined) throw new Error(r.error ?? "import impossible");
  return JSON.parse(r.text) as KeyEntry[];
}

async function backendRemove(fingerprint: string): Promise<void> {
  if (inTauri) await invoke("remove_key", { fingerprint });
  else await ask({ kind: "key-remove", fingerprint });
}

export async function listKeys(): Promise<KeyEntry[]> {
  if (inTauri) return invoke<KeyEntry[]>("list_keys");
  const r = await ask({ kind: "key-list" });
  return JSON.parse(r.text ?? "[]") as KeyEntry[];
}

/** Réimporte le trousseau mémorisé (au démarrage, avant toute analyse). */
export async function restoreKeys(): Promise<void> {
  const store = loadStore();
  for (const f of store.files) {
    try {
      await backendImport(f.name, fromB64(f.b64));
    } catch {
      /* fichier devenu illisible : ignoré */
    }
  }
  for (const fp of store.removed) await backendRemove(fp);
}

/** Importe des fichiers de clés ; retourne les entrées ajoutées et les erreurs par fichier. */
export async function importKeyFiles(files: File[]): Promise<{ added: KeyEntry[]; errors: string[] }> {
  const store = loadStore();
  const added: KeyEntry[] = [];
  const errors: string[] = [];
  for (const file of files) {
    if (file.size > 1024 * 1024) {
      errors.push(`${file.name} : fichier trop volumineux pour une clé (1 Mo max.)`);
      continue;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      const entries = await backendImport(file.name, bytes);
      added.push(...entries);
      const b64 = toB64(bytes);
      if (!store.files.some((f) => f.b64 === b64)) store.files.push({ name: file.name, b64 });
      store.removed = store.removed.filter((fp) => !entries.some((e) => e.fingerprint === fp));
    } catch (e) {
      errors.push(`${file.name} : ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  saveStore(store);
  return { added, errors };
}

export async function removeKey(fingerprint: string): Promise<void> {
  await backendRemove(fingerprint);
  const store = loadStore();
  if (!store.removed.includes(fingerprint)) store.removed.push(fingerprint);
  saveStore(store);
}

export async function clearKeys(): Promise<void> {
  for (const k of await listKeys()) await backendRemove(k.fingerprint);
  saveStore({ files: [], removed: [] });
}

/** Ré-analyse toutes les preuves ouvertes avec le trousseau à jour ; retourne les résumés. */
export async function reanalyzeAll(): Promise<Summary[]> {
  if (inTauri) return invoke<Summary[]>("reanalyze_all");
  const out: Summary[] = [];
  if (webBoxes.length) await ask({ kind: "box-forget" });
  for (let i = 0; i < webViews.length; i++) {
    const r = await ask({ kind: "reanalyze", key: webKeys[i] });
    if (r.ok && r.view) webViews[i] = r.view;
    out.push(summarize(i, webViews[i]));
  }
  return out;
}

/** FR-051 : ouvre un lien de vérification externe, seulement après confirmation explicite. */
export async function openVerificationLink(link: ExternalLink): Promise<boolean> {
  const ok = await confirmBox(
    `Ouvrir ${link.label} dans le navigateur ?\n\n${link.url}\n\nCette consultation sort du cadre hors-ligne : le service consulté saura qu'on recherche cette clé ou cette adresse.`,
    "Vérification externe",
    "Ouvrir",
  );
  if (!ok) return false;
  if (inTauri) await invoke("open_verification_link", { url: link.url });
  else window.open(link.url, "_blank", "noopener,noreferrer");
  return true;
}

// ——— Boîtes PST / OST (feature 002) : Tauri sur le bureau, Worker WebAssembly dans le navigateur ———

/** Lignes d'un dossier, lues dans sa table, sans ouvrir les éléments. */
async function boxAsk(job: Record<string, unknown>): Promise<WorkerReply> {
  const r = await ask(job);
  if (!r.ok) throw new Error(r.error ?? "erreur de la boîte");
  return r;
}

export async function boxList(boxId: number, folder: number): Promise<ItemSummary[]> {
  if (!inTauri) return (await boxAsk({ kind: "box-list", box: boxId, folder })).json as ItemSummary[];
  return invoke<ItemSummary[]>("box_list", { boxId, folder });
}

/** Filtre d'une boîte (FR-007) : tables de dossiers seulement, plus les éléments déjà ouverts. */
export interface BoxFilter {
  folder?: number | null;
  text?: string | null;
  from_name?: string | null;
  to?: string | null;
  subject?: string | null;
  message_id?: string | null;
  /** AAAA-MM-JJ (UTC) */
  after?: string | null;
  before?: string | null;
  min_size?: number | null;
  max_size?: number | null;
  has_attachments?: boolean | null;
  analyzed_only?: boolean;
  verdict?: VerdictLevel[];
  from_address?: string | null;
  from_domain?: string | null;
}

/** Lignes correspondant au filtre, sans ouvrir aucun élément. */
export async function boxFilter(boxId: number, filter: BoxFilter): Promise<ItemSummary[]> {
  if (!inTauri) return (await boxAsk({ kind: "box-filter", box: boxId, filter: JSON.stringify(filter) })).json as ItemSummary[];
  return invoke<ItemSummary[]>("box_filter", { boxId, filter });
}

/** Indicateurs des éléments ouverts de la boîte, avec la provenance de chacun. */
export async function boxIocs(boxId: number): Promise<IocGroup[]> {
  if (!inTauri) return (await boxAsk({ kind: "box-iocs", box: boxId })).json as IocGroup[];
  return invoke<IocGroup[]>("box_iocs", { boxId });
}

/** Ouvre et analyse un élément : le seul appel qui lit un message. */
export async function boxItem(boxId: number, id: number): Promise<MessageView> {
  if (!inTauri) return (await boxAsk({ kind: "box-item", box: boxId, item: id })).view as MessageView;
  return invoke<MessageView>("box_item", { boxId, id });
}

export async function boxReport(boxId: number, id: number, path: number[], format: "html" | "json"): Promise<string> {
  if (!inTauri) return (await boxAsk({ kind: "box-report", box: boxId, item: id, path, format, generated: nowUtc() })).text ?? "";
  return invoke<string>("box_report", { boxId, id, path, format, generated: nowUtc() });
}

export async function boxSaveAttachment(boxId: number, id: number, path: number[], att: Attachment): Promise<string | null> {
  if (!inTauri) {
    const r = await boxAsk({ kind: "box-extract", box: boxId, item: id, path, index: att.index, filename: att.filename });
    return downloadBytes(r.data as ArrayBuffer, r.name ?? "piece-jointe");
  }
  const { save } = await import("@tauri-apps/plugin-dialog");
  const dest = await save({ defaultPath: att.filename.replace(/[\\/]/g, "_"), title: "Enregistrer la pièce jointe" });
  if (!dest) return null;
  await invoke<string>("box_save_attachment", { boxId, id, path, index: att.index, dest });
  return dest;
}

/** Progression du calcul d'empreinte des boîtes. */
export async function onBoxHash(fn: (h: BoxHash) => void): Promise<void> {
  if (!inTauri) {
    boxHashListeners.push(fn);
    return;
  }
  const { listen } = await import("@tauri-apps/api/event");
  await listen<BoxHash>("box-hash", (e) => fn(e.payload));
}
