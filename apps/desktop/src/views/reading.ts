// Panneau de lecture : scellé de la preuve, enveloppe, bouton des en-têtes (FR-035),
// corps sûr, et colonne d'inventaire « Fichiers contenus » (FR-036) + « URL » (FR-037).

import { h, humanSize, toast } from "../dom";
import type { Address, Attachment, AuthResult, BlockedKind, BlockedResource, Endpoint, Finding, Header, Hop, Ioc, IocKind, IpScope, MailRoute, Message, MessageView, Severity, SourceRef, UrlEntry, UrlLocation } from "../ipc";

export interface ReadingActions {
  headersOpen: boolean;
  path: number[];
  onToggleHeaders: () => void;
  onOpenEmbedded: (index: number) => void;
  /** FR-038 : téléchargement après confirmation. */
  onDownload: (attachment: Attachment) => void;
  /** FR-044 : rapport d'analyse du message affiché. */
  onReport: (format: "html" | "json") => void;
  /** FR-023 : export des indicateurs du message affiché. */
  onExportIocs: (format: "csv" | "json") => void;
  onGoToDepth: (depth: number) => void;
}

/** Fil d'Ariane : noms des PJ traversées, fournis par l'appelant. */
export interface Crumb {
  label: string;
}


export function renderReading(view: MessageView, crumbs: Crumb[], a: ReadingActions): HTMLElement {
  const m = view.message;
  const main = h("div", { class: "reading-main" });

  if (crumbs.length > 1) main.append(breadcrumb(crumbs, a));

  main.append(h("h1", { class: "subject-line" }, m.subject?.trim() || "(sans objet)"));
  main.append(envelope(view));
  if (m.issues.length) main.append(h("ul", { class: "issues" }, ...m.issues.map((i) => h("li", {}, i))));
  main.append(analysisSection(m, a));

  // FR-035 — bouton « Afficher / Masquer les en-têtes »
  const panelId = "headers-panel";
  main.append(
    h(
      "div",
      { class: "header-toggle-row" },
      h(
        "button",
        {
          class: "btn",
          type: "button",
          "aria-expanded": String(a.headersOpen),
          "aria-controls": panelId,
          onclick: a.onToggleHeaders,
        },
        `${a.headersOpen ? "Masquer" : "Afficher"} les en-têtes (${m.headers.length})`,
      ),
      h("span", { class: "kbd", title: "Raccourci clavier" }, "H"),
      h("span", { class: "spacer" }),
      h("span", { class: "muted-label" }, "Rapport"),
      h("button", { class: "btn btn-small report-html", type: "button", onclick: () => a.onReport("html") }, "HTML (imprimable)"),
      h("button", { class: "btn btn-small report-json", type: "button", onclick: () => a.onReport("json") }, "JSON"),
    ),
  );
  if (a.headersOpen) {
    const panel = headersPanel(panelId, m.headers);
    main.append(panel);
    const target = pendingHeader;
    if (target !== null) {
      pendingHeader = null;
      requestAnimationFrame(() => {
        const li = panel.querySelector(`li[data-hidx="${target}"]`);
        if (li) flash(li);
      });
    }
  }

  main.append(body(view));

  const grid = h("div", { class: "reading-grid" }, main, inventory(seal(view), m.attachments, m.urls, a, m.blocked_resources, m.route, m.hops, m.iocs));
  return grid;
}

function seal(view: MessageView): HTMLElement {
  const name = view.evidence.path.split(/[\\/]/).pop() ?? view.evidence.path;
  return h(
    "dl",
    { class: "seal", title: view.evidence.path },
    h("div", { class: "seal-file" }, `${name} — ${view.evidence.format.toUpperCase()}, ${humanSize(view.evidence.size)}`),
    h("dt", {}, "SHA-256"),
    h("dd", {}, view.evidence.sha256),
    h("dt", {}, "MD5"),
    h("dd", {}, view.evidence.md5),
  );
}

function breadcrumb(crumbs: Crumb[], a: ReadingActions): HTMLElement {
  const nav = h("nav", { class: "breadcrumb", "aria-label": "Provenance du message" });
  crumbs.forEach((c, depth) => {
    if (depth > 0) nav.append(h("span", { "aria-hidden": "true" }, "›"));
    if (depth < crumbs.length - 1) {
      nav.append(h("button", { type: "button", onclick: () => a.onGoToDepth(depth) }, c.label));
    } else {
      nav.append(h("strong", { "aria-current": "page" }, c.label));
    }
  });
  return nav;
}

function addr(x: Address): HTMLElement {
  const label =
    x.display_name && x.address && x.display_name !== x.address
      ? `${x.display_name} <${x.address}>`
      : (x.address ?? x.display_name ?? "");
  return h("span", { class: "addr" }, label, x.x500_dn ? h("span", { class: "x500" }, `Exchange : ${x.x500_dn}`) : null);
}

function addrList(list: Address[]): HTMLElement {
  const dd = h("dd");
  list.forEach((x, i) => {
    if (i) dd.append(", ");
    dd.append(addr(x));
  });
  return dd;
}

function envelope(view: MessageView): HTMLElement {
  const m = view.message;
  const dl = h("dl", { class: "envelope" });
  const row = (label: string, dd: HTMLElement) => dl.append(h("dt", {}, label), dd);
  row("De", addrList(m.from));
  if (m.sender) row("Envoyé par", addrList([m.sender]));
  if (m.reply_to.length) row("Répondre à", addrList(m.reply_to));
  row("À", addrList(m.to));
  if (m.cc.length) row("Cc", addrList(m.cc));
  if (m.bcc.length) row("Cci", addrList(m.bcc));
  row(
    "Date",
    h(
      "dd",
      {},
      m.date_raw ?? "—",
      m.date_utc ? h("span", { class: "utc" }, ` (UTC ${m.date_utc.replace("T", " ").replace(/\+00:00$/, "")})`) : null,
    ),
  );
  return dl;
}

function headersPanel(id: string, headers: Header[]): HTMLElement {
  if (!headers.length) {
    return h("div", { class: "headers-panel", id }, h("p", { class: "empty" }, "Ce message ne contient aucun en-tête de transport."));
  }
  return h(
    "div",
    { class: "headers-panel", id, role: "region", "aria-label": "En-têtes bruts" },
    h(
      "ol",
      {},
      ...headers.map((hd) => {
        const value = hd.raw.slice(hd.raw.indexOf(":") + 1).replace(/^ /, "");
        return h(
          "li",
          { title: hd.offset ? `octets ${hd.offset[0]}–${hd.offset[1]}` : "", "data-hidx": String(hd.index) },
          h("span", { class: "hidx" }, String(hd.index + 1)),
          h("span", { class: "hname" }, `${hd.name}:`),
          h("span", {}, value),
        );
      }),
    ),
  );
}

// ——— Corps du message : rendu HTML neutralisé, texte, source HTML (FR-008, FR-039) ———

type BodyMode = "html" | "text" | "source";
let bodyMode: BodyMode = "html";
/** Liste des ressources bloquées dépliée ou non (mémorisé pendant la session). */
let blockedOpen = false;
/** Action à effectuer une fois la vue reconstruite (aller au repère / à la ligne). */
let pendingFocus: { target: "render"; marker: number } | { target: "source"; line: number } | null = null;

const KIND_LABEL: Record<BlockedKind, string> = {
  image: "Image",
  background: "Image de fond",
  stylesheet: "Feuille de style",
  script: "Script",
  frame: "Cadre",
  media: "Média",
  object: "Objet",
  other: "Autre",
};

/** Styles injectés dans l'iframe du rendu : repères des ressources bloquées. */
const FRAME_CSS =
  "body{font:15px/1.45 system-ui,sans-serif;margin:16px;color:#1c2733;background:#fff;overflow-wrap:anywhere}" +
  "img{max-width:100%;height:auto}a{color:#1f6f78;text-decoration:underline dotted;cursor:default}" +
  ".mf-blocked{outline:2px dashed #b88a00;outline-offset:-2px}" +
  ".mf-badge{display:inline-block;font:700 11px/1.6 system-ui,sans-serif;color:#3d2f00;background:#f2c230;" +
  "border-radius:9px;padding:0 7px;margin:2px;vertical-align:middle;white-space:nowrap}" +
  ".mf-flash{outline:3px solid #1f6f78!important;outline-offset:2px;box-shadow:0 0 0 6px rgba(31,111,120,.25)}";

function blockedPanel(m: Message, rebuild: () => void): HTMLElement | null {
  const list = m.blocked_resources;
  if (!list.length) return null;
  const details = h("details", { class: "blocked-panel", open: blockedOpen }) as HTMLDetailsElement;
  details.addEventListener("toggle", () => (blockedOpen = details.open));
  details.append(
    h(
      "summary",
      {},
      `${list.length} ressource${list.length > 1 ? "s" : ""} distante${list.length > 1 ? "s" : ""} bloquée${list.length > 1 ? "s" : ""}`,
      h("span", { class: "summary-hint" }, blockedOpen ? "masquer le détail" : "voir où elles se trouvent"),
    ),
    h(
      "p",
      { class: "blocked-why" },
      "Le message demande à charger ces éléments depuis Internet. Ils ne sont jamais chargés : le serveur distant apprendrait que le message a été ouvert, quand, et depuis quelle adresse IP (pixel de suivi).",
    ),
    h(
      "ol",
      { class: "blocked-list" },
      ...list.map((b) =>
        h(
          "li",
          {},
          h("span", { class: "num", "aria-label": `Ressource ${b.number}` }, String(b.number)),
          h(
            "div",
            { class: "blocked-body" },
            h(
              "div",
              { class: "blocked-what" },
              h("strong", {}, KIND_LABEL[b.kind]),
              h("span", { class: "tagname" }, `<${b.element} ${b.attribute}>`),
              b.line ? h("span", {}, `ligne ${b.line} du HTML`) : null,
              h("span", { class: "muted" }, b.marker !== null ? "repère dans le rendu" : "retiré du rendu"),
            ),
            h("div", { class: "url-text" }, b.url),
            h(
              "div",
              { class: "blocked-actions" },
              b.marker !== null
                ? h(
                    "button",
                    {
                      class: "btn btn-small",
                      type: "button",
                      onclick: () => {
                        pendingFocus = { target: "render", marker: b.marker as number };
                        bodyMode = "html";
                        rebuild();
                      },
                    },
                    "Voir dans le rendu",
                  )
                : null,
              b.line
                ? h(
                    "button",
                    {
                      class: "btn btn-small",
                      type: "button",
                      onclick: () => {
                        pendingFocus = { target: "source", line: b.line as number };
                        bodyMode = "source";
                        rebuild();
                      },
                    },
                    "Voir dans la source",
                  )
                : null,
              h("button", { class: "btn btn-small", type: "button", onclick: () => copy(b.url, "URL") }, "Copier"),
            ),
          ),
        ),
      ),
    ),
  );
  return details;
}

/** Repères visibles dans le rendu, à l'emplacement de chaque ressource bloquée. */
function decorateRender(doc: Document, m: Message): Map<number, Element> {
  const byMarker = new Map<number, BlockedResource[]>();
  for (const b of m.blocked_resources) {
    if (b.marker !== null) byMarker.set(b.marker, [...(byMarker.get(b.marker) ?? []), b]);
  }
  const found = new Map<number, Element>();
  for (const el of doc.querySelectorAll("img[src*='#mf-blocked-'], [background*='#mf-blocked-']")) {
    const v = el.getAttribute("src") ?? el.getAttribute("background") ?? "";
    const k = Number(v.slice(v.indexOf("#mf-blocked-") + 12));
    if (k) found.set(k, el);
  }
  for (const el of doc.querySelectorAll<HTMLElement>("[style*='--mf-blocked']")) {
    const k = Number(el.style.getPropertyValue("--mf-blocked").trim());
    if (k) found.set(k, el);
  }
  for (const [k, el] of found) {
    const items = byMarker.get(k) ?? [];
    if (!items.length) continue;
    el.classList.add("mf-blocked");
    const badge = doc.createElement("span");
    badge.className = "mf-badge";
    badge.textContent = `bloqué ${items.map((b) => b.number).join(", ")}`;
    badge.title = items.map((b) => `${b.number}. ${KIND_LABEL[b.kind]} : ${b.url}`).join("\n");
    const tag = el.tagName.toLowerCase();
    if (tag === "td" || tag === "th") el.prepend(badge);
    else if (tag === "tr") (el.firstElementChild ?? el).prepend(badge);
    else el.before(badge);
  }
  return found;
}

function flash(el: Element): void {
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.add("mf-flash");
  setTimeout(() => el.classList.remove("mf-flash"), 2200);
}

function sourceView(m: Message): HTMLElement {
  const lines = (m.body_html ?? "").split(/\r?\n/);
  const atLine = new Map<number, number[]>();
  for (const b of m.blocked_resources) if (b.line) atLine.set(b.line, [...(atLine.get(b.line) ?? []), b.number]);
  return h(
    "ol",
    { class: "html-source", "aria-label": "Code source HTML du message" },
    ...lines.map((text, i) => {
      const nums = atLine.get(i + 1);
      return h(
        "li",
        { "data-line": String(i + 1), class: nums ? "has-blocked" : undefined },
        h("span", { class: "ln", "aria-hidden": "true" }, String(i + 1)),
        h("code", {}, text || " "),
        nums ? h("span", { class: "num" }, nums.join(", ")) : null,
      );
    }),
  );
}

/** Iframe du rendu HTML : sanitisé par le moteur, puis sandbox sans scripts + CSP stricte. */
function renderFrame(m: Message, onReady: (markers: Map<number, Element>) => void, autoHeight = true): HTMLIFrameElement {
  const doc =
    `<!doctype html><html><head><meta charset="utf-8">` +
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">` +
    `<style>${FRAME_CSS}</style></head><body>${m.body_html_safe ?? ""}</body></html>`;
  const frame = h("iframe", {
    class: "body-frame",
    sandbox: "allow-same-origin",
    referrerpolicy: "no-referrer",
    title: "Corps HTML neutralisé",
  }) as HTMLIFrameElement;
  frame.srcdoc = doc;
  frame.addEventListener("load", () => {
    const d = frame.contentDocument;
    if (!d) return;
    const markers = decorateRender(d, m);
    if (autoHeight) frame.style.height = `${Math.min(d.documentElement.scrollHeight + 8, 4000)}px`;
    onReady(markers);
  });
  return frame;
}

/** Rendu HTML sur toute la fenêtre ; Échap ou « Fermer » pour revenir. */
function openFullscreen(m: Message): void {
  const close = () => {
    overlay.remove();
    document.removeEventListener("keydown", onKey, true);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      e.preventDefault();
      close();
    }
  };
  const overlay = h(
    "div",
    { class: "fullscreen", role: "dialog", "aria-modal": "true", "aria-label": "Rendu HTML en plein écran" },
    h(
      "div",
      { class: "fullscreen-bar" },
      h("strong", {}, m.subject?.trim() || "(sans objet)"),
      h("span", { class: "spacer" }),
      h("button", { class: "btn btn-small", type: "button", onclick: close }, "Fermer (Échap)"),
    ),
    renderFrame(m, () => {}, false),
  );
  document.addEventListener("keydown", onKey, true);
  document.body.append(overlay);
  overlay.querySelector<HTMLButtonElement>("button")?.focus();
}

function body(view: MessageView): HTMLElement {
  const m = view.message;
  const wrap = h("section", { "aria-label": "Corps du message" });
  const rebuild = () => wrap.replaceWith(body(view));
  const hasHtml = !!m.body_html_safe;
  const hasText = !!m.body_text;
  let mode: BodyMode = bodyMode;
  if (!hasHtml && mode !== "text") mode = "text";
  if (mode === "text" && !hasText && hasHtml) mode = "html";

  const tabs = h("div", { class: "body-tabs" });
  const choices: [BodyMode, string, boolean][] = [
    ["html", "HTML", hasHtml],
    ["text", "Texte", hasText],
    ["source", "Source HTML", hasHtml],
  ];
  // FR-041 : les trois vues restent visibles ; une vue absente est grisée avec son explication.
  for (const [k, label, ok] of choices) {
    tabs.append(
      h(
        "button",
        {
          class: "btn btn-small",
          type: "button",
          "aria-pressed": String(mode === k),
          disabled: !ok,
          title: ok ? "" : k === "text" ? "Pas de version texte dans ce message" : "Pas de version HTML dans ce message",
          onclick: () => {
            bodyMode = k;
            rebuild();
          },
        },
        label,
      ),
    );
  }
  if (mode !== "text" && m.html_source === "rtf") {
    tabs.append(h("span", { class: "provenance" }, "HTML d'origine reconstitué depuis le RTF Outlook"));
  } else if (!hasHtml) {
    tabs.append(h("span", { class: "provenance" }, "Ce message n'a pas de version HTML"));
  }
  if (mode === "html" && m.body_html_safe) {
    tabs.append(
      h("span", { class: "spacer" }),
      h("button", { class: "btn btn-small", type: "button", onclick: () => openFullscreen(m) }, "Plein écran"),
    );
  }
  wrap.append(tabs);
  if (mode !== "text") {
    const panel = blockedPanel(m, rebuild);
    if (panel) wrap.append(panel);
  }

  if (mode === "html" && m.body_html_safe) {
    const frame = renderFrame(m, (markers) => {
      const focus = pendingFocus;
      if (focus?.target === "render") {
        pendingFocus = null;
        const el = markers.get(focus.marker);
        if (el) setTimeout(() => flash(el), 50);
      }
    });
    wrap.append(frame);
  } else if (mode === "source") {
    const src = sourceView(m);
    wrap.append(src);
    const focus = pendingFocus;
    if (focus?.target === "source") {
      pendingFocus = null;
      requestAnimationFrame(() => {
        const li = src.querySelector(`li[data-line="${focus.line}"]`);
        if (li) flash(li);
      });
    }
  } else if (hasText) {
    wrap.append(h("pre", { class: "body-text" }, m.body_text ?? ""));
  } else {
    wrap.append(h("p", { class: "none" }, "Aucun corps lisible dans ce message."));
  }
  return wrap;
}

// ——— Acheminement : IP et DNS d'envoi et de réception (FR-042) ———

const SCOPE_LABEL: Partial<Record<IpScope, string>> = {
  private: "IP privée",
  loopback: "boucle locale",
  link_local: "lien local",
  shared: "CGNAT",
  documentation: "plage de documentation",
};

function fmtDuration(s: number): string {
  const sign = s < 0 ? "−" : "+";
  const a = Math.abs(s);
  if (a < 60) return `${sign}${a} s`;
  if (a < 3600) return `${sign}${Math.floor(a / 60)} min ${a % 60} s`;
  return `${sign}${Math.floor(a / 3600)} h ${Math.floor((a % 3600) / 60)} min`;
}

function fmtUtc(utc: string | null): string {
  return utc ? `${utc.replace("T", " ").replace(/(\+00:00|Z)$/, "")} UTC` : "";
}

function endpointBlock(label: string, e: Endpoint, hint: string): HTMLElement {
  const dns: [string, string | null][] = [
    ["DNS inverse", e.rdns],
    ["Nom annoncé", e.name],
  ];
  return h(
    "div",
    { class: "route-block" },
    h("div", { class: "route-label" }, h("span", {}, label), h("span", {}, hint)),
    e.ip
      ? h(
          "div",
          { class: "route-ip" },
          h("code", {}, e.ip),
          e.ip_scope && SCOPE_LABEL[e.ip_scope] ? h("span", { class: "scope" }, SCOPE_LABEL[e.ip_scope] ?? "") : null,
          h("button", { class: "btn btn-small", type: "button", onclick: () => copy(e.ip ?? "", "IP") }, "Copier"),
        )
      : null,
    dns.some(([, v]) => v)
      ? h("dl", { class: "route-dns" }, ...dns.filter(([, v]) => v).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "")]))
      : null,
  );
}

function routeSection(r: MailRoute, hops: Hop[]): HTMLElement {
  const sec = h(
    "section",
    { class: "route", "aria-label": "Acheminement du message" },
    h("h2", { class: "route-title" }, r.sender ?? "Expéditeur inconnu"),
    h(
      "p",
      { class: "route-sub" },
      hops.length
        ? `${hops.length} relais${r.transit_seconds !== null ? ` · acheminé en ${fmtDuration(r.transit_seconds).slice(1)}` : ""}`
        : "Aucun en-tête Received : message interne, brouillon ou en-têtes de transport absents.",
    ),
  );
  const hop = (e: Endpoint) => (e.hop > 0 ? `saut ${e.hop}` : e.source);
  if (r.origin) sec.append(endpointBlock("Envoi", r.origin, hop(r.origin)));
  if (r.originating_ip_header)
    sec.append(endpointBlock("IP du client de l'expéditeur", r.originating_ip_header, r.originating_ip_header.source));
  if (r.first_public) sec.append(endpointBlock("Première IP publique", r.first_public, hop(r.first_public)));
  if (r.last_public) sec.append(endpointBlock("Remis au destinataire par", r.last_public, hop(r.last_public)));
  if (r.receiver) {
    sec.append(
      h(
        "div",
        { class: "route-block" },
        h("div", { class: "route-label" }, h("span", {}, "Réception"), h("span", {}, hop(r.receiver))),
        r.receiver.ip
          ? h("div", { class: "route-ip" }, h("code", {}, r.receiver.ip),
              h("button", { class: "btn btn-small", type: "button", onclick: () => copy(r.receiver?.ip ?? "", "IP") }, "Copier"))
          : null,
        h(
          "dl",
          { class: "route-dns" },
          h("dt", {}, "Serveur"),
          h("dd", {}, r.receiver.name ?? "non indiqué"),
          r.received_utc ? h("dt", {}, "Reçu le") : null,
          r.received_utc ? h("dd", {}, fmtUtc(r.received_utc)) : null,
        ),
      ),
    );
  }
  if (hops.length) {
    sec.append(
      h(
        "details",
        {},
        h("summary", {}, `Chemin complet (${hops.length} sauts)`),
        h(
          "ol",
          { class: "hops" },
          ...hops.map((x) =>
            h(
              "li",
              {},
              h("span", { class: "num" }, String(x.index)),
              h(
                "div",
                {},
                h(
                  "div",
                  { class: "hop-line" },
                  `${x.from_rdns ?? x.from_name ?? "—"}${x.from_ip ? ` [${x.from_ip}]` : ""} → ${x.by_name ?? "—"}`,
                ),
                h(
                  "div",
                  { class: "hop-meta" },
                  [x.with, fmtUtc(x.date_utc)].filter(Boolean).join(" · "),
                  x.delay_seconds !== null
                    ? h("span", { class: x.delay_seconds < 0 ? "negative" : undefined, title: x.delay_seconds < 0 ? "Horodatage antérieur au saut précédent : horloge décalée ou en-tête falsifié" : "" }, ` (${fmtDuration(x.delay_seconds)})`)
                    : null,
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
  sec.append(
    h(
      "p",
      { class: "route-note" },
      "Noms DNS tels qu'enregistrés dans les en-têtes Received par les serveurs, au moment du transit. Aucune requête DNS n'est effectuée.",
    ),
  );
  return sec;
}

function inventory(evidence: HTMLElement, files: Attachment[], urls: UrlEntry[], a: ReadingActions, blocked: BlockedResource[], route: MailRoute | null, hops: Hop[], iocs: Ioc[]): HTMLElement {
  return h(
    "aside",
    { class: "inventory", "aria-label": "Contenu du message" },
    evidence,
    route ? routeSection(route, hops) : null,
    filesSection(files, a),
    urlsSection(urls, blocked),
    iocSection(iocs, a),
  );
}

function filesSection(files: Attachment[], a: ReadingActions): HTMLElement {
  const sec = h("section", { class: "files" }, h("h2", {}, "Fichiers contenus", h("span", { class: "count" }, String(files.length))));
  if (!files.length) {
    sec.append(h("p", { class: "none" }, "Aucun fichier"));
    return sec;
  }
  sec.append(
    h(
      "ul",
      {},
      ...files.map((f) =>
        h(
          "li",
          {},
          h("div", { class: "file-name", "data-att": String(f.index) }, f.filename),
          f.flags.length ? h("div", { class: "flags" }, ...f.flags.map((fl) => flagBadge(ATT_FLAGS[fl] ?? [fl, "low"]))) : null,
          h(
            "div",
            { class: "file-meta" },
            h("span", {}, f.declared_mime ?? "type non déclaré"),
            f.detected_type ? h("span", { class: f.flags.includes("type_mismatch") ? "detected bad" : "detected", title: "Type réel d'après le contenu" }, `réel : ${f.detected_type}`) : null,
            h("span", {}, humanSize(f.size)),
            f.disposition === "inline" ? h("span", { class: "tag-inline" }, "inline") : h("span", {}, "attaché"),
          ),
          // Les deux empreintes en clair (FR-036) : le MD5 n'est plus caché dans une infobulle.
          h("dl", { class: "file-hash" }, h("dt", {}, "SHA-256"), h("dd", {}, f.sha256), h("dt", {}, "MD5"), h("dd", {}, f.md5)),
          h(
            "div",
            { class: "file-actions" },
            f.extractable
              ? h(
                  "button",
                  { class: "btn btn-small download", type: "button", onclick: () => a.onDownload(f) },
                  "Télécharger",
                )
              : h(
                  "button",
                  {
                    class: "btn btn-small download",
                    type: "button",
                    disabled: true,
                    title: "Message Outlook embarqué : il n'existe pas de fichier d'origine à extraire. Ouvrez-le pour consulter son contenu.",
                  },
                  "Téléchargement indisponible",
                ),
            f.embedded
              ? h(
                  "button",
                  { class: "btn btn-small open-embedded", type: "button", onclick: () => a.onOpenEmbedded(f.index) },
                  `Ouvrir le message joint (${f.embedded.attachments.length} fichier(s), ${f.embedded.urls.length} URL)`,
                )
              : null,
          ),
        ),
      ),
    ),
  );
  return sec;
}

function locationLabel(l: UrlLocation): string {
  switch (l.kind) {
    case "header":
      return `en-tête ${l.name}`;
    case "body_text":
      return "texte";
    case "html_attribute":
      return `HTML ${l.attribute}`;
    case "html_text":
      return "texte HTML";
    case "html_css":
      return "CSS";
  }
}

async function copy(text: string, what: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} copiée`);
  } catch {
    toast("Copie impossible : sélectionnez l'URL puis Ctrl+C");
  }
}

function urlsSection(urls: UrlEntry[], blocked: BlockedResource[]): HTMLElement {
  const sec = h("section", {}, h("h2", {}, "URL", h("span", { class: "count" }, String(urls.length))));
  if (!urls.length) {
    sec.append(h("p", { class: "none" }, "Aucune URL"));
    return sec;
  }
  sec.append(
    h(
      "ul",
      {},
      ...urls.map((u) =>
        h(
          "li",
          {},
          // Jamais un lien : texte sélectionnable uniquement.
          h("div", { class: "url-text", "data-url": u.url }, u.url),
          u.flags.length
            ? h(
                "div",
                { class: "flags" },
                ...u.flags.map((fl) => {
                  const [label, sev] = URL_FLAGS[fl] ?? [fl, "low"];
                  return flagBadge([fl === "lookalike" && u.lookalike_of ? `Sosie de ${u.lookalike_of}` : label, sev]);
                }),
              )
            : null,
          u.unicode_host ? h("div", { class: "url-note" }, `Domaine réel : ${u.unicode_host}`) : null,
          u.display_texts.length ? h("div", { class: "url-note" }, `Texte affiché : « ${u.display_texts.join(" » / « ")} »`) : null,
          h(
            "div",
            { class: "url-meta" },
            h("span", {}, u.locations.map(locationLabel).join(", ")),
            u.occurrences > 1 ? h("span", {}, `${u.occurrences} fois`) : null,
            ((nums) =>
              nums.length
                ? h("span", { class: "tag-blocked", title: "Ressource que le message chargerait automatiquement : bloquée" }, `chargement bloqué (${nums.join(", ")})`)
                : null)(blocked.filter((b) => b.url === u.url).map((b) => b.number)),
            h(
              "span",
              { class: "actions" },
              h("button", { class: "btn btn-small", type: "button", onclick: () => copy(u.url, "URL") }, "Copier"),
              h(
                "button",
                { class: "btn btn-small", type: "button", title: u.defanged, onclick: () => copy(u.defanged, "URL défangée") },
                "Copier défangée",
              ),
            ),
          ),
        ),
      ),
    ),
  );
  return sec;
}

// ——— Analyse : authentification, constats, indicateurs (FR-013 à FR-023, FR-043) ———

/** En-tête à mettre en évidence une fois le panneau des en-têtes ouvert. */
let pendingHeader: number | null = null;
let analysisOpen = (() => {
  try {
    return localStorage.getItem("mf.analysisOpen") !== "0";
  } catch {
    return true;
  }
})();
let minorOpen = false;

const SEV_LABEL: Record<Severity, string> = { high: "Élevé", medium: "Moyen", low: "Faible", info: "Info" };

const ATT_FLAGS: Record<string, [string, Severity]> = {
  executable: ["Exécutable", "high"],
  double_extension: ["Double extension", "high"],
  type_mismatch: ["Extension trompeuse", "high"],
  bidi_or_control_chars: ["Nom maquillé", "high"],
  macros: ["Macros", "high"],
  encrypted_archive: ["Archive chiffrée", "medium"],
  html_attachment: ["Page HTML", "medium"],
  risky_extension: ["Type à risque", "medium"],
  tnef: ["TNEF (winmail.dat)", "info"],
  zero_length: ["Vide", "info"],
};

const URL_FLAGS: Record<string, [string, Severity]> = {
  lookalike: ["Domaine sosie", "high"],
  mixed_script: ["Alphabets mélangés", "high"],
  credentials: ["Destination masquée (user@hôte)", "high"],
  text_target_mismatch: ["Texte ≠ destination", "medium"],
  raw_ip: ["Adresse IP", "medium"],
  punycode: ["Punycode", "medium"],
};

const IOC_LABEL: Record<IocKind, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domaines",
  url: "URL",
  email: "Adresses",
  sha256: "SHA-256",
  md5: "MD5",
};

function flagBadge([label, sev]: [string, Severity]): HTMLElement {
  return h("span", { class: `sev sev-${sev}` }, label);
}

/** Va à l'élément cité par un constat (en-tête, pièce jointe, URL). */
function goTo(r: SourceRef, a: ReadingActions): void {
  if (r.kind === "header") {
    pendingHeader = r.index;
    if (!a.headersOpen) a.onToggleHeaders();
    else {
      const li = document.querySelector(`.headers-panel li[data-hidx="${r.index}"]`);
      pendingHeader = null;
      if (li) flash(li);
    }
    return;
  }
  const sel =
    r.kind === "attachment"
      ? `.inventory .file-name[data-att="${r.index}"]`
      : r.kind === "url"
        ? `.inventory .url-text[data-url="${CSS.escape(r.url)}"]`
        : `.hops li:nth-child(${r.index})`;
  if (r.kind === "hop") document.querySelector<HTMLDetailsElement>(".route details")?.setAttribute("open", "");
  const el = document.querySelector(sel);
  if (el) flash(el.closest("li") ?? el);
}

function refLabel(r: SourceRef): string {
  switch (r.kind) {
    case "header":
      return r.name;
    case "attachment":
      return `PJ ${r.index}`;
    case "url": {
      // Hôte seul, défangé : le libellé reste lisible et n'est jamais cliquable comme un lien.
      const host = /^[a-z][a-z0-9+.-]*:\/\/(?:[^/@]*@)?([^/:?#]+)/i.exec(r.url)?.[1] ?? r.url.slice(0, 40);
      return `URL ${host.replace(/\./g, "[.]")}`;
    }
    case "hop":
      return `saut ${r.index}`;
  }
}

function findingItem(f: Finding, a: ReadingActions): HTMLElement {
  return h(
    "li",
    { class: `finding sev-border-${f.severity}` },
    h("span", { class: `sev sev-${f.severity}` }, SEV_LABEL[f.severity]),
    h(
      "div",
      {},
      h("div", { class: "finding-title" }, f.title),
      h("div", { class: "finding-detail" }, f.detail),
      f.refs.length
        ? h(
            "div",
            { class: "finding-refs" },
            ...f.refs.slice(0, 6).map((r) =>
              h("button", { class: "link-btn", type: "button", title: "Aller à l'élément", onclick: () => goTo(r, a) }, refLabel(r)),
            ),
          )
        : null,
    ),
  );
}

function authChip(label: string, r: AuthResult | undefined): HTMLElement {
  const res = r?.result ?? "absent";
  const cls = res === "pass" ? "ok" : ["fail", "permerror"].includes(res) ? "high" : res === "softfail" ? "medium" : "low";
  return h(
    "span",
    {
      class: `auth-chip auth-${cls}`,
      title: r ? `${r.header_name} n° ${r.header_index + 1}${r.authserv_id ? ` — verdict de ${r.authserv_id}` : ""}\n${r.properties.map(([k, v]) => `${k}=${v}`).join(" ")}` : "Non évalué",
    },
    h("strong", {}, label),
    ` ${res}`,
  );
}

function verdictOf(m: Message, method: string): AuthResult | undefined {
  return m.auth.find((x) => x.method === method && x.most_recent) ?? m.auth.find((x) => x.method === method && !x.header_name.startsWith("ARC"));
}

function analysisSection(m: Message, a: ReadingActions): HTMLElement {
  const count = (s: Severity) => m.findings.filter((f) => f.severity === s).length;
  const major = m.findings.filter((f) => f.severity === "high" || f.severity === "medium");
  const minor = m.findings.filter((f) => f.severity === "low" || f.severity === "info");
  const sec = h("section", { class: `analysis${analysisOpen ? "" : " collapsed"}`, "aria-label": "Analyse du message" });
  const content = h("div", { class: "analysis-body", id: "analysis-body", hidden: !analysisOpen });
  const toggle = h(
    "button",
    { class: "btn btn-small analysis-toggle", type: "button", "aria-expanded": String(analysisOpen), "aria-controls": "analysis-body" },
    analysisOpen ? "Replier" : "Déplier",
  );
  toggle.addEventListener("click", () => {
    analysisOpen = !analysisOpen;
    try {
      localStorage.setItem("mf.analysisOpen", analysisOpen ? "1" : "0");
    } catch {
      /* stockage indisponible : l'état reste en mémoire */
    }
    content.hidden = !analysisOpen;
    sec.classList.toggle("collapsed", !analysisOpen);
    toggle.setAttribute("aria-expanded", String(analysisOpen));
    toggle.textContent = analysisOpen ? "Replier" : "Déplier";
  });
  sec.append(
    h(
      "div",
      { class: "analysis-head" },
      h("h2", {}, "Analyse"),
      ...(["high", "medium", "low", "info"] as Severity[])
        .filter((s) => count(s) > 0)
        .map((s) => h("span", { class: `sev sev-${s}` }, `${count(s)} ${SEV_LABEL[s].toLowerCase()}`)),
      m.findings.length ? null : h("span", { class: "muted-label" }, "aucun constat"),
      h("span", { class: "spacer" }),
      toggle,
    ),
    content,
  );
  if (m.auth.length || m.dkim.length) {
    const row = h("div", { class: "auth-row" }, authChip("SPF", verdictOf(m, "spf")), authChip("DKIM", verdictOf(m, "dkim")), authChip("DMARC", verdictOf(m, "dmarc")));
    for (const d of m.dkim) {
      const state = d.body_hash_ok === true ? "corps intact depuis la signature" : d.body_hash_ok === false ? "corps modifié depuis la signature" : "corps non vérifiable";
      row.append(
        h(
          "span",
          { class: `dkim-state ${d.body_hash_ok === false ? "bad" : d.body_hash_ok ? "good" : ""}`, title: d.note ?? `Empreinte recalculée hors-ligne : ${d.body_hash_computed ?? "—"}` },
          `DKIM ${d.domain ?? "?"} : ${state}`,
        ),
      );
    }
    content.append(row);
  } else if (m.hops.length) {
    content.append(h("p", { class: "muted-label" }, "Aucun résultat SPF / DKIM / DMARC dans les en-têtes."));
  }
  if (major.length) content.append(h("ol", { class: "findings" }, ...major.map((f) => findingItem(f, a))));
  if (minor.length) {
    const d = h("details", { class: "minor", open: minorOpen || !major.length }) as HTMLDetailsElement;
    d.addEventListener("toggle", () => (minorOpen = d.open));
    d.append(h("summary", {}, `${minor.length} constat${minor.length > 1 ? "s" : ""} mineur${minor.length > 1 ? "s" : ""}`), h("ol", { class: "findings" }, ...minor.map((f) => findingItem(f, a))));
    content.append(d);
  }
  return sec;
}

function iocSection(iocs: Ioc[], a: ReadingActions): HTMLElement {
  const sec = h(
    "section",
    { class: "iocs" },
    h("h2", {}, "Indicateurs", h("span", { class: "count" }, String(iocs.length))),
  );
  if (!iocs.length) {
    sec.append(h("p", { class: "none" }, "Aucun indicateur"));
    return sec;
  }
  sec.append(
    h(
      "div",
      { class: "file-actions" },
      h("button", { class: "btn btn-small ioc-csv", type: "button", onclick: () => a.onExportIocs("csv") }, "Exporter CSV"),
      h("button", { class: "btn btn-small ioc-json", type: "button", onclick: () => a.onExportIocs("json") }, "JSON"),
      h("button", { class: "btn btn-small", type: "button", onclick: () => copy(iocs.map((i) => i.defanged).join("\n"), "Liste défangée") }, "Copier (défangés)"),
    ),
  );
  const kinds = [...new Set(iocs.map((i) => i.kind))];
  for (const k of kinds) {
    const items = iocs.filter((i) => i.kind === k);
    sec.append(
      h(
        "details",
        { class: "ioc-group", open: k !== "sha256" && k !== "md5" && items.length <= 8 },
        h("summary", {}, `${IOC_LABEL[k]} (${items.length})`),
        h("ul", {}, ...items.map((i) => h("li", { title: i.locations.join("\n") }, h("code", {}, i.defanged), h("span", { class: "ioc-loc" }, i.locations[0] ?? "")))),
      ),
    );
  }
  return sec;
}
