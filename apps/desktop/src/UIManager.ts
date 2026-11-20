// Rendu de la liste latérale et du panneau de lecture (rôle de UIManager.js dans msg-reader).

import { formatDate, h, humanSize, toast } from "./dom";
import {
  boxItem,
  boxList,
  boxReport,
  boxSaveAttachment,
  buildReport,
  confirmBox,
  exportIocs,
  getMessage,
  saveAttachment,
  saveText,
  VERDICT_LABEL,
  clearKeys,
  importKeyFiles,
  listKeys,
  openVerificationLink,
  reanalyzeAll,
  removeKey,
  type KeyEntry,
  type FolderInfo,
  type ItemSummary,
  type BoxHash,
  type Attachment,
  type IocGroup,
  type Message,
  type MessageView,
} from "./ipc";
import type { BoxState, MessageHandler } from "./MessageHandler";
import { renderReading, type Crumb } from "./views/reading";

/** Hauteur fixe d'une ligne de la liste virtualisée (px), alignée sur `.box-row`. */
const ROW = 76;

const FOLDER_ICON: Partial<Record<FolderInfo["kind"], string>> = {
  inbox: "📥",
  sent: "📤",
  deleted: "🗑",
  drafts: "📝",
  outbox: "📮",
  junk: "⚠",
  search: "🔎",
  system: "⚙",
};

/** Icône d'un dossier non courriel, d'après sa classe (IPF.Contact…). */
function classIcon(c: string | null): string {
  const k = (c ?? "").toLowerCase();
  if (k.startsWith("ipf.contact")) return "👤";
  if (k.startsWith("ipf.appointment")) return "📅";
  if (k.startsWith("ipf.task")) return "✅";
  if (k.startsWith("ipf.stickynote")) return "🗒";
  if (k.startsWith("ipf.journal")) return "📓";
  return "📁";
}

export class UIManager {
  private list = document.getElementById("message-list") as HTMLUListElement;
  private status = document.getElementById("list-status") as HTMLDivElement;
  private reading = document.getElementById("reading") as HTMLElement;
  private cache = new Map<number, MessageView>();
  /** Éléments de boîte déjà ouverts : clé `boîte:nœud`. */
  private boxCache = new Map<string, MessageView>();
  /** Liste virtualisée : seules les lignes visibles sont construites. */
  private onListScroll: (() => void) | null = null;
  /** Dossier affiché dans la liste (garde le défilement entre deux rendus). */
  private listKey = "";
  private listSel = "";
  /** Dossiers repliés de l'arborescence : clé `boîte:dossier`. */
  private collapsed = new Set<string>();
  private renderToken = 0;
  private lastKey = "";

  constructor(private state: MessageHandler) {
    state.onChange(() => void this.render());
  }

  async render(): Promise<void> {
    this.renderList();
    await this.renderReading();
  }

  private renderList(): void {
    const s = this.state;
    this.status.textContent = s.lastNotice;
    if (this.onListScroll) {
      this.list.removeEventListener("scroll", this.onListScroll);
      this.onListScroll = null;
    }
    this.list.classList.toggle("in-box", s.view.kind === "box");
    if (s.view.kind === "box") {
      const b = s.box(s.view.boxId);
      if (b) return this.renderBox(b, s.view.folder);
    }
    this.list.replaceChildren(
      ...s.boxes.map((b) =>
        h(
          "li",
          { class: "message-item box-entry", role: "option", "aria-selected": "false", tabindex: "-1", onclick: () => s.openBox(b.boxId) },
          h("span", { class: "from" }, `📦 ${b.store.name}`),
          h("span", { class: "date" }, b.store.format === "ost4k" ? "OST" : b.store.format === "ansi" ? "PST ANSI" : "PST"),
          h("span", { class: "subject" }, `${b.store.folders} dossiers · ${b.store.items} éléments`),
          h("span", { class: "badges" }, h("span", {}, humanSize(b.store.size)), b.hash?.sha256 ? h("span", {}, "empreinte ✓") : h("span", {}, "empreinte en cours")),
        ),
      ),
      ...s.sorted().map((m) => {
        const selected = m.id === s.selectedId;
        const pinned = s.pinned.has(m.id);
        return h(
          "li",
          {
            class: "message-item",
            role: "option",
            "aria-selected": String(selected),
            tabindex: selected ? "0" : "-1",
            onclick: () => s.select(m.id),
          },
          h("span", { class: "from" }, m.from ?? m.file_name),
          h("span", { class: "date" }, formatDate(m.date_utc)),
          h("span", { class: "subject" }, m.subject?.trim() || "(sans objet)"),
          h(
            "span",
            { class: "badges" },
            h(
              "button",
              {
                class: "pin",
                type: "button",
                "aria-pressed": String(pinned),
                "aria-label": pinned ? "Désépingler" : "Épingler",
                title: "Épingler (P)",
                onclick: (e: Event) => {
                  e.stopPropagation();
                  s.togglePin(m.id);
                },
              },
              pinned ? "★" : "☆",
            ),
            m.verdict ? h("span", { class: `verdict-pill v-${m.verdict}`, title: "Verdict automatique" }, VERDICT_LABEL[m.verdict]) : null,
            h("span", {}, m.format.toUpperCase()),
            m.attachments ? h("span", {}, `${m.attachments} fichier(s)`) : null,
            m.urls ? h("span", {}, `${m.urls} URL`) : null,
            m.issues ? h("span", {}, `${m.issues} avertissement(s)`) : null,
          ),
        );
      }),
      ...s.failed.map((f) =>
        h(
          "li",
          { class: "message-item failed" },
          h("span", { class: "from" }, f.path.split(/[\\/]/).pop() ?? f.path),
          h("span", { class: "subject" }, `Illisible : ${f.error}`),
        ),
      ),
    );
  }

  // ——— Boîtes PST / OST (feature 002) ———

  /** Progression de l'empreinte, mise à jour sans redessiner la liste. */
  showBoxHash(hp: BoxHash): void {
    const v = this.state.view;
    if (v.kind !== "box" || v.boxId !== hp.box_id || hp.sha256) return;
    const el = this.list.querySelector<HTMLElement>(".box-hash");
    if (el) el.textContent = `Empreinte : ${hp.total ? Math.floor((hp.done / hp.total) * 100) : 0} %`;
  }

  private boxHead(b: BoxState, folder: FolderInfo | null): HTMLElement {
    const s = this.state;
    const pct = b.hash && b.hash.total ? Math.floor((b.hash.done / b.hash.total) * 100) : 0;
    const read = s.analyzedCount(b.boxId);
    return h(
      "li",
      { class: "box-head" },
      h(
        "div",
        { class: "box-nav" },
        h("button", { class: "btn btn-small box-back", type: "button", onclick: () => s.back() }, folder ? "‹ Dossiers" : "‹ Fichiers"),
        h("strong", { class: "box-title", title: b.path }, folder ? folder.name || "Boîte" : b.store.display_name || b.store.name),
      ),
      h(
        "div",
        { class: "box-meta" },
        `${b.store.name} · ${b.store.format === "ost4k" ? "OST 2013+" : b.store.format === "ansi" ? "PST ANSI" : "PST"} · ${humanSize(b.store.size)}`,
        b.store.password_protected ? " · protégé par mot de passe" : "",
      ),
      h(
        "div",
        { class: "box-meta box-hash", title: b.hash?.sha256 ? `SHA-256 ${b.hash.sha256}\nMD5 ${b.hash.md5 ?? ""}` : "Calcul de l'empreinte de la boîte" },
        b.hash?.sha256 ? `SHA-256 ${b.hash.sha256.slice(0, 16)}…` : `Empreinte : ${pct} %`,
      ),
      h("div", { class: "box-meta box-read" }, `${read} élément(s) lu(s) sur ${b.store.items} — seuls les éléments ouverts sont lus`),
      b.store.unreadable.length
        ? h(
            "details",
            { class: "box-meta bad" },
            h("summary", {}, `${b.store.unreadable.length} élément(s) illisible(s)`),
            h(
              "ul",
              { class: "box-unreadable" },
              ...b.store.unreadable.map((u) => h("li", {}, `${u.folder_path.join(" › ") || "(racine)"} — ${u.kind} #${u.node_id} : ${u.reason}`)),
            ),
          )
        : null,
    );
  }

  private renderBox(b: BoxState, folderId: number | null): void {
    const folder = folderId === null ? null : (b.folders.find((f) => f.id === folderId) ?? null);
    if (!folder) {
      this.listKey = "";
      const byId = new Map(b.folders.map((f) => [f.id, f]));
      const parents = new Set(b.folders.map((f) => f.parent));
      const hidden = (f: FolderInfo): boolean => {
        for (let p = byId.get(f.parent ?? -1), n = 0; p && n < 64; p = byId.get(p.parent ?? -1), n++) {
          if (this.collapsed.has(`${b.boxId}:${p.id}`)) return true;
        }
        return false;
      };
      const visible = b.folders.filter((f) => f.kind !== "root" && f.kind !== "ipm" && !hidden(f));
      const toggle = (e: Event, f: FolderInfo) => {
        e.stopPropagation();
        const k = `${b.boxId}:${f.id}`;
        if (!this.collapsed.delete(k)) this.collapsed.add(k);
        const top = this.list.scrollTop;
        this.renderList();
        this.list.scrollTop = top;
      };
      this.list.replaceChildren(
        this.boxHead(b, null),
        ...visible.map((f) =>
          h(
            "li",
            {
              class: `folder-row kind-${f.kind}`,
              role: "option",
              "aria-selected": "false",
              tabindex: "-1",
              style: `padding-left: ${8 + Math.max(0, f.depth - 1) * 14}px`,
              title: f.path.join(" › "),
              onclick: () => void this.openFolder(b.boxId, f.id),
            },
            parents.has(f.id)
              ? h(
                  "button",
                  {
                    class: "folder-caret",
                    type: "button",
                    "aria-expanded": String(!this.collapsed.has(`${b.boxId}:${f.id}`)),
                    title: this.collapsed.has(`${b.boxId}:${f.id}`) ? "Déplier" : "Replier",
                    onclick: (e: Event) => toggle(e, f),
                  },
                  this.collapsed.has(`${b.boxId}:${f.id}`) ? "▸" : "▾",
                )
              : h("span", { class: "folder-caret", "aria-hidden": "true" }),
            h("span", { class: "folder-icon", "aria-hidden": "true" }, FOLDER_ICON[f.kind] ?? classIcon(f.container_class)),
            h("span", { class: "folder-name" }, f.name || "(sans nom)"),
            f.item_count ? h("span", { class: "folder-count" }, String(f.item_count)) : null,
          ),
        ),
      );
      return;
    }
    const rows = b.rows.get(folder.id);
    if (!rows) {
      this.list.replaceChildren(this.boxHead(b, folder), h("li", { class: "box-meta" }, "Lecture de la table du dossier…"));
      return;
    }
    if (!rows.length) {
      this.list.replaceChildren(this.boxHead(b, folder), h("li", { class: "box-meta none" }, "Dossier vide."));
      return;
    }
    // Liste virtualisée : lignes de hauteur fixe, seules celles visibles sont construites.
    const viewKey = `${b.boxId}:${folder.id}`;
    const keep = viewKey === this.listKey ? this.list.scrollTop : 0;
    this.listKey = viewKey;
    const head = this.boxHead(b, folder);
    const top = h("li", { class: "v-spacer", "aria-hidden": "true" });
    const bottom = h("li", { class: "v-spacer", "aria-hidden": "true" });
    bottom.style.height = `${rows.length * ROW}px`;
    this.list.replaceChildren(head, top, bottom);
    this.list.scrollTop = keep;
    // Sélection au clavier : la ligne choisie reste visible.
    const sel = this.state.selectedBoxItem;
    const idx = sel && sel.boxId === b.boxId ? rows.findIndex((r) => r.id === sel.id) : -1;
    const selKey = idx >= 0 ? `${viewKey}:${rows[idx].id}` : "";
    const moved = selKey !== this.listSel;
    this.listSel = selKey;
    if (idx >= 0 && moved) {
      const y = head.offsetHeight + idx * ROW;
      const view = this.list.clientHeight || 800;
      if (y < this.list.scrollTop + head.offsetHeight) this.list.scrollTop = Math.max(0, y - head.offsetHeight);
      else if (y + ROW > this.list.scrollTop + view) this.list.scrollTop = y + ROW - view;
    }
    let first = -1;
    let last = -1;
    const paint = () => {
      const headH = head.offsetHeight;
      const y = Math.max(0, this.list.scrollTop - headH);
      const view = this.list.clientHeight || 800;
      const a = Math.max(0, Math.floor(y / ROW) - 10);
      const z = Math.min(rows.length, Math.ceil((y + view) / ROW) + 10);
      if (a === first && z === last) return;
      first = a;
      last = z;
      top.style.height = `${a * ROW}px`;
      bottom.style.height = `${(rows.length - z) * ROW}px`;
      while (top.nextSibling && top.nextSibling !== bottom) top.nextSibling.remove();
      const frag = document.createDocumentFragment();
      for (let i = a; i < z; i++) frag.append(this.itemRow(b.boxId, rows[i]));
      bottom.before(frag);
    };
    paint();
    this.onListScroll = paint;
    this.list.addEventListener("scroll", paint, { passive: true });
  }

  private itemRow(boxId: number, r: ItemSummary): HTMLElement {
    const s = this.state;
    const selected = s.selectedBoxItem?.boxId === boxId && s.selectedBoxItem.id === r.id;
    const kind = r.message_class && !/^IPM\.Note/i.test(r.message_class) ? r.message_class.replace(/^IPM\./i, "") : null;
    return h(
      "li",
      {
        class: "message-item box-row",
        role: "option",
        "aria-selected": String(selected),
        tabindex: selected ? "0" : "-1",
        "data-id": String(r.id),
        onclick: () => s.selectBoxItem(boxId, r.id),
      },
      h("span", { class: "from" }, r.from_address ?? r.from_name ?? "—"),
      h("span", { class: "date" }, formatDate(r.received ?? r.sent)),
      h("span", { class: "subject" }, r.subject?.trim() || "(sans objet)"),
      h(
        "span",
        { class: "badges" },
        r.verdict ? h("span", { class: `verdict-pill v-${r.verdict}`, title: "Verdict de l'élément ouvert" }, VERDICT_LABEL[r.verdict]) : null,
        kind ? h("span", {}, kind) : null,
        r.has_attachments ? h("span", {}, "📎 pièce(s) jointe(s)") : null,
        r.size ? h("span", {}, humanSize(r.size)) : null,
      ),
    );
  }

  private async openFolder(boxId: number, folder: number): Promise<void> {
    const s = this.state;
    s.openFolder(folder);
    const b = s.box(boxId);
    if (!b || b.rows.has(folder)) return;
    try {
      const rows = await boxList(boxId, folder);
      rows.sort((x, y) => (y.received ?? y.sent ?? "").localeCompare(x.received ?? x.sent ?? ""));
      s.setRows(boxId, folder, rows);
      this.list.scrollTop = 0;
    } catch (e) {
      toast(`Dossier illisible : ${e instanceof Error ? e.message : String(e)}`);
      s.setRows(boxId, folder, []);
    }
  }

  private async renderBoxItem(boxId: number, id: number): Promise<void> {
    const s = this.state;
    const token = ++this.renderToken;
    const key = `${boxId}:${id}`;
    let root = this.boxCache.get(key);
    if (!root) {
      this.reading.replaceChildren(h("p", { class: "empty-state" }, "Lecture et analyse de l'élément…"));
      try {
        root = await boxItem(boxId, id);
      } catch (e) {
        if (token === this.renderToken) this.reading.replaceChildren(h("p", { class: "empty-state" }, `Ouverture impossible : ${String(e)}`));
        return;
      }
      this.boxCache.set(key, root);
      s.markAnalyzed(boxId, id, root.message.verdict?.level ?? null, root.message.from[0]?.address ?? null);
    }
    if (token !== this.renderToken) return;
    const b = s.box(boxId);
    const prov = root.message.provenance;
    const crumbs: Crumb[] = [{ label: b?.store.name ?? "boîte" }, ...(prov?.folder_path ?? []).map((label) => ({ label })), { label: `élément #${id}` }];
    let message: Message = root.message;
    for (const idx of s.path) {
      const att = message.attachments.find((a) => a.index === idx);
      if (!att?.embedded) break;
      crumbs.push({ label: `PJ ${idx} : ${att.filename}` });
      message = att.embedded;
    }
    const sameKey = `box:${key}:${s.path.join("/")}`;
    const same = sameKey === this.lastKey;
    const scrolls = [this.reading, ...this.reading.querySelectorAll<HTMLElement>(".reading-main, .inventory")].map((el) => (same ? el.scrollTop : 0));
    this.lastKey = sameKey;
    const view = root;
    // L'empreinte de la boîte arrive après coup : on l'affiche dès qu'elle est connue.
    const evidence = { ...view.evidence, sha256: view.evidence.sha256 || b?.hash?.sha256 || "", md5: view.evidence.md5 || b?.hash?.md5 || "" };
    this.reading.replaceChildren(
      renderReading({ evidence, message }, crumbs, {
        headersOpen: s.headersOpen,
        path: s.path,
        onToggleHeaders: () => s.toggleHeaders(),
        onOpenEmbedded: (i) => s.openEmbedded(i),
        onDownload: (att) => void this.downloadFromBox(boxId, id, [...s.path], att, crumbs),
        onReport: (format) => void this.boxReport(boxId, id, [...s.path], format, b?.store.name ?? "boite"),
        onExportIocs: (format) => void this.exportIocs([{ source: crumbs.map((c) => c.label).join(" › "), iocs: message.iocs }], format, null),
        onGoToDepth: (d) => s.goToDepth(d),
        onImportKeys: () => void this.importKeys(),
        onExternalLink: (l) => void openVerificationLink(l),
        onSaveCert: (pem, name) => void saveText(pem, name, "application/x-pem-file").then((n) => n && toast(`Certificat enregistré : ${n}`)),
      }),
    );
    [this.reading, ...this.reading.querySelectorAll<HTMLElement>(".reading-main, .inventory")].forEach((el, i) => (el.scrollTop = scrolls[i] ?? 0));
  }

  private async boxReport(boxId: number, id: number, path: number[], format: "html" | "json", name: string): Promise<void> {
    try {
      toast("Rapport : calcul de l'empreinte de la boîte si nécessaire…");
      const text = await boxReport(boxId, id, path, format);
      const base = name.replace(/\.[^.]+$/, "").replace(/[^\p{L}\p{N}_-]+/gu, "_").slice(0, 40);
      const saved = await saveText(text, `rapport_${base}_${id}${path.length ? `_pj${path.join("-")}` : ""}.${format}`, format === "html" ? "text/html" : "application/json");
      if (saved) toast(`Rapport enregistré : ${saved}`);
    } catch (e) {
      toast(`Rapport impossible : ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async downloadFromBox(boxId: number, id: number, path: number[], att: Attachment, crumbs: Crumb[]): Promise<void> {
    const ok = await confirmBox(
      [
        `Fichier : ${att.filename}`,
        `Type déclaré : ${att.declared_mime ?? "non déclaré"}`,
        `Taille : ${humanSize(att.size)}`,
        `SHA-256 : ${att.sha256}`,
        `Provenance : ${crumbs.map((c) => c.label).join(" › ")} › PJ ${att.index}`,
        "",
        "Ce fichier provient d'un courriel suspect et peut être malveillant. Ne l'ouvrez que dans un environnement d'analyse isolé.",
      ].join("\n"),
      "Télécharger cette pièce jointe ?",
    );
    if (!ok) return;
    try {
      const saved = await boxSaveAttachment(boxId, id, path, att);
      if (saved) toast(`Enregistré : ${saved}`);
    } catch (e) {
      toast(`Téléchargement impossible : ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async renderReading(): Promise<void> {
    const s = this.state;
    if (s.selectedBoxItem) return this.renderBoxItem(s.selectedBoxItem.boxId, s.selectedBoxItem.id);
    const token = ++this.renderToken;
    if (s.selectedId === null) {
      this.reading.replaceChildren(
        h(
          "div",
          { class: "empty-state" },
          h("h1", {}, "Déposez des fichiers .eml, .msg, ou une boîte .pst / .ost"),
          h("p", {}, "Ou un dossier entier. Chaque fichier est haché puis lu en lecture seule ; rien n'est modifié ni envoyé sur le réseau. Dans une boîte Outlook, seuls les messages que vous ouvrez sont lus."),
        ),
      );
      return;
    }
    let root = this.cache.get(s.selectedId);
    if (!root) {
      try {
        root = await getMessage(s.selectedId, []);
      } catch (e) {
        this.reading.replaceChildren(h("p", { class: "empty-state" }, `Ouverture impossible : ${String(e)}`));
        return;
      }
      this.cache.set(s.selectedId, root);
    }
    if (token !== this.renderToken) return; // une sélection plus récente a pris la main

    // Descente dans les messages embarqués (déjà présents dans la vue racine).
    const crumbs: Crumb[] = [{ label: root.evidence.path.split(/[\\/]/).pop() ?? "preuve" }];
    let message: Message = root.message;
    for (const idx of s.path) {
      const att = message.attachments.find((a) => a.index === idx);
      if (!att?.embedded) break;
      crumbs.push({ label: `PJ ${idx} : ${att.filename}` });
      message = att.embedded;
    }

    // Garder la position de lecture quand on déplie les en-têtes, pas en changeant de message.
    const key = `${s.selectedId}:${s.path.join("/")}`;
    // Trois zones défilent : le panneau (écran étroit), le corps du message et le panneau de droite.
    const same = key === this.lastKey;
    const scrolls = [this.reading, ...this.reading.querySelectorAll<HTMLElement>(".reading-main, .inventory")].map((el) => (same ? el.scrollTop : 0));
    this.lastKey = key;
    this.reading.replaceChildren(
      renderReading({ evidence: root.evidence, message }, crumbs, {
        headersOpen: s.headersOpen,
        path: s.path,
        onToggleHeaders: () => s.toggleHeaders(),
        onOpenEmbedded: (i) => s.openEmbedded(i),
        onDownload: (att) => void this.download(root.evidence.path, s.selectedId, [...s.path], att),
        onReport: (format) => void this.report(root, s.selectedId, [...s.path], format),
        onExportIocs: (format) => void this.exportIocs([{ source: this.source(root, s.path), iocs: message.iocs }], format, root),
        onGoToDepth: (d) => s.goToDepth(d),
        onImportKeys: () => void this.importKeys(),
        onExternalLink: (l) => void openVerificationLink(l),
        onSaveCert: (pem, name) => void saveText(pem, name, "application/x-pem-file").then((n) => n && toast(`Certificat enregistré : ${n}`)),
      }),
    );
    [this.reading, ...this.reading.querySelectorAll<HTMLElement>(".reading-main, .inventory")].forEach((el, i) => (el.scrollTop = scrolls[i] ?? 0));
  }

  private source(root: MessageView, path: number[]): string {
    const file = root.evidence.path.split(/[\\/]/).pop() ?? root.evidence.path;
    return path.length ? `${file} › PJ ${path.join(" › PJ ")}` : file;
  }

  private base(root: MessageView): string {
    const file = root.evidence.path.split(/[\\/]/).pop() ?? "message";
    return file.replace(/\.[^.]+$/, "").replace(/[^\p{L}\p{N}_-]+/gu, "_").slice(0, 60) || "message";
  }

  /** FR-044 : rapport d'analyse du message affiché, téléchargé ou enregistré. */
  private async report(root: MessageView, id: number | null, path: number[], format: "html" | "json"): Promise<void> {
    if (id === null) return;
    try {
      const text = await buildReport(id, path, format);
      const name = `rapport_${this.base(root)}${path.length ? `_pj${path.join("-")}` : ""}.${format}`;
      const saved = await saveText(text, name, format === "html" ? "text/html" : "application/json");
      if (saved) toast(`Rapport enregistré : ${saved}`);
    } catch (e) {
      toast(`Rapport impossible : ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async exportIocs(groups: IocGroup[], format: "csv" | "json", root: MessageView | null): Promise<void> {
    try {
      const text = await exportIocs(groups, format, false);
      const name = `indicateurs_${root ? this.base(root) : "tous"}.${format}`;
      const saved = await saveText(text, name, format === "csv" ? "text/csv" : "application/json");
      if (saved) toast(`Indicateurs enregistrés : ${saved}`);
    } catch (e) {
      toast(`Export impossible : ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** FR-044 : indicateurs de tous les messages chargés (messages joints compris), fusionnés. */
  async exportAllIocs(format: "csv" | "json"): Promise<void> {
    const groups: IocGroup[] = [];
    const walk = (root: MessageView, m: Message, path: number[]) => {
      if (m.iocs.length) groups.push({ source: this.source(root, path), iocs: m.iocs });
      for (const a of m.attachments) if (a.embedded) walk(root, a.embedded, [...path, a.index]);
    };
    for (const item of this.state.items) {
      let view = this.cache.get(item.id);
      if (!view) {
        view = await getMessage(item.id, []);
        this.cache.set(item.id, view);
      }
      walk(view, view.message, []);
    }
    if (!groups.length) {
      toast("Aucun indicateur dans les messages chargés");
      return;
    }
    await this.exportIocs(groups, format, null);
  }

  /** FR-038 : boîte de confirmation, puis enregistrement de la pièce jointe. */
  // ——— Trousseau (FR-049 à FR-051) ———

  /** Sélection de fichiers de clés (même code bureau et web : les octets sont lus ici). */
  private pickKeyFiles(): Promise<File[]> {
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      input.multiple = true;
      input.accept = ".asc,.gpg,.pgp,.pem,.cer,.crt,.der,.key";
      input.addEventListener("change", () => resolve([...(input.files ?? [])]));
      input.addEventListener("cancel", () => resolve([]));
      input.click();
    });
  }

  async importKeys(files?: File[]): Promise<void> {
    const picked = files ?? (await this.pickKeyFiles());
    if (!picked.length) return;
    const { added, errors } = await importKeyFiles(picked);
    if (errors.length) toast(errors.join(" — "));
    if (added.length) {
      toast(`${added.length} clé(s) ou certificat(s) importé(s) : nouvelle analyse…`);
      await this.reanalyze();
    }
    if (this.keyDialog?.open) await this.fillKeyDialog();
  }

  /** Nouvelle analyse de toutes les preuves avec le trousseau à jour. */
  async reanalyze(): Promise<void> {
    const summaries = await reanalyzeAll();
    this.cache.clear();
    this.boxCache.clear();
    this.lastKey = "";
    this.state.replaceItems(summaries);
    this.updateKeyButton();
  }

  private keyDialog: HTMLDialogElement | null = null;
  keyButton: HTMLButtonElement | null = null;

  async updateKeyButton(): Promise<void> {
    if (!this.keyButton) return;
    const n = (await listKeys()).length;
    this.keyButton.textContent = n ? `Clés et certificats (${n})` : "Clés et certificats";
  }

  async openKeyDialog(): Promise<void> {
    if (!this.keyDialog) {
      this.keyDialog = h("dialog", { class: "key-dialog", "aria-label": "Clés et certificats" }) as HTMLDialogElement;
      document.body.append(this.keyDialog);
    }
    await this.fillKeyDialog();
    this.keyDialog.showModal();
  }

  private async fillKeyDialog(): Promise<void> {
    const d = this.keyDialog;
    if (!d) return;
    const keys: KeyEntry[] = await listKeys();
    const close = () => d.close();
    d.replaceChildren(
      h("h2", {}, "Clés et certificats"),
      h(
        "p",
        { class: "muted-label" },
        "Clés publiques PGP (.asc, .gpg) et certificats X.509 (.pem, .cer, .crt) utilisés pour vérifier les signatures. Ils restent sur ce poste et ne sont jamais envoyés.",
      ),
      keys.length
        ? h(
            "ul",
            { class: "key-list" },
            ...keys.map((k) =>
              h(
                "li",
                {},
                h("span", { class: "key-kind" }, k.kind === "pgp" ? "PGP" : "X.509"),
                h("div", {}, h("div", { class: "key-label" }, k.label), h("div", { class: "fp" }, k.fingerprint.replace(/(.{4})/g, "$1 ").trim()), h("div", { class: "muted-label" }, k.source)),
                h(
                  "button",
                  {
                    class: "btn btn-small",
                    type: "button",
                    onclick: async () => {
                      await removeKey(k.fingerprint);
                      await this.reanalyze();
                      await this.fillKeyDialog();
                    },
                  },
                  "Retirer",
                ),
              ),
            ),
          )
        : h("p", { class: "none" }, "Aucune clé importée."),
      h(
        "div",
        { class: "file-actions" },
        h("button", { class: "btn key-import", type: "button", onclick: () => void this.importKeys() }, "Importer…"),
        keys.length
          ? h(
              "button",
              {
                class: "btn",
                type: "button",
                onclick: async () => {
                  await clearKeys();
                  await this.reanalyze();
                  await this.fillKeyDialog();
                },
              },
              "Tout effacer",
            )
          : null,
        h("span", { class: "spacer" }),
        h("button", { class: "btn key-close", type: "button", onclick: close }, "Fermer"),
      ),
    );
  }

  private async download(evidencePath: string, id: number | null, path: number[], att: Attachment): Promise<void> {
    if (id === null) return;
    const source = evidencePath.split(/[\\/]/).pop() ?? evidencePath;
    const ok = await confirmBox(
      [
        `Fichier : ${att.filename}`,
        `Type déclaré : ${att.declared_mime ?? "non déclaré"}`,
        `Taille : ${humanSize(att.size)}`,
        `SHA-256 : ${att.sha256}`,
        `Provenance : ${source}${path.length ? ` › PJ ${path.join(" › PJ ")}` : ""} › PJ ${att.index}`,
        "",
        "Ce fichier provient d'un courriel suspect et peut être malveillant. Ne l'ouvrez que dans un environnement d'analyse isolé.",
      ].join("\n"),
      "Télécharger cette pièce jointe ?",
    );
    if (!ok) return;
    try {
      const saved = await saveAttachment(id, path, att);
      if (saved) toast(`Enregistré : ${saved}`);
    } catch (e) {
      toast(`Téléchargement impossible : ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}
