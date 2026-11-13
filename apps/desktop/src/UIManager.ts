// Rendu de la liste latérale et du panneau de lecture (rôle de UIManager.js dans msg-reader).

import { formatDate, h, humanSize, toast } from "./dom";
import {
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
  type Attachment,
  type IocGroup,
  type Message,
  type MessageView,
} from "./ipc";
import type { MessageHandler } from "./MessageHandler";
import { renderReading, type Crumb } from "./views/reading";

export class UIManager {
  private list = document.getElementById("message-list") as HTMLUListElement;
  private status = document.getElementById("list-status") as HTMLDivElement;
  private reading = document.getElementById("reading") as HTMLElement;
  private cache = new Map<number, MessageView>();
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
    this.list.replaceChildren(
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

  private async renderReading(): Promise<void> {
    const s = this.state;
    const token = ++this.renderToken;
    if (s.selectedId === null) {
      this.reading.replaceChildren(
        h(
          "div",
          { class: "empty-state" },
          h("h1", {}, "Déposez des fichiers .eml ou .msg"),
          h("p", {}, "Ou un dossier entier. Chaque fichier est haché puis lu en lecture seule ; rien n'est modifié ni envoyé sur le réseau."),
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
