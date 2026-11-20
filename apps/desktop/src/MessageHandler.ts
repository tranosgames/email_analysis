// État de la session (même rôle que MessageHandler.js de msg-reader) :
// liste des preuves, sélection, épingles, message embarqué courant, en-têtes dépliés.

import type { BoxHash, FolderInfo, ItemSummary, OpenResult, StoreInfo, Summary } from "./ipc";

/** Boîte PST/OST ouverte : arborescence connue, lignes des dossiers chargées à la demande. */
export interface BoxState {
  boxId: number;
  path: string;
  store: StoreInfo;
  folders: FolderInfo[];
  hash: BoxHash | null;
  rows: Map<number, ItemSummary[]>;
}

/** Ce que montre le panneau de gauche. */
export type ListView = { kind: "files" } | { kind: "box"; boxId: number; folder: number | null };

export interface FailedEntry {
  path: string;
  error: string;
}

type Listener = () => void;

export class MessageHandler {
  readonly items: Summary[] = [];
  readonly failed: FailedEntry[] = [];
  readonly pinned = new Set<number>();
  readonly boxes: BoxState[] = [];
  view: ListView = { kind: "files" };
  /** Élément de boîte affiché (exclusif avec `selectedId`). */
  selectedBoxItem: { boxId: number; id: number } | null = null;
  selectedId: number | null = null;
  /** Indices de PJ menant au message embarqué affiché ([] = message racine). */
  path: number[] = [];
  /** FR-035 : replié par défaut, mémorisé pour toute la session. */
  headersOpen = false;
  lastNotice = "";
  private listeners: Listener[] = [];

  onChange(fn: Listener): void {
    this.listeners.push(fn);
  }

  private emit(): void {
    for (const fn of this.listeners) fn();
  }

  addResults(results: OpenResult[]): void {
    let added = 0;
    let boxes = 0;
    let dup = 0;
    for (const r of results) {
      if (r.kind === "ready") {
        this.items.push(r.summary);
        added++;
      } else if (r.kind === "mailbox") {
        this.boxes.push({ boxId: r.box_id, path: r.path, store: r.store, folders: r.folders, hash: null, rows: new Map() });
        boxes++;
      } else if (r.kind === "duplicate") dup++;
      else this.failed.push({ path: r.path, error: r.error });
    }
    const failed = results.filter((r) => r.kind === "failed").length;
    const parts = [`${added} message(s) ajouté(s)`];
    if (boxes) parts.push(`${boxes} boîte(s) Outlook`);
    if (dup) parts.push(`${dup} doublon(s) ignoré(s)`);
    if (failed) parts.push(`${failed} fichier(s) illisible(s)`);
    this.lastNotice = parts.join(", ");
    if (this.selectedId === null && this.selectedBoxItem === null && this.items.length) this.select(this.sorted()[0].id);
    else if (boxes && !added && this.view.kind === "files") this.openBox(this.boxes[this.boxes.length - 1].boxId);
    else this.emit();
  }

  /** Résumés recalculés (ré-analyse après import de clés) : même identifiants. */
  replaceItems(summaries: Summary[]): void {
    for (const s of summaries) {
      const i = this.items.findIndex((x) => x.id === s.id);
      if (i >= 0) this.items[i] = s;
    }
    this.emit();
  }

  /** Épinglés d'abord, puis du plus récent au plus ancien. */
  sorted(): Summary[] {
    return [...this.items].sort((a, b) => {
      const pa = this.pinned.has(a.id) ? 0 : 1;
      const pb = this.pinned.has(b.id) ? 0 : 1;
      if (pa !== pb) return pa - pb;
      return (b.date_utc ?? "").localeCompare(a.date_utc ?? "");
    });
  }

  select(id: number): void {
    this.selectedId = id;
    this.selectedBoxItem = null;
    this.path = [];
    this.emit();
  }

  // ——— Navigation dans une boîte ———

  box(boxId: number): BoxState | undefined {
    return this.boxes.find((b) => b.boxId === boxId);
  }

  openBox(boxId: number): void {
    this.view = { kind: "box", boxId, folder: null };
    this.emit();
  }

  openFolder(folder: number): void {
    if (this.view.kind !== "box") return;
    this.view = { ...this.view, folder };
    this.emit();
  }

  back(): void {
    if (this.view.kind === "box" && this.view.folder !== null) this.view = { ...this.view, folder: null };
    else this.view = { kind: "files" };
    this.emit();
  }

  setRows(boxId: number, folder: number, rows: ItemSummary[]): void {
    this.box(boxId)?.rows.set(folder, rows);
    this.emit();
  }

  selectBoxItem(boxId: number, id: number): void {
    this.selectedBoxItem = { boxId, id };
    this.selectedId = null;
    this.path = [];
    this.emit();
  }

  /** Après ouverture d'un élément : verdict et adresse reportés sur sa ligne. */
  markAnalyzed(boxId: number, id: number, verdict: ItemSummary["verdict"], fromAddress: string | null): void {
    const b = this.box(boxId);
    if (!b) return;
    let changed = false;
    for (const rows of b.rows.values()) {
      for (const r of rows) {
        if (r.id === id && (r.verdict !== verdict || r.from_address !== fromAddress)) {
          r.verdict = verdict;
          r.from_address = fromAddress;
          changed = true;
        }
      }
    }
    if (changed) this.emit();
  }

  setHash(h: BoxHash): void {
    const b = this.box(h.box_id);
    if (!b) return;
    const finished = !!h.sha256 && !b.hash?.sha256;
    b.hash = h;
    // La progression est affichée directement par l'interface ; on ne redessine qu'à la fin.
    if (finished) this.emit();
  }

  /** Nombre d'éléments ouverts (donc lus) dans une boîte. */
  analyzedCount(boxId: number): number {
    const b = this.box(boxId);
    if (!b) return 0;
    const seen = new Set<number>();
    for (const rows of b.rows.values()) for (const r of rows) if (r.verdict) seen.add(r.id);
    return seen.size;
  }

  move(delta: number): void {
    if (this.view.kind === "box" && this.view.folder !== null) {
      const rows = this.box(this.view.boxId)?.rows.get(this.view.folder) ?? [];
      if (!rows.length) return;
      const cur = this.selectedBoxItem;
      const i = cur ? rows.findIndex((r) => r.id === cur.id) : -1;
      const next = rows[Math.min(rows.length - 1, Math.max(0, i + delta))];
      this.selectBoxItem(this.view.boxId, next.id);
      return;
    }
    const list = this.sorted();
    if (!list.length) return;
    const i = list.findIndex((s) => s.id === this.selectedId);
    const next = list[Math.min(list.length - 1, Math.max(0, i + delta))];
    this.select(next.id);
  }

  togglePin(id: number | null = this.selectedId): void {
    if (id === null) return;
    if (this.pinned.has(id)) this.pinned.delete(id);
    else this.pinned.add(id);
    this.emit();
  }

  toggleHeaders(): void {
    this.headersOpen = !this.headersOpen;
    this.emit();
  }

  openEmbedded(attachmentIndex: number): void {
    this.path = [...this.path, attachmentIndex];
    this.emit();
  }

  goToDepth(depth: number): void {
    this.path = this.path.slice(0, depth);
    this.emit();
  }
}
