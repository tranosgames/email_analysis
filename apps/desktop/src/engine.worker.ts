// Web Worker de la version web (feature 003, contracts/wasm-api.md) : le moteur Rust compilé en
// WebAssembly analyse les octets hors du fil principal. Rien n'est envoyé sur le réseau.
// Le worker conserve les octets de chaque preuve pour l'extraction des pièces jointes (FR-038).

import init, {
  analyze,
  box_close,
  box_extract,
  box_filter,
  box_iocs,
  box_forget,
  box_hash_step,
  box_item,
  box_list,
  box_open,
  box_report,
  engine_version, extract_attachment, import_key, iocs_export, list_keys, remove_key, report, safe_file_name } from "./wasm/mf_wasm.js";
import wasmUrl from "./wasm/mf_wasm_bg.wasm?url";

type Job =
  | { id: number; kind: "analyze"; name: string; bytes: ArrayBuffer }
  | { id: number; kind: "extract"; key: number; path: number[]; index: number; filename: string }
  | { id: number; kind: "release"; key: number }
  | { id: number; kind: "report"; key: number; path: number[]; format: string; generated: string }
  | { id: number; kind: "iocs"; json: string; format: string; defang: boolean }
  | { id: number; kind: "key-import"; name: string; bytes: ArrayBuffer }
  | { id: number; kind: "key-remove"; fingerprint: string }
  | { id: number; kind: "key-list" }
  | { id: number; kind: "reanalyze"; key: number }
  // Boîtes PST / OST (feature 002) : le `File` est transmis une fois, jamais copié en entier.
  | { id: number; kind: "box-open"; box: number; name: string; file: File }
  | { id: number; kind: "box-list"; box: number; folder: number }
  | { id: number; kind: "box-item"; box: number; item: number }
  | { id: number; kind: "box-filter"; box: number; filter: string }
  | { id: number; kind: "box-iocs"; box: number }
  | { id: number; kind: "box-report"; box: number; item: number; path: number[]; format: string; generated: string }
  | { id: number; kind: "box-extract"; box: number; item: number; path: number[]; index: number; filename: string }
  | { id: number; kind: "box-forget" }
  | { id: number; kind: "box-close"; box: number };

/** `FileReaderSync` n'existe que dans un Worker (absent des types DOM). */
declare const FileReaderSync: { new (): { readAsArrayBuffer(blob: Blob): ArrayBuffer } };

/** Lecteur par tranches d'un `File` pour le moteur (BlobReader côté Rust). */
function blobReader(file: File) {
  const fr = new FileReaderSync();
  return {
    size: file.size,
    read(offset: number, buf: Uint8Array): number {
      const part = new Uint8Array(fr.readAsArrayBuffer(file.slice(offset, offset + buf.length)));
      buf.set(part);
      return part.length;
    },
  };
}

const boxes = new Set<number>();

/** Empreinte de la boîte par pas de 8 Mo, entre deux messages : le Worker reste réactif. */
function hashLoop(box: number): void {
  let last = 0;
  const step = () => {
    if (!boxes.has(box)) return;
    try {
      const p = JSON.parse(box_hash_step(box, 8 * 1024 * 1024)) as { done: number; total: number; sha256: string | null; md5: string | null };
      const now = Date.now();
      if (p.sha256 || now - last >= 100) {
        last = now;
        scope.postMessage({ event: "box-hash", hash: { box_id: box, ...p } });
      }
      if (!p.sha256) setTimeout(step, 0);
    } catch (err) {
      scope.postMessage({ event: "box-hash-error", box, error: err instanceof Error ? err.message : String(err) });
    }
  };
  setTimeout(step, 0);
}

/** `self` d'un worker dédié (le tsconfig cible le DOM, pas WebWorker). */
const scope = self as unknown as { postMessage(message: unknown, transfer?: Transferable[]): void };

const evidence = new Map<number, { name: string; bytes: Uint8Array }>();

const ready = init({ module_or_path: wasmUrl }).then(() => {
  scope.postMessage({ ready: true, version: engine_version() });
});

self.onmessage = async (e: MessageEvent<Job>) => {
  const job = e.data;
  try {
    await ready;
    if (job.kind === "analyze") {
      const bytes = new Uint8Array(job.bytes);
      const view = JSON.parse(analyze(job.name, bytes));
      evidence.set(job.id, { name: job.name, bytes });
      scope.postMessage({ id: job.id, ok: true, view, key: job.id });
    } else if (job.kind === "extract") {
      const ev = evidence.get(job.key);
      if (!ev) throw new Error("preuve inconnue");
      const data = extract_attachment(ev.name, ev.bytes, new Uint32Array(job.path), job.index);
      const buf = data.buffer as ArrayBuffer;
      scope.postMessage({ id: job.id, ok: true, data: buf, name: safe_file_name(job.filename) }, [buf]);
    } else if (job.kind === "report") {
      const ev = evidence.get(job.key);
      if (!ev) throw new Error("preuve inconnue");
      const text = report(ev.name, ev.bytes, new Uint32Array(job.path), job.format, job.generated);
      scope.postMessage({ id: job.id, ok: true, text });
    } else if (job.kind === "key-import") {
      scope.postMessage({ id: job.id, ok: true, text: import_key(job.name, new Uint8Array(job.bytes)) });
    } else if (job.kind === "key-remove") {
      remove_key(job.fingerprint);
      scope.postMessage({ id: job.id, ok: true });
    } else if (job.kind === "key-list") {
      scope.postMessage({ id: job.id, ok: true, text: list_keys() });
    } else if (job.kind === "reanalyze") {
      // FR-049 : nouvelle analyse des mêmes octets, avec le trousseau à jour.
      const ev = evidence.get(job.key);
      if (!ev) throw new Error("preuve inconnue");
      scope.postMessage({ id: job.id, ok: true, view: JSON.parse(analyze(ev.name, ev.bytes)) });
    } else if (job.kind === "box-open") {
      const opened = JSON.parse(box_open(job.box, job.name, blobReader(job.file)));
      boxes.add(job.box);
      hashLoop(job.box);
      scope.postMessage({ id: job.id, ok: true, json: opened });
    } else if (job.kind === "box-list") {
      scope.postMessage({ id: job.id, ok: true, json: JSON.parse(box_list(job.box, job.folder)) });
    } else if (job.kind === "box-filter") {
      scope.postMessage({ id: job.id, ok: true, json: JSON.parse(box_filter(job.box, job.filter)) });
    } else if (job.kind === "box-iocs") {
      scope.postMessage({ id: job.id, ok: true, json: JSON.parse(box_iocs(job.box)) });
    } else if (job.kind === "box-item") {
      scope.postMessage({ id: job.id, ok: true, view: JSON.parse(box_item(job.box, job.item)) });
    } else if (job.kind === "box-report") {
      scope.postMessage({ id: job.id, ok: true, text: box_report(job.box, job.item, new Uint32Array(job.path), job.format, job.generated) });
    } else if (job.kind === "box-extract") {
      const data = box_extract(job.box, job.item, new Uint32Array(job.path), job.index);
      const buf = data.buffer as ArrayBuffer;
      scope.postMessage({ id: job.id, ok: true, data: buf, name: safe_file_name(job.filename) }, [buf]);
    } else if (job.kind === "box-forget") {
      for (const b of boxes) box_forget(b);
      scope.postMessage({ id: job.id, ok: true });
    } else if (job.kind === "box-close") {
      boxes.delete(job.box);
      box_close(job.box);
      scope.postMessage({ id: job.id, ok: true });
    } else if (job.kind === "iocs") {
      scope.postMessage({ id: job.id, ok: true, text: iocs_export(job.json, job.format, job.defang) });
    } else {
      evidence.delete(job.key);
      scope.postMessage({ id: job.id, ok: true });
    }
  } catch (err) {
    scope.postMessage({ id: job.id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};
