// Web Worker de la version web (feature 003, contracts/wasm-api.md) : le moteur Rust compilé en
// WebAssembly analyse les octets hors du fil principal. Rien n'est envoyé sur le réseau.
// Le worker conserve les octets de chaque preuve pour l'extraction des pièces jointes (FR-038).

import init, {
  analyze,
  box_close,
  box_export,
  box_extract,
  box_filter,
  box_iocs,
  box_forget,
  box_hash_feed,
  box_item,
  box_list,
  box_open,
  box_report,
  engine_memory_bytes,
  FreshHasher,
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
  | { id: number; kind: "box-export"; box: number; ids: number[]; format: string; generated: string }
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
/** Fin du calcul d'empreinte en flux, par boîte (un rapport l'attend au lieu de relire le fichier). */
const hashing = new Map<number, Promise<void>>();
/** Fichier de chaque boîte, pour la revérification de son empreinte avant un export. */
const boxFiles = new Map<number, File>();

/**
 * Empreinte recalculée en flux, dans un tampon réutilisé, indépendamment de la session : sert à
 * vérifier, juste avant un export, que la boîte n'a pas changé depuis son ouverture.
 */
async function freshHash(file: File): Promise<[string, string]> {
  const CHUNK = 4 * 1024 * 1024;
  const h = new FreshHasher(file.size);
  try {
    let buffer: ArrayBuffer = new ArrayBuffer(CHUNK);
    const stream = file.stream();
    let byob: ReadableStreamBYOBReader | null = null;
    try {
      byob = stream.getReader({ mode: "byob" });
    } catch {
      byob = null;
    }
    const reader = byob ?? stream.getReader();
    let pos = 0;
    let result: string[] | undefined = file.size === 0 ? (h.feed(0, new Uint8Array(0)) as string[] | undefined) : undefined;
    while (!result) {
      const r = byob ? await byob.read(new Uint8Array(buffer, 0, CHUNK)) : await (reader as ReadableStreamDefaultReader<Uint8Array>).read();
      if (r.done || !r.value) break;
      const chunk = r.value as Uint8Array;
      result = h.feed(pos, chunk) as string[] | undefined;
      if (byob) buffer = chunk.buffer as ArrayBuffer;
      pos += chunk.byteLength;
      await yieldToMessages();
    }
    await reader.cancel().catch(() => undefined);
    if (!result) throw new Error("le fichier a changé pendant la revérification de son empreinte");
    return [result[0], result[1]];
  } finally {
    h.free();
  }
}
// Mesure de la mémoire du moteur (tests de performance) : lecture seule, sans effet.
(self as unknown as { mfEngineMemory: () => number }).mfEngineMemory = () => engine_memory_bytes();

type Progress = { done: number; total: number; sha256: string | null; md5: string | null };

/**
 * Rend la main aux autres messages du Worker (recherche, ouverture d'un élément) : les lectures du
 * flux se résolvent sans passer par la file des messages, une boucle de lecture les affamerait.
 * Un message posté sur un canal passe par cette file, sans le délai minimal de `setTimeout`.
 */
const yieldChannel = new MessageChannel();
function yieldToMessages(): Promise<void> {
  return new Promise((resolve) => {
    yieldChannel.port1.onmessage = () => resolve();
    yieldChannel.port2.postMessage(0);
  });
}

/**
 * Empreinte de la boîte en flux, dans un seul tampon de 4 Mo réutilisé (lecteur « BYOB ») : aucune
 * allocation par pas, donc pas de mémoire qui s'accumule sur un fichier de plusieurs Go (SC-004).
 * Chaque `await` rend la main : le Worker répond aux autres demandes pendant le calcul. Si un
 * rapport a fait avancer le calcul entre-temps, la lecture reprend là où il en est.
 */
async function hashLoop(box: number, file: File): Promise<void> {
  const CHUNK = 4 * 1024 * 1024;
  let buffer: ArrayBuffer = new ArrayBuffer(CHUNK);
  let last = 0;
  const post = (p: Progress) => {
    const now = Date.now();
    if (p.sha256 || now - last >= 100) {
      last = now;
      scope.postMessage({ event: "box-hash", hash: { box_id: box, ...p } });
    }
  };
  try {
    let p = JSON.parse(box_hash_feed(box, 0, new Uint8Array(0))) as Progress;
    while (!p.sha256 && boxes.has(box)) {
      const stream = file.slice(p.done).stream();
      let pos = p.done;
      let byob: ReadableStreamBYOBReader | null = null;
      try {
        byob = stream.getReader({ mode: "byob" });
      } catch {
        byob = null; // navigateur sans lecteur BYOB sur un Blob : morceaux alloués par le navigateur
      }
      const reader = byob ?? stream.getReader();
      let resync = false;
      for (;;) {
        const r = byob ? await byob.read(new Uint8Array(buffer, 0, CHUNK)) : await (reader as ReadableStreamDefaultReader<Uint8Array>).read();
        if (r.done || !r.value || !boxes.has(box)) break;
        const chunk = r.value as Uint8Array;
        p = JSON.parse(box_hash_feed(box, pos, chunk)) as Progress;
        if (byob) buffer = chunk.buffer as ArrayBuffer; // le tampon revient, prêt à resservir
        pos += chunk.byteLength;
        post(p);
        if (p.sha256) break;
        if (p.done !== pos) {
          resync = true; // un rapport a déjà fait avancer le calcul
          break;
        }
        await yieldToMessages();
      }
      await reader.cancel().catch(() => undefined);
      if (!resync && !p.sha256 && boxes.has(box)) {
        // Fin du flux sans fin de calcul : fichier raccourci pendant la lecture.
        throw new Error("le fichier a changé pendant le calcul d'empreinte");
      }
    }
    if (p.sha256) post(p);
  } catch (err) {
    scope.postMessage({ event: "box-hash-error", box, error: err instanceof Error ? err.message : String(err) });
  }
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
      hashing.set(job.box, hashLoop(job.box, job.file));
      boxFiles.set(job.box, job.file);
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
      // Le rapport porte l'empreinte de la boîte : on attend le calcul en flux déjà lancé (les
      // autres demandes continuent d'être servies pendant ce temps).
      await hashing.get(job.box);
      scope.postMessage({ id: job.id, ok: true, text: box_report(job.box, job.item, new Uint32Array(job.path), job.format, job.generated) });
    } else if (job.kind === "box-extract") {
      const data = box_extract(job.box, job.item, new Uint32Array(job.path), job.index);
      const buf = data.buffer as ArrayBuffer;
      scope.postMessage({ id: job.id, ok: true, data: buf, name: safe_file_name(job.filename) }, [buf]);
    } else if (job.kind === "box-export") {
      // L'empreinte de l'ouverture d'abord, puis une revérification complète en flux.
      await hashing.get(job.box);
      const file = boxFiles.get(job.box);
      if (!file) throw new Error("boîte fermée");
      const [sha, md5] = await freshHash(file);
      const r = box_export(job.box, new Uint32Array(job.ids), job.format, job.generated, sha, md5);
      try {
        const zip = r.zip();
        const buf = zip.buffer as ArrayBuffer;
        scope.postMessage({ id: job.id, ok: true, data: buf, json: JSON.parse(r.manifest()) }, [buf]);
      } finally {
        r.free();
      }
    } else if (job.kind === "box-forget") {
      for (const b of boxes) box_forget(b);
      scope.postMessage({ id: job.id, ok: true });
    } else if (job.kind === "box-close") {
      boxes.delete(job.box);
      boxFiles.delete(job.box);
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
