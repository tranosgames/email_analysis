import init, { bench } from "./pstbench.js";
self.onmessage = async (e) => {
  const file = e.data;
  const wasm = await init();
  const reader = new FileReaderSync();
  let jsTime = 0;
  // Lecture synchrone d'une tranche du fichier : seul ce morceau est chargé en mémoire.
  globalThis.pstReadAt = (offset, len) => {
    const t = performance.now();
    const buf = new Uint8Array(reader.readAsArrayBuffer(file.slice(offset, offset + len)));
    jsTime += performance.now() - t;
    return buf;
  };
  const t0 = performance.now();
  const r = JSON.parse(bench(file.size));
  r.ms = Math.round(performance.now() - t0);
  r.io_ms = Math.round(jsTime);
  r.wasm_memory_mb = +(wasm.memory.buffer.byteLength / 1e6).toFixed(1);
  self.postMessage(r);
};
