// Interface des boîtes PST (feature 002) dans le navigateur, avec un faux pont Tauri nourri par la
// CLI `mf` sur tests/corpus/pst/support.pst : arborescence, liste, lecture d'un élément, empreinte.
// Usage : npm run test:box (construit l'interface de bureau dans un dossier temporaire).
const { chromium } = require("playwright");
const { execFileSync } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const root = path.resolve(__dirname, "../../..");
const pst = path.join(root, "tests/corpus/pst/support.pst");
execFileSync("cargo", ["build", "-q", "-p", "mf-cli"], { cwd: root, stdio: "inherit" });
const mf = path.join(root, "target/debug/mf");
const j = (...a) => JSON.parse(execFileSync(mf, ["--json", "pst", ...a, pst], { encoding: "utf8" }));
const info = j("info", "--no-hash").store;
const tree = j("tree");
const rows = {};
const items = {};
for (const f of tree) {
  if (!f.item_count || f.kind === "search") continue;
  rows[f.id] = j("ls", "--folder", String(f.id));
  for (const r of rows[f.id]) items[r.id] = j("show", "--id", String(r.id));
}
const data = JSON.stringify({ info, tree, rows, items });

const dist = fs.mkdtempSync(path.join(os.tmpdir(), "mf-box-ui-"));
execFileSync("npx", ["vite", "build", "--outDir", dist, "--emptyOutDir"], { cwd: path.resolve(__dirname, ".."), stdio: "ignore" });

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? "ok  " : "ÉCHEC"}  ${label}`);
  if (!ok) failures++;
};

const srv = http
  .createServer((q, r) => {
    let p = path.join(dist, decodeURIComponent(q.url.split("?")[0]));
    if (p.endsWith("/")) p += "index.html";
    if (!fs.existsSync(p)) return r.writeHead(404).end();
    const t = { ".js": "text/javascript", ".css": "text/css", ".html": "text/html" }[path.extname(p)] || "application/octet-stream";
    r.writeHead(200, { "content-type": t }).end(fs.readFileSync(p));
  })
  .listen(0);

(async () => {
  const browser = await chromium.launch();
  const pg = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  const errs = [];
  pg.on("pageerror", (e) => errs.push(String(e)));
  await pg.addInitScript((raw) => {
    const D = JSON.parse(raw);
    window.__calls = [];
    window.__listeners = {};
    let cb = 1;
    window.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main", windowLabel: "main" } },
      transformCallback(fn) {
        const id = cb++;
        window["_" + id] = fn;
        return id;
      },
      async invoke(cmd, args) {
        window.__calls.push(cmd);
        switch (cmd) {
          case "initial_paths":
            return ["/cas/support.pst"];
          case "list_keys":
            return [];
          case "open_paths":
            return [{ kind: "mailbox", box_id: 0, path: "/cas/support.pst", store: D.info, folders: D.tree }];
          case "box_list":
            return D.rows[args.folder] || [];
          case "box_item":
            return D.items[args.id];
          case "plugin:event|listen":
            (window.__listeners[args.event] ||= []).push(args.handler);
            return args.handler;
          default:
            return null;
        }
      },
    };
    window.__emit = (ev, payload) => (window.__listeners[ev] || []).forEach((h) => window["_" + h]({ event: ev, id: 0, payload }));
  }, data);
  await pg.goto(`http://127.0.0.1:${srv.address().port}/`);
  await pg.waitForSelector(".box-head", { timeout: 15000 });
  check(true, "la boîte s'ouvre directement sur son arborescence");
  const folders = await pg.$$eval(".folder-row", (e) => e.map((x) => x.textContent));
  check(folders.some((t) => t.includes("Drafts")), "dossier Drafts présent");
  await pg.evaluate(() => window.__emit("box-hash", { box_id: 0, done: 1, total: 4, sha256: null, md5: null }));
  check((await pg.textContent(".box-hash")).includes("25 %"), "progression de l'empreinte affichée");
  check(!(await pg.evaluate(() => window.__calls.includes("box_item"))), "aucun élément lu à l'ouverture");

  await pg.click('.folder-row:has-text("Drafts")');
  await pg.waitForSelector(".box-row");
  check((await pg.$$eval(".box-row", (e) => e.length)) === 6, "Drafts : 6 lignes lues dans la table");
  await pg.click(".box-row >> nth=0");
  await pg.waitForSelector(".reading-main", { timeout: 15000 });
  const crumbs = await pg.textContent(".breadcrumb");
  check(crumbs.includes("support.pst") && crumbs.includes("Drafts"), `provenance : ${crumbs}`);
  check((await pg.evaluate(() => window.__calls.filter((c) => c === "box_item").length)) === 1, "un seul élément lu");
  await pg.keyboard.press("ArrowDown");
  await pg.waitForFunction(() => window.__calls.filter((c) => c === "box_item").length === 2);
  check(true, "flèche bas : élément suivant");

  await pg.evaluate(() => window.__emit("box-hash", { box_id: 0, done: 4, total: 4, sha256: "ab".repeat(32), md5: "cd".repeat(16) }));
  await pg.waitForFunction(() => document.querySelector(".box-hash")?.textContent.includes("SHA-256"));
  check((await pg.textContent(".seal")).includes("abab"), "empreinte de la boîte reportée sur le scellé");

  await pg.click(".box-back");
  await pg.waitForSelector(".folder-row");
  const before = await pg.$$eval(".folder-row", (e) => e.length);
  const caret = await pg.$('.folder-caret[aria-expanded="true"]');
  if (caret) {
    await caret.click();
    check((await pg.$$eval(".folder-row", (e) => e.length)) < before, "dossier replié");
  }
  await pg.click(".box-back");
  check((await pg.$$eval(".box-entry", (e) => e.length)) === 1, "retour à la liste des fichiers");
  check(errs.length === 0, `aucune erreur JavaScript (${JSON.stringify(errs)})`);
  await browser.close();
  srv.close();
  fs.rmSync(dist, { recursive: true, force: true });
  console.log(`\n${failures} échec(s)`);
  process.exit(failures ? 1 : 0);
})();
