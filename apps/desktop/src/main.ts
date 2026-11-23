// Orchestration (rôle de main.js dans msg-reader) + raccourcis clavier.
import "./styles.css";
import { initTheme, mountThemeToggle } from "./theme";

initTheme();
import { FileHandler } from "./FileHandler";
import { MessageHandler } from "./MessageHandler";
import { UIManager } from "./UIManager";
import { onBoxHash, restoreKeys, warmUp } from "./ipc";

const state = new MessageHandler();
const ui = new UIManager(state);
const files = new FileHandler(state);
void onBoxHash((h) => {
  state.setHash(h);
  ui.showBoxHash(h);
});

// Liste des fichiers repliable ; état mémorisé sur ce poste (confort, facultatif).
const app = document.getElementById("app") as HTMLElement;
const collapseBtn = document.getElementById("collapse-list") as HTMLButtonElement;
const expandBtn = document.getElementById("expand-list") as HTMLButtonElement;
function setListCollapsed(collapsed: boolean): void {
  app.classList.toggle("list-collapsed", collapsed);
  collapseBtn.setAttribute("aria-expanded", String(!collapsed));
  expandBtn.hidden = !collapsed;
  try {
    localStorage.setItem("mf.listCollapsed", collapsed ? "1" : "0");
  } catch {
    /* stockage indisponible : l'état n'est simplement pas mémorisé */
  }
  (collapsed ? expandBtn : collapseBtn).focus({ preventScroll: true });
}
collapseBtn.addEventListener("click", () => setListCollapsed(true));
expandBtn.addEventListener("click", () => setListCollapsed(false));
try {
  if (localStorage.getItem("mf.listCollapsed") === "1") {
    app.classList.add("list-collapsed");
    collapseBtn.setAttribute("aria-expanded", "false");
    expandBtn.hidden = false;
  }
} catch {
  /* idem */
}

document.addEventListener("keydown", (e) => {
  const target = e.target as HTMLElement;
  if (e.ctrlKey || e.metaKey || e.altKey || target.matches("input, textarea, select")) return;
  // Fenêtre modale ouverte (fichiers, URL, indicateurs) : elle gère ses touches, dont Échap.
  if (document.querySelector("dialog[open]")) return;
  switch (e.key) {
    case "l":
    case "L":
      setListCollapsed(!app.classList.contains("list-collapsed"));
      break;
    case "ArrowDown":
    case "j":
      state.move(1);
      break;
    case "ArrowUp":
    case "k":
      state.move(-1);
      break;
    case "h":
    case "H":
      state.toggleHeaders(); // FR-035
      break;
    case "p":
    case "P":
      state.togglePin();
      break;
    case "Escape":
      if (state.path.length) state.goToDepth(state.path.length - 1);
      break;
    default:
      return;
  }
  e.preventDefault();
});

warmUp();
const footer = document.querySelector<HTMLElement>(".list-footer");
if (footer) {
  // FR-044 : indicateurs de tous les messages chargés, fusionnés et dédoublonnés.
  const all = document.createElement("button");
  all.type = "button";
  all.className = "btn export-all";
  all.textContent = "Télécharger tous les indicateurs";
  all.title = "Exporter en CSV les indicateurs de tous les messages chargés";
  all.addEventListener("click", () => void ui.exportAllIocs("csv"));
  footer.append(all);
  // FR-049/050 : trousseau de l'analyste (clés PGP, certificats).
  const keys = document.createElement("button");
  keys.type = "button";
  keys.className = "btn keys-button";
  keys.textContent = "Clés et certificats";
  keys.title = "Clés publiques PGP et certificats pour vérifier les signatures";
  keys.addEventListener("click", () => void ui.openKeyDialog());
  footer.append(keys);
  ui.keyButton = keys;
  mountThemeToggle(footer);
}
void ui.render();
// Le trousseau mémorisé est réimporté avant toute analyse (les fichiers ouverts au lancement en profitent).
void restoreKeys()
  .catch(() => undefined)
  .then(() => {
    void ui.updateKeyButton();
    return files.init();
  });
