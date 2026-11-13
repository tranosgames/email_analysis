// Orchestration (rôle de main.js dans msg-reader) + raccourcis clavier.
import "./styles.css";
import { initTheme, mountThemeToggle } from "./theme";

initTheme();
import { FileHandler } from "./FileHandler";
import { MessageHandler } from "./MessageHandler";
import { UIManager } from "./UIManager";
import { restoreKeys, warmUp } from "./ipc";

const state = new MessageHandler();
const ui = new UIManager(state);
const files = new FileHandler(state);

document.addEventListener("keydown", (e) => {
  const target = e.target as HTMLElement;
  if (e.ctrlKey || e.metaKey || e.altKey || target.matches("input, textarea")) return;
  switch (e.key) {
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
