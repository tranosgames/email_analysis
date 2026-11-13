// Orchestration (rôle de main.js dans msg-reader) + raccourcis clavier.
import "./styles.css";
import { initTheme, mountThemeToggle } from "./theme";

initTheme();
import { FileHandler } from "./FileHandler";
import { MessageHandler } from "./MessageHandler";
import { UIManager } from "./UIManager";
import { warmUp } from "./ipc";

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
  mountThemeToggle(footer);
}
void ui.render();
void files.init();
