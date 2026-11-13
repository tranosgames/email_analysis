// FR-040 : thème Auto (système) / Clair / Sombre, mémorisé sur le poste.
// Le stockage local peut être indisponible (navigation privée, politique) : l'interface
// fonctionne alors en mode Auto sans mémorisation.

export type ThemeChoice = "auto" | "light" | "dark";

const KEY = "mf-theme";
const ORDER: ThemeChoice[] = ["auto", "light", "dark"];
const LABEL: Record<ThemeChoice, string> = { auto: "Thème : auto", light: "Thème : clair", dark: "Thème : sombre" };

function load(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "auto";
  } catch {
    return "auto";
  }
}

function apply(choice: ThemeChoice): void {
  if (choice === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = choice;
}

/** À appeler avant le premier rendu, pour éviter un flash du mauvais thème. */
export function initTheme(): void {
  apply(load());
}

/** Bouton qui fait défiler Auto → Clair → Sombre. */
export function mountThemeToggle(container: HTMLElement): void {
  let choice = load();
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn theme-toggle";
  const render = () => {
    btn.textContent = LABEL[choice];
    btn.title = "Changer de thème (Auto suit le réglage du système)";
  };
  btn.addEventListener("click", () => {
    choice = ORDER[(ORDER.indexOf(choice) + 1) % ORDER.length];
    apply(choice);
    try {
      if (choice === "auto") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, choice);
    } catch {
      /* mémorisation impossible : le choix vaut pour cette session */
    }
    render();
  });
  render();
  container.append(btn);
}
