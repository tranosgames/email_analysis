# MailForensics (`email_reader`)

Outil d'analyse forensic de courriels **EML** et **MSG** (PST/OST prévu), en **Rust**, avec une
interface de bureau inspirée de [msg-reader](https://github.com/Rasalas/msg-reader) :
glisser-déposer, liste des messages, panneau de lecture, épinglage, tri — enrichie de vues
d'enquête (en-têtes et chaîne de relais, SPF/DKIM/DMARC, pièces jointes et imbrication, IOC,
propriétés MAPI brutes, rapport et journal d'audit).

Le projet est structuré avec [spec-kit](https://github.com/github/spec-kit) (Spec-Driven Development).

## Où en est-on

| Étape spec-kit | Feature 001 — EML/MSG | Feature 002 — PST |
|---|---|---|
| Feature 003 — version web | ✅ spec, plan, tâches, implémentation (W001–W021) | |
| `/speckit-constitution` | ✅ `.specify/memory/constitution.md` v1.0.0 | (partagée) |
| `/speckit-specify` | ✅ `spec.md` + checklist | ✅ `spec.md` (brouillon) |
| `/speckit-clarify` | ✅ session 2026-10-14 : en-têtes, fichiers, URL (FR-035–037) | — |
| `/speckit-plan` | ✅ `plan.md`, `research.md`, `data-model.md`, `contracts/`, `quickstart.md` | à faire |
| `/speckit-tasks` | ✅ `tasks.md` (97 tâches, 9 phases) | à faire |
| `/speckit-implement` | 🚧 lecture, en-têtes, fichiers, URL, acheminement, analyse (SPF/DKIM/DMARC, constats, PJ dangereuses, sosies), indicateurs, rapport (T091–T125) | — |

## Arborescence

```text
.specify/                 # spec-kit : constitution, templates, scripts
.claude/skills/speckit-*  # commandes spec-kit pour Claude Code
specs/
├── 001-email-forensic-viewer/   # feature active (.specify/feature.json)
└── 002-pst-support/
crates/                   # moteur Rust : mf-core, mf-eml, mf-msg, mf-analysis, mf-engine, mf-cli
apps/desktop/             # interface TypeScript (src/) partagée : application Tauri 2 (src-tauri/) et version web
crates/mf-wasm/           # moteur compilé en WebAssembly pour la version web
tests/corpus/             # EML/MSG de référence (voir son README)
spikes/crate-validation/  # prototype Phase 0 : valide mail-parser, cfb, msg_parser, outlook-pst
```

## Pile technique (voir `specs/001-email-forensic-viewer/research.md`)

- EML : `mail-parser` · MSG : `cfb` + couche MAPI maison (oracle de test : `msg_parser`) · PST : `outlook-pst` (Microsoft, lecture seule)
- UI : Tauri 2 + TypeScript vanilla + CSS natif, polices embarquées (même découpage que msg-reader : `FileHandler`, `MessageHandler`, `UIManager`)
- CLI `mf` pour l'automatisation et la contre-vérification

## Utiliser

**Application de bureau** — prérequis : Rust stable, Node.js ≥ 20 ; sous Linux `libwebkit2gtk-4.1-dev libsoup-3.0-dev librsvg2-dev` ; sous Windows WebView2 (déjà présent sur Windows 10/11).

```console
cd apps/desktop
npm install
npm run tauri dev          # développement
npm run tauri build        # installeurs .msi/.exe, .dmg, .deb/.AppImage
```

Déposez des `.eml` / `.msg` (ou un dossier) dans la fenêtre. Pour chaque message :

- **Acheminement** (en haut à droite, sous l'adresse de l'expéditeur) : IP et DNS de la machine d'envoi (DNS inverse et nom annoncé HELO, tels qu'enregistrés dans les en-têtes `Received` — aucune requête DNS), première IP publique si l'origine est privée, IP qui a remis le message au destinataire, serveur de réception et chemin complet avec les délais entre relais.
- **HTML / Texte / Source HTML** : le rendu HTML (neutralisé) est la vue par défaut ; pour les `.msg` Outlook dont la mise en forme n'existe qu'en RTF, le HTML d'origine est reconstitué depuis le RTF. **Plein écran** affiche le rendu sur toute la fenêtre.
- **Thème** (en bas de la liste) : auto, clair ou sombre, mémorisé sur le poste.
- **Afficher les en-têtes** (bouton ou touche `H`) déplie tous les en-têtes bruts, dans l'ordre d'origine ; l'état reste mémorisé d'un message à l'autre.
- **Fichiers contenus** liste chaque pièce jointe (nom, type, taille, inline/attaché, SHA-256 et MD5) ; un message joint (`.eml`, `.msg`) s'ouvre avec **Ouvrir le message joint**, qui affiche ses propres en-têtes, fichiers et URL.
- **Télécharger** (sous chaque fichier) ouvre une boîte de confirmation rappelant nom, type, taille, SHA-256 et le risque ; le fichier enregistré est identique octet pour octet à celui du message, sous un nom assaini. Un message Outlook embarqué en objet MAPI n'a pas de fichier d'origine : il s'ouvre mais ne se télécharge pas.
- **Ressources distantes bloquées** : le corps HTML est affiché sans rien charger depuis Internet (pixels de suivi, images, feuilles de style, scripts, cadres). Le bandeau « N ressources distantes bloquées » se déplie : pour chacune, son URL, son type, l'élément HTML (`<img src>`, `<td style>`…) et sa ligne dans le code HTML. **Voir dans le rendu** amène au repère numéroté placé à son emplacement, **Voir dans la source** à la ligne de l'onglet **Source HTML**.
- **URL** liste toutes les URL du message, dédoublonnées, avec leur emplacement (en-tête, texte, HTML `href`/`src`, CSS) ; elles ne sont jamais cliquables et se copient brutes ou défangées. Chaque URL porte ses alertes : texte affiché différent de la destination, IP brute, punycode (avec le domaine Unicode réel), alphabets mélangés, domaine sosie d'une marque, `user@hôte`.
- **Empreintes de la preuve** (SHA-256, MD5 du fichier ouvert) : en tête du panneau de droite.
- **Analyse** (au-dessus des en-têtes, **Replier / Déplier**, état mémorisé), entièrement locale :
  - verdicts **SPF / DKIM / DMARC** lus dans `Authentication-Results` (le plus récent fait foi), `ARC-Authentication-Results` et `Received-SPF` ;
  - **DKIM** : l'empreinte du corps (`bh=`) est recalculée hors-ligne (canonicalisation simple/relaxed, `l=`) — un corps modifié depuis la signature est signalé. La signature `b=` n'est pas vérifiable sans requête DNS (clé publique) : elle ne l'est pas, par principe. Un `.msg` ne conserve pas le corps MIME d'origine : l'empreinte n'y est pas vérifiable ;
  - **constats** classés par gravité : expéditeur (domaine sosie, Reply-To / Return-Path d'un autre domaine, nom affiché trompeur, Message-ID étranger), chronologie (date dans le futur, relais qui remontent le temps), liens, pièces jointes. Chaque constat renvoie à l'en-tête, la pièce jointe ou l'URL concernée.
- **Pièces jointes dangereuses** : type réel reconnu par signature (PE, ELF, LNK, OLE, ZIP/OOXML, ISO, RAR, 7z…) comparé à l'extension et au type déclaré ; exécutables, double extension, caractères de direction Unicode, archives chiffrées, documents à macros, pièces HTML, TNEF.
- **Indicateurs** (sous les URL) : adresses, domaines, IP publiques, URL et empreintes des pièces jointes, dédoublonnés et défangés ; **Copier (défangés)**, **Exporter CSV / JSON** pour le message, **Indicateurs (tous)** en bas de la liste pour tous les messages chargés.
- **Rapport** (à droite du bouton des en-têtes) : **HTML (imprimable)** — document autonome, sans aucune ressource externe, à imprimer en PDF depuis le navigateur — ou **JSON** (schéma versionné). Il reprend preuve et empreintes, constats, authentification, acheminement, pièces jointes, URL et indicateurs défangés, et l'annexe des en-têtes.

Autres raccourcis : `↑`/`↓` changer de message, `P` épingler, `Échap` revenir au message parent.

**Version web** (même interface, même moteur compilé en WebAssembly, aucun serveur) — prérequis supplémentaires :
`rustup target add wasm32-unknown-unknown` et `cargo install wasm-bindgen-cli --version 0.2.129`.

```console
cd apps/desktop
npm run dev:web            # http://localhost:5173
npm run build:web          # → dist-web/ (2,5 Mo), à servir par n'importe quel serveur statique
npm run test:web           # e2e : concordance avec la CLI, zéro requête réseau, hors-ligne
```

Les fichiers sont lus et analysés dans le navigateur : rien n'est envoyé, et aucune requête n'est émise
après le chargement de la page (CSP stricte, vérifiée par le test e2e). Une poussée sur `main` publie
la page sur GitHub Pages (`.github/workflows/pages.yml`). Limites : 500 Mo par fichier, pas
d'association de fichiers ni de PST.

**Ligne de commande** :

```console
cargo build --release
./target/release/mf show courriel.eml --headers      # résumé + en-têtes + fichiers + URL
./target/release/mf urls suspect.msg --defang
./target/release/mf attachments suspect.msg          # arborescence des messages joints
./target/release/mf show suspect.msg --path 3 --json # message joint n°3, en JSON
./target/release/mf extract suspect.eml --index 1 --out ./pj   # enregistre la PJ n°1
./target/release/mf findings *.eml                    # authentification + constats
./target/release/mf iocs *.eml *.msg --format csv --defang > indicateurs.csv
./target/release/mf report suspect.eml --out rapport.html      # ou --format json
```

**Tests** : `cargo test` (tests unitaires et corpus, concordance avec `msg_parser`, parité fichier / octets) et `npm run test:web`.

## Continuer

```console
uv tool install specify-cli     # ou: pip install specify-cli
claude                          # dans ce dossier ; les skills /speckit-* sont déjà installés
/speckit-clarify                # facultatif
/speckit-analyze
/speckit-implement              # poursuit le MVP (US1), puis US2…US6
```

Prototype de validation des crates :

```console
cd spikes/crate-validation && cargo run -- samples/phishing-basic.eml chemin/vers/un.msg
```

## Décisions à confirmer

1. Vérification DKIM/S-MIME **en ligne** (DNS) exclue de la v1 pour rester hors-ligne ; seule la vérification hors-ligne du hash du corps est faite.
2. Pas d'enrichissement externe (WHOIS, VirusTotal) en v1.
3. Mono-analyste, pas de serveur.
4. Décodage TNEF (`winmail.dat`) après le MVP.

## Licence

[Apache-2.0](LICENSE). Le design s'inspire de [msg-reader](https://github.com/Rasalas/msg-reader) (MIT) sans en reprendre le code ;
les fichiers `.msg` du corpus de test proviennent du jeu de test de [msg_parser](https://github.com/marirs/msg-parser-rs) (MIT, voir `tests/corpus/README.md`).
