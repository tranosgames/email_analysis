---

description: "Task list for 002 — Boîtes PST/OST"
---

# Tasks: Lecture forensic des boîtes PST/OST

**Input**: Design documents from `/specs/002-pst-support/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: **inclus et obligatoires** — Constitution V (test-first sur corpus). Chaque test est écrit et doit ÉCHOUER avant l'implémentation correspondante. L'oracle est libpff (`pypff`), utilisé uniquement pour produire les valeurs de référence.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1…US3 ; US4 reportée)

## Path Conventions

Workspace Cargo : `crates/mf-*/src/`, copie embarquée : `vendor/outlook-pst/`, app : `apps/desktop/`,
corpus : `tests/corpus/pst/`. Numérotation propre à la feature, préfixe `P`.

---

## Phase 1: Setup (Shared Infrastructure)

- [x] P001 Copier `outlook-pst` 1.2 dans `vendor/outlook-pst/` (LICENSE MIT et `NOTICE.md` décrivant l'origine et chaque modification), le déclarer dans `[workspace.dependencies]` par chemin, et vérifier sa compilation native et `wasm32-unknown-unknown`
- [x] P002 [P] Constituer `tests/corpus/pst/` : `32-bit.pst` (ANSI), `support.pst`, `dist-list.pst`, `passworded.pst` versionnés ; `fetch.sh` pour Enron 14 Mo et 29 Mo, les 3 OST et l'export Gmail 56 Mo (URL figées, SHA-256 vérifiés, dossier `large/` ignoré par git) ; `README.md` (origine, licence, empreinte de chaque fichier)
- [x] P003 [P] Script `tests/corpus/pst/oracle.py` (libpff) produisant `expected.json` : par fichier, format, encodage, et par dossier (chemin) le nombre d'éléments et de pièces jointes ; versionner `expected.json`
- [x] P004 [P] Créer la crate `crates/mf-pst` (`#![forbid(unsafe_code)]`, `deny(unwrap_used, panic)`), membre du workspace

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ CRITICAL**: aucune user story ne commence avant la fin de cette phase.

- [x] P005 Test : `crates/mf-pst/tests/oracle.rs` — pour chaque fichier présent de `expected.json`, compter éléments et pièces jointes par dossier (doit échouer : crate vide)
- [x] P006 Appliquer `spikes/pst-browser/outlook-pst-tolerance.patch` à `vendor/outlook-pst/` (compteur d'espace libre, messages sans sous-nœuds) ; consigner dans `NOTICE.md`
- [x] P007 Retirer de la copie embarquée le chemin d'écriture (`writer`, `start_write`, reconstruction AMap) et remplacer les `unwrap`/`panic` déclenchables par le contenu du fichier par des erreurs ; test : PST tronqués et altérés générés depuis `support.pst` (`tests/corpus/pst/malformed/`) → erreur, jamais de panique
- [x] P008 [P] `crates/mf-pst/src/source.rs` : trait `ByteSource`, `FileSource` (lecture positionnée), `MemSource`, lecteur paginé `Paged` (pages de 512 Ko, LRU 16, compteurs) ; tests unitaires de lecture à cheval sur deux pages et en fin de fichier
- [x] P009 [P] `crates/mf-core/src/model.rs` : `Provenance`, `ItemSummary`, `Store`, `Folder`, `UnreadableItem`, `BoxFilter` (data-model.md) ; champ `provenance: Option<Provenance>` dans `Message`
- [x] P010 `crates/mf-msg/src/source.rs` : trait `PropertySource` (chaîne avec page de code, binaire, u32, date, booléen, destinataires, pièces jointes, message embarqué) ; `convert` générique ; implémentation sur le fichier composé ; tous les tests MSG existants restent verts (aucune régression)
- [x] P011 `crates/mf-pst/src/store.rs` : ouverture Unicode puis ANSI depuis un `ByteSource`, `Store` (format, encodage, protection par mot de passe, nom), parcours de l'arborescence IPM avec chemins et types de dossiers spéciaux, éléments illisibles collectés — P005 passe pour les PST

**Checkpoint**: P005 vert pour tous les PST (hors OST) ; comptes identiques à libpff

---

## Phase 3: User Story 1 — Ouvrir une boîte et parcourir ses dossiers (Priority: P1) 🎯 MVP

**Goal**: arborescence, liste d'un dossier, ouverture d'un élément avec toutes les vues, provenance — CLI puis bureau.

**Independent Test**: quickstart scénarios 1 à 3 (étapes 1 et 2).

### Tests

- [x] P012 [P] [US1] `crates/mf-pst/tests/items.rs` : pour 5 éléments annotés d'Enron 29 Mo (objet, expéditeur SMTP, date, nombre et noms des pièces jointes, présence des en-têtes de transport), l'élément converti est conforme ; un élément avec message embarqué s'ouvre en cascade
- [x] P013 [P] [US1] `crates/mf-pst/tests/integrity.rs` : SHA-256 du fichier identique avant et après ouverture et parcours complet (SC-001)
- [x] P014 [P] [US1] `crates/mf-cli/tests/pst.rs` : `mf pst info|tree|ls|show` sur `support.pst` (sorties JSON conformes à contracts/cli.md)

### Implementation

- [x] P015 [US1] `crates/mf-pst/src/item.rs` : `PropertySource` sur un message PST (propriétés, table des destinataires, pièces jointes, objets embarqués) ; `list(folder, offset, limit)` depuis la table de contenu **sans ouvrir** les éléments ; `open_item` → `Message` + `Provenance`
- [x] P016 [US1] `crates/mf-pst/src/hash.rs` : SHA-256 + MD5 en flux par blocs de 8 Mo, `hash_step(budget)` avec progression
- [x] P017 [US1] `crates/mf-engine` : `open_box` et `BoxSession` (contracts/engine-api.md) ; `open_item` passe par l'analyse complète existante (clés, signatures)
- [x] P018 [US1] `crates/mf-cli` : `mf pst info|tree|ls|show|report|bench` ; provenance dans `mf show` et dans le rapport HTML/JSON (`crates/mf-report`)
- [x] P019 [US1] Tauri : thread de travail par boîte (objets non `Send`), commandes `box_open|box_list|box_item|box_close`, événements de progression ; fichier `.pst`/`.ost` reconnu au dépôt et à l'ouverture de dossier ; même boîte déposée deux fois signalée en doublon par empreinte
- [x] P020 [US1] Interface : panneau d'arborescence (dossiers repliables, compteurs), liste virtualisée (50 000 lignes fluides), message ouvert avec toutes les vues, fil d'Ariane de provenance, progression de l'empreinte, liste des éléments illisibles
- [x] P021 [US1] Éléments non courriel (rendez-vous, contacts, tâches, notes) : classe affichée, propriétés principales, pas de verdict

> Écarts assumés (MVP) : l'ouverture passe par `open_paths` (pas de `box_open` séparé) et la boîte reste
> ouverte jusqu'à la fermeture de l'application (pas de `box_close`) ; le doublon est détecté par chemin
> canonique à l'ouverture, l'empreinte n'étant connue qu'après le calcul en arrière-plan. Interface
> vérifiée par `npm run test:box` (pont Tauri simulé, données produites par `mf` sur `support.pst`).

**Checkpoint**: une boîte PST s'ouvre et se lit entièrement dans la CLI et l'application de bureau

---

## Phase 4: User Story 2 — Retrouver un message sans tout lire (Priority: P1)

**Goal**: filtres sur les tables de dossiers, sans ouvrir aucun message ; verdicts et indicateurs des seuls messages ouverts.

**Independent Test**: quickstart scénario 3 (étapes 3 et 4).

### Tests

- [x] P022 [P] [US2] `crates/mf-pst/tests/filter.rs` : filtres combinés (nom d'expéditeur, destinataire, objet, période, taille, pièces jointes, Message-ID) sur Enron 29 Mo conformes à `expected.json`, **compteur de messages lus à zéro** après filtrage de toute la boîte — *`crates/mf-engine/tests/filter.rs` : support.pst et Enron, comparés à un filtrage indépendant et aux comptes libpff ; 0 élément lu*
- [x] P023 [P] [US2] `crates/mf-pst/tests/opened.rs` : ouvrir 3 éléments → seuls ces 3 sont lus (compteur à 3), leur verdict et leur adresse d'expéditeur apparaissent dans leurs `ItemSummary`, « analysés seulement » et le filtre par verdict ou domaine ne portent que sur eux, les indicateurs exportés ne viennent que d'eux ; rouvrir un élément ne le relit pas — *`opened_items_only` (même fichier) ; indicateurs avec provenance, messages joints compris*
- [x] P024 [P] [US2] Bench reproductible `mf pst bench` : temps d'arborescence, de liste du plus gros dossier, de filtre de toute la boîte et d'ouverture d'un message, octets lus ; seuils de SC-003 et SC-005 vérifiés sur Enron 29 Mo — *`mf pst bench` : filtre de toute la boîte à froid et à chaud ; Enron 29 Mo : 65 ms à froid, 0,7 ms ensuite, 0 lu*

### Implementation

- [x] P025 [US2] `crates/mf-pst/src/index.rs` : `BoxIndex` — tables de dossiers lues à la demande et gardées, filtre linéaire (`BoxFilter`), cache des éléments ouverts (`Analyzed`), `iocs()` fusionnés avec provenances — *dans `crates/mf-engine/src/{filter.rs,mailbox.rs}` (tables gardées par dossier, `BoxFilter` en ET, mots sans casse ni accents, `iocs()`) plutôt que `mf-pst/src/index.rs`*
- [x] P026 [US2] Compteur des messages lus exposé par la session (tests, CLI `info`, interface « 3 messages lus sur 2 178 ») : preuve que rien d'autre n'est lu (FR-006) — *`items_read` (CLI `info`, `ls`, `iocs`) ; interface « N élément(s) lu(s) sur M »*
- [x] P027 [US2] CLI : filtres de `mf pst ls`, `mf pst iocs --id` — *`mf pst ls --text --from-name --to --subject --message-id --after --before --min-size --max-size --attachments/--no-attachments`, `mf pst iocs --id`*
- [x] P028 [US2] Tauri + interface : barre de filtres (dossier ou toute la boîte), tri des colonnes, pastille de verdict sur les messages ouverts, « analysés seulement », export des indicateurs des messages analysés — *bureau et web : recherche, panneau de filtres (portée dossier ou boîte), tri, verdict dans la liste, « analysés seulement », export CSV/JSON ; e2e web comparé à la CLI*
- [x] P029 [US2] Profiler l'analyse complète d'un message (coût fixe de 3 à 4 ms mesuré) et supprimer les initialisations répétées (nettoyeur HTML, expressions, tables) — non bloquant — *aucune initialisation répétée : expressions compilées une fois ; coût restant = décodage d'images pour les QR codes (voir `research.md` R10)*

**Checkpoint**: US1 et US2 complètes sur le bureau et en CLI ; aucun message lu sans clic

---

## Phase 5: Version web (US1 + US2)

**Goal**: mêmes capacités dans le navigateur, lecture par tranches, mémoire bornée.

**Independent Test**: quickstart scénario 4.

- [x] P030 [P] `tests/web_e2e.py` : ouverture de `support.pst` et d'Enron 29 Mo (si présent), arborescence, message ouvert, filtres ; résultats identiques à la CLI ; zéro requête réseau ; mémoire du Worker relevée
  > Fait sauf les filtres (Phase 4, pas encore livrée) et la mesure mémoire (P033) : ouverture de
  > `support.pst` et d'Enron 29 Mo (0,1 s), arborescence, ligne et pièces jointes identiques à la
  > CLI, seul l'élément cliqué est lu, pièce jointe téléchargée à l'identique, empreinte de la boîte
  > identique, aucune requête réseau.
- [x] P031 `crates/mf-wasm` : `BlobSource` (fonction de lecture fournie par le Worker), API de boîte (contracts/engine-api.md, messages du Worker)
- [x] P032 `apps/desktop/src/engine.worker.ts` + `ipc.ts` : `File` transmis une fois au Worker, `FileReaderSync` sur `File.slice`, boucles `*_step` entrecoupées de messages de progression, mêmes appels que Tauri pour l'interface
- [x] P033 Mesurer la mémoire de l'onglet sur la plus grosse boîte disponible ; objectif < 300 Mo (SC-004) ; consigner dans `research.md` — *2 Go et 8 Go : < 310 Mo au pic, 210 Mo retenus ; empreinte en flux dans un tampon réutilisé (voir `research.md` R10)*

---

## Phase 6: OST Outlook 2013+ (US1)

**Goal**: lire les OST à pages de 4 Ko (R3).

- [x] P034 Test : P005 étendu aux 3 OST du corpus (doit échouer) — *fait avec le lecteur intégré : les 4 OST du corpus sont comparés à libpff (`counts_match_libpff`)*
- [x] P035 `vendor/outlook-pst` : en-tête OST (magic `SO`), taille de page paramétrée par le type de fichier, tailles de blocs, décompression des blocs (`flate2`) ; consigner dans `NOTICE.md` — *apporté par les correctifs `outlook-pst-ost` intégrés dans `vendor/outlook-pst` (voir `NOTICE.md`)*
- [x] P036 Repli : si la lecture d'un OST échoue, message explicite « format non pris en charge » sans bloquer le reste (FR-009) ; test sur un OST tronqué — *`crates/mf-engine/tests/truncated.rs` : raison explicite lue dans l'en-tête (trop court, pas de « !BDN », version inconnue, tronquée à n %) ; ouverture partielle avec la coupure signalée ; dossiers illisibles ou tables lues en partie et éléments illisibles signalés (Enron abîmée : 1 708 lus + 29 illisibles + 441 signalés = 2 178) ; e2e web : boîte tronquée parmi d'autres fichiers*

**Checkpoint**: P005 vert pour tous les PST et OST

---

## Phase 7: User Story 3 — Exporter des éléments (Priority: P2)

**Goal**: `.msg` fidèle, `.eml` reconstruit, manifeste ; ZIP sur le web.

**Independent Test**: quickstart scénario 5.

### Tests

- [x] P037 [P] [US3] `crates/mf-pst/tests/export.rs` : aller-retour de 10 éléments d'Enron en `.msg` rouverts par `mf-msg` (champs clés, en-têtes de transport, empreintes des pièces jointes identiques — SC-006) ; manifeste complet ; empreinte de la boîte revérifiée — *`crates/mf-engine/tests/export.rs` (l'export orchestre session et manifeste, d'où le crate) : support (17), Enron (10), OST (2) en .msg et .eml, 20 rendez-vous en .msg ; relus par `mf-msg` et par `msg_parser` ; en-têtes de transport, destinataires, corps, pièces jointes et empreintes identiques ; propriétés nommées conservées ; export reproductible. Contrôle supplémentaire hors CI avec `extract-msg` (Python) : 25/25*
- [x] P038 [P] [US3] Export refusé dans le dossier de la preuve, dans un dossier non vide, et si l'empreinte de la boîte a changé — *même fichier, `refusals` : dossier de la preuve et ses sous-dossiers, dossier non vide, boîte modifiée après l'ouverture (rien n'est écrit) ; CLI : `crates/mf-cli/tests/pst.rs`*

### Implementation

- [x] P039 [US3] `crates/mf-pst/src/export.rs` : écriture `.msg` (fichier composé `cfb` : propriétés, destinataires, pièces jointes, messages embarqués), `.eml` reconstruit avec `X-MailForensics-Reconstructed: pst`, manifeste JSON et CSV — *`crates/mf-pst/src/msg_writer.rs` (.msg v3 comme Outlook, table des noms de la boîte copiée) et `crates/mf-engine/src/export.rs` (.eml reconstruit, manifeste JSON/CSV, ZIP) ; empreinte du contenu de l'élément (`Provenance.item_sha256`), aussi affichée dans le scellé*
- [x] P040 [US3] CLI `mf pst export` ; Tauri `box_export` (destination choisie) ; web : ZIP téléchargé — *`mf pst export --id|filtre --format --out` ; Tauri `box_export` asynchrone (sous-dossier neuf dans le dossier choisi) ; web : empreinte recalculée en flux puis ZIP téléchargé*
- [x] P041 [US3] Interface : sélection multiple dans la liste, « Exporter la sélection » et « Exporter le filtre » — *cases à cocher (Maj+clic pour une plage), « Tout », format .msg/.eml, « Exporter la sélection » ou, sans sélection, le dossier ou les résultats du filtre ; e2e web : ZIP contrôlé avec la CLI*

---

## Phase 8: Polish & Cross-Cutting Concerns

- [ ] P042 [P] Fuzzing : cible `pst_open` (`fuzz/`) sur le chemin d'ouverture et de parcours ; corpus de départ = PST du corpus
- [ ] P043 [P] Proposer les correctifs (tolérance, OST) en amont à `outlook-pst` ; consigner l'état dans `NOTICE.md` — *préparé, non soumis : `vendor/outlook-pst/upstream-proposal/` (patch contre `main` cfb721d, 11 tests amont réussis, texte de la demande en anglais) ; état consigné dans `NOTICE.md`. Le correctif officiel d0f9f00 (blocage de `root_hierarchy_table`) a été repris dans notre copie. Soumission : décision du mainteneur*
- [x] P044 [P] README et documentation projet : PST/OST, mesures, limites ; capture d'écran — *README : boîtes, recherche, export, empreinte de l'élément, limites ; captures `apercu-pst*.png` ; mesures dans `research.md` R10 et `quickstart.md`*
- [ ] P045 Valider SC-003 sur une boîte volumineuse fournie par l'utilisateur (`mf pst bench` + page web) ; consigner les mesures
- [x] P046 Exécuter quickstart.md de bout en bout — *`quickstart.md`, section « Exécution du 2026-11-23 » : scénarios 1, 2, 4, 5 et mesures réussis ; scénario 3 vérifié par `test:box` et l'e2e web (fenêtre Tauri non exécutable ici)*

---

## Itération ultérieure — User Story 4 (Priority: P3)

- [x] P047 [US4] Étude : lecture des éléments supprimés encore référencés et des nœuds orphelins (comportement de libpff comme référence) ; décision documentée avant toute implémentation — *étude faite (`research.md` R11) : 0 orphelin lisible sur les 14 boîtes publiques ; décision : implémentation reportée jusqu'à une boîte réelle avec suppressions, en commençant par les orphelins*

---

## Dependencies & Execution Order

- **Phase 1 → Phase 2** : la copie embarquée (P001) et le corpus (P002, P003) précèdent tout.
- **Phase 2** bloque toutes les user stories ; P010 (conversion générique) précède P015.
- **US1 (Phase 3)** est le MVP ; **US2 (Phase 4)** dépend de US1 (session de boîte, liste).
- **Phase 5 (web)** dépend des Phases 3 et 4 (même API) ; **Phase 6 (OST)** dépend seulement de la Phase 2 et peut se faire en parallèle des Phases 3 à 5.
- **US3 (Phase 7)** dépend de US1 ; indépendante de US2.
- Dans chaque story : tests d'abord (doivent échouer), puis modèle, moteur, CLI, interface.

### Parallel Opportunities

- P002, P003, P004 ; P008 et P009 ; P012, P013, P014 ; P022, P023, P024 ; P037 et P038 ; P042, P043, P044.
- La Phase 6 (OST) en parallèle des Phases 3 à 5, dans un autre fichier (`vendor/`).

## Implementation Strategy

1. **MVP** : Phases 1 → 3 (une boîte PST se lit entièrement, CLI et bureau). Démontrer.
2. **Tri** : Phase 4 (filtres sur les tables de dossiers, verdicts des messages ouverts).
3. **Web** : Phase 5 (le prototype a levé le risque principal).
4. **OST** : Phase 6, risque le plus élevé, isolé.
5. **Export** : Phase 7, puis finitions.

## Traçabilité

| Exigence | Tâches |
|---|---|
| FR-001 | P006, P007, P011, P013, P034–P036 |
| FR-002 | P016, P013 |
| FR-003 | P011, P020 |
| FR-004 | P010, P015, P017, P020 |
| FR-005 | P009, P015, P018, P020 |
| FR-006 | P022, P023, P025, P026 |
| FR-007 | P022, P025, P027, P028 |
| FR-008 | P037–P041 |
| FR-009 | P007, P011, P020, P036 |
| FR-010 | P014, P018, P028, P040 |
| FR-011 | P030–P033 |
| FR-012 | P011 |
| FR-013 | P023, P025, P027, P028 |
| FR-014 | P047 (ultérieur) |
| SC-001 | P013, P037 |
| SC-002 | P005, P034 |
| SC-003 | P024, P045 |
| SC-004 | P033 |
| SC-005 | P022, P024 |
| SC-006 | P037 |
