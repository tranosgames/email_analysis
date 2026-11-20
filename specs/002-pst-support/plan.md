# Implementation Plan: Lecture forensic des boîtes PST/OST

**Branch**: `002-pst-support` | **Date**: 2026-11-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-pst-support/spec.md`

## Summary

Ouvrir des boîtes Outlook `.pst` / `.ost` de plusieurs Go dans les trois interfaces existantes
(CLI, application de bureau, page web), sans serveur : arborescence des dossiers, listes lues dans
les tables de dossiers, filtres sur ces listes, et **seuls les messages ouverts par l'analyste sont
lus et analysés** avec toutes les vues de la feature 001 ; export en `.msg` avec manifeste.

Approche : une crate `mf-pst` au-dessus d'une copie corrigée de `outlook-pst` (Microsoft), lisant
par pages à travers une abstraction `ByteSource` (fichier natif ou Blob du navigateur) ; la
conversion vers le modèle unifié réutilise celle de `mf-msg` via un trait `PropertySource`. Le
prototype `spikes/pst-browser/` valide l'approche : 11 Mo de mémoire quelle que soit la taille,
0,3 ms par message dans le navigateur, résultats identiques à libpff après correctif.

## Technical Context

**Language/Version**: Rust stable 1.97 (édition 2024) ; TypeScript 5 (frontend)

**Primary Dependencies**: `outlook-pst` 1.2 (copie embarquée corrigée, `vendor/outlook-pst/`) ;
existantes : `cfb` (lecture et écriture `.msg`), `sha2`, `md-5`, `zip`, `serde`, `clap`,
`wasm-bindgen` ; `flate2` (décompression des blocs OST, R3) ; tests : `pypff` (libpff) comme oracle
hors produit

**Storage**: aucun ; index de boîte en mémoire pour la session ; exports vers une destination
choisie par l'analyste (ZIP téléchargé sur le web)

**Testing**: `cargo test` (unitaires, corpus PST/OST avec comptes de référence libpff), aller-retour
d'export `.msg`, `npm run test:web` (scénarios PST dans Chromium, zéro requête réseau, mémoire),
mesures de performance reproductibles (`mf pst bench`)

**Target Platform**: Windows 10+, macOS 13+, Linux ; navigateurs récents (Chromium, Firefox, Safari)
avec Web Workers et `FileReaderSync`

**Project Type**: bibliothèques + CLI + application de bureau + page web (workspace Cargo existant)

**Performance Goals**: arborescence < 10 s pour 5 Go ; liste d'un dossier de 10 000 messages < 2 s
natif, < 5 s web ; filtre de toute la boîte < 1 s ; message ouvert et analysé < 2 s

**Constraints**: lecture seule stricte ; jamais de chargement intégral du fichier ; mémoire web
< 300 Mo ; hors-ligne ; `#![forbid(unsafe_code)]` dans les crates du projet ; aucune panique sur
entrée (la copie embarquée est passée au crible : `unwrap` sur données de fichier remplacés)

**Scale/Scope**: boîtes jusqu'à 50 Go / 200 000 éléments ; 4 user stories (US4 reportée) ; 14 FR

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification dans ce plan | Statut |
|---|---|---|
| I. Intégrité de la preuve | Ouverture en lecture seule, aucune API d'écriture de la bibliothèque appelée (le chemin d'écriture de `outlook-pst` est retiré de la copie embarquée) ; empreinte en flux, revérifiée avant export ; export refusé dans le dossier de la preuve | ✅ |
| II. Traçabilité | Provenance (chemin de dossier + identifiant de nœud) sur chaque élément, dans l'interface, la CLI, le rapport et le manifeste d'export ; éléments illisibles listés | ✅ |
| III. Moteur d'abord | Toute la logique dans `mf-pst` / `mf-engine` ; CLI, Tauri et Worker ne font que relayer | ✅ |
| IV. Contenu hostile | Même rendu neutralisé que la feature 001 ; mémoire bornée (cache de pages, limites de taille par propriété et pièce jointe) ; fuzzing de l'ouverture d'un PST | ✅ |
| V. Tests sur corpus | PST/OST réels du corpus, comptes de référence libpff versionnés, tests écrits avant le code | ✅ |
| VI. Hors-ligne | Aucune requête ; lecture par tranches dans le navigateur ; aucun serveur | ✅ |
| VII. Simplicité | Lecture à la demande uniquement, filtres linéaires sur les tables de dossiers, pas de moteur de recherche ni de base | ✅ (deux entrées en Complexity Tracking) |

**Re-check post-design (Phase 1)** : data-model, contrats et quickstart respectent les 7 principes.

## Project Structure

### Documentation (this feature)

```text
specs/002-pst-support/
├── spec.md
├── plan.md              # ce fichier
├── research.md          # R1–R9 : décisions et mesures
├── data-model.md        # Store, Folder, ItemSummary, Provenance, BoxIndex, Export
├── quickstart.md        # scénarios de validation
├── contracts/
│   ├── cli.md           # mf pst …
│   └── engine-api.md    # API du moteur, commandes Tauri, messages du Worker
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
vendor/outlook-pst/          # copie MIT corrigée (tolérance, OST 4 Ko, sans écriture) + NOTICE
crates/
├── mf-core/                 # + Provenance, ItemSummary ; Evidence étendue (format de boîte)
├── mf-msg/                  # convert() générique sur le trait PropertySource
├── mf-pst/                  # NOUVEAU : ByteSource, lecteur paginé, Store/Folder/Item, conversion,
│                            #           filtres sur les tables, export .msg/.eml + manifeste
├── mf-engine/               # + ouverture d'une boîte, session de boîte
├── mf-cli/                  # + sous-commandes `mf pst`
└── mf-wasm/                 # + BlobSource (FileReaderSync), API de boîte
apps/desktop/
├── src-tauri/               # + commandes de boîte, thread de travail par boîte
└── src/                     # + arborescence des dossiers, liste virtualisée, progression, filtres
tests/corpus/pst/            # petits PST versionnés, fetch.sh pour les gros, expected.json (libpff)
```

**Structure Decision**: une crate `mf-pst` dédiée (comme `mf-eml` / `mf-msg`), qui dépend de
`mf-msg` pour la conversion ; la copie de `outlook-pst` reste isolée sous `vendor/` pour pouvoir
être remplacée par la version amont dès que les correctifs y sont publiés.

## Phases

1. **Socle** : copie embarquée + correctif ; `ByteSource` et lecteur paginé ; corpus et oracle.
2. **Conversion** : trait `PropertySource`, `convert` générique ; élément PST → `Message`.
3. **Boîte (US1)** : arborescence, liste d'un dossier, ouverture d'un élément ; CLI `mf pst ls/show`.
4. **Bureau (US1)** : sélection de boîte, arborescence, liste virtualisée, provenance.
5. **Filtres (US2)** : filtres sur les tables de dossiers, verdicts des messages ouverts, indicateurs des messages analysés.
6. **Web (US1–US2)** : `BlobSource`, empreinte en flux, mêmes vues ; mémoire < 300 Mo.
7. **OST 4 Ko** (R3).
8. **Export (US3)** : `.msg` fidèle, `.eml` reconstruit, manifeste ; ZIP sur le web.
9. **Finitions** : performances sur grosse boîte, documentation, proposition des correctifs en amont.

US4 (éléments supprimés) : hors de cette itération.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Copie embarquée et corrigée de `outlook-pst` (`vendor/`) | La version publiée rejette des PST valides (26 % des messages d'Enron lus) et ne lit pas les OST récents | Dépendre de la version publiée : lecture incomplète silencieuse, inacceptable en forensic ; attendre l'amont : délai inconnu |
| Preuve relue par pages au lieu d'une lecture unique en mémoire (règle R8 de la feature 001) | Un PST de plusieurs Go ne tient pas en mémoire, a fortiori dans un navigateur | Lecture intégrale : impossible au-delà de quelques Go ; l'intégrité reste garantie par la lecture seule et la revérification d'empreinte avant export |
