# Research: Lecture forensic des boîtes PST/OST

**Feature**: `002-pst-support` · **Date**: 2026-11-20

Les mesures citées viennent du prototype `spikes/pst-browser/` (même code en natif et en
WebAssembly, lecteur paginé au-dessus du fichier ou d'un Blob) et d'un passage du moteur actuel
sur le corpus de la feature 001.

## R1 — Sans serveur, sur les deux interfaces

- **Décision** : aucune infrastructure serveur. Bureau : lecture native du fichier. Web : lecture
  par tranches dans le Worker (`File.slice` + `FileReaderSync`), via un lecteur paginé
  (pages de 512 Ko, cache LRU de 8 Mo) qui implémente `Read + Seek`.
- **Justification** : un PST est une base à accès aléatoire (arbres B des nœuds et des blocs) ;
  seules les pages utiles sont lues. Mesures : mémoire de 11 Mo quelle que soit la taille ;
  2 178 messages parcourus en 0,69 s dans Chromium (87 ms en natif) ; pages de 512 Ko deux fois
  plus rapides que 64 Ko (moins d'appels JS↔WASM).
- **Alternatives rejetées** : serveur d'analyse (envoi de dizaines de Go de preuve : chaîne de
  preuve, confidentialité, coût, contraire à la Constitution VI) ; chargement du fichier entier en
  mémoire dans le navigateur (impossible au-delà de quelques Go, limite de 4 Go de WASM32).

## R2 — Bibliothèque PST : `outlook-pst` corrigée, embarquée

- **Décision** : `outlook-pst` 1.2 (Microsoft, MIT), copiée dans `vendor/outlook-pst/` avec :
  (a) le correctif de tolérance du prototype (`outlook-pst-tolerance.patch`) ; (b) l'ajout des OST
  Outlook 2013+ (R3). Les correctifs sont proposés en amont ; le jour où ils sont publiés, la copie
  embarquée est retirée.
- **Justification** : bibliothèque en Rust pur, lecture seule, compatible WebAssembly (vérifié),
  accepte toute source `Read + Seek` (`UnicodePstFile::read_from`). Sans correctif elle ne lit que
  568/2 178 messages d'un PST Enron réel et 0/71 d'un autre (contrôles trop stricts d'un compteur
  d'espace libre et de la présence de sous-nœuds) ; corrigée, elle égale libpff.
- **Alternatives rejetées** : libpff (C, LGPL-3 : liaison statique dans le WASM et l'application
  incompatible avec notre distribution simple ; chaîne emscripten en plus) — retenue comme
  **oracle de test** uniquement ; `go-pst` (Go, hors pile) ; réécriture complète (plusieurs semaines
  de format NDB/LTP déjà correctement implémentées par Microsoft).

## R3 — OST Outlook 2013+ (pages de 4 Ko)

- **Constat** : les OST récents (magic client `SO`, version de format 36) utilisent des pages de
  4 Ko, des blocs plus grands et peuvent compresser les blocs de données (zlib). `outlook-pst` fixe
  `PAGE_SIZE = 512` et refuse le magic `SO` : les 3 OST du corpus sont rejetés ; libpff les lit.
- **Décision** : ajouter la variante 4 Ko dans la copie embarquée (taille de page paramétrée par le
  type de fichier, en-tête OST, décompression des blocs), derrière les mêmes interfaces `Store` /
  `Folder` / `Message`. Livraison dans une phase dédiée, après le PST.
- **Risque** : élevé (format peu documenté hors MS-PST ; l'implémentation de libpff sert de
  référence de comportement, sans copie de code). Repli si bloqué : OST signalés « non pris en
  charge » (FR-009) sans bloquer le reste de la feature.

## R4 — Conversion vers le modèle unifié : réutiliser `mf-msg`

- **Décision** : extraire de `mf-msg` un trait `PropertySource` (chaînes avec page de code,
  binaires, entiers, dates, booléens, destinataires, pièces jointes, message embarqué) ; la fonction
  `convert` actuelle devient générique. `mf-msg` l'implémente sur le fichier composé, `mf-pst` sur
  les messages PST.
- **Justification** : un message PST porte les mêmes propriétés MAPI qu'un `.msg` (objet, adresses,
  `PR_TRANSPORT_MESSAGE_HEADERS`, corps texte/HTML/RTF compressé, pièces jointes, messages
  embarqués) : toute la logique existante (RTF → HTML, adresse SMTP réelle, en-têtes) s'applique
  sans duplication, et l'analyse de la feature 001 fonctionne telle quelle.
- **Alternative rejetée** : seconde conversion propre au PST (double maintenance, divergences).

## R5 — Analyse de la boîte en deux niveaux

- **Mesure** : le moteur actuel analyse un message du corpus en 3 à 4 ms hors gros contenus, et
  jusqu'à 80 ms pour un `.msg` de 840 Ko riche en images (décodage des QR codes, nettoyage HTML).
  Extrapolation pour 50 000 messages : ~5 min en natif, ~30 min dans le navigateur — trop long.
- **Décision** : en arrière-plan, une **analyse rapide** par message : en-têtes, authentification,
  acheminement, liens et pièces jointes (types, drapeaux), verdict, indicateurs — **sans** décodage
  d'images, pages HTML jointes, signatures ni recalcul DKIM. L'**analyse complète** s'exécute à
  l'ouverture d'un message, et peut être lancée sur une sélection. Le verdict de l'analyse rapide est
  marqué comme tel ; s'il diffère après analyse complète, la liste est mise à jour.
- **Objectif** : < 1 ms par message en analyse rapide (natif), soit < 1 min pour 50 000 messages, et
  < 5 min dans le navigateur. Profilage avant optimisation (coût fixe actuel suspect : construction
  des nettoyeurs HTML et des expressions à chaque appel).

## R6 — Index de boîte en mémoire, filtres linéaires

- **Décision** : un `ItemSummary` par élément (≈ 0,5 Ko) en mémoire ; filtres par parcours linéaire
  (50 000 × 0,5 Ko = 25 Mo, parcours < 50 ms). Recherche dans le corps : nouveau parcours de la
  boîte en flux, avec progression et annulation, sans stocker les corps.
- **Justification** : Constitution VII — pas de moteur de recherche ni de base de données. Les
  ordres de grandeur tiennent l'objectif SC-005 (< 1 s).
- **Alternative rejetée** : index plein texte (tantivy) : mémoire ou disque importants, complexité ;
  à reconsidérer seulement si la recherche dans le corps s'avère trop lente en usage réel.

## R7 — Empreinte d'un fichier de plusieurs Go

- **Décision** : SHA-256 et MD5 en flux, par blocs de 8 Mo, dans le même processus que la lecture
  (thread dédié en natif, Worker sur le web), avec progression ; l'arborescence s'affiche sans
  attendre. Les exports sont refusés tant que l'empreinte n'est pas calculée, puis la revérifient.
- **Note** : en natif, la preuve n'est plus lue une seule fois en mémoire (règle R8 de la feature
  001) : elle est relue par pages. L'intégrité reste garantie par l'ouverture en lecture seule et la
  revérification de l'empreinte avant export (Complexity Tracking du plan).

## R8 — Export

- **`.msg`** : écriture d'un fichier composé (`cfb`, déjà utilisé en lecture) reprenant les
  propriétés MAPI de l'élément, ses destinataires et pièces jointes ; relu par `mf-msg` en test
  (aller-retour). C'est le format fidèle.
- **`.eml`** : reconstruction à partir des en-têtes de transport et des corps ; un en-tête
  `X-MailForensics-Reconstructed: pst` et le manifeste le signalent.
- **Web** : archive ZIP (`zip`, déjà dans les dépendances) téléchargée.

## R9 — Corpus et oracle

- **PST/OST publics** trouvés dans les jeux de test de projets libres (MIT, Apache-2.0) et un export
  Gmail (DFIR Artifact Museum, MIT). Les plus petits (32-bit.pst ANSI 64 Ko, support.pst 1 Mo,
  dist-list.pst 271 Ko) entrent dans `tests/corpus/pst/` ; les plus gros (Enron 14 et 29 Mo, OST
  16 Mo, Gmail 56 Mo) sont téléchargés par `tests/corpus/pst/fetch.sh` avec vérification
  d'empreinte, et leurs tests sont ignorés s'ils sont absents.
- **Oracle** : comptes par dossier (messages, pièces jointes) produits par libpff (`pypff`) et
  versionnés dans `tests/corpus/pst/expected.json` ; libpff n'est jamais une dépendance du produit.
- **Volume** : aucun PST de plusieurs Go public n'a pu être récupéré depuis l'environnement de
  développement ; SC-003/SC-004 seront vérifiés sur un PST fourni par l'utilisateur (et, en CI, sur un
  PST synthétique généré à partir du corpus si la bibliothèque le permet).
