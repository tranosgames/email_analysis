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

## R5 — Ne lire que ce que l'analyste ouvre

- **Décision (clarification 2026-11-20)** : aucune lecture des messages en arrière-plan. Trois
  niveaux de lecture, du plus léger au plus lourd :
  1. **ouverture de la boîte** : en-tête, arbres B et tables de hiérarchie des dossiers seulement ;
  2. **ouverture d'un dossier** : sa table de contenu, qui fournit déjà la ligne de liste de chaque
     message sans l'ouvrir ;
  3. **clic sur un message** : lecture complète et **analyse complète** de la feature 001
     (verdict, signatures, QR codes, pages HTML jointes…), une seule fois, résultat gardé en mémoire.
- **Justification** : demande explicite de l'analyste ; coût proportionnel à ce qui est consulté ;
  l'analyse complète actuelle (3 à 80 ms par message mesurés) est imperceptible sur un clic. La
  double analyse « rapide / complète » envisagée pour un tri de toute la boîte devient inutile.
- **Seule exception** : le calcul d'empreinte parcourt tout le fichier, octet par octet, sans
  interpréter les messages (R7, Constitution I).

## R6 — Filtres sur les tables de dossiers

- **Constat (vérifié sur le PST Enron)** : la table de contenu d'un dossier porte 49 colonnes, dont
  l'objet (`0x0037`), le nom affiché de l'expéditeur (`0x0042`), les destinataires affichés
  (`0x0E04`, `0x0E03`), les dates d'envoi et de réception (`0x0039`, `0x0E06`), la taille
  (`0x0E08`), les drapeaux dont « pièces jointes » (`0x0E07`), la classe (`0x001A`) et le
  Message-ID (`0x1035`). **L'adresse email de l'expéditeur n'y figure pas.**
- **Décision** : les lignes de liste (`ItemSummary`) sont lues dans ces tables ; filtres et tris par
  parcours linéaire en mémoire (≈ 0,5 Ko par ligne, 25 Mo pour 50 000 messages). Filtrer toute la
  boîte lit les tables de tous les dossiers, jamais les messages. Le filtre par adresse, domaine
  d'expéditeur ou verdict ne porte que sur les messages déjà ouverts.
- **Rejeté** : index plein texte, recherche dans les corps (exigerait de lire tous les messages).

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

## R10 — Mesures (2026-11-23)

**Coût d'analyse d'un message (P029)**, binaire `--release`, une seule session :

| Cas | 1ʳᵉ analyse | Ensuite |
|---|---|---|
| `phishing-basic.eml` | 4,1 ms | 0,07 ms |
| Élément Enron (moyenne sur 300) | — | 0,11 ms |
| `unicode.msg` (2 TIFF de 1 Mo) | 14 ms | 10,6 ms |
| `quishing-html-attachment.eml` (images, QR) | 17 ms | 18 ms |

Les expressions régulières sont compilées une fois (`LazyLock`) : les 4 ms de la première analyse ne
se répètent pas. Le reste du temps vient du décodage des images pour y chercher un QR code, coût
voulu et borné (nombre et taille d'images limités). Aucune initialisation répétée à supprimer.

**Mémoire de l'onglet web (P033, SC-004)** : RSS des processus de rendu de Chromium (page, Worker et
WebAssembly compris), Chromium 2026, sans ramasse-miettes forcé. Les fichiers de 2 et 8 Go sont la
boîte Gmail de 56 Mo suivie d'espace vide (fichier creux) : la lecture et l'empreinte portent bien
sur toute la taille.

| Boîte | Page seule | Boîte ouverte | Pic pendant l'empreinte | Empreinte | Filtre sur toute la boîte | 17 éléments ouverts |
|---|---|---|---|---|---|---|
| Enron 29 Mo | 136 Mo | 179 Mo | 188 Mo | 0,6 s | 208 Mo | 302 Mo |
| Gmail 56 Mo | 142 Mo | 163 Mo | 163 Mo | 0,6 s | 208 Mo | 291 Mo |
| 2 Go | 140 Mo | 162 Mo | 170 Mo | 18 s | 216 Mo | 288 Mo |
| 8 Go | 138 Mo | 160 Mo | 177 Mo | 73 s | 197 Mo | 273 Mo |

La mémoire ne dépend pas de la taille du fichier. Avec un ramasse-miettes forcé, 31 éléments ouverts
sur Enron retombent à 210 Mo (JavaScript de la page 10 Mo, mémoire WebAssembly du moteur 26 Mo) :
l'écart avec la colonne « 17 éléments ouverts » est fait de déchets que Chromium récupère plus tard.
Objectif < 300 Mo tenu pour la mémoire retenue ; le pic reste sous 310 Mo.

Deux corrections issues de ces mesures :
- L'empreinte lisait le fichier par `FileReaderSync`, qui crée un tampon de 8 Mo à chaque pas : sur
  2 Go, le pic montait à 453 Mo. Elle lit maintenant le flux du fichier dans un seul tampon de 4 Mo
  réutilisé (lecteur « BYOB ») et le moteur reçoit ces octets (`box_hash_feed`) : pic à 170 Mo, et
  calcul plus rapide (18 s au lieu de 22 s).
- Les lectures du flux se résolvant sans passer par la file des messages, la boucle d'empreinte
  affamait le Worker : une recherche attendait la fin du calcul. La boucle rend maintenant la main
  après chaque morceau ; un rapport demandé pendant le calcul attend le calcul en cours au lieu de
  relire le fichier.

## R11 — Éléments supprimés et nœuds orphelins (P047, étude)

**Question.** Faut-il lire les éléments supprimés encore présents dans le fichier (FR-014, P3) ?

**Ce qui existe.** Deux cas distincts :
- **Nœuds orphelins** : l'élément est encore référencé par l'arbre des nœuds de la boîte, mais plus
  par aucun dossier (suppression définitive non encore compactée). Lecture fiable : mêmes
  structures que les éléments normaux, seul le lien vers le dossier manque.
- **Blocs récupérés** : données encore présentes dans l'espace libre (pages et blocs marqués
  libres). C'est ce que fait `pffexport -m recovered` de libpff : parcours de l'espace non alloué
  et reconstitution heuristique ; résultats partiels, faux positifs possibles.

**Mesure sur le corpus (libpff 20261030, binding Python : seuls les orphelins sont exposés).**
13 des 14 boîtes publiques : 0 orphelin. `outlook-com-a.ost` : 1 orphelin annoncé, illisible
même par libpff. La récupération dans l'espace libre (`pffexport`) n'est pas mesurable ici.

**Décision.** Pas d'implémentation pour l'instant :
1. Le corpus public ne permet ni de développer ni de vérifier la fonction (aucun élément à
   retrouver) ; une implémentation non vérifiée contre la référence violerait la règle du projet
   (chaque lecture comparée à libpff).
2. L'interface et le modèle sont prêts à l'accueillir : un dossier virtuel « Éléments
   récupérés », éléments marqués comme tels dans la provenance, jamais mêlés aux autres
   (FR-014), et listés dans le manifeste d'export.
3. À reprendre dès qu'une boîte réelle contenant des suppressions est disponible (boîte de
   l'utilisateur, ou PST fabriqué par Outlook avec suppressions définitives puis non compacté) :
   d'abord les **orphelins** (fiables, peu de code : parcours de l'arbre des nœuds, différence
   avec les éléments rattachés), puis seulement l'espace libre, derrière une option explicite.
