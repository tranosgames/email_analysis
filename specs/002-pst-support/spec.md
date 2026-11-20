# Feature Specification: Lecture forensic des boîtes PST/OST

**Feature Branch**: `002-pst-support`

**Created**: 2026-10-14 · **Updated**: 2026-11-20

**Status**: Ready for planning

**Input**: User description: "Potentiellement dans le futur manipuler des fichiers PST." ; puis
« Comment intégrer les PST : serveur externe ou serverless ? » → prototype de lecture dans le
navigateur (`spikes/pst-browser/`) concluant ; « reprends la spécification PST ».

## Clarifications

### Session 2026-11-20

- Q: Serveur ou sans serveur ? → A: **Sans serveur**, sur les deux interfaces : l'application de
  bureau lit le PST nativement ; la version web le lit **par tranches** dans le navigateur, sans
  jamais l'envoyer ni le charger entièrement. Le prototype mesure 11 Mo de mémoire quelle que soit
  la taille, 0,3 ms par message dans Chromium (2 178 messages en 0,7 s), 4 à 7 fois le temps natif.
- Q: Quel socle de lecture ? → A: `outlook-pst` (Microsoft, MIT), **avec le correctif de tolérance**
  du prototype : sans lui, la bibliothèque ne lit que 568 des 2 178 messages d'un PST Enron réel, et
  aucun des 71 d'un autre ; avec lui, les résultats égalent ceux de libpff (référence).
- Q: Les OST ? → A: Pris en charge dans cette feature : les OST d'Outlook 2013+ (pages de 4 Ko) sont
  aujourd'hui refusés par la bibliothèque et doivent être ajoutés ; ce sont des pièces fréquentes en
  enquête (poste de travail saisi).
- Q: Ordre de livraison ? → A: Moteur et CLI d'abord, puis application de bureau, puis version web,
  le même moteur servant les trois.
- Q: Faut-il analyser chaque message (verdict, constats, indicateurs) à l'échelle d'une boîte ? → A:
  Oui, en arrière-plan après l'affichage de l'arborescence, avec progression, pause et reprise ;
  la liste se trie et se filtre par verdict au fur et à mesure.
- Q: Format d'export ? → A: `.msg` en priorité : c'est le seul format qui reprend **à l'identique**
  les propriétés MAPI stockées dans le PST. L'export `.eml` est une **reconstruction** (le PST ne
  conserve pas le MIME d'origine) et est marqué comme tel.
- Q: Récupération des éléments supprimés ? → A: Conservée en P3, hors de la première itération : la
  bibliothèque retenue ne sait pas lire les éléments orphelins.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Ouvrir une boîte PST/OST et parcourir ses dossiers (Priority: P1)

L'analyste dépose un fichier `.pst` ou `.ost` de plusieurs Go, dans l'application ou dans la page
web. L'arborescence des dossiers (Boîte de réception, Éléments envoyés, Éléments supprimés,
dossiers personnalisés) s'affiche en quelques secondes, avec le nombre d'éléments, pendant que
l'empreinte du fichier se calcule. Il ouvre un dossier : la liste de ses messages apparaît dans la
même interface que pour les EML/MSG ; chaque message s'ouvre avec toutes les vues existantes
(verdict, analyse, signatures, en-têtes, pièces jointes, URL, indicateurs, rapport).

**Why this priority**: Les PST/OST sont la forme habituelle des boîtes saisies ; sans navigation,
aucune autre capacité n'a de valeur.

**Independent Test**: Ouvrir chaque PST/OST du corpus ; le nombre de messages et de pièces jointes
par dossier égale celui de libpff ; l'empreinte du fichier est identique avant et après la session.

**Acceptance Scenarios**:

1. **Given** un PST Unicode de 5 Go, **When** il est déposé, **Then** l'arborescence s'affiche en moins de 10 s, l'empreinte se calcule avec une progression, et l'interface reste utilisable.
2. **Given** un message d'un dossier PST, **When** il est ouvert, **Then** il est présenté comme un MSG, et sa provenance indique `boite.pst › Boîte de réception › …` avec l'identifiant interne du nœud.
3. **Given** un PST ANSI (Outlook 97-2002) ou un OST Outlook 2013+, **When** il est déposé, **Then** il est lu comme un PST Unicode.
4. **Given** la version web et un PST de 5 Go, **When** il est déposé, **Then** aucune donnée n'est envoyée, la mémoire de l'onglet reste sous 300 Mo, et le résultat est identique à l'application de bureau.
5. **Given** un PST dont certains éléments sont illisibles (corruption, format inattendu), **When** il est parcouru, **Then** les éléments lisibles s'affichent, les autres sont listés comme illisibles avec leur dossier et la raison, et rien n'est « réparé ».

---

### User Story 2 - Trier la boîte : verdicts, recherche, filtres (Priority: P1)

Une fois l'arborescence affichée, l'outil analyse chaque message en arrière-plan (verdict,
constats, indicateurs). L'analyste voit la progression, peut mettre en pause, et filtre la boîte
entière : par verdict, expéditeur, destinataire, domaine, période, objet, présence de pièces
jointes, type de pièce jointe, et par recherche dans le corps.

**Why this priority**: Une boîte compte des dizaines de milliers de messages : le tri automatique
est ce qui rend la lecture d'un PST possible en enquête.

**Independent Test**: Sur le PST Enron de 2 178 messages, filtrer « Malveillant » et « avec pièce
jointe » retourne exactement les messages attendus d'une liste annotée ; une recherche dans le corps
retrouve un message connu.

**Acceptance Scenarios**:

1. **Given** une boîte en cours d'analyse, **When** l'analyste filtre par verdict, **Then** la liste se met à jour au fil de l'analyse, et indique la part de la boîte déjà analysée.
2. **Given** une boîte entièrement analysée, **When** un filtre sur les métadonnées est appliqué, **Then** le résultat s'affiche en moins de 1 s pour 50 000 messages.
3. **Given** une recherche dans le corps des messages, **When** elle est lancée, **Then** elle parcourt la boîte avec une progression, peut être annulée, et liste les messages trouvés.
4. **Given** une boîte analysée, **When** l'analyste exporte les indicateurs, **Then** ceux de toute la boîte sont fusionnés et dédoublonnés, avec la provenance de chaque occurrence.

---

### User Story 3 - Exporter des éléments d'un PST (Priority: P2)

L'analyste exporte une sélection de messages en `.msg` individuels (et, au besoin, en `.eml`
reconstruits), avec leurs pièces jointes et un manifeste listant provenance et empreintes, pour
les transmettre ou les analyser à part.

**Why this priority**: Produit des pièces ciblées pour le dossier sans remettre la boîte entière.

**Independent Test**: Exporter 10 messages en `.msg`, les rouvrir dans l'outil : champs clés,
en-têtes de transport et empreintes des pièces jointes identiques à ceux lus dans le PST.

**Acceptance Scenarios**:

1. **Given** une sélection de 10 messages, **When** ils sont exportés en `.msg`, **Then** 10 fichiers et un manifeste (provenance, empreinte de chaque fichier, empreinte du PST source) sont créés, et le PST reste inchangé.
2. **Given** un export `.eml`, **When** il est produit, **Then** chaque fichier porte un en-tête signalant qu'il s'agit d'une reconstruction depuis un PST, et le manifeste le précise.
3. **Given** la version web, **When** l'analyste exporte une sélection, **Then** il reçoit une archive ZIP contenant les fichiers et le manifeste.

---

### User Story 4 - Éléments supprimés et récupération (Priority: P3, itération ultérieure)

L'analyste voit les éléments des dossiers « Éléments supprimés » et « Éléments récupérables »
encore référencés, et les éléments orphelins détectables, clairement marqués comme récupérés.

**Why this priority**: Forte valeur probante, mais exige une lecture bas niveau que la bibliothèque
retenue ne fournit pas.

**Independent Test**: Sur un PST de corpus où des messages ont été supprimés de façon connue, les
éléments récupérables sont listés et marqués.

**Acceptance Scenarios**:

1. **Given** un PST contenant des éléments supprimés non purgés, **When** l'analyste ouvre la vue « Récupérés », **Then** ils apparaissent avec la mention de leur origine et ne sont jamais mélangés aux éléments actifs.

---

### Edge Cases

- PST protégé par mot de passe : le mot de passe PST n'est pas un chiffrement ; le contenu est lu, et la protection est signalée dans les métadonnées de la boîte.
- PST « chiffré » par permutation ou cyclique : décodage transparent, méthode indiquée.
- PST tronqué ou corrompu : lecture partielle, éléments et dossiers illisibles listés, aucune écriture.
- PST de plus de 50 Go : jamais chargé en mémoire, ni en natif ni dans le navigateur.
- Éléments non courriel (rendez-vous, contacts, tâches, notes) : listés avec leur classe de message et leurs propriétés, sans verdict de courriel.
- Message sans en-têtes de transport (brouillon, élément interne) : signalé comme pour un MSG ; le verdict reste « À vérifier ».
- Pièces jointes de type « objet » (message embarqué) : ouvertes en cascade comme pour un MSG.
- Page web rechargée : le fichier doit être déposé à nouveau (le navigateur ne conserve pas l'accès) ; l'analyse déjà faite est perdue, sauf export.
- Même PST déposé deux fois : doublon signalé par empreinte.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Le système DOIT ouvrir les PST (Unicode et ANSI) et OST (y compris Outlook 2013+) en lecture seule stricte, sans jamais déclencher de réparation ni d'écriture.
- **FR-002**: Le système DOIT calculer l'empreinte du fichier (SHA-256, MD5) en flux, avec progression, sans bloquer la navigation, et la revérifier avant tout export.
- **FR-003**: Le système DOIT afficher l'arborescence complète des dossiers avec leurs compteurs, avant la fin du calcul d'empreinte et de l'analyse.
- **FR-004**: Le système DOIT présenter chaque élément via le modèle unifié existant, avec toutes les vues de la feature 001 (verdict, analyse, signatures, en-têtes, pièces jointes, URL, indicateurs, rapport).
- **FR-005**: Le système DOIT indiquer pour chaque élément sa provenance (chemin de dossier, identifiant interne de nœud), dans l'interface, la CLI et le rapport.
- **FR-006**: Le système DOIT analyser en arrière-plan tous les messages de la boîte (verdict, constats, indicateurs), avec progression, pause et reprise.
- **FR-007**: Le système DOIT filtrer la boîte par verdict, expéditeur, destinataire, domaine, période, objet, présence et type de pièce jointe, et rechercher dans le corps avec progression et annulation.
- **FR-008**: Le système DOIT exporter une sélection en `.msg` (propriétés MAPI reprises à l'identique) ou en `.eml` marqué comme reconstruit, avec pièces jointes et manifeste d'empreintes et de provenance.
- **FR-009**: Le système DOIT poursuivre la lecture lorsqu'un élément ou un dossier est illisible, lister ces éléments avec la raison, et ne jamais les masquer silencieusement.
- **FR-010**: Toutes les capacités DOIVENT être disponibles en CLI (`mf pst …`) avec sortie JSON.
- **FR-011**: La version web DOIT lire le fichier par tranches dans un Worker, sans l'envoyer ni le charger entièrement, avec une mémoire bornée indépendante de sa taille.
- **FR-012**: Le système DOIT signaler la protection par mot de passe et la méthode d'encodage d'une boîte dans ses métadonnées.
- **FR-013**: Le système DOIT exporter les indicateurs de toute la boîte, fusionnés et dédoublonnés, avec la provenance de chaque occurrence.
- **FR-014**: Le système DOIT lister séparément les éléments supprimés récupérables, marqués comme tels (P3, itération ultérieure).

### Key Entities

- **Store** : la boîte PST/OST (preuve) — format (Unicode, ANSI, OST 4 Ko), encodage, protection par mot de passe, empreintes, statistiques, éléments illisibles.
- **Folder** : dossier — identifiant de nœud, nom, chemin, type, compteurs, parent.
- **ItemSummary** : ligne de liste — identifiant de nœud, dossier, classe de message, objet, expéditeur, destinataires, dates, taille, pièces jointes, verdict (une fois analysé).
- **Item** : élément complet, converti en `Message` du modèle unifié, avec sa provenance.
- **Index de boîte** : résumés et résultats d'analyse de tous les éléments, en mémoire, jamais écrits à côté de la preuve.
- **Export** : fichiers produits + manifeste (provenance, empreintes, empreinte du PST source, nature « original » ou « reconstruit »).

## Success Criteria *(mandatory)*

- **SC-001**: Empreinte du PST identique avant et après ouverture, analyse et export (100 % du corpus).
- **SC-002**: Nombre de messages et de pièces jointes par dossier identique à libpff sur 100 % des PST/OST du corpus.
- **SC-003**: Arborescence affichée en moins de 10 s pour un PST de 5 Go ; parcours complet de 50 000 messages en moins de 1 min en natif et 3 min dans le navigateur ; analyse complète (verdicts) en moins de 10 min.
- **SC-004**: Mémoire de l'onglet web sous 300 Mo, quelle que soit la taille du PST.
- **SC-005**: Filtre sur les métadonnées d'une boîte de 50 000 messages en moins de 1 s.
- **SC-006**: Les messages exportés en `.msg` puis rouverts sont identiques sur les champs clés, les en-têtes de transport et les empreintes des pièces jointes.

## Assumptions

- Socle : `outlook-pst` 1.2 (Microsoft, MIT), embarqué dans le dépôt avec le correctif de tolérance
  du prototype et l'ajout des OST 4 Ko ; les correctifs sont proposés en amont.
- libpff sert d'**oracle de test** (outil de développement, jamais embarqué dans le produit).
- Les PST conservent les mêmes propriétés MAPI qu'un `.msg` : la conversion vers le modèle unifié
  réutilise celle de `mf-msg` (corps texte, HTML, RTF, adresses, en-têtes de transport, pièces jointes).
- L'index de boîte vit en mémoire le temps de la session ; sa persistance dans un dossier d'enquête
  relève des tâches T071–T076 de la feature 001.
- La modification de PST (écriture) reste hors périmètre : contraire à la Constitution I.
