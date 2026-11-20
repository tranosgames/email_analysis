# outlook-pst — copie embarquée

Ce dossier contient le code de lecture des fichiers Outlook `.pst` / `.ost` utilisé par
`crates/mf-pst`. Il n'est pas maintenu par Microsoft.

## Origine

| Étape | Source | Licence |
|---|---|---|
| Base | `outlook-pst` 1.2.0, Microsoft (`microsoft/outlook-pst-rs`, crates.io) | MIT, © Microsoft Corporation (`LICENSE`) |
| Correctifs | `outlook-pst-ost` 1.3.0 (crates.io, publié le 2026-11-03, projet `markdown-extract`), qui ajoute à 1.2.0 les corrections décrites dans `UPSTREAM-FORK.md` ; chaque modification y est marquée `markdown-extract:` | MIT |
| Ce dépôt | modifications marquées `mailforensics:` (ci-dessous) | MIT |

## Pourquoi une copie

La version publiée par Microsoft (1.2.0) rejette des fichiers valides : elle ne lit que 568 des
2 178 messages d'un PST Enron réel, aucun des 71 d'un autre, et aucun OST d'Outlook 2013+. Le fork
1.3.0 corrige ces cas ; il n'a qu'une version et peu d'utilisateurs : plutôt que d'en dépendre, son
code a été **relu intégralement** (≈ 385 lignes de différences avec 1.2.0 : pas d'`unsafe`, pas
d'accès disque ou réseau, décompression zlib bornée à la taille annoncée) puis copié ici.

Vérification (2026-11-20) contre libpff, lecteur de référence, sur 10 PST/OST publics : nombres de
dossiers, de messages et de pièces jointes identiques pour tous (voir `tests/corpus/pst/`).

## Modifications propres à MailForensics

1. `src/lib.rs`, `open()` : **lecture seule stricte**. L'original ouvrait aussi le fichier en
   écriture ; aucune poignée d'écriture n'est désormais créée.
2. `src/messaging/message.rs`, trait `Message` : méthode `open_attachment(self: Rc<Self>, …)`,
   pour ouvrir les pièces jointes d'un message embarqué, que la bibliothèque n'expose que sous la
   forme `Rc<dyn Message>`.

## Retour à la version officielle

Les correctifs ont été proposés à Microsoft par l'auteur du fork. Dès qu'une version officielle
les contient (et lit les OST 2013+), ce dossier est supprimé au profit de la dépendance publiée.
