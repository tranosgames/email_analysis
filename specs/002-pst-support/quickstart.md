# Quickstart — 002 Boîtes PST/OST

Validation de bout en bout de la feature (dernière tâche de `tasks.md`).

## Préparer le corpus

```console
sh tests/corpus/pst/fetch.sh          # télécharge les gros PST/OST publics, vérifie leurs empreintes
cargo test -p mf-pst                  # comptes par dossier comparés à expected.json (libpff)
```

## Scénario 1 — Intégrité et arborescence (US1, SC-001, SC-002)

```console
sha256sum tests/corpus/pst/large/enron-29.pst > /tmp/avant
mf pst info tests/corpus/pst/large/enron-29.pst     # empreinte identique à sha256sum
mf pst tree tests/corpus/pst/large/enron-29.pst     # 2 178 éléments au total
sha256sum -c /tmp/avant                             # OK
```

## Scénario 2 — Formats (US1)

`mf pst info` sur `32-bit.pst` (ANSI), `support.pst`, `dist-list.pst`, `passworded.pst`
(protection signalée), et les OST : aucun refus, comptes identiques à `expected.json`.

## Scénario 3 — Application de bureau (US1, US2)

1. Ouvrir `enron-29.pst` : l'arborescence s'affiche, l'empreinte se calcule avec une progression.
2. Ouvrir « Inbox », puis un message : toutes les vues de la feature 001 ; provenance
   `enron-29.pst › … › Inbox` affichée et reprise dans le rapport.
3. Filtrer toute la boîte par nom d'expéditeur et période, puis « avec pièce jointe » : résultat
   identique à `mf pst ls` avec les mêmes critères, et compteur de messages lus à zéro.
4. Ouvrir trois messages : leur verdict apparaît dans la liste ; « analysés seulement » les affiche ;
   l'export des indicateurs ne contient que ces trois messages.

## Scénario 4 — Version web (US1, US2, SC-004)

`npm run test:web` : mêmes étapes que le scénario 3 dans Chromium ; aucune requête réseau ;
mémoire de l'onglet sous 300 Mo ; résultats identiques à l'application de bureau.

## Scénario 5 — Export (US3, SC-006)

```console
mf pst export enron-29.pst --id <10 identifiants> --out /tmp/pieces --format msg
mf show /tmp/pieces/*.msg --json        # champs, en-têtes de transport, empreintes des PJ identiques
mf pst export enron-29.pst --id … --out /tmp/pieces-dans-la-preuve   # refusé si dans le dossier de la preuve
```

## Scénario 6 — Performances (SC-003)

`mf pst bench <grosse boîte>` en natif ; mesure équivalente dans la page web : arborescence < 10 s
(5 Go), liste d'un dossier de 10 000 messages < 2 s natif / 5 s web, message ouvert < 2 s. À exécuter sur une boîte fournie
par l'utilisateur (aucun PST public de cette taille n'est disponible dans le corpus).

## Exécution du 2026-11-23 (P046)

| Scénario | Résultat |
|---|---|
| Préparation | `fetch.sh` : 9 boîtes téléchargées, empreintes vérifiées ; `cargo test -p mf-pst` : 8 tests réussis |
| 1 — Intégrité | SHA-256 de `mf pst info` identique à `sha256sum` ; 2 178 éléments ; fichier inchangé après lecture |
| 2 — Formats | ANSI, Unicode, liste de distribution, boîte protégée (signalée), OST 2013 et Outlook.com : comptes identiques à libpff |
| 3 — Bureau | Fenêtre Tauri non exécutable dans l'environnement de construction ; la même interface est vérifiée par `npm run test:box` (pont Tauri simulé, données réelles produites par `mf`) et par l'e2e web ; commandes Tauri compilées et testées par les tests du moteur |
| 4 — Web | `npm run test:web` : 0 échec, aucune requête réseau ; mémoire mesurée jusqu'à 8 Go (`research.md` R10) |
| 5 — Export | 10 éléments d'Enron en `.msg` : 10/10 identiques à l'élément (objet, en-têtes de transport, empreintes des PJ) relus par `mf show` ; export dans le dossier de la preuve refusé, rien de créé |
| 6 — Performances | Mesures ci-dessous ; la validation sur une boîte réelle de 5 Go reste à faire (P045, boîte fournie par l'utilisateur) |

`mf pst bench`, binaire `--release` :

| Boîte | Ouverture | Plus gros dossier | Élément ouvert | Filtre sur toute la boîte | Empreinte |
|---|---|---|---|---|---|
| Enron 29 Mo | 8 ms (5 Mo lus) | 846 lignes en 32 ms | 1,8 ms | 104 ms à froid, 1 ms ensuite | 81 ms |
| Gmail 56 Mo | 1,4 ms | 481 lignes en 18 ms | 12 ms | 20 ms | 153 ms |
| 8 Go (Gmail + espace vide) | 3,5 ms (2 Mo lus) | 481 lignes en 33 ms | 9 ms | 25 ms | 24 s |

L'ouverture, la liste et le filtre ne dépendent pas de la taille du fichier ; seule l'empreinte la
parcourt entièrement (en arrière-plan). Le fichier de 8 Go ne contient que 481 éléments : il ne
remplace pas une vraie boîte de 50 000 messages pour SC-003.
