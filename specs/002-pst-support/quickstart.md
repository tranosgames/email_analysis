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
3. Laisser l'analyse de la boîte se terminer ; filtrer « Malveillant » puis « avec pièce jointe » :
   résultat conforme à la liste annotée `tests/corpus/pst/expected.json`.
4. Rechercher un mot connu du corps d'un message : il est trouvé ; annuler une recherche en cours.

## Scénario 4 — Version web (US1, US2, SC-004)

`npm run test:web` : mêmes étapes que le scénario 3 dans Chromium ; aucune requête réseau ;
mémoire de l'onglet sous 300 Mo ; résultats identiques à l'application de bureau.

## Scénario 5 — Export (US3, SC-006)

```console
mf pst export enron-29.pst --filter "attachments" --out /tmp/pieces --format msg
mf show /tmp/pieces/*.msg --json        # champs, en-têtes de transport, empreintes des PJ identiques
mf pst export enron-29.pst --id … --out /tmp/pieces-dans-la-preuve   # refusé si dans le dossier de la preuve
```

## Scénario 6 — Performances (SC-003)

`mf pst bench <grosse boîte>` en natif ; mesure équivalente dans la page web : arborescence < 10 s
(5 Go), parcours < 1 min natif / 3 min web pour 50 000 messages. À exécuter sur une boîte fournie
par l'utilisateur (aucun PST public de cette taille n'est disponible dans le corpus).
