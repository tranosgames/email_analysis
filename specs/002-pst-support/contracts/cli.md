# Contrat CLI — `mf pst`

Sous-commandes de `mf` pour les boîtes `.pst` / `.ost` (FR-010). Mêmes conventions que la
feature 001 : lecture seule, `--json` sur toutes les commandes, codes de sortie `0` succès,
`1` usage, `2` boîte illisible, `3` divergence d'empreinte, `4` erreur d'écriture de l'export.
Les éléments se désignent par leur identifiant de nœud (`--id 2097188`) ; un dossier par son
identifiant ou son chemin (`--folder "Boîte de réception/Fournisseurs"`).

| Commande | Description | FR |
|---|---|---|
| `mf pst info <boîte>` | Format, encodage, protection, empreintes (calcul en flux), statistiques, éléments illisibles | FR-001, FR-002, FR-009, FR-012 |
| `mf pst tree <boîte>` | Arborescence des dossiers avec compteurs | FR-003 |
| `mf pst ls <boîte> [--folder …] [filtres]` | Résumés des éléments (`ItemSummary`) ; filtres : `--verdict malicious,suspicious --from … --to … --domain … --subject … --after 2026-09-01 --before … --attachments [--attachment-kind exe,html]` | FR-005, FR-007 |
| `mf pst show <boîte> --id <nid> [--headers]` | Élément complet, comme `mf show`, avec sa provenance | FR-004, FR-005 |
| `mf pst analyze <boîte> [--depth quick\|full] [filtres]` | Analyse de toute la boîte (ou du filtre) : verdicts et constats, progression sur stderr | FR-006 |
| `mf pst grep <boîte> <texte> [--folder …]` | Recherche dans le corps, objet et noms de pièces jointes | FR-007 |
| `mf pst iocs <boîte> [--format csv\|json] [--defang]` | Indicateurs de toute la boîte avec provenances | FR-013 |
| `mf pst export <boîte> --id 1,2,3 \| --filter … --out <dossier> [--format msg\|eml]` | Export + `manifest.json` / `manifest.csv` ; refuse le dossier de la preuve et un dossier non vide | FR-008 |
| `mf pst report <boîte> --id <nid> --out <rapport>` | Rapport d'un élément (comme `mf report`), provenance incluse | FR-005 |
| `mf pst bench <boîte>` | Parcours complet chronométré (lectures, octets, mémoire) : mesure de SC-003 | — |

Les options `--keys` (signatures, feature 001) s'appliquent à `show`, `analyze --depth full` et `report`.

## Exemples

```console
$ mf pst info enron.pst
enron.pst — PST Unicode, encodage permute, 29,0 Mo
  sha256 …  md5 …
  15 dossiers · 2 178 éléments · 0 illisible

$ mf pst ls enron.pst --folder "Inbox" --attachments --json | jq length
$ mf pst analyze enron.pst --json > verdicts.json
$ mf pst export enron.pst --filter "verdict=malicious" --out ./pieces --format msg
12 éléments → ./pieces (manifest.json, manifest.csv) ; empreinte de la boîte revérifiée
```
