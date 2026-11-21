# Corpus PST / OST

Boîtes Outlook publiques servant aux tests de `crates/mf-pst` (feature 002). Les valeurs de
référence (`expected.json` : par fichier, encodage, nombres d'éléments et de pièces jointes, et
par dossier) sont produites par **libpff**, lecteur indépendant, avec `oracle.py`.

## Versionnés ici

| Fichier | Origine | Licence | SHA-256 | Intérêt |
|---|---|---|---|---|
| `32-bit.pst` | go-pst (`data/32-bit.pst`) | Apache-2.0 | `e1d6fc71…0b63` | format **ANSI** (Outlook 97-2002) |
| `support.pst` | go-pst (`data/support.pst`) | Apache-2.0 | `5872c9ae…1a7c` | petit PST Unicode, 17 éléments, 2 pièces jointes |
| `dist-list.pst` | java-libpst (`src/test/resources`) | Apache-2.0 | `c86841da…ac` | liste de diffusion : message **sans sous-nœuds** |
| `passworded.pst` | java-libpst (`src/test/resources`) | Apache-2.0 | `e1085e21…f217` | PST **protégé par mot de passe** |
| `empty.pst` | Microsoft outlook-pst-rs (`crates/pst/examples/Empty.pst`, commit `cfb721da`) | MIT | `c16ae985…d5c5` | boîte **vide** créée par Outlook : 0 élément |

## Téléchargés par `fetch.sh` (dans `large/`, ignoré par git)

| Fichier | Origine | Licence | Taille | Intérêt |
|---|---|---|---|---|
| `enron-29.pst` | go-pst (`data/enron.pst`) | Apache-2.0 | 29 Mo | 2 178 éléments, 168 pièces jointes, données réelles |
| `enron-14.pst` | pst-extractor (`src/__tests__/testdata`) | MIT | 14 Mo | 71 éléments, 70 pièces jointes |
| `example-2013.ost` | java-libpst | Apache-2.0 | 16 Mo | **OST Outlook 2013** (pages de 4 Ko) |
| `outlook-com-a.ost`, `outlook-com-b.ost` | pst-extractor | MIT | 16 Mo | OST Outlook.com, blocs compressés |
| `outlook-com-c.ost` | pst-extractor (`example/testdata`, compte « pdf ») | MIT | 16 Mo | OST Outlook.com, 53 dossiers, 162 éléments, 12 pièces jointes |
| `gmail-takeout-56.pst` | DFIR Artifact Museum (export Google Takeout converti) | MIT | 56 Mo | 481 éléments |
| `gmail-takeout-16a.pst`, `gmail-takeout-16b.pst` | DFIR Artifact Museum (même boîte, exports du 2024-11-02) | MIT | 16 Mo | 238 et 256 éléments ; objets avec guillemets typographiques (a révélé un plantage de l'analyse des entités HTML) |

Les URL pointent vers des commits figés et chaque empreinte est vérifiée au téléchargement.
Les tests qui dépendent de ces fichiers sont ignorés tant qu'ils sont absents. Pour ouvrir et analyser
**tous** leurs éléments (≈ 3 800) : `cargo test --release -p mf-engine --test mailbox -- --ignored`.

## Régénérer les valeurs de référence

```console
pip install libpff-python
sh tests/corpus/pst/fetch.sh
python3 -I tests/corpus/pst/oracle.py > tests/corpus/pst/expected.json
```
