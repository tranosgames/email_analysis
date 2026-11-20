# Prototype : lire un PST dans le navigateur, sans serveur

Question : peut-on ouvrir une boîte Outlook `.pst` dans la version web, sans l'envoyer à un serveur
et sans la charger entièrement en mémoire ?

Principe : un PST est une base de données à accès aléatoire. Le Worker lit **uniquement les tranches
demandées** du fichier (`File.slice` + `FileReaderSync`) ; la bibliothèque `outlook-pst` (Microsoft)
accepte n'importe quelle source `Read + Seek`, ici un lecteur paginé (pages de 512 Ko, cache 8 Mo).
Le même code est mesuré en natif et compilé en WebAssembly.

Le test parcourt **toute** la boîte : chaque dossier, chaque message ouvert avec toutes ses
propriétés, et la table des pièces jointes.

## Mesures (2026-11-20)

Jeu de test : 3 PST issus d'un export Google Takeout converti (DFIR Artifact Museum, licence MIT,
non inclus ici). Format Unicode, aucun ne contient de pièce jointe.

| Fichier | Messages | Natif | Navigateur (Chromium) | Mémoire navigateur |
|---|---|---|---|---|
| 16 Mo | 256 | 38 ms | 262–290 ms | 11 Mo |
| 16 Mo | 238 | 37 ms | 265–266 ms | 11 Mo |
| 56 Mo | 481 | 97–107 ms | 437–471 ms | 11 Mo |

Deux passages chacun ; le temps navigateur inclut l'ouverture de la boîte.

Taille des pages (PST de 56 Mo, navigateur) : 64 Ko → 976 ms (897 lectures, 80 % du temps en
lectures) ; **512 Ko → 437 ms** (161 lectures) ; 1 Mo → 509 ms.

Constats :

- ça fonctionne : 0 erreur, mêmes résultats qu'en natif ;
- la mémoire reste faible et **ne dépend pas de la taille du fichier** (cache borné) ;
- le navigateur est environ **4 à 7 fois plus lent** que le natif (l'écart diminue avec la taille), surtout à cause des lectures ;
- le moteur PST compilé pèse 0,8 Mo.

Extrapolation, **non mesurée** : environ 1 ms par message ouvert dans le navigateur, soit de l'ordre
d'une minute pour parcourir intégralement 50 000 messages (contre une dizaine de secondes en natif).
Afficher la liste d'un dossier ne demande pas d'ouvrir chaque message : c'est bien plus rapide.
Reste à valider sur un PST volumineux, avec pièces jointes, et sur un PST ANSI (Outlook 97-2002).

## Robustesse sur d'autres échantillons (2026-11-20)

Échantillons publics trouvés sur GitHub, dans les jeux de test de projets de lecture PST
(licences MIT et Apache-2.0, non inclus ici), comparés au lecteur de référence libpff :

| Fichier | Format | libpff | outlook-pst 1.2 | outlook-pst corrigé | Natif | Navigateur |
|---|---|---|---|---|---|---|
| enron.pst (29 Mo) | Unicode | 2 178 messages, 168 PJ | 568 messages | **2 178, 168 PJ** | 87 ms | 692 ms |
| enron.pst (14 Mo) | Unicode | 71 messages, 70 PJ | 0 | **71, 70 PJ** | 7 ms | 67 ms |
| support.pst (1 Mo) | Unicode | 17, 2 PJ | 17 | 17, 2 PJ | 3 ms | 36 ms |
| dist-list.pst | Unicode | 4 (1 erreur) | 2 | 3 | < 1 ms | 6 ms |
| 32-bit.pst | **ANSI** | 1 | 1 | 1 | < 1 ms | 9 ms |
| 3 fichiers `.ost` (Outlook 2013+) | OST | lus | **refusés** | **refusés** | — | — |

La bibliothèque de Microsoft rejetait des fichiers valides à cause de deux contrôles trop stricts :
un compteur d'espace libre (utile seulement à l'écriture) et l'absence de sous-nœuds pour un message
sans destinataires ni pièces jointes stockés à part. Le correctif `outlook-pst-tolerance.patch`
(une vingtaine de lignes) les assouplit : les résultats rejoignent alors ceux de libpff.
**Les fichiers OST récents ne sont pas pris en charge** par cette bibliothèque (variante à pages de
4 Ko) : il faudra l'ajouter.

Sur Enron (2 178 messages), le navigateur met 0,32 ms par message, soit environ 16 s pour un
parcours complet de 50 000 messages (extrapolation), contre 2 s en natif.

## Reproduire

```console
cargo build --release --bin native
./target/release/native boite.pst

RUSTC_BOOTSTRAP=1 cargo build --release --lib --target wasm32-unknown-unknown -Zbuild-std=std,panic_abort
wasm-bindgen --target web --out-dir web target/wasm32-unknown-unknown/release/pstbench.wasm
python3 run.py web boite.pst
```
