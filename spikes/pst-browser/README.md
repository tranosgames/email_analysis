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

## Reproduire

```console
cargo build --release --bin native
./target/release/native boite.pst

RUSTC_BOOTSTRAP=1 cargo build --release --lib --target wasm32-unknown-unknown -Zbuild-std=std,panic_abort
wasm-bindgen --target web --out-dir web target/wasm32-unknown-unknown/release/pstbench.wasm
python3 run.py web boite.pst
```
