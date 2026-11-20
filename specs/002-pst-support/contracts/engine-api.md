# Contrat — API du moteur pour les boîtes

Une **session de boîte** par fichier ouvert. En natif, elle vit sur un thread de travail dédié
(les objets `outlook-pst` ne sont pas `Send`) et communique par messages ; sur le web, dans le
Worker. L'interface ne voit que des types sérialisables du data-model.

## API Rust (`mf-engine`)

```rust
pub fn open_box(source: Box<dyn ByteSource>, name: &str) -> Result<BoxSession, EngineError>;

impl BoxSession {
    pub fn store(&self) -> &Store;                                  // FR-001, FR-012
    pub fn folders(&self) -> Vec<Folder>;                           // FR-003
    pub fn list(&self, folder: FolderId, offset: usize, limit: usize) -> Vec<ItemSummary>;
    pub fn open_item(&self, id: u32, keys: &Keyring) -> Result<Analyzed, EngineError>; // FR-004, FR-005
    pub fn hash_step(&mut self, budget_bytes: u64) -> HashProgress; // FR-002, appelé en boucle
    pub fn filter(&mut self, f: &BoxFilter) -> Vec<ItemSummary>;    // FR-007 : tables de dossiers seulement
    pub fn analyzed(&self) -> Vec<u32>;                             // messages déjà ouverts
    pub fn iocs(&self) -> Vec<Ioc>;                                 // FR-013 : messages ouverts
    pub fn export_msg(&self, id: u32) -> Result<ExportedFile, EngineError>; // FR-008
    pub fn export_eml(&self, id: u32) -> Result<ExportedFile, EngineError>;
}
```

`open_item` est le seul appel qui lit un message (FR-006) ; son résultat est gardé pour la session.
`hash_step` fait une quantité bornée de travail et rend la main, pour que le calcul d'empreinte ne
bloque ni le thread natif ni le Worker.

## Commandes Tauri

| Commande | Retour |
|---|---|
| `box_open(path)` | `{ box_id, store, folders }` |
| `box_list(box_id, folder, offset, limit)` | `ItemSummary[]` |
| `box_item(box_id, id)` | `Analyzed` (comme `open_paths`) |
| `box_filter(box_id, filter)` | `ItemSummary[]` |
| `box_iocs(box_id)` | `IocGroup` (messages ouverts) |

Progression de l'empreinte : événement `box-hash` `{done, total}`.
| `box_export(box_id, ids, format, dest)` | manifeste |
| `box_close(box_id)` | — |

Les événements de progression sont émis au plus 10 fois par seconde.

## Messages du Worker (web)

Mêmes opérations, sous la forme `{ id, kind: "box-open" | "box-list" | … }`. Le fichier (`File`)
est transmis au Worker une fois ; les tranches sont lues de façon synchrone par `FileReaderSync`.
L'export produit un ZIP renvoyé comme `ArrayBuffer` transférable. Aucune requête réseau.
