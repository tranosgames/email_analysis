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
    pub fn analyze_step(&mut self, budget_items: usize) -> AnalysisProgress; // FR-006
    pub fn filter(&self, f: &BoxFilter) -> Vec<ItemSummary>;        // FR-007
    pub fn search_step(&mut self, query: &str, budget_items: usize) -> SearchProgress;
    pub fn iocs(&self) -> Vec<Ioc>;                                 // FR-013
    pub fn export_msg(&self, id: u32) -> Result<ExportedFile, EngineError>; // FR-008
    pub fn export_eml(&self, id: u32) -> Result<ExportedFile, EngineError>;
}
```

Les fonctions `*_step` font une quantité bornée de travail et rendent la main : la pause est
l'absence d'appel, l'annulation l'abandon de la recherche. Ainsi le même code sert le thread natif
et le Worker, sans primitives de concurrence.

## Commandes Tauri

| Commande | Retour |
|---|---|
| `box_open(path)` | `{ box_id, store, folders }` |
| `box_list(box_id, folder, offset, limit)` | `ItemSummary[]` |
| `box_item(box_id, id)` | `Analyzed` (comme `open_paths`) |
| `box_filter(box_id, filter)` | `ItemSummary[]` |
| `box_search(box_id, query)` / `box_search_cancel` | événements `box-search` |
| `box_analyze(box_id, run: bool)` | événements `box-progress` `{hash, analysis}` |
| `box_iocs(box_id)` | `IocGroup` |
| `box_export(box_id, ids, format, dest)` | manifeste |
| `box_close(box_id)` | — |

Les événements de progression sont émis au plus 10 fois par seconde.

## Messages du Worker (web)

Mêmes opérations, sous la forme `{ id, kind: "box-open" | "box-list" | … }`. Le fichier (`File`)
est transmis au Worker une fois ; les tranches sont lues de façon synchrone par `FileReaderSync`.
L'export produit un ZIP renvoyé comme `ArrayBuffer` transférable. Aucune requête réseau.
