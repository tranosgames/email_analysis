# Data Model: Lecture forensic des boîtes PST/OST

**Feature**: `002-pst-support` · **Date**: 2026-11-20

Les entités de la feature 001 (`Evidence`, `Message`, `Attachment`, `Finding`, `Verdict`,
`Ioc`…) sont réutilisées telles quelles. Ajouts :

## ByteSource *(trait, `mf-pst`)*

Source d'octets à accès aléatoire, en lecture seule.

| Méthode | Rôle |
|---|---|
| `len() -> u64` | taille du fichier |
| `read_at(offset, buf) -> usize` | lecture d'une tranche |

Implémentations : `FileSource` (natif, `pread`), `BlobSource` (web, `FileReaderSync` sur
`File.slice`), `MemSource` (tests). Le **lecteur paginé** (`Read + Seek`) l'enveloppe : pages de
512 Ko, cache LRU de 16 pages (8 Mo), compteurs de lectures.

## Store *(boîte)*

| Champ | Type | Note |
|---|---|---|
| `evidence` | `Evidence` | nom, taille, empreintes (renseignées à la fin du calcul en flux) |
| `format` | `unicode` \| `ansi` \| `ost4k` | |
| `encoding` | `none` \| `permute` \| `cyclic` | méthode d'encodage NDB |
| `password_protected` | bool | `PR_PST_PASSWORD` non nul : signalé, ne bloque pas |
| `display_name` | string | nom de la boîte |
| `root` | `FolderId` | racine de l'arborescence IPM |
| `stats` | `{folders, items, unreadable}` | mis à jour au fil du parcours |
| `unreadable` | `[UnreadableItem]` | éléments ou dossiers illisibles (FR-009) |

## Folder

| Champ | Type | Note |
|---|---|---|
| `id` | `u32` | identifiant de nœud (NID) |
| `name` | string | |
| `path` | `[string]` | du sommet IPM jusqu'au dossier |
| `kind` | `inbox` \| `sent` \| `deleted` \| `drafts` \| `junk` \| `other` | d'après les identifiants de dossiers spéciaux de la boîte |
| `container_class` | string? | `IPF.Note`, `IPF.Appointment`… |
| `item_count`, `unread_count` | u32 | |
| `children` | `[FolderId]` | |

## ItemSummary *(ligne de liste, lue dans la table du dossier ; ≈ 0,5 Ko)*

| Champ | Type | Note |
|---|---|---|
| `id` | `u32` | NID de l'élément |
| `folder` | `FolderId` | |
| `message_class` | string | `IPM.Note`, `IPM.Appointment`… |
| `subject` | string | `0x0037` |
| `from_name` | string | nom affiché, `0x0042` (l'adresse n'est pas dans la table) |
| `to`, `cc` | string | destinataires affichés, `0x0E04`, `0x0E03` |
| `sent`, `received` | date UTC ? | `0x0039`, `0x0E06` |
| `size` | u32 | `0x0E08` |
| `has_attachments` | bool | drapeau de `0x0E07` |
| `message_id` | string? | `0x1035` |
| `from_address` | string? | renseignée quand le message a été ouvert |
| `verdict` | `VerdictLevel?` | renseigné quand le message a été ouvert |

## Provenance

Ajoutée à `Message` pour un élément issu d'une boîte.

| Champ | Type |
|---|---|
| `store_sha256` | string (vide tant que l'empreinte est en cours) |
| `store_name` | string |
| `folder_path` | `[string]` |
| `node_id` | u32 |

Affichée sous la forme `boite.pst › Boîte de réception › Fournisseurs` ; citée dans le rapport,
les indicateurs et le manifeste d'export.

## BoxIndex *(session)*

`ItemSummary` des dossiers déjà listés (tables lues à la demande) + `Analyzed` des seuls messages
ouverts (verdict, indicateurs avec provenances). Aucune lecture de message en arrière-plan.

**Filtre** (`BoxFilter`) : `from_name`, `to`, `subject`, `message_id`, `after`, `before`,
`min_size`, `max_size`, `has_attachments`, `folder?` (sinon toute la boîte) — lus dans les tables ;
`analyzed_only`, `verdict[]`, `from_address`, `from_domain` — sur les messages ouverts. Tous
combinés en ET ; texte insensible à la casse et aux accents.

## UnreadableItem

| Champ | Type |
|---|---|
| `node_id` | u32 |
| `folder_path` | `[string]` |
| `kind` | `folder` \| `item` \| `attachment` |
| `reason` | string (erreur de la bibliothèque, traduite) |

## Export

**ExportRequest** : `ids[]`, `format` (`msg` \| `eml`), `destination` (natif) ou ZIP (web).

**Manifeste** (`manifest.json` + `manifest.csv`) :

| Champ | Note |
|---|---|
| `generated_utc`, `tool_version` | |
| `store` | nom, taille, SHA-256 et MD5 de la boîte, **revérifiés** au moment de l'export |
| `items[]` | `node_id`, `folder_path`, `file`, `format`, `nature` (`original_properties` pour `.msg`, `reconstructed` pour `.eml`), `sha256` et `md5` du fichier produit, pièces jointes (nom, SHA-256) |

## Limites (protection contre les fichiers piégés)

| Élément | Limite |
|---|---|
| Profondeur de l'arborescence | 64 |
| Propriété texte ou binaire chargée | 64 Mo |
| Pièce jointe chargée pour analyse | 64 Mo (au-delà : empreinte en flux, analyse du type seulement) |
| Messages embarqués en cascade | 8 niveaux |
| Cache de pages | 8 Mo |
