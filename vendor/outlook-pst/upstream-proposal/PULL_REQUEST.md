# Read real-world PST files and Outlook 2013+ OST files

Draft pull request for [microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs),
prepared from the copy of the crate embedded in Email Analysis. **Not submitted**: the maintainer
of Email Analysis decides whether and how to open it (the fixes in the first four sections
come from the `outlook-pst-ost` 1.3.0 fork, MIT; its author may prefer to submit them).

Base: `main` at `cfb721d` (2026-09-14). Patch: `0001-read-real-world-pst-and-ost-2013.patch`
(9 files, +344 / −50). `cargo test -p outlook-pst` passes (11 tests).

## Why

`outlook-pst` 1.2.0 rejects valid files produced by Outlook. On public samples it opens 568 of
the 2,178 messages of an EDRM Enron PST, none of the 71 messages of another one, and no OST
written by Outlook 2013 or later. With this patch, folder, message and attachment counts match
libpff exactly on 14 public PST/OST files (Unicode, ANSI, password-protected, empty, three
Outlook.com OSTs), and every message of them opens.

## Changes

1. **Heap page free count** (`ltp/heap.rs`, `HeapNodePageMap::new`): a heap page whose
   `HNPAGEMAP.cFree` disagrees with the freed entries of its allocation table is accepted.
   `cFree` only counts freed allocations, which reading never uses, and real files carry a
   stale value. Without this, every message of the Enron PSTs fails with
   `InvalidHeapPageFreeCount`.
2. **Messages without a sub-node tree** (`messaging/message.rs`): such a message opens with no
   recipient or attachment table instead of failing with `MessageSubNodeTreeNotFound`. Outlook
   writes messages this way when they have neither (java-libpst's `dist-list.pst`).
3. **OST files from Outlook 2013 and later** (`ndb/header.rs`, `ndb/page.rs`,
   `ndb/block.rs`, `ndb/read_write.rs`, `lib.rs`): the 4 KB page layout (`wVer` 36) and
   zlib-compressed data blocks are read; the decompressed size is bounded by the size announced
   in the block trailer. Writing such files is refused explicitly rather than corrupting them.
4. **`PtypMultipleGuid`** (`ltp/prop_context.rs`): GUIDs are read concatenated, with no
   count in front, like the other fixed-size multi-valued types and as `write` stores them.
5. **`Message::open_attachment`** (new trait method): opens an attachment from an
   `Rc<dyn Message>`, including an embedded message, without knowing whether the file is
   Unicode or ANSI. Useful to walk nested messages generically.

Not included: Email Analysis also opens files strictly read-only (no write handle); that is a
product choice, not a library fix.

## Test files (all public)

| File | Source | Licence |
|---|---|---|
| `enron.pst` (29 MB), `enron-14` (14 MB) | go-pst, pst-extractor (EDRM Enron data set, CC BY 3.0) | Apache-2.0 / MIT |
| `dist-list.pst`, `passworded.pst`, `example-2013.ost` | java-libpst | Apache-2.0 |
| `32-bit.pst`, `support.pst` | go-pst | Apache-2.0 |
| three Outlook.com `.ost` | pst-extractor | MIT |
| Gmail Takeout PSTs | DFIR Artifact Museum | MIT |
| `Empty.pst` | this repository (`crates/pst/examples`) | MIT |

Pinned URLs and SHA-256 are in Email Analysis's `tests/corpus/pst/fetch.sh`; expected counts
from libpff in `tests/corpus/pst/expected.json`.

## Applying

```console
git checkout -b read-real-world-pst cfb721d
git apply 0001-read-real-world-pst-and-ost-2013.patch
cargo test -p outlook-pst
```
