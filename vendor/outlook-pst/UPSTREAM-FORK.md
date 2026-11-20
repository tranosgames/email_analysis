# outlook-pst-ost

An unofficial copy of Microsoft's [`outlook-pst`](https://crates.io/crates/outlook-pst)
1.2.0 ([microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs),
MIT, see `LICENSE`) with fixes for reading real PST files and support for the
OST layout of Outlook 2013 and later, published so
that [`pst-markdown`](https://crates.io/crates/pst-markdown) can depend on them
from crates.io. It is not maintained by Microsoft. The library name is still
`outlook_pst`, so code written for `outlook-pst` builds unchanged:

```toml
outlook-pst = { package = "outlook-pst-ost", version = "1.3.0" }
```

Versions up to 1.2.0 were published as `outlook-pst-fixed`; from 1.3.0 the
crate is `outlook-pst-ost`, and `outlook-pst-fixed` is no longer updated.

## 1.2.0: two reader fixes

Each is marked `markdown-extract:` in the source:

1. In `src/ltp/heap.rs` (`HeapNodePageMap::new`): a heap page whose
   `HNPAGEMAP.cFree` disagrees with the freed entries in its allocation table
   is accepted instead of failing with `InvalidHeapPageFreeCount`. `cFree` only
   counts freed allocations, which reading never uses, and real files carry a
   stale one: without this, every message in the EDRM Enron PSTs fails to open.
2. In `src/messaging/message.rs` (`MessageInner::read_embedded`): a message
   node with no sub-node tree opens with no recipient or attachment table
   instead of failing with `MessageSubNodeTreeNotFound`. Outlook writes
   messages that way when they have neither (java-libpst's `dist-list.pst`).

Both have been offered upstream.

## 1.3.0: Outlook 2013 OSTs, and two more fixes

Outlook 2013 and later write OSTs in a layout MS-PST does not describe (`wVer`
36, `NdbVersion::Unicode4k`), read here as `UnicodePstFile` and only read:
`lock()` refuses to write one.

- BTree pages are 4 KiB: entries, then `cEnt` and `cEntMax` as two bytes each,
  `cbEnt`, `cLevel` and padding at 4056, and a 24-byte trailer at 4072 whose
  CRC covers the 4072 bytes before it. `read_unicode_btree_page` tells the two
  page sizes apart by where a trailer with a matching CRC sits.
- A block BTree leaf entry carries the block's inflated size where the 512-byte
  layout has `cRef`'s padding (`BlockBTreeEntry::inflated_size`).
- Blocks sit in 512-byte aligned slots with a 24-byte trailer, hold up to
  65512 bytes, and a data block whose inflated size differs from its stored one
  is a zlib stream (`read_4k_block` in `src/ndb/block.rs`).
- The header's `wVerClient` is 12, and an OST's `wMagicClient` is `SO`
  (`0x4F53`), which also failed every OST in the 512-byte layout before.

Checked against the three Outlook-written OSTs in java-libpst and
pst-extractor: every item of each lists and converts.

The other fix: a `PtypMultipleGuid` value was read with a count in front,
which the format does not have (and `write` does not write), so a real OST's
GUID list was taken as a count of 16 GB worth of GUIDs and aborted the process.
It is now read as concatenated GUIDs, like the other fixed-size multi-valued
types.

Once an `outlook-pst` release carries these, `pst-markdown` goes back to it
and this crate is no longer updated.
