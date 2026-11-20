//! Prototype : parcours complet d'un PST à travers un lecteur à accès aléatoire paginé, pour
//! mesurer le coût en natif et dans le navigateur (lecture par morceaux d'un Blob).
use outlook_pst::{
    messaging::store::{AnsiStore, Store, UnicodeStore},
    ndb::node_id::NodeId,
    AnsiPstFile, UnicodePstFile,
};
use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom};
use std::rc::Rc;

/// Source d'octets à accès aléatoire (fichier natif ou Blob du navigateur).
pub trait Source {
    fn len(&self) -> u64;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize;
}

pub struct Stats {
    pub calls: Cell<u64>,
    pub bytes: Cell<u64>,
}

/// Lecteur paginé (pages de 512 Ko, cache LRU de 8 Mo) au-dessus d'une `Source`.
pub struct Paged<S: Source> {
    src: S,
    pos: u64,
    pages: Vec<(u64, Vec<u8>)>,
    stats: Rc<Stats>,
}

const PAGE: u64 = 512 * 1024;
const CACHE: usize = 16; // 8 Mo

impl<S: Source> Paged<S> {
    pub fn new(src: S, stats: Rc<Stats>) -> Self {
        Self { src, pos: 0, pages: Vec::new(), stats }
    }
    fn page(&mut self, n: u64) -> &[u8] {
        if let Some(i) = self.pages.iter().position(|(p, _)| *p == n) {
            let e = self.pages.remove(i);
            self.pages.push(e);
        } else {
            let start = n * PAGE;
            let len = PAGE.min(self.src.len().saturating_sub(start)) as usize;
            let mut buf = vec![0u8; len];
            let got = self.src.read_at(start, &mut buf);
            buf.truncate(got);
            self.stats.calls.set(self.stats.calls.get() + 1);
            self.stats.bytes.set(self.stats.bytes.get() + got as u64);
            if self.pages.len() >= CACHE {
                self.pages.remove(0);
            }
            self.pages.push((n, buf));
        }
        &self.pages.last().unwrap().1
    }
}

impl<S: Source> Read for Paged<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.src.len() || out.is_empty() {
            return Ok(0);
        }
        let n = self.pos / PAGE;
        let off = (self.pos % PAGE) as usize;
        let p = self.page(n);
        let k = out.len().min(p.len().saturating_sub(off));
        out[..k].copy_from_slice(&p[off..off + k]);
        self.pos += k as u64;
        Ok(k)
    }
}

impl<S: Source> Seek for Paged<S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => (self.src.len() as i64 + d) as u64,
            SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
        };
        Ok(self.pos)
    }
}

pub struct Report {
    pub format: &'static str,
    pub folders: u64,
    pub messages: u64,
    pub with_body: u64,
    pub attachments: u64,
    pub properties: u64,
    pub errors: u64,
}

fn walk(store: Rc<dyn Store>, r: &mut Report) -> io::Result<()> {
    let root = store.properties().ipm_sub_tree_entry_id()?;
    let mut todo = vec![store.open_folder(&root)?];
    while let Some(f) = todo.pop() {
        r.folders += 1;
        if let Some(h) = f.hierarchy_table() {
            for row in h.rows_matrix() {
                let id = store.properties().make_entry_id(NodeId::from(u32::from(row.id())))?;
                match store.open_folder(&id) {
                    Ok(sub) => todo.push(sub),
                    Err(_) => r.errors += 1,
                }
            }
        }
        if let Some(c) = f.contents_table() {
            for row in c.rows_matrix() {
                let id = store.properties().make_entry_id(NodeId::from(u32::from(row.id())))?;
                match store.open_message(&id, None) {
                    Ok(m) => {
                        r.messages += 1;
                        let p = m.properties();
                        r.properties += p.iter().count() as u64;
                        if p.get(0x1000).is_some() || p.get(0x1013).is_some() || p.get(0x1009).is_some() {
                            r.with_body += 1;
                        }
                        if let Some(a) = m.attachment_table() {
                            r.attachments += a.rows_matrix().count() as u64;
                        }
                    }
                    Err(e) => {
                        r.errors += 1;
                        if r.errors <= 3 && std::env::var("PST_DEBUG").is_ok() {
                            eprintln!("  erreur message : {e:?}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Parcourt toute la boîte : dossiers, messages (toutes propriétés), tables de pièces jointes.
pub fn run<S: Source + 'static>(make: impl Fn() -> S, stats: Rc<Stats>) -> io::Result<Report> {
    let mut r = Report { format: "unicode", folders: 0, messages: 0, with_body: 0, attachments: 0, properties: 0, errors: 0 };
    let store: Rc<dyn Store> = match UnicodePstFile::read_from(Box::new(Paged::new(make(), stats.clone()))) {
        Ok(f) => UnicodeStore::read(Rc::new(f))?,
        Err(_) => {
            r.format = "ansi";
            AnsiStore::read(Rc::new(AnsiPstFile::read_from(Box::new(Paged::new(make(), stats.clone())))?))?
        }
    };
    walk(store, &mut r)?;
    Ok(r)
}

#[cfg(target_arch = "wasm32")]
mod web {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        /// Fournie par le Worker : lecture synchrone d'une tranche du Blob (FileReaderSync).
        #[wasm_bindgen(js_namespace = globalThis, js_name = pstReadAt)]
        fn pst_read_at(offset: f64, len: u32) -> js_sys::Uint8Array;
    }

    struct BlobSource(u64);
    impl Source for BlobSource {
        fn len(&self) -> u64 { self.0 }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize {
            let a = pst_read_at(offset as f64, buf.len() as u32);
            let n = (a.length() as usize).min(buf.len());
            a.subarray(0, n as u32).copy_to(&mut buf[..n]);
            n
        }
    }

    #[wasm_bindgen]
    pub fn bench(size: f64) -> String {
        let stats = Rc::new(Stats { calls: Cell::new(0), bytes: Cell::new(0) });
        let size = size as u64;
        match run(move || BlobSource(size), stats.clone()) {
            Ok(r) => format!(
                r#"{{"format":"{}","folders":{},"messages":{},"with_body":{},"attachments":{},"properties":{},"errors":{},"read_calls":{},"bytes_read":{}}}"#,
                r.format, r.folders, r.messages, r.with_body, r.attachments, r.properties, r.errors, stats.calls.get(), stats.bytes.get()
            ),
            Err(e) => format!(r#"{{"error":"{e}"}}"#),
        }
    }
}
