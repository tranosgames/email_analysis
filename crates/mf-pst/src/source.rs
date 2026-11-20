//! Sources d'octets à accès aléatoire et lecteur paginé (R1).
//!
//! La boîte n'est jamais chargée en entier : la bibliothèque PST demande des positions précises,
//! servies par pages de 512 Ko gardées dans un petit cache (8 Mo). Le même lecteur sert le fichier
//! natif et, dans le navigateur, un `Blob` lu par tranches.

use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom};
use std::rc::Rc;

/// Source d'octets en lecture seule.
pub trait ByteSource {
    fn len(&self) -> u64;
    /// Lit à partir de `offset` ; retourne le nombre d'octets lus (moins en fin de source).
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Fichier natif, ouvert en lecture seule.
pub struct FileSource {
    file: std::fs::File,
    len: u64,
}

impl FileSource {
    pub fn open(path: &std::path::Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl ByteSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut done = 0;
        while done < buf.len() {
            match self.file.read(&mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }
}

/// Octets en mémoire (tests, petits fichiers).
pub struct MemSource(pub Vec<u8>);

impl ByteSource for MemSource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.0.len());
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }
}

/// Compteurs de lecture, partagés avec la session (mesures, tests).
#[derive(Debug, Default)]
pub struct ReadStats {
    pub page_reads: Cell<u64>,
    pub bytes_read: Cell<u64>,
}

pub const PAGE: u64 = 512 * 1024;
const CACHE_PAGES: usize = 16;

/// Lecteur `Read + Seek` paginé au-dessus d'une [`ByteSource`].
pub struct Paged {
    src: Box<dyn ByteSource>,
    len: u64,
    pos: u64,
    /// Pages en cache, la plus récente en dernier.
    pages: Vec<(u64, Vec<u8>)>,
    stats: Rc<ReadStats>,
}

impl Paged {
    pub fn new(src: Box<dyn ByteSource>, stats: Rc<ReadStats>) -> Self {
        let len = src.len();
        Self {
            src,
            len,
            pos: 0,
            pages: Vec::with_capacity(CACHE_PAGES),
            stats,
        }
    }

    fn page(&mut self, n: u64) -> io::Result<&[u8]> {
        if let Some(i) = self.pages.iter().position(|(p, _)| *p == n) {
            let e = self.pages.remove(i);
            self.pages.push(e);
        } else {
            let start = n * PAGE;
            let len = usize::try_from(PAGE.min(self.len.saturating_sub(start))).unwrap_or(0);
            let mut buf = vec![0u8; len];
            let got = self.src.read_at(start, &mut buf)?;
            buf.truncate(got);
            self.stats.page_reads.set(self.stats.page_reads.get() + 1);
            self.stats
                .bytes_read
                .set(self.stats.bytes_read.get() + got as u64);
            if self.pages.len() >= CACHE_PAGES {
                self.pages.remove(0);
            }
            self.pages.push((n, buf));
        }
        Ok(self.pages.last().map_or(&[][..], |(_, b)| b.as_slice()))
    }
}

impl Read for Paged {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || out.is_empty() {
            return Ok(0);
        }
        let n = self.pos / PAGE;
        let off = usize::try_from(self.pos % PAGE).unwrap_or(0);
        let page = self.page(n)?;
        let k = out.len().min(page.len().saturating_sub(off));
        out[..k].copy_from_slice(&page[off..off + k]);
        self.pos += k as u64;
        Ok(k)
    }
}

impl Seek for Paged {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "position négative"))?;
        Ok(self.pos)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_across_pages_and_at_end() {
        let data: Vec<u8> = (0..(PAGE as usize * 2 + 100))
            .map(|i| (i % 251) as u8)
            .collect();
        let stats = Rc::new(ReadStats::default());
        let mut r = Paged::new(Box::new(MemSource(data.clone())), stats.clone());
        // À cheval sur deux pages.
        r.seek(SeekFrom::Start(PAGE - 10)).unwrap();
        let mut buf = [0u8; 20];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[PAGE as usize - 10..PAGE as usize + 10]);
        // Fin de fichier : lecture partielle puis 0.
        r.seek(SeekFrom::End(-5)).unwrap();
        let mut tail = Vec::new();
        r.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, &data[data.len() - 5..]);
        assert!(r.seek(SeekFrom::Current(-(data.len() as i64) - 1)).is_err());
        assert_eq!(stats.page_reads.get(), 3);
    }
}
