//! Empreinte d'une boîte en flux (R7) : SHA-256 et MD5 par blocs, par pas bornés pour ne bloquer
//! ni le thread de la session ni le Worker du navigateur.

use crate::source::ByteSource;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::io;

const CHUNK: usize = 8 * 1024 * 1024;

pub struct StreamHasher {
    sha: Sha256,
    md5: Md5,
    done: u64,
    total: u64,
    buf: Vec<u8>,
}

/// Résultat final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    pub sha256: String,
    pub md5: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl StreamHasher {
    pub fn new(total: u64) -> Self {
        Self {
            sha: Sha256::new(),
            md5: Md5::new(),
            done: 0,
            total,
            buf: Vec::new(),
        }
    }

    pub fn progress(&self) -> (u64, u64) {
        (self.done, self.total)
    }

    /// Ajoute des octets lus ailleurs (flux du navigateur), s'ils commencent exactement là où
    /// le calcul en est ; sinon rien n'est fait et l'appelant reprend à `progress().0`.
    pub fn feed(&mut self, offset: u64, data: &[u8]) -> Option<Digests> {
        if offset != self.done || self.done >= self.total {
            return None;
        }
        let take = usize::try_from((self.total - self.done).min(data.len() as u64)).unwrap_or(0);
        self.sha.update(&data[..take]);
        self.md5.update(&data[..take]);
        self.done += take as u64;
        (self.done >= self.total).then(|| Digests {
            sha256: hex(&std::mem::take(&mut self.sha).finalize()),
            md5: hex(&std::mem::take(&mut self.md5).finalize()),
        })
    }

    /// Lit au plus `budget` octets ; retourne les empreintes une fois le fichier entièrement lu.
    pub fn step(&mut self, src: &mut dyn ByteSource, budget: u64) -> io::Result<Option<Digests>> {
        let end = self.total.min(self.done.saturating_add(budget.max(1)));
        while self.done < end {
            let n = usize::try_from((end - self.done).min(CHUNK as u64)).unwrap_or(CHUNK);
            self.buf.resize(n, 0);
            let got = src.read_at(self.done, &mut self.buf[..n])?;
            if got == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fichier raccourci pendant le calcul d'empreinte",
                ));
            }
            self.sha.update(&self.buf[..got]);
            self.md5.update(&self.buf[..got]);
            self.done += got as u64;
        }
        if self.done < self.total {
            return Ok(None);
        }
        Ok(Some(Digests {
            sha256: hex(&std::mem::take(&mut self.sha).finalize()),
            md5: hex(&std::mem::take(&mut self.md5).finalize()),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod feed_tests {
    use super::*;
    use crate::source::MemSource;

    #[test]
    fn feed_matches_step_and_resyncs() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
        let want = digests(&mut MemSource(data.clone())).unwrap();
        let mut h = StreamHasher::new(data.len() as u64);
        assert!(h.feed(0, &data[..1000]).is_none());
        // Mauvaise position : ignorée, la progression ne bouge pas.
        assert!(h.feed(5000, &data[5000..6000]).is_none());
        assert_eq!(h.progress().0, 1000);
        // Un pas lu par la source avance aussi ; le flux reprend où il faut.
        assert!(
            h.step(&mut MemSource(data.clone()), 500_000)
                .unwrap()
                .is_none()
        );
        let at = h.progress().0 as usize;
        let got = h.feed(at as u64, &data[at..]).unwrap();
        assert_eq!(got, want);
    }
}

/// Empreinte complète d'une source.
pub fn digests(src: &mut dyn ByteSource) -> io::Result<Digests> {
    let mut h = StreamHasher::new(src.len());
    loop {
        if let Some(d) = h.step(src, u64::MAX)? {
            return Ok(d);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    #[test]
    fn stepwise_equals_one_shot() {
        let data: Vec<u8> = (0..20_000_000u32).map(|i| (i % 253) as u8).collect();
        let mut src = MemSource(data.clone());
        let mut h = StreamHasher::new(src.len());
        let mut steps = 0;
        let d = loop {
            steps += 1;
            if let Some(d) = h.step(&mut src, 3_000_000).unwrap() {
                break d;
            }
        };
        assert_eq!(steps, 7);
        assert_eq!(d.sha256, hex(&Sha256::digest(&data)));
        assert_eq!(d.md5, hex(&Md5::digest(&data)));
    }
}
