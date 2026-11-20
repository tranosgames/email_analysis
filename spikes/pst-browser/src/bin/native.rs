use pstbench::*;
use std::cell::Cell;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::rc::Rc;
use std::time::Instant;

struct FileSource(File, u64);
impl Source for FileSource {
    fn len(&self) -> u64 { self.1 }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize {
        self.0.read_at(buf, offset).unwrap_or(0)
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("chemin du PST");
    let size = std::fs::metadata(&path).unwrap().len();
    let stats = Rc::new(Stats { calls: Cell::new(0), bytes: Cell::new(0) });
    let t = Instant::now();
    let p = path.clone();
    let r = run(move || FileSource(File::open(&p).unwrap(), size), stats.clone()).unwrap();
    let ms = t.elapsed().as_millis();
    let mut ru: libc_rusage = unsafe { std::mem::zeroed() };
    unsafe { getrusage(0, &mut ru) };
    println!(
        "{path}\n  format {} · {} Mo · {} dossiers · {} messages ({} avec corps, {} erreurs) · {} pièces jointes · {} propriétés\n  {} ms · {} lectures · {:.1} Mo lus · mémoire max {:.1} Mo",
        r.format, size / 1_000_000, r.folders, r.messages, r.with_body, r.errors, r.attachments, r.properties,
        ms, stats.calls.get(), stats.bytes.get() as f64 / 1e6, ru.maxrss as f64 / 1024.0
    );
}

#[repr(C)]
struct libc_rusage { utime: [i64; 2], stime: [i64; 2], maxrss: i64, rest: [i64; 13] }
extern "C" { fn getrusage(who: i32, usage: *mut libc_rusage) -> i32; }
