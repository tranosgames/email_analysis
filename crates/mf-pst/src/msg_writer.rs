//! Écriture d'un `.msg` (MS-OXMSG) à partir d'un élément de boîte (feature 002, FR-008).
//!
//! Un message PST et un `.msg` portent le même modèle de propriétés MAPI : les propriétés sont
//! reprises telles quelles, avec destinataires, pièces jointes et messages joints. Les propriétés
//! nommées (identifiants ≥ 0x8000) gardent leur identifiant : la table des noms de la boîte est
//! copiée telle quelle dans `__nameid_version1.0`, qui a le même format (MS-OXMSG 2.2.3 reprend
//! MS-PST 2.4.7). Seules sont écartées les colonnes internes des tables de la boîte et les objets
//! autres que le message joint ; sans table des noms lisible, les propriétés nommées sont
//! écartées et comptées pour le manifeste.

use crate::item::PstObj;
use cfb::CompoundFile;
use mf_msg::PropertySource;
use outlook_pst::ltp::prop_context::PropertyValue;
use std::io::{self, Cursor, Write};

const PR_ATTACH_DATA: u16 = 0x3701;
const PR_ATTACH_METHOD: u16 = 0x3705;
const PR_STORE_SUPPORT_MASK: u16 = 0x340D;
const PR_LAST_MODIFICATION_TIME: u16 = 0x3008;
/// `STORE_UNICODE_OK` : les chaînes sont en Unicode.
const STORE_UNICODE_OK: i32 = 0x0004_0000;
/// Colonnes internes des tables de la boîte (identifiant et version de ligne).
const LTP_ROW_ID: u16 = 0x67F2;
const LTP_ROW_VER: u16 = 0x67F3;
/// Propriété lisible et modifiable.
const FLAGS: u32 = 0x0000_0006;
/// Message joint : profondeur bornée (les boîtes hostiles peuvent s'imbriquer).
const MAX_DEPTH: usize = 16;

/// Ce que l'écriture a dû laisser de côté.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MsgReport {
    /// Propriétés nommées non exportées (toutes profondeurs) : seulement si la table des noms
    /// de la boîte est illisible.
    pub named_skipped: u32,
    keep_named: bool,
}

/// Rendu d'un message en `.msg` (fichier composé en mémoire).
pub(crate) fn write_msg(
    obj: &PstObj,
    nameid: Option<&[(u16, Vec<u8>)]>,
) -> io::Result<(Vec<u8>, MsgReport)> {
    // Version 3 (secteurs de 512 octets), comme les `.msg` d'Outlook : certains lecteurs
    // n'acceptent que celle-ci.
    let mut cf = CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new()))?;
    let mut report = MsgReport {
        named_skipped: 0,
        keep_named: nameid.is_some(),
    };
    write_message(&mut cf, "", obj, true, 0, &mut report)?;
    // Table des propriétés nommées : celle de la boîte, flux pour flux (GUID 0x0002, entrées
    // 0x0003, chaînes 0x0004, seaux de hachage 0x1000 et suivants).
    cf.create_storage("/__nameid_version1.0")?;
    match nameid {
        Some(streams) => {
            for (id, data) in streams {
                cf.create_stream(format!("/__nameid_version1.0/__substg1.0_{id:04X}0102"))?
                    .write_all(data)?;
            }
        }
        None => {
            for s in ["00020102", "00030102", "00040102"] {
                cf.create_stream(format!("/__nameid_version1.0/__substg1.0_{s}"))?;
            }
        }
    }
    // Dates des stockages : celle de la dernière modification de l'élément (sinon 1970), pour
    // qu'un même élément donne toujours le même fichier, donc la même empreinte.
    let ts = match obj.props().get(&PR_LAST_MODIFICATION_TIME) {
        Some(PropertyValue::Time(t)) => filetime_to_system(*t),
        _ => web_time::SystemTime::UNIX_EPOCH,
    };
    let paths: Vec<_> = cf.walk().map(|e| e.path().to_path_buf()).collect();
    for p in paths {
        cf.set_created_time(&p, ts)?;
        cf.set_modified_time(&p, ts)?;
    }
    cf.flush()?;
    Ok((cf.into_inner().into_inner(), report))
}

fn write_message(
    cf: &mut CompoundFile<Cursor<Vec<u8>>>,
    base: &str,
    obj: &PstObj,
    top: bool,
    depth: usize,
    report: &mut MsgReport,
) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(io::Error::other(
            "messages joints imbriqués trop profondément",
        ));
    }
    let recipients = obj.recipients();
    let attachments = obj.attachments();
    let mut entries = Vec::new();
    // En-tête : 32 octets (message racine) ou 24 (message joint).
    entries.extend_from_slice(&[0u8; 8]);
    entries.extend_from_slice(&(recipients.len() as u32).to_le_bytes());
    entries.extend_from_slice(&(attachments.len() as u32).to_le_bytes());
    entries.extend_from_slice(&(recipients.len() as u32).to_le_bytes());
    entries.extend_from_slice(&(attachments.len() as u32).to_le_bytes());
    if top {
        entries.extend_from_slice(&[0u8; 8]);
    }
    let mut props: Vec<(u16, PropertyValue)> =
        obj.props().iter().map(|(k, v)| (*k, v.clone())).collect();
    // Objet sans le marqueur de préfixe propre au stockage dans la boîte (voir `item.rs`).
    let subject = obj.string(crate::item::PR_SUBJECT);
    if top && !props.iter().any(|(k, _)| *k == PR_STORE_SUPPORT_MASK) {
        props.push((
            PR_STORE_SUPPORT_MASK,
            PropertyValue::Integer32(STORE_UNICODE_OK),
        ));
    }
    write_props(cf, base, &props, &mut entries, report, subject.as_deref())?;
    cf.create_stream(format!("{base}/__properties_version1.0"))?
        .write_all(&entries)?;

    for (i, r) in recipients.iter().enumerate() {
        let path = format!("{base}/__recip_version1.0_#{i:08X}");
        cf.create_storage(&path)?;
        let mut e = vec![0u8; 8];
        let props: Vec<(u16, PropertyValue)> = r
            .props()
            .iter()
            .filter(|(k, _)| **k != LTP_ROW_ID && **k != LTP_ROW_VER)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        write_props(cf, &path, &props, &mut e, report, None)?;
        cf.create_stream(format!("{path}/__properties_version1.0"))?
            .write_all(&e)?;
    }

    for (i, a) in attachments.iter().enumerate() {
        let path = format!("{base}/__attach_version1.0_#{i:08X}");
        cf.create_storage(&path)?;
        let mut e = vec![0u8; 8];
        let mut props: Vec<(u16, PropertyValue)> = a
            .props()
            .iter()
            .filter(|(k, _)| **k != LTP_ROW_ID && **k != LTP_ROW_VER && **k != PR_ATTACH_DATA)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let embedded = a.embedded();
        if embedded.is_none() {
            if let Some(data) = a.binary(PR_ATTACH_DATA) {
                props.push((
                    PR_ATTACH_DATA,
                    PropertyValue::Binary(outlook_pst::ltp::prop_context::BinaryValue::new(
                        data.into_owned(),
                    )),
                ));
            }
        }
        write_props(cf, &path, &props, &mut e, report, None)?;
        if let Some(m) = embedded {
            // Message joint : sous-stockage 0x3701000D, taille « inconnue » dans l'entrée.
            e.extend_from_slice(&((u32::from(PR_ATTACH_DATA) << 16) | 0x000D).to_le_bytes());
            e.extend_from_slice(&FLAGS.to_le_bytes());
            e.extend_from_slice(&u32::MAX.to_le_bytes());
            e.extend_from_slice(&[0u8; 4]);
            let sub = format!("{path}/__substg1.0_3701000D");
            cf.create_storage(&sub)?;
            write_message(cf, &sub, &m, false, depth + 1, report)?;
            if !props.iter().any(|(k, _)| *k == PR_ATTACH_METHOD) {
                // Méthode 5 : message embarqué (normalement déjà présente).
                e.extend_from_slice(&((u32::from(PR_ATTACH_METHOD) << 16) | 0x0003).to_le_bytes());
                e.extend_from_slice(&FLAGS.to_le_bytes());
                e.extend_from_slice(&5u32.to_le_bytes());
                e.extend_from_slice(&[0u8; 4]);
            }
        }
        cf.create_stream(format!("{path}/__properties_version1.0"))?
            .write_all(&e)?;
    }
    Ok(())
}

/// FILETIME (centaines de ns depuis 1601) vers une date système ; 1970 si hors bornes.
fn filetime_to_system(ft: i64) -> web_time::SystemTime {
    const EPOCH_DIFF: i64 = 11_644_473_600; // secondes entre 1601 et 1970
    let secs = ft / 10_000_000 - EPOCH_DIFF;
    let nanos = (ft % 10_000_000) * 100;
    match (u64::try_from(secs), u32::try_from(nanos)) {
        (Ok(s), Ok(n)) => web_time::SystemTime::UNIX_EPOCH + std::time::Duration::new(s, n),
        _ => web_time::SystemTime::UNIX_EPOCH,
    }
}

/// Code de type MAPI d'une valeur.
fn type_code(v: &PropertyValue) -> Option<u16> {
    use PropertyValue as P;
    Some(match v {
        P::Integer16(_) => 0x0002,
        P::Integer32(_) => 0x0003,
        P::Floating32(_) => 0x0004,
        P::Floating64(_) => 0x0005,
        P::Currency(_) => 0x0006,
        P::FloatingTime(_) => 0x0007,
        P::ErrorCode(_) => 0x000A,
        P::Boolean(_) => 0x000B,
        P::Integer64(_) => 0x0014,
        P::String8(_) => 0x001E,
        P::Unicode(_) => 0x001F,
        P::Time(_) => 0x0040,
        P::Guid(_) => 0x0048,
        P::Binary(_) => 0x0102,
        P::MultipleInteger16(_) => 0x1002,
        P::MultipleInteger32(_) => 0x1003,
        P::MultipleFloating32(_) => 0x1004,
        P::MultipleFloating64(_) => 0x1005,
        P::MultipleCurrency(_) => 0x1006,
        P::MultipleFloatingTime(_) => 0x1007,
        P::MultipleInteger64(_) => 0x1014,
        P::MultipleString8(_) => 0x101E,
        P::MultipleUnicode(_) => 0x101F,
        P::MultipleTime(_) => 0x1040,
        P::MultipleGuid(_) => 0x1048,
        P::MultipleBinary(_) => 0x1102,
        // Nul, objets (sauf le message joint, traité à part) : rien à écrire.
        P::Null | P::Object(_) => return None,
    })
}

fn guid_bytes(g: &outlook_pst::ltp::prop_context::GuidValue) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.data1().to_le_bytes());
    b[4..6].copy_from_slice(&g.data2().to_le_bytes());
    b[6..8].copy_from_slice(&g.data3().to_le_bytes());
    b[8..].copy_from_slice(g.data4());
    b
}

fn utf16(s: &[u16]) -> Vec<u8> {
    // Sans le zéro final éventuel : la taille déclarée l'ajoute (MS-OXMSG 2.1.3).
    let s = s.strip_suffix(&[0]).unwrap_or(s);
    s.iter().flat_map(|c| c.to_le_bytes()).collect()
}

fn str8(b: &[u8]) -> Vec<u8> {
    b.strip_suffix(&[0]).unwrap_or(b).to_vec()
}

/// Entrées de propriétés (16 octets chacune) et flux des valeurs de longueur variable.
fn write_props(
    cf: &mut CompoundFile<Cursor<Vec<u8>>>,
    base: &str,
    props: &[(u16, PropertyValue)],
    entries: &mut Vec<u8>,
    report: &mut MsgReport,
    subject: Option<&str>,
) -> io::Result<()> {
    use PropertyValue as P;
    let mut sorted: Vec<&(u16, PropertyValue)> = props.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    for (id, v) in sorted {
        if *id >= 0x8000 && !report.keep_named {
            report.named_skipped += 1;
            continue;
        }
        if let (true, Some(text)) = (*id == crate::item::PR_SUBJECT, subject) {
            // Objet réécrit en Unicode, sans le marqueur de préfixe de la boîte.
            let b: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            cf.create_stream(format!("{base}/__substg1.0_0037001F"))?
                .write_all(&b)?;
            entries.extend_from_slice(&((u32::from(*id) << 16) | 0x001F).to_le_bytes());
            entries.extend_from_slice(&FLAGS.to_le_bytes());
            entries.extend_from_slice(&(b.len() as u32 + 2).to_le_bytes());
            entries.extend_from_slice(&[0u8; 4]);
            continue;
        }
        let Some(ty) = type_code(v) else { continue };
        let tag = (u32::from(*id) << 16) | u32::from(ty);
        let stream = |suffix: &str| format!("{base}/__substg1.0_{id:04X}{ty:04X}{suffix}");
        let mut value = [0u8; 8];
        // Valeurs fixes : dans l'entrée ; variables : flux à part, la taille dans l'entrée.
        let fixed: Option<Vec<u8>> = match v {
            P::Integer16(x) => Some(x.to_le_bytes().to_vec()),
            P::Integer32(x) | P::ErrorCode(x) => Some(x.to_le_bytes().to_vec()),
            P::Floating32(x) => Some(x.to_le_bytes().to_vec()),
            P::Floating64(x) | P::FloatingTime(x) => Some(x.to_le_bytes().to_vec()),
            P::Currency(x) | P::Integer64(x) | P::Time(x) => Some(x.to_le_bytes().to_vec()),
            P::Boolean(b) => Some(vec![u8::from(*b)]),
            _ => None,
        };
        if let Some(f) = fixed {
            value[..f.len()].copy_from_slice(&f);
        } else {
            let size: u32 = match v {
                P::String8(s) => {
                    let b = str8(s.buffer());
                    cf.create_stream(stream(""))?.write_all(&b)?;
                    b.len() as u32 + 1
                }
                P::Unicode(s) => {
                    let b = utf16(s.buffer());
                    cf.create_stream(stream(""))?.write_all(&b)?;
                    b.len() as u32 + 2
                }
                P::Binary(b) => {
                    cf.create_stream(stream(""))?.write_all(b.buffer())?;
                    b.buffer().len() as u32
                }
                P::Guid(g) => {
                    cf.create_stream(stream(""))?.write_all(&guid_bytes(g))?;
                    16
                }
                // Multivaluées de taille fixe : valeurs bout à bout dans un seul flux.
                P::MultipleInteger16(x) => {
                    fixed_mv(cf, &stream(""), x.iter().flat_map(|v| v.to_le_bytes()))?
                }
                P::MultipleInteger32(x) => {
                    fixed_mv(cf, &stream(""), x.iter().flat_map(|v| v.to_le_bytes()))?
                }
                P::MultipleFloating32(x) => {
                    fixed_mv(cf, &stream(""), x.iter().flat_map(|v| v.to_le_bytes()))?
                }
                P::MultipleFloating64(x) | P::MultipleFloatingTime(x) => {
                    fixed_mv(cf, &stream(""), x.iter().flat_map(|v| v.to_le_bytes()))?
                }
                P::MultipleCurrency(x) | P::MultipleInteger64(x) | P::MultipleTime(x) => {
                    fixed_mv(cf, &stream(""), x.iter().flat_map(|v| v.to_le_bytes()))?
                }
                P::MultipleGuid(x) => fixed_mv(cf, &stream(""), x.iter().flat_map(guid_bytes))?,
                // Multivaluées de taille variable : flux des longueurs + un flux par valeur.
                P::MultipleString8(x) => {
                    let vals: Vec<Vec<u8>> = x
                        .iter()
                        .map(|s| {
                            let mut b = str8(s.buffer());
                            b.push(0);
                            b
                        })
                        .collect();
                    var_mv(cf, &stream, &vals, false)?
                }
                P::MultipleUnicode(x) => {
                    let vals: Vec<Vec<u8>> = x
                        .iter()
                        .map(|s| {
                            let mut b = utf16(s.buffer());
                            b.extend_from_slice(&[0, 0]);
                            b
                        })
                        .collect();
                    var_mv(cf, &stream, &vals, false)?
                }
                P::MultipleBinary(x) => {
                    let vals: Vec<Vec<u8>> = x.iter().map(|b| b.buffer().to_vec()).collect();
                    var_mv(cf, &stream, &vals, true)?
                }
                _ => continue,
            };
            value[..4].copy_from_slice(&size.to_le_bytes());
        }
        entries.extend_from_slice(&tag.to_le_bytes());
        entries.extend_from_slice(&FLAGS.to_le_bytes());
        entries.extend_from_slice(&value);
    }
    Ok(())
}

fn fixed_mv(
    cf: &mut CompoundFile<Cursor<Vec<u8>>>,
    path: &str,
    bytes: impl Iterator<Item = u8>,
) -> io::Result<u32> {
    let b: Vec<u8> = bytes.collect();
    cf.create_stream(path)?.write_all(&b)?;
    Ok(b.len() as u32)
}

fn var_mv(
    cf: &mut CompoundFile<Cursor<Vec<u8>>>,
    stream: &dyn Fn(&str) -> String,
    vals: &[Vec<u8>],
    binary: bool,
) -> io::Result<u32> {
    let mut lengths = Vec::new();
    for (i, v) in vals.iter().enumerate() {
        lengths.extend_from_slice(&(v.len() as u32).to_le_bytes());
        if binary {
            lengths.extend_from_slice(&[0u8; 4]);
        }
        cf.create_stream(stream(&format!("-{i:08X}")))?
            .write_all(v)?;
    }
    cf.create_stream(stream(""))?.write_all(&lengths)?;
    Ok(lengths.len() as u32)
}
