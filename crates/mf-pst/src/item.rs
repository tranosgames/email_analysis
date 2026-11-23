//! Éléments d'une boîte vus comme des objets MAPI : un message PST porte les mêmes propriétés
//! qu'un `.msg`, la conversion de `mf-msg` s'applique donc telle quelle (R4).

use chrono::{DateTime, Utc};
use mf_msg::{PropertySource, decode_codepage, filetime};
use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::ltp::table_context::TableContext;
use outlook_pst::messaging::attachment::{Attachment, AttachmentData};
use outlook_pst::messaging::message::Message;
use outlook_pst::ndb::node_id::NodeId;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::rc::Rc;

const PR_ATTACH_DATA: u16 = 0x3701;
pub(crate) const PR_SUBJECT: u16 = 0x0037;
const PR_INTERNET_CPID: u16 = 0x3FDE;
const PR_MESSAGE_CODEPAGE: u16 = 0x3FFD;

enum Kind {
    Message(Rc<dyn Message>),
    Recipient,
    Attachment(Rc<dyn Attachment>),
}

/// Message, destinataire ou pièce jointe d'une boîte.
pub(crate) struct PstObj {
    props: BTreeMap<u16, PropertyValue>,
    kind: Kind,
    codepage: Option<u32>,
    /// Anomalies rencontrées en lisant les sous-objets (pièces jointes illisibles…).
    pub(crate) issues: std::cell::RefCell<Vec<String>>,
}

fn int(v: Option<&PropertyValue>) -> Option<u32> {
    match v? {
        PropertyValue::Integer32(i) => Some(*i as u32),
        PropertyValue::Integer16(i) => Some(*i as u16 as u32),
        _ => None,
    }
}

/// Lignes d'une table (destinataires, pièces jointes, contenu d'un dossier) : identifiant de ligne
/// et propriétés présentes.
pub(crate) fn table_rows(table: &Rc<dyn TableContext>) -> Vec<(u32, BTreeMap<u16, PropertyValue>)> {
    let ctx = table.context();
    table
        .rows_matrix()
        .map(|row| {
            let mut props = BTreeMap::new();
            if let Ok(cols) = row.columns(ctx) {
                for (col, value) in ctx.columns().iter().zip(cols) {
                    if let Some(value) = value {
                        if let Ok(v) = table.read_column(&value, col.prop_type()) {
                            props.insert(col.prop_id(), v);
                        }
                    }
                }
            }
            (u32::from(row.id()), props)
        })
        .collect()
}

impl PstObj {
    pub(crate) fn message(m: Rc<dyn Message>) -> Self {
        let props: BTreeMap<u16, PropertyValue> = m
            .properties()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let codepage =
            int(props.get(&PR_INTERNET_CPID)).or_else(|| int(props.get(&PR_MESSAGE_CODEPAGE)));
        Self {
            props,
            kind: Kind::Message(m),
            codepage,
            issues: Default::default(),
        }
    }

    fn child(&self, props: BTreeMap<u16, PropertyValue>, kind: Kind) -> Self {
        Self {
            props,
            kind,
            codepage: self.codepage,
            issues: Default::default(),
        }
    }

    /// Propriétés de l'objet (écriture `.msg`).
    pub(crate) fn props(&self) -> &BTreeMap<u16, PropertyValue> {
        &self.props
    }

    fn get(&self, id: u16) -> Option<&PropertyValue> {
        self.props.get(&id)
    }
}

/// Octets d'une valeur, pour l'empreinte canonique d'un message embarqué.
fn value_bytes(v: &PropertyValue) -> Vec<u8> {
    match v {
        PropertyValue::Unicode(s) => s.to_string().into_bytes(),
        PropertyValue::String8(s) => s.buffer().to_vec(),
        PropertyValue::Binary(b) => b.buffer().to_vec(),
        PropertyValue::Integer16(i) => i.to_le_bytes().to_vec(),
        PropertyValue::Integer32(i) => i.to_le_bytes().to_vec(),
        PropertyValue::Integer64(i) | PropertyValue::Currency(i) | PropertyValue::Time(i) => {
            i.to_le_bytes().to_vec()
        }
        PropertyValue::Boolean(b) => vec![u8::from(*b)],
        other => format!("{other:?}").into_bytes(),
    }
}

impl PropertySource for PstObj {
    fn string(&self, id: u16) -> Option<String> {
        let v = match self.get(id)? {
            PropertyValue::Unicode(s) => s.to_string().trim_end_matches('\0').to_string(),
            PropertyValue::String8(s) => decode_codepage(s.buffer(), self.codepage)
                .trim_end_matches('\0')
                .to_string(),
            _ => return None,
        };
        // Objet : la boîte le stocke précédé d'un marqueur de préfixe (0x01, longueur), artefact
        // de stockage absent des `.msg` d'Outlook.
        Some(if id == PR_SUBJECT {
            crate::store::strip_subject_prefix(&v)
        } else {
            v
        })
    }

    fn binary(&self, id: u16) -> Option<Cow<'_, [u8]>> {
        if id == PR_ATTACH_DATA {
            if let Kind::Attachment(a) = &self.kind {
                if let Some(AttachmentData::Binary(b)) = a.data() {
                    return Some(Cow::Owned(b.buffer().to_vec()));
                }
            }
        }
        match self.get(id)? {
            PropertyValue::Binary(b) => Some(Cow::Borrowed(b.buffer())),
            _ => None,
        }
    }

    fn decode_internet(&self, bytes: &[u8]) -> String {
        decode_codepage(bytes, self.codepage.or(Some(65001)))
    }

    fn u32(&self, id: u16) -> Option<u32> {
        int(self.get(id))
    }

    fn bool(&self, id: u16) -> Option<bool> {
        match self.get(id)? {
            PropertyValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    fn time(&self, id: u16) -> Option<DateTime<Utc>> {
        match self.get(id)? {
            PropertyValue::Time(t) => filetime(*t as u64),
            _ => None,
        }
    }

    fn recipients(&self) -> Vec<Self> {
        let Kind::Message(m) = &self.kind else {
            return Vec::new();
        };
        m.recipient_table()
            .map(|t| {
                table_rows(t)
                    .into_iter()
                    .map(|(_, props)| self.child(props, Kind::Recipient))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn attachments(&self) -> Vec<Self> {
        let Kind::Message(m) = &self.kind else {
            return Vec::new();
        };
        let Some(table) = m.attachment_table() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (row, row_props) in table_rows(table) {
            match m.clone().open_attachment(NodeId::from(row)) {
                Ok(a) => {
                    let props = a
                        .properties()
                        .iter()
                        .map(|(k, v)| (*k, v.clone()))
                        .collect();
                    out.push(self.child(props, Kind::Attachment(a)));
                }
                Err(e) => {
                    // Pièce jointe illisible : signalée, et présente avec ce que dit sa ligne.
                    self.issues
                        .borrow_mut()
                        .push(format!("pièce jointe {row:#x} illisible : {e}"));
                    out.push(self.child(row_props, Kind::Recipient));
                }
            }
        }
        out
    }

    fn embedded(&self) -> Option<Self> {
        let Kind::Attachment(a) = &self.kind else {
            return None;
        };
        match a.data()? {
            AttachmentData::Message(m) => Some(PstObj::message(m.clone())),
            AttachmentData::Binary(_) => None,
        }
    }

    fn total_len(&self) -> u64 {
        self.props
            .values()
            .map(|v| value_bytes(v).len() as u64)
            .sum::<u64>()
            + self
                .attachments()
                .iter()
                .map(PropertySource::total_len)
                .sum::<u64>()
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        // Propriétés triées (identifiant + longueur + valeur), puis pièces jointes dans l'ordre.
        let mut out = Vec::new();
        for (id, v) in &self.props {
            let b = value_bytes(v);
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(b.len() as u64).to_le_bytes());
            out.extend_from_slice(&b);
        }
        for a in self.attachments() {
            if let Some(d) = a.binary(PR_ATTACH_DATA) {
                out.extend_from_slice(&(d.len() as u64).to_le_bytes());
                out.extend_from_slice(&d);
            }
            if let Some(e) = a.embedded() {
                out.extend_from_slice(&e.canonical_bytes());
            }
        }
        out
    }
}
