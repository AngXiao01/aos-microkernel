//! The object-change part of a branch's diff (SPEC §7.4, item 3): what committing the
//! branch would change on the current `main`, grouped by type, with per-field counts for
//! bulk summaries and per-object detail for drill-down.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use aos_types::{Object, TypeId, Ulid};

use crate::store::State;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Created,
    Updated,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectChange {
    pub id: Ulid,
    pub kind: ChangeKind,
    /// Changed field names. Non-field parts appear as `@type`, `@extra`, `@blobs`,
    /// `@sensitivity`, `@taint` and `@derived_from` (field names cannot start with `@`).
    pub fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeChanges {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    /// How many updated objects changed each field.
    pub field_counts: BTreeMap<String, usize>,
    pub objects: Vec<ObjectChange>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub types: BTreeMap<TypeId, TypeChanges>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

fn changed_fields(before: &Object, after: &Object) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = before
        .fields
        .keys()
        .chain(after.fields.keys())
        .filter(|k| before.fields.get(*k) != after.fields.get(*k))
        .cloned()
        .collect();
    let mut mark = |changed: bool, name: &str| {
        if changed {
            out.insert(String::from(name));
        }
    };
    mark(before.type_id != after.type_id, "@type");
    mark(before.extra != after.extra, "@extra");
    mark(before.blobs != after.blobs, "@blobs");
    mark(before.sensitivity != after.sensitivity, "@sensitivity");
    mark(before.provenance.taint != after.provenance.taint, "@taint");
    mark(before.provenance.derived_from != after.provenance.derived_from, "@derived_from");
    out
}

impl State {
    pub(crate) fn diff(&self, fork: Ulid) -> Option<Diff> {
        let f = self.forks.get(&fork)?;
        let mut diff = Diff::default();
        for (id, recs) in &f.overlay.objects {
            let after = recs.last().and_then(|r| r.object.as_ref());
            let before = self.main.objects.get(id).and_then(|v| v.last()).and_then(|r| r.object.as_ref());
            let (type_id, change) = match (before, after) {
                (None, Some(a)) => (
                    &a.type_id,
                    ObjectChange { id: *id, kind: ChangeKind::Created, fields: a.fields.keys().cloned().collect() },
                ),
                (Some(b), None) => {
                    (&b.type_id, ObjectChange { id: *id, kind: ChangeKind::Deleted, fields: BTreeSet::new() })
                }
                (Some(b), Some(a)) => {
                    let fields = changed_fields(b, a);
                    if fields.is_empty() {
                        continue;
                    }
                    (&a.type_id, ObjectChange { id: *id, kind: ChangeKind::Updated, fields })
                }
                (None, None) => continue,
            };
            let t = diff.types.entry(type_id.clone()).or_default();
            match change.kind {
                ChangeKind::Created => t.created += 1,
                ChangeKind::Deleted => t.deleted += 1,
                ChangeKind::Updated => {
                    t.updated += 1;
                    for name in &change.fields {
                        *t.field_counts.entry(name.clone()).or_default() += 1;
                    }
                }
            }
            t.objects.push(change);
        }
        Some(diff)
    }
}
