//! The object store over the log: snapshot reads, optimistic transactions, branches,
//! commit and revert (SPEC §7).
//!
//! State is a function of the log: every change is first checked against the current
//! state, then appended, then applied. Replay on open runs the same check and apply.
//!
//! Each branch is an overlay of object versions keyed by log sequence number. A fork sees
//! `main` up to its base plus its own overlay, so forking copies nothing (O(1)).
//! Transactions read a snapshot and are validated at apply time against everything they
//! read or wrote (optimistic concurrency), which makes each branch serializable.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use aos_log::{Anchor, Log, LogError, LogStorage, OpenError};
use aos_types::codec::{FormatError, FromCbor, ToCbor};
use aos_types::{Actor, Object, ObjectRef, Origin, Taint, Timestamp, Ulid, UlidGenerator, Value};

use crate::predicate::{Lookup, Predicate};
use crate::record::{BranchId, Change, Op, Record, Rejection, Write};

/// Time and randomness from the platform; the core library has no I/O (SPEC §18).
pub trait Env {
    fn now(&mut self) -> Timestamp;
    fn entropy(&mut self) -> [u8; 10];
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VersionRec {
    pub(crate) seq: u64,
    pub(crate) version: u64,
    /// `None` is a tombstone.
    pub(crate) object: Option<Object>,
}

/// Object versions written on one branch, ascending by (seq, version) per object.
#[derive(Clone, Debug, Default)]
pub(crate) struct Overlay {
    pub(crate) objects: BTreeMap<Ulid, Vec<VersionRec>>,
}

impl Overlay {
    /// The latest version of `id` among entries with `seq < before`.
    fn at(&self, id: Ulid, before: u64) -> Option<&VersionRec> {
        let recs = self.objects.get(&id)?;
        recs.partition_point(|r| r.seq < before).checked_sub(1).map(|i| &recs[i])
    }

    fn with_version(&self, id: Ulid, version: u64, before: u64) -> Option<&VersionRec> {
        self.objects.get(&id)?.iter().find(|r| r.version == version && r.seq < before)
    }

    fn push(&mut self, id: Ulid, rec: VersionRec) {
        self.objects.entry(id).or_default().push(rec);
    }
}

/// A consistent read-only view: a fork's overlay (entries before a bound) over `main`
/// (entries before another bound).
#[derive(Clone, Copy)]
pub struct View<'a> {
    main: &'a Overlay,
    main_before: u64,
    fork: Option<(&'a Overlay, u64)>,
}

impl<'a> View<'a> {
    fn rec(&self, id: Ulid) -> Option<&'a VersionRec> {
        if let Some((overlay, before)) = self.fork
            && let Some(r) = overlay.at(id, before)
        {
            return Some(r);
        }
        self.main.at(id, self.main_before)
    }

    fn rec_with_version(&self, id: Ulid, version: u64) -> Option<&'a VersionRec> {
        if let Some((overlay, before)) = self.fork
            && let Some(r) = overlay.with_version(id, version, before)
        {
            return Some(r);
        }
        self.main.with_version(id, version, self.main_before)
    }

    /// A specific version, or the latest if `r.version` is `None`; `None` if deleted.
    pub fn resolve(&self, r: ObjectRef) -> Option<&'a Object> {
        match r.version {
            None => self.object(r.id),
            Some(v) => self.rec_with_version(r.id, v)?.object.as_ref(),
        }
    }

    pub fn object(&self, id: Ulid) -> Option<&'a Object> {
        self.rec(id)?.object.as_ref()
    }
}

impl Lookup for View<'_> {
    fn object(&self, id: Ulid) -> Option<&Object> {
        View::object(self, id)
    }

    fn version(&self, id: Ulid) -> Option<u64> {
        self.rec(id).map(|r| r.version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Open {
        note: Option<String>,
    },
    /// Waiting for the human; `rejection` explains the last failed commit, if any.
    Review {
        rejection: Option<Rejection>,
    },
    Committed {
        merge_seq: u64,
    },
    Discarded,
}

#[derive(Clone, Debug)]
pub(crate) struct Fork {
    pub(crate) base: u64,
    pub(crate) status: Status,
    pub(crate) overlay: Overlay,
    /// Write transactions on the fork, in order, with their preconditions.
    txs: Vec<(Ulid, u64, Vec<Predicate>)>,
}

/// Per object written by a transaction: the version before its first write and after its last.
#[derive(Clone, Copy, Debug)]
struct Written {
    id: Ulid,
    first_prev: Option<u64>,
    last_new: u64,
}

#[derive(Clone, Debug)]
struct TxLoc {
    branch: BranchId,
    seq: u64,
    written: Vec<Written>,
}

/// Replay found a record that does not follow from the state before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    Format(FormatError),
    Inconsistent(&'static str),
}

impl From<FormatError> for ReplayError {
    fn from(e: FormatError) -> ReplayError {
        ReplayError::Format(e)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError<E> {
    Log(LogError<E>),
    UnknownBranch(BranchId),
    /// Writes need `main` or an open fork.
    NotWritable(BranchId),
    /// The branch's status does not allow this lifecycle step.
    WrongStatus(BranchId),
    UnknownTx(Ulid),
    /// The transaction is not part of the branch's history.
    NotVisible(Ulid),
    /// Objects changed since they were read (transaction, rebase) or since the transaction
    /// being reverted wrote them.
    Conflict(Vec<Ulid>),
    NotFound(Ulid),
    /// A `derived_from` reference does not resolve in the transaction's snapshot.
    MissingInput(ObjectRef),
    PreconditionFailed(u32),
    /// The commit was refused and recorded; the branch stays in review.
    Rejected(Rejection),
    IdsExhausted,
    /// A bug: a record built by the store failed its own consistency check.
    Internal(ReplayError),
}

#[derive(Clone, Debug, Default)]
pub struct TxMeta {
    pub capability: Option<Ulid>,
    pub action: Option<String>,
    pub inputs: BTreeMap<String, Value>,
    /// Checked against the branch when the transaction is applied, and again on commit.
    pub preconditions: Vec<Predicate>,
}

/// A transaction in progress. It does not borrow the store; reads and writes go through
/// [`Store::read`], [`Store::put`] and [`Store::delete`], and [`Store::apply`] ends it.
#[derive(Debug)]
pub struct Tx {
    id: Ulid,
    timestamp: Timestamp,
    branch: BranchId,
    actor: Actor,
    meta: TxMeta,
    /// Snapshot bounds: fork entries before `snapshot`, `main` entries before `main_before`.
    snapshot: u64,
    main_before: u64,
    /// Version observed for every object read or written (`None`: never existed).
    reads: BTreeMap<Ulid, Option<u64>>,
    writes: Vec<Write>,
    /// The transaction's own latest write per object, visible to its later reads:
    /// (version, index into `writes`).
    pending: BTreeMap<Ulid, (u64, usize)>,
}

impl Tx {
    pub fn id(&self) -> Ulid {
        self.id
    }

    pub fn branch(&self) -> BranchId {
        self.branch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub tx: Ulid,
    /// `None` if nothing was logged (a transaction without writes).
    pub seq: Option<u64>,
}

/// Everything derived from the log.
#[derive(Default)]
pub(crate) struct State {
    pub(crate) main: Overlay,
    pub(crate) forks: BTreeMap<Ulid, Fork>,
    txs: BTreeMap<Ulid, TxLoc>,
    /// Largest ULID seen (transactions and branches), to resume the generator.
    last_id: Option<Ulid>,
}

impl State {
    pub(crate) fn head_view(&self, branch: BranchId) -> Option<View<'_>> {
        match branch {
            BranchId::Main => Some(View { main: &self.main, main_before: u64::MAX, fork: None }),
            BranchId::Fork(id) => {
                let f = self.forks.get(&id)?;
                Some(View { main: &self.main, main_before: f.base, fork: Some((&f.overlay, u64::MAX)) })
            }
        }
    }

    /// The branch as it was just before entry `seq`.
    fn view_before(&self, branch: BranchId, seq: u64) -> Option<View<'_>> {
        match branch {
            BranchId::Main => Some(View { main: &self.main, main_before: seq, fork: None }),
            BranchId::Fork(id) => {
                let f = self.forks.get(&id)?;
                Some(View { main: &self.main, main_before: f.base, fork: Some((&f.overlay, seq)) })
            }
        }
    }

    fn writable(&self, branch: BranchId) -> bool {
        match branch {
            BranchId::Main => true,
            BranchId::Fork(id) => self.forks.get(&id).is_some_and(|f| matches!(f.status, Status::Open { .. })),
        }
    }

    /// Objects the fork wrote whose `main` version moved since the fork read them.
    fn conflicts(&self, fork: &Fork) -> Vec<Ulid> {
        fork.overlay
            .objects
            .iter()
            .filter(|(id, recs)| {
                let prev = recs[0].version.checked_sub(1).filter(|v| *v > 0);
                self.main.at(**id, u64::MAX).map(|r| r.version) != prev
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// The first precondition that fails when the fork's transactions are replayed on
    /// top of the current `main`.
    fn failed_precondition(&self, fork: &Fork) -> Option<Rejection> {
        for (tx, seq, preconditions) in &fork.txs {
            let view = View { main: &self.main, main_before: u64::MAX, fork: Some((&fork.overlay, *seq)) };
            if let Some(index) = preconditions.iter().position(|p| !p.eval(&view)) {
                return Some(Rejection::Precondition { tx: *tx, index: index as u32 });
            }
        }
        None
    }

    fn fork_in(&self, branch: BranchId, allowed: impl Fn(&Status) -> bool) -> Result<&Fork, ReplayError> {
        let BranchId::Fork(id) = branch else { return Err(ReplayError::Inconsistent("lifecycle step on main")) };
        let fork = self.forks.get(&id).ok_or(ReplayError::Inconsistent("unknown branch"))?;
        if allowed(&fork.status) { Ok(fork) } else { Err(ReplayError::Inconsistent("lifecycle step not allowed")) }
    }

    /// Checks that `record`, appended as entry `seq`, follows from the current state.
    pub(crate) fn check(&self, seq: u64, record: &Record) -> Result<(), ReplayError> {
        let open = |s: &Status| matches!(s, Status::Open { .. });
        let review = |s: &Status| matches!(s, Status::Review { .. });
        match &record.op {
            Op::Write { writes, reverts, .. } => {
                if !self.writable(record.branch) {
                    return Err(ReplayError::Inconsistent("write to a branch that is not writable"));
                }
                if let Some(target) = reverts
                    && !self.txs.contains_key(target)
                {
                    return Err(ReplayError::Inconsistent("revert of an unknown transaction"));
                }
                if writes.iter().any(|w| matches!(&w.change, Change::Put(o) if o.provenance.tx != record.tx)) {
                    return Err(ReplayError::Inconsistent("written object names another transaction"));
                }
                self.check_tx_id(record.tx)?;
                let view = self.head_view(record.branch).ok_or(ReplayError::Inconsistent("unknown branch"))?;
                check_chain(&view, writes)
            }
            Op::Merge { from, base, writes } => {
                if record.branch != BranchId::Main || *base != seq {
                    return Err(ReplayError::Inconsistent("merge not on main at its own sequence number"));
                }
                let fork = self.fork_in(BranchId::Fork(*from), review)?;
                if !self.conflicts(fork).is_empty() {
                    return Err(ReplayError::Inconsistent("merge with conflicts"));
                }
                self.check_tx_id(record.tx)?;
                let view = self.head_view(BranchId::Main).ok_or(ReplayError::Inconsistent("no main"))?;
                check_chain(&view, writes)
            }
            Op::Fork { base } => match record.branch {
                BranchId::Fork(id) if *base == seq && !self.forks.contains_key(&id) => Ok(()),
                _ => Err(ReplayError::Inconsistent("fork")),
            },
            Op::Rebase { base } => {
                let fork = self.fork_in(record.branch, |s| open(s) || review(s))?;
                if *base != seq || !self.conflicts(fork).is_empty() {
                    return Err(ReplayError::Inconsistent("rebase"));
                }
                Ok(())
            }
            Op::Submit => self.fork_in(record.branch, open).map(|_| ()),
            Op::Reopen { .. } | Op::Rejected(_) => self.fork_in(record.branch, review).map(|_| ()),
            Op::Discard => self.fork_in(record.branch, |s| open(s) || review(s)).map(|_| ()),
        }
    }

    fn check_tx_id(&self, tx: Ulid) -> Result<(), ReplayError> {
        if self.txs.contains_key(&tx) { Err(ReplayError::Inconsistent("duplicate transaction id")) } else { Ok(()) }
    }

    pub(crate) fn apply(&mut self, seq: u64, record: Record) {
        self.last_id = self.last_id.max(Some(record.tx));
        if let BranchId::Fork(id) = record.branch {
            self.last_id = self.last_id.max(Some(id));
        }
        match record.op {
            Op::Write { writes, preconditions, .. } => {
                let written = summarize(&writes);
                match record.branch {
                    BranchId::Main => push_writes(&mut self.main, seq, writes),
                    BranchId::Fork(id) => {
                        let fork = self.forks.get_mut(&id).expect("checked");
                        push_writes(&mut fork.overlay, seq, writes);
                        fork.txs.push((record.tx, seq, preconditions));
                    }
                }
                self.txs.insert(record.tx, TxLoc { branch: record.branch, seq, written });
            }
            Op::Merge { from, writes, .. } => {
                let written = summarize(&writes);
                push_writes(&mut self.main, seq, writes);
                self.txs.insert(record.tx, TxLoc { branch: BranchId::Main, seq, written });
                self.set_status(BranchId::Fork(from), Status::Committed { merge_seq: seq });
            }
            Op::Fork { base } => {
                if let BranchId::Fork(id) = record.branch {
                    let fork = Fork {
                        base,
                        status: Status::Open { note: None },
                        overlay: Overlay::default(),
                        txs: Vec::new(),
                    };
                    self.forks.insert(id, fork);
                }
            }
            Op::Rebase { base } => {
                if let BranchId::Fork(id) = record.branch {
                    self.forks.get_mut(&id).expect("checked").base = base;
                }
            }
            Op::Submit => self.set_status(record.branch, Status::Review { rejection: None }),
            Op::Reopen { note } => self.set_status(record.branch, Status::Open { note }),
            Op::Rejected(r) => self.set_status(record.branch, Status::Review { rejection: Some(r) }),
            Op::Discard => self.set_status(record.branch, Status::Discarded),
        }
    }

    fn set_status(&mut self, branch: BranchId, status: Status) {
        if let BranchId::Fork(id) = branch {
            self.forks.get_mut(&id).expect("checked").status = status;
        }
    }
}

/// Each write must continue the version chain of its object, as seen in `view` and in
/// the earlier writes of the same record.
fn check_chain(view: &View<'_>, writes: &[Write]) -> Result<(), ReplayError> {
    let mut latest: BTreeMap<Ulid, (u64, bool)> = BTreeMap::new();
    for w in writes {
        let (current, live) = match latest.get(&w.id) {
            Some(&(v, live)) => (Some(v), live),
            None => match view.rec(w.id) {
                Some(r) => (Some(r.version), r.object.is_some()),
                None => (None, false),
            },
        };
        if current != w.prev_version {
            return Err(ReplayError::Inconsistent("write does not continue the version chain"));
        }
        if matches!(w.change, Change::Delete) && !live {
            return Err(ReplayError::Inconsistent("delete of an object that does not exist"));
        }
        latest.insert(w.id, (w.new_version(), matches!(w.change, Change::Put(_))));
    }
    Ok(())
}

fn summarize(writes: &[Write]) -> Vec<Written> {
    let mut out: Vec<Written> = Vec::new();
    let mut index: BTreeMap<Ulid, usize> = BTreeMap::new();
    for w in writes {
        match index.get(&w.id) {
            Some(&i) => out[i].last_new = w.new_version(),
            None => {
                index.insert(w.id, out.len());
                out.push(Written { id: w.id, first_prev: w.prev_version, last_new: w.new_version() });
            }
        }
    }
    out
}

/// Every version a fork wrote, in log order, as writes onto `main`.
fn merge_writes(overlay: &Overlay) -> Vec<Write> {
    let mut recs: Vec<(u64, Ulid, &VersionRec)> =
        overlay.objects.iter().flat_map(|(id, recs)| recs.iter().map(move |r| (r.seq, *id, r))).collect();
    recs.sort_by_key(|(seq, id, r)| (*seq, *id, r.version));
    recs.into_iter()
        .map(|(_, id, r)| Write {
            id,
            prev_version: r.version.checked_sub(1).filter(|v| *v > 0),
            change: r.object.clone().map_or(Change::Delete, Change::Put),
        })
        .collect()
}

fn push_writes(overlay: &mut Overlay, seq: u64, writes: Vec<Write>) {
    for w in writes {
        let version = w.new_version();
        let object = match w.change {
            Change::Put(o) => Some(o),
            Change::Delete => None,
        };
        overlay.push(w.id, VersionRec { seq, version, object });
    }
}

pub struct Store<S, E> {
    log: Log<S>,
    env: E,
    ids: UlidGenerator,
    pub(crate) state: State,
}

type StoreResult<T, E> = core::result::Result<T, StoreError<E>>;

impl<S: LogStorage, E: Env> Store<S, E> {
    /// Opens a store on `storage`, verifying the log (against `anchor` if given) and
    /// replaying it.
    pub fn open(
        storage: S,
        env: E,
        anchor: Option<Anchor>,
    ) -> core::result::Result<Self, OpenError<S::Error, ReplayError>> {
        let mut state = State::default();
        let log = Log::open(storage, anchor, |entry| {
            let record = Record::from_cbor(&entry.record)?;
            if record.to_cbor() != entry.record {
                return Err(ReplayError::Format(FormatError::NotCanonical));
            }
            state.check(entry.seq, &record)?;
            state.apply(entry.seq, record);
            Ok(())
        })?;
        let ids = state.last_id.map_or(UlidGenerator::new(), UlidGenerator::resume);
        Ok(Store { log, env, ids, state })
    }

    pub fn anchor(&self) -> Anchor {
        self.log.anchor()
    }

    pub fn log(&self) -> &Log<S> {
        &self.log
    }

    pub fn env_mut(&mut self) -> &mut E {
        &mut self.env
    }

    /// A fresh ULID for a new object (monotonic with transaction and branch ids).
    pub fn new_id(&mut self) -> StoreResult<Ulid, S::Error> {
        let now = self.env.now();
        self.next_id(now)
    }

    fn next_id(&mut self, now: Timestamp) -> StoreResult<Ulid, S::Error> {
        let entropy = self.env.entropy();
        self.ids.generate(now.0, entropy).map_err(|_| StoreError::IdsExhausted)
    }

    fn append(&mut self, record: Record) -> StoreResult<u64, S::Error> {
        let seq = self.log.len();
        self.state.check(seq, &record).map_err(StoreError::Internal)?;
        self.log.append(record.to_cbor()).map_err(StoreError::Log)?;
        self.state.apply(seq, record);
        Ok(seq)
    }

    fn lifecycle(&mut self, branch: BranchId, actor: Actor, op: Op) -> StoreResult<u64, S::Error> {
        let timestamp = self.env.now();
        let tx = self.next_id(timestamp)?;
        let record =
            Record { tx, timestamp, branch, actor, capability: None, action: None, inputs: BTreeMap::new(), op };
        self.append(record)
    }

    fn fork_status(&self, fork: Ulid) -> StoreResult<&Status, S::Error> {
        self.state.forks.get(&fork).map(|f| &f.status).ok_or(StoreError::UnknownBranch(BranchId::Fork(fork)))
    }

    // ---- reads ----

    pub fn view(&self, branch: BranchId) -> Option<View<'_>> {
        self.state.head_view(branch)
    }

    pub fn get(&self, branch: BranchId, id: Ulid) -> Option<&Object> {
        self.state.head_view(branch)?.object(id)
    }

    /// The latest version of `id` on `branch`, counting tombstones.
    pub fn version(&self, branch: BranchId, id: Ulid) -> Option<u64> {
        self.state.head_view(branch)?.version(id)
    }

    pub fn resolve(&self, branch: BranchId, r: ObjectRef) -> Option<&Object> {
        self.state.head_view(branch)?.resolve(r)
    }

    /// All live objects visible on `branch`. O(objects); meant for tests and tools.
    pub fn objects(&self, branch: BranchId) -> BTreeMap<Ulid, Object> {
        let Some(view) = self.state.head_view(branch) else { return BTreeMap::new() };
        let fork_ids = match branch {
            BranchId::Fork(id) => self.state.forks.get(&id).map(|f| f.overlay.objects.keys()),
            BranchId::Main => None,
        };
        self.state
            .main
            .objects
            .keys()
            .chain(fork_ids.into_iter().flatten())
            .filter_map(|id| view.object(*id).map(|o| (*id, o.clone())))
            .collect()
    }

    pub fn status(&self, fork: Ulid) -> Option<&Status> {
        self.state.forks.get(&fork).map(|f| &f.status)
    }

    pub fn forks(&self) -> impl Iterator<Item = (Ulid, &Status)> {
        self.state.forks.iter().map(|(id, f)| (*id, &f.status))
    }

    // ---- transactions ----

    pub fn begin(&mut self, branch: BranchId, actor: Actor, meta: TxMeta) -> StoreResult<Tx, S::Error> {
        if !self.state.writable(branch) {
            return Err(match self.state.head_view(branch) {
                Some(_) => StoreError::NotWritable(branch),
                None => StoreError::UnknownBranch(branch),
            });
        }
        let timestamp = self.env.now();
        let id = self.next_id(timestamp)?;
        let snapshot = self.log.len();
        let main_before = match branch {
            BranchId::Main => snapshot,
            BranchId::Fork(f) => self.state.forks[&f].base,
        };
        Ok(Tx {
            id,
            timestamp,
            branch,
            actor,
            meta,
            snapshot,
            main_before,
            reads: BTreeMap::new(),
            writes: Vec::new(),
            pending: BTreeMap::new(),
        })
    }

    fn snapshot<'a>(&'a self, tx: &Tx) -> View<'a> {
        let fork = match tx.branch {
            BranchId::Main => None,
            BranchId::Fork(id) => self.state.forks.get(&id).map(|f| (&f.overlay, tx.snapshot)),
        };
        let main_before = if tx.branch == BranchId::Main { tx.snapshot } else { tx.main_before };
        View { main: &self.state.main, main_before, fork }
    }

    /// What the transaction sees for `id` (own writes first): the version, and `f` applied
    /// to the live object. Records the read.
    fn observe<R>(&self, tx: &mut Tx, id: Ulid, f: impl FnOnce(Option<&Object>) -> R) -> (Option<u64>, R) {
        if let Some(&(v, i)) = tx.pending.get(&id) {
            let object = match &tx.writes[i].change {
                Change::Put(o) => Some(o),
                Change::Delete => None,
            };
            return (Some(v), f(object));
        }
        let rec = self.snapshot(tx).rec(id);
        let version = rec.map(|r| r.version);
        tx.reads.entry(id).or_insert(version);
        (version, f(rec.and_then(|r| r.object.as_ref())))
    }

    pub fn read(&self, tx: &mut Tx, id: Ulid) -> Option<Object> {
        self.observe(tx, id, |o| o.cloned()).1
    }

    /// Writes `object` as the next version of `object.id` (creating it if needed). The
    /// store sets `version`, `provenance.actor` and `provenance.tx`, and raises the taint:
    /// external origin or any tainted input makes the object tainted (SPEC §10).
    pub fn put(&self, tx: &mut Tx, mut object: Object) -> StoreResult<(), S::Error> {
        let taint_of = |o: Option<&Object>| o.map(|o| o.provenance.taint);
        let mut taint = object.provenance.taint;
        if matches!(object.provenance.origin, Origin::External { .. }) {
            taint = Taint::External;
        }
        for r in &object.provenance.derived_from {
            // An unpinned input is part of the read set; a pinned version never changes.
            let input = match r.version {
                None => self.observe(tx, r.id, taint_of).1,
                Some(v) => match tx.pending.get(&r.id) {
                    Some(&(pv, i)) if pv == v => match &tx.writes[i].change {
                        Change::Put(o) => Some(o.provenance.taint),
                        Change::Delete => None,
                    },
                    _ => taint_of(self.snapshot(tx).resolve(*r)),
                },
            };
            taint = taint.max(input.ok_or(StoreError::MissingInput(*r))?);
        }
        let (prev, ()) = self.observe(tx, object.id, |_| ());
        object.version = prev.map_or(1, |v| v + 1);
        object.provenance.taint = taint;
        object.provenance.actor = tx.actor.clone();
        object.provenance.tx = tx.id;
        tx.pending.insert(object.id, (object.version, tx.writes.len()));
        tx.writes.push(Write { id: object.id, prev_version: prev, change: Change::Put(object) });
        Ok(())
    }

    pub fn delete(&self, tx: &mut Tx, id: Ulid) -> StoreResult<(), S::Error> {
        let (prev, live) = self.observe(tx, id, |o| o.is_some());
        let Some(prev) = prev.filter(|_| live) else { return Err(StoreError::NotFound(id)) };
        tx.pending.insert(id, (prev + 1, tx.writes.len()));
        tx.writes.push(Write { id, prev_version: Some(prev), change: Change::Delete });
        Ok(())
    }

    /// Validates and commits the transaction atomically: either every write is logged
    /// and applied, or nothing is.
    pub fn apply(&mut self, tx: Tx) -> StoreResult<Receipt, S::Error> {
        if !self.state.writable(tx.branch) {
            return Err(StoreError::NotWritable(tx.branch));
        }
        let head = self.state.head_view(tx.branch).ok_or(StoreError::UnknownBranch(tx.branch))?;
        let conflicts: Vec<Ulid> =
            tx.reads.iter().filter(|(id, seen)| head.version(**id) != **seen).map(|(id, _)| *id).collect();
        if !conflicts.is_empty() {
            return Err(StoreError::Conflict(conflicts));
        }
        if let Some(i) = tx.meta.preconditions.iter().position(|p| !p.eval(&head)) {
            return Err(StoreError::PreconditionFailed(i as u32));
        }
        if tx.writes.is_empty() {
            return Ok(Receipt { tx: tx.id, seq: None });
        }
        let record = Record {
            tx: tx.id,
            timestamp: tx.timestamp,
            branch: tx.branch,
            actor: tx.actor,
            capability: tx.meta.capability,
            action: tx.meta.action,
            inputs: tx.meta.inputs,
            op: Op::Write { writes: tx.writes, preconditions: tx.meta.preconditions, reverts: None },
        };
        let seq = self.append(record)?;
        Ok(Receipt { tx: tx.id, seq: Some(seq) })
    }

    // ---- undo ----

    /// Appends the inverse of transaction `target` to `branch` (SPEC §7.6). Every object
    /// the target wrote returns to its state before the target. Refused with `Conflict`
    /// if any of them was written again since, so later work is never silently lost.
    pub fn revert(&mut self, branch: BranchId, target: Ulid, actor: Actor) -> StoreResult<Receipt, S::Error> {
        if !self.state.writable(branch) {
            return Err(StoreError::NotWritable(branch));
        }
        let loc = self.state.txs.get(&target).ok_or(StoreError::UnknownTx(target))?;
        let visible = loc.branch == branch
            || match (loc.branch, branch) {
                (BranchId::Main, BranchId::Fork(f)) => loc.seq < self.state.forks[&f].base,
                _ => false,
            };
        if !visible {
            return Err(StoreError::NotVisible(target));
        }
        let head = self.state.head_view(branch).ok_or(StoreError::UnknownBranch(branch))?;
        let conflicts: Vec<Ulid> =
            loc.written.iter().filter(|w| head.version(w.id) != Some(w.last_new)).map(|w| w.id).collect();
        if !conflicts.is_empty() {
            return Err(StoreError::Conflict(conflicts));
        }
        let before = self.state.view_before(loc.branch, loc.seq).ok_or(StoreError::UnknownBranch(loc.branch))?;
        let restored: Vec<(Written, Option<Object>, bool)> = loc
            .written
            .iter()
            .map(|w| {
                let old = w.first_prev.and_then(|v| before.rec_with_version(w.id, v)).and_then(|r| r.object.clone());
                (*w, old, head.object(w.id).is_some())
            })
            .collect();

        let timestamp = self.env.now();
        let tx = self.next_id(timestamp)?;
        let mut writes = Vec::new();
        for (w, old, live) in restored {
            match old {
                Some(mut o) => {
                    o.version = w.last_new + 1;
                    o.provenance.actor = actor.clone();
                    o.provenance.tx = tx;
                    writes.push(Write { id: w.id, prev_version: Some(w.last_new), change: Change::Put(o) });
                }
                None if live => writes.push(Write { id: w.id, prev_version: Some(w.last_new), change: Change::Delete }),
                None => {} // created and deleted by the target: nothing to undo
            }
        }
        let record = Record {
            tx,
            timestamp,
            branch,
            actor,
            capability: None,
            action: None,
            inputs: BTreeMap::new(),
            op: Op::Write { writes, preconditions: Vec::new(), reverts: Some(target) },
        };
        let seq = self.append(record)?;
        Ok(Receipt { tx, seq: Some(seq) })
    }

    // ---- branches ----

    /// Forks a branch from the current `main` in O(1).
    pub fn fork(&mut self, actor: Actor) -> StoreResult<BranchId, S::Error> {
        let timestamp = self.env.now();
        let id = self.next_id(timestamp)?;
        let base = self.log.len();
        let record = Record {
            tx: id,
            timestamp,
            branch: BranchId::Fork(id),
            actor,
            capability: None,
            action: None,
            inputs: BTreeMap::new(),
            op: Op::Fork { base },
        };
        self.append(record)?;
        Ok(BranchId::Fork(id))
    }

    /// Moves the fork's base to the current `main`; refused if `main` changed an object the
    /// fork wrote.
    pub fn rebase(&mut self, fork: Ulid, actor: Actor) -> StoreResult<u64, S::Error> {
        let status = self.fork_status(fork)?;
        if !matches!(status, Status::Open { .. } | Status::Review { .. }) {
            return Err(StoreError::WrongStatus(BranchId::Fork(fork)));
        }
        let conflicts = self.state.conflicts(&self.state.forks[&fork]);
        if !conflicts.is_empty() {
            return Err(StoreError::Conflict(conflicts));
        }
        let base = self.log.len();
        self.lifecycle(BranchId::Fork(fork), actor, Op::Rebase { base })
    }

    /// Sends the branch to review (`aos.submit`, SPEC §13.1).
    pub fn submit(&mut self, fork: Ulid, actor: Actor) -> StoreResult<u64, S::Error> {
        if !matches!(self.fork_status(fork)?, Status::Open { .. }) {
            return Err(StoreError::WrongStatus(BranchId::Fork(fork)));
        }
        self.lifecycle(BranchId::Fork(fork), actor, Op::Submit)
    }

    /// Returns a branch under review to the agent, with a note.
    pub fn reopen(&mut self, fork: Ulid, note: Option<String>, actor: Actor) -> StoreResult<u64, S::Error> {
        if !matches!(self.fork_status(fork)?, Status::Review { .. }) {
            return Err(StoreError::WrongStatus(BranchId::Fork(fork)));
        }
        self.lifecycle(BranchId::Fork(fork), actor, Op::Reopen { note })
    }

    pub fn discard(&mut self, fork: Ulid, actor: Actor) -> StoreResult<u64, S::Error> {
        if !matches!(self.fork_status(fork)?, Status::Open { .. } | Status::Review { .. }) {
            return Err(StoreError::WrongStatus(BranchId::Fork(fork)));
        }
        self.lifecycle(BranchId::Fork(fork), actor, Op::Discard)
    }

    /// Commits a branch under review to `main` (SPEC §7.5): rebase onto the current `main`,
    /// detect conflicts per object version, re-evaluate every precondition, then write all
    /// of the branch's writes to `main` as one transaction. A refusal is logged and leaves
    /// the branch in review with the reason.
    pub fn commit(&mut self, fork: Ulid, actor: Actor) -> StoreResult<Receipt, S::Error> {
        if !matches!(self.fork_status(fork)?, Status::Review { .. }) {
            return Err(StoreError::WrongStatus(BranchId::Fork(fork)));
        }
        let rejection = {
            let f = &self.state.forks[&fork];
            let conflicts = self.state.conflicts(f);
            if conflicts.is_empty() { self.state.failed_precondition(f) } else { Some(Rejection::Conflict(conflicts)) }
        };
        if let Some(r) = rejection {
            self.lifecycle(BranchId::Fork(fork), actor, Op::Rejected(r.clone()))?;
            return Err(StoreError::Rejected(r));
        }
        let writes = merge_writes(&self.state.forks[&fork].overlay);

        let timestamp = self.env.now();
        let tx = self.next_id(timestamp)?;
        let base = self.log.len();
        let record = Record {
            tx,
            timestamp,
            branch: BranchId::Main,
            actor,
            capability: None,
            action: None,
            inputs: BTreeMap::new(),
            op: Op::Merge { from: fork, base, writes },
        };
        let seq = self.append(record)?;
        Ok(Receipt { tx, seq: Some(seq) })
    }
}
