//! Transactions, branches, diffs and undo over the AOS log (SPEC §7).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod codec;
pub mod diff;
pub mod predicate;
pub mod record;
pub mod store;

pub use diff::{ChangeKind, Diff, ObjectChange, TypeChanges};
pub use predicate::{Cmp, Lookup, Predicate};
pub use record::{BranchId, Change, Op, Record, Rejection, Write};
pub use store::{Env, Receipt, ReplayError, Status, Store, StoreError, Tx, TxMeta, View};

impl<S: aos_log::LogStorage, E: Env> Store<S, E> {
    /// What committing `fork` would change on the current `main`; `None` for an unknown fork.
    pub fn diff(&self, fork: aos_types::Ulid) -> Option<Diff> {
        self.state.diff(fork)
    }
}
