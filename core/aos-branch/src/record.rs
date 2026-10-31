//! Log records: the schema of every log entry written by the store (SPEC §7.1).
//!
//! Besides transactions, branch lifecycle events (fork, rebase, submit, reopen, merge,
//! rejection, discard) are records too, so the whole store state is a replay of the log.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{fmt, str::FromStr};

use aos_types::cbor::Cbor;
use aos_types::codec::{self, FormatError, FromCbor, ToCbor};
use aos_types::{Actor, Object, Timestamp, Ulid, Value};

use crate::codec::{MapBuilder, MapReader, array, text, uint, ulid_from, ulid_to};
use crate::predicate::Predicate;

/// `main` is reality (SPEC §7.3); every other branch forks from it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum BranchId {
    Main,
    Fork(Ulid),
}

impl fmt::Display for BranchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BranchId::Main => f.write_str("main"),
            BranchId::Fork(id) => write!(f, "branch/{id}"),
        }
    }
}

impl FromStr for BranchId {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<BranchId, FormatError> {
        if s == "main" {
            return Ok(BranchId::Main);
        }
        let id = s.strip_prefix("branch/").and_then(|u| Ulid::parse(u).ok());
        match id {
            Some(id) if alloc::format!("{id}") == s["branch/".len()..] => Ok(BranchId::Fork(id)),
            _ => Err(FormatError::InvalidValue("branch")),
        }
    }
}

// Almost every write is a `Put`, so boxing the object would only add an allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The object's new state; its `version` is the write's new version.
    Put(Object),
    /// Tombstone (SPEC §6.3): the version exists, the object no longer does.
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    pub id: Ulid,
    /// `None` when the object is created.
    pub prev_version: Option<u64>,
    pub change: Change,
}

impl Write {
    pub fn new_version(&self) -> u64 {
        self.prev_version.map_or(1, |v| v + 1)
    }
}

/// Why a commit was refused; the branch stays in review with this reason (SPEC §7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Objects changed on `main` since the branch read them.
    Conflict(Vec<Ulid>),
    /// Precondition `index` of transaction `tx` no longer holds on the rebased branch.
    Precondition { tx: Ulid, index: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Write {
        writes: Vec<Write>,
        preconditions: Vec<Predicate>,
        reverts: Option<Ulid>,
    },
    /// `branch` forks from `main`; it sees `main` entries with `seq < base`.
    Fork {
        base: u64,
    },
    Rebase {
        base: u64,
    },
    Submit,
    /// Sent back to the agent ("退回并附意见", SPEC §13.2).
    Reopen {
        note: Option<String>,
    },
    /// Recorded on `main`: the writes of branch `from`, rebased onto `base`, as one transaction.
    Merge {
        from: Ulid,
        base: u64,
        writes: Vec<Write>,
    },
    Rejected(Rejection),
    Discard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub tx: Ulid,
    pub timestamp: Timestamp,
    pub branch: BranchId,
    pub actor: Actor,
    pub capability: Option<Ulid>,
    pub action: Option<String>,
    pub inputs: BTreeMap<String, Value>,
    pub op: Op,
}

impl ToCbor for BranchId {
    fn to_cbor(&self) -> Cbor {
        Cbor::Text(alloc::format!("{self}"))
    }
}

impl FromCbor for BranchId {
    fn from_cbor(value: &Cbor) -> Result<BranchId, FormatError> {
        text(value, "branch")?.parse()
    }
}

impl ToCbor for Write {
    fn to_cbor(&self) -> Cbor {
        let b = MapBuilder::new()
            .put("id", ulid_to(self.id))
            .put_opt("prev_version", self.prev_version.map(Cbor::Unsigned));
        match &self.change {
            Change::Put(object) => b.put("put", object.to_cbor()),
            Change::Delete => b.put("delete", Cbor::Bool(true)),
        }
        .build()
    }
}

impl FromCbor for Write {
    fn from_cbor(value: &Cbor) -> Result<Write, FormatError> {
        let mut r = MapReader::new(value, "write")?;
        let id = ulid_from(r.req("id")?)?;
        let prev_version = r.opt("prev_version").map(|v| uint(v, "prev_version")).transpose()?;
        let change = match (r.opt("put"), r.opt("delete")) {
            (Some(o), None) => Change::Put(Object::from_cbor(o)?),
            (None, Some(Cbor::Bool(true))) => Change::Delete,
            _ => return Err(FormatError::InvalidValue("write change")),
        };
        r.finish()?;
        let write = Write { id, prev_version, change };
        if let Change::Put(o) = &write.change
            && (o.id != id || o.version != write.new_version())
        {
            return Err(FormatError::InvalidValue("written object id or version"));
        }
        Ok(write)
    }
}

fn writes_to(writes: &[Write]) -> Cbor {
    Cbor::Array(writes.iter().map(ToCbor::to_cbor).collect())
}

fn writes_from(value: &Cbor) -> Result<Vec<Write>, FormatError> {
    array(value, "writes")?.iter().map(Write::from_cbor).collect()
}

impl ToCbor for Rejection {
    fn to_cbor(&self) -> Cbor {
        match self {
            Rejection::Conflict(ids) => {
                MapBuilder::new().put("conflict", Cbor::Array(ids.iter().map(|id| ulid_to(*id)).collect()))
            }
            Rejection::Precondition { tx, index } => MapBuilder::new().put(
                "precondition",
                MapBuilder::new().put("tx", ulid_to(*tx)).put("index", Cbor::Unsigned((*index).into())).build(),
            ),
        }
        .build()
    }
}

impl FromCbor for Rejection {
    fn from_cbor(value: &Cbor) -> Result<Rejection, FormatError> {
        let mut r = MapReader::new(value, "rejection")?;
        let rejection = match (r.opt("conflict"), r.opt("precondition")) {
            (Some(ids), None) => {
                Rejection::Conflict(array(ids, "conflict")?.iter().map(ulid_from).collect::<Result<_, _>>()?)
            }
            (None, Some(p)) => {
                let mut pr = MapReader::new(p, "precondition")?;
                let tx = ulid_from(pr.req("tx")?)?;
                let index =
                    u32::try_from(uint(pr.req("index")?, "index")?).map_err(|_| FormatError::InvalidValue("index"))?;
                pr.finish()?;
                Rejection::Precondition { tx, index }
            }
            _ => return Err(FormatError::InvalidValue("rejection")),
        };
        r.finish()?;
        Ok(rejection)
    }
}

impl ToCbor for Op {
    fn to_cbor(&self) -> Cbor {
        let kind = |k: &str| MapBuilder::new().put("kind", Cbor::text(k));
        match self {
            Op::Write { writes, preconditions, reverts } => kind("write")
                .put("writes", writes_to(writes))
                .put("preconditions", Cbor::Array(preconditions.iter().map(ToCbor::to_cbor).collect()))
                .put_opt("reverts", reverts.map(ulid_to)),
            Op::Fork { base } => kind("fork").put("base", Cbor::Unsigned(*base)),
            Op::Rebase { base } => kind("rebase").put("base", Cbor::Unsigned(*base)),
            Op::Submit => kind("submit"),
            Op::Reopen { note } => kind("reopen").put_opt("note", note.clone().map(Cbor::Text)),
            Op::Merge { from, base, writes } => kind("merge")
                .put("from", ulid_to(*from))
                .put("base", Cbor::Unsigned(*base))
                .put("writes", writes_to(writes)),
            Op::Rejected(r) => kind("rejected").put("reason", r.to_cbor()),
            Op::Discard => kind("discard"),
        }
        .build()
    }
}

impl FromCbor for Op {
    fn from_cbor(value: &Cbor) -> Result<Op, FormatError> {
        let mut r = MapReader::new(value, "op")?;
        let op = match text(r.req("kind")?, "kind")? {
            "write" => Op::Write {
                writes: writes_from(r.req("writes")?)?,
                preconditions: array(r.req("preconditions")?, "preconditions")?
                    .iter()
                    .map(Predicate::from_cbor)
                    .collect::<Result<_, _>>()?,
                reverts: r.opt("reverts").map(ulid_from).transpose()?,
            },
            "fork" => Op::Fork { base: uint(r.req("base")?, "base")? },
            "rebase" => Op::Rebase { base: uint(r.req("base")?, "base")? },
            "submit" => Op::Submit,
            "reopen" => Op::Reopen { note: r.opt("note").map(|n| text(n, "note").map(String::from)).transpose()? },
            "merge" => Op::Merge {
                from: ulid_from(r.req("from")?)?,
                base: uint(r.req("base")?, "base")?,
                writes: writes_from(r.req("writes")?)?,
            },
            "rejected" => Op::Rejected(Rejection::from_cbor(r.req("reason")?)?),
            "discard" => Op::Discard,
            _ => return Err(FormatError::InvalidValue("op kind")),
        };
        r.finish()?;
        Ok(op)
    }
}

impl ToCbor for Record {
    fn to_cbor(&self) -> Cbor {
        MapBuilder::new()
            .put("tx", ulid_to(self.tx))
            .put("timestamp", Cbor::Unsigned(self.timestamp.0))
            .put("branch", self.branch.to_cbor())
            .put("actor", Cbor::Text(alloc::format!("{}", self.actor)))
            .put_opt("capability", self.capability.map(ulid_to))
            .put_opt("action", self.action.clone().map(Cbor::Text))
            .put("inputs", codec::text_map(&self.inputs, Value::to_cbor))
            .put("op", self.op.to_cbor())
            .build()
    }
}

impl FromCbor for Record {
    fn from_cbor(value: &Cbor) -> Result<Record, FormatError> {
        let mut r = MapReader::new(value, "record")?;
        let tx = ulid_from(r.req("tx")?)?;
        let timestamp = Timestamp(uint(r.req("timestamp")?, "timestamp")?);
        let branch = BranchId::from_cbor(r.req("branch")?)?;
        let actor: Actor = text(r.req("actor")?, "actor")?.parse()?;
        let capability = r.opt("capability").map(ulid_from).transpose()?;
        let action = r.opt("action").map(|a| text(a, "action").map(String::from)).transpose()?;
        let inputs = match Value::from_cbor(r.req("inputs")?)? {
            Value::Map(m) => m,
            _ => return Err(FormatError::WrongType("inputs")),
        };
        let op = Op::from_cbor(r.req("op")?)?;
        r.finish()?;
        Ok(Record { tx, timestamp, branch, actor, capability, action, inputs, op })
    }
}
