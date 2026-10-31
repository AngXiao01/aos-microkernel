//! The action runtime (SPEC §8.3–8.4): runs WASM core modules in wasmi with only the AOS
//! host ABI, inside one transaction on the caller's branch, and enforces the declaration.
//!
//! - Before running: inputs are bound and validated; the capability token must cover the
//!   action's right and every input object; preconditions must hold; the cost estimate must
//!   fit the remaining budget. Fuel is limited by the CPU budget.
//! - While running: every object access is checked against the declared read/write types
//!   and the token's object scope, every intent against the declared egress channels and the
//!   token. A breach ends the run: the transaction is dropped and a `sys/ActionViolation`
//!   object records what happened. Importing anything but the host ABI (ambient I/O) is a
//!   breach too.
//! - Everything an action writes derives from everything it read, so taint (SPEC §10)
//!   cannot be laundered by action code.
//! - After running: the CPU actually used and one step are charged; the transaction is
//!   applied, and the store re-checks the preconditions on apply and again on commit.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod host;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};

use aos_action::{ActionDecl, BindError, DeclError, abi};
use aos_branch::{BranchId, Env, Receipt, Store, StoreError, TxMeta};
use aos_cap::{Authority, CapError, Limits, Token};
use aos_log::LogStorage;
use aos_types::cbor::{self, Cbor};
use aos_types::{Actor, Hash256, Object, Origin, Provenance, Sensitivity, Taint, Timestamp, TypeName, Ulid, Value};
use wasmi::{Config, Engine, Module};

/// Interpreter fuel per millisecond of CPU budget (a rough calibration of wasmi).
pub const FUEL_PER_CPU_MS: u64 = 1_000_000;

/// Content-addressed blob storage (SPEC §6.4).
pub trait BlobStore {
    fn put(&mut self, bytes: &[u8]) -> Hash256;
    fn get(&self, hash: &Hash256) -> Option<&[u8]>;
}

#[derive(Default)]
pub struct MemBlobs {
    blobs: BTreeMap<Hash256, Vec<u8>>,
}

impl BlobStore for MemBlobs {
    fn put(&mut self, bytes: &[u8]) -> Hash256 {
        let h = Hash256::digest(bytes);
        self.blobs.entry(h).or_insert_with(|| bytes.to_vec());
        h
    }

    fn get(&self, hash: &Hash256) -> Option<&[u8]> {
        self.blobs.get(hash).map(Vec::as_slice)
    }
}

/// The state actions operate on.
pub struct World<S, E> {
    pub store: Store<S, E>,
    pub authority: Authority,
    pub blobs: MemBlobs,
}

/// A loaded action: its declaration and compiled module.
pub struct Action {
    decl: ActionDecl,
    module: Module,
    /// An import outside the host ABI, if any: invoking the action is a violation.
    forbidden_import: Option<String>,
}

impl Action {
    pub fn decl(&self) -> &ActionDecl {
        &self.decl
    }
}

#[derive(Debug)]
pub enum LoadError {
    Declaration(DeclError),
    Wasm(String),
    MissingExport(&'static str),
}

pub struct Invocation {
    pub token: Token,
    pub branch: BranchId,
    pub actor: Actor,
    pub inputs: BTreeMap<String, Value>,
    pub now: Timestamp,
}

#[derive(Debug)]
pub struct Outcome {
    pub receipt: Receipt,
    pub outputs: BTreeMap<String, Value>,
    pub logs: Vec<(u32, String)>,
    /// Intents the action created (SPEC §11.1).
    pub intents: Vec<Ulid>,
    pub cpu_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    /// The module imports something other than the host ABI (ambient I/O).
    ForbiddenImport(String),
    UndeclaredRead(TypeName),
    UndeclaredWrite(TypeName),
    /// An intent on a channel the declaration or the capability does not allow.
    UndeclaredEgress(String),
    OutOfScope(Ulid),
    BadOutput(String),
}

impl Violation {
    fn kind(&self) -> &'static str {
        match self {
            Violation::ForbiddenImport(_) => "forbidden_import",
            Violation::UndeclaredRead(_) => "undeclared_read",
            Violation::UndeclaredWrite(_) => "undeclared_write",
            Violation::UndeclaredEgress(_) => "undeclared_egress",
            Violation::OutOfScope(_) => "out_of_scope",
            Violation::BadOutput(_) => "bad_output",
        }
    }

    fn detail(&self) -> String {
        match self {
            Violation::ForbiddenImport(s) | Violation::UndeclaredEgress(s) | Violation::BadOutput(s) => s.clone(),
            Violation::UndeclaredRead(t) | Violation::UndeclaredWrite(t) => format!("{t}"),
            Violation::OutOfScope(id) => format!("{id}"),
        }
    }
}

#[derive(Debug)]
pub enum InvokeError<E> {
    Capability(CapError),
    Inputs(BindError),
    Precondition(u32),
    /// The cost estimate exceeds the remaining budget.
    Budget,
    /// The action broke its declaration; `record` is the `sys/ActionViolation` object.
    Violation {
        violation: Violation,
        record: Ulid,
    },
    /// The module trapped or reported failure; nothing was written.
    Failed(String),
    OutOfFuel,
    Store(StoreError<E>),
}

impl<E> From<StoreError<E>> for InvokeError<E> {
    fn from(e: StoreError<E>) -> InvokeError<E> {
        InvokeError::Store(e)
    }
}

const ABI_FUNCS: [&str; 11] = [
    abi::READ,
    abi::WRITE,
    abi::DELETE,
    abi::CREATE,
    abi::QUERY,
    abi::BLOB_WRITE,
    abi::BLOB_READ,
    abi::INTENT_CREATE,
    abi::JOB_SUBMIT,
    abi::LOG,
    abi::OUTPUT,
];

pub const VIOLATION_TYPE: &str = "sys/ActionViolation@1";
pub const INTENT_TYPE: &str = "sys/EgressIntent@1";

/// The runtime with the world it operates on.
pub struct Sandbox<S, E> {
    engine: Engine,
    world: Option<World<S, E>>,
}

impl<S: LogStorage + 'static, E: Env + 'static> Sandbox<S, E> {
    pub fn new(world: World<S, E>) -> Sandbox<S, E> {
        let mut config = Config::default();
        config.consume_fuel(true);
        Sandbox { engine: Engine::new(&config), world: Some(world) }
    }

    pub fn world(&self) -> &World<S, E> {
        self.world.as_ref().expect("the world is only lent out during an invocation")
    }

    pub fn world_mut(&mut self) -> &mut World<S, E> {
        self.world.as_mut().expect("the world is only lent out during an invocation")
    }

    pub fn load(&self, decl: ActionDecl, wasm: &[u8]) -> Result<Action, LoadError> {
        decl.check().map_err(LoadError::Declaration)?;
        let module = Module::new(&self.engine, wasm).map_err(|e| LoadError::Wasm(format!("{e}")))?;
        let forbidden_import = module
            .imports()
            .find(|i| i.module() != abi::MODULE || !ABI_FUNCS.contains(&i.name()))
            .map(|i| format!("{}::{}", i.module(), i.name()));
        for name in ["memory", "aos_alloc", "run"] {
            if module.exports().all(|e| e.name() != name) {
                return Err(LoadError::MissingExport(name));
            }
        }
        Ok(Action { decl, module, forbidden_import })
    }

    pub fn invoke(&mut self, action: &Action, inv: Invocation) -> Result<Outcome, InvokeError<S::Error>> {
        let world = self.world.take().expect("invocations do not nest");
        let (world, result) = host::run(&self.engine, world, action, inv);
        self.world = Some(world);
        result
    }
}

/// Records a violation as its own transaction on the branch (SPEC §8.3.5).
fn record_violation<S: LogStorage, E: Env>(
    world: &mut World<S, E>,
    action: &ActionDecl,
    inv: &Invocation,
    violation: &Violation,
) -> Result<Ulid, StoreError<S::Error>> {
    let id = world.store.new_id()?;
    let meta = TxMeta { capability: Some(inv.token.id.0), action: Some(action.id()), ..TxMeta::default() };
    let mut tx = world.store.begin(inv.branch, Actor::System, meta)?;
    let mut fields = BTreeMap::new();
    fields.insert("action".into(), Value::Text(action.id()));
    fields.insert("kind".into(), Value::text(violation.kind()));
    fields.insert("detail".into(), Value::Text(violation.detail()));
    fields.insert("capability".into(), Value::Text(format!("{}", inv.token.id)));
    fields.insert("actor".into(), Value::Text(format!("{}", inv.actor)));
    world.store.put(&mut tx, new_object(id, VIOLATION_TYPE, fields, BTreeSet::new(), Sensitivity::Internal))?;
    world.store.apply(tx)?;
    Ok(id)
}

fn new_object(
    id: Ulid,
    type_id: &str,
    fields: BTreeMap<String, Value>,
    derived_from: BTreeSet<aos_types::ObjectRef>,
    sensitivity: Sensitivity,
) -> Object {
    Object {
        id,
        type_id: type_id.parse().expect("system type ids are valid"),
        version: 0,
        fields,
        blobs: BTreeSet::new(),
        provenance: Provenance {
            actor: Actor::System,
            origin: Origin::Internal,
            taint: Taint::Clean,
            derived_from,
            tx: Ulid::from_u128(0),
        },
        sensitivity,
        extra: BTreeMap::new(),
    }
}

fn cbor_map(values: &BTreeMap<String, Value>) -> Vec<u8> {
    cbor::encode(&aos_types::ToCbor::to_cbor(&Value::Map(values.clone())))
}

fn charge<E>(authority: &mut Authority, token: &Token, cpu_ms: u64) -> Result<(), InvokeError<E>> {
    authority.charge(token.id, Limits { cpu_ms, steps: 1, ..Limits::default() }).map_err(InvokeError::Capability)
}

pub(crate) fn decode_map(bytes: &[u8]) -> Option<aos_types::CborMap> {
    match cbor::decode(bytes).ok()? {
        Cbor::Map(m) => Some(m),
        _ => None,
    }
}
