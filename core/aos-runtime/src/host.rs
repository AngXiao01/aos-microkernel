//! One invocation: prepare (bind, authorize, preconditions, budget), execute the module
//! with the host ABI, finish (charge, record violations, apply).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};

use aos_action::{Bound, abi};
use aos_branch::{Env, Predicate, StoreError, Tx, TxMeta};
use aos_cap::Token;
use aos_log::LogStorage;
use aos_types::cbor::{self, Cbor, CborMap};
use aos_types::value::{hash_from_cbor, ulid_from_cbor, ulid_to_cbor};
use aos_types::{
    FromCbor, Hash256, Object, ObjectRef, Origin, Provenance, Sensitivity, Taint, Timestamp, ToCbor, TypeId, Ulid,
    Value,
};
use wasmi::core::TrapCode;
use wasmi::{Caller, Engine, Extern, Linker};

use crate::{
    Action, FUEL_PER_CPU_MS, INTENT_TYPE, Invocation, InvokeError, Outcome, Violation, World, cbor_map, charge,
    decode_map, record_violation,
};

/// Calls with side effects require at least this much output space, so that a too-small
/// buffer never tempts the action into repeating them.
const MIN_EFFECT_OUT: i32 = 64;
const DEFAULT_QUERY_LIMIT: u64 = 50;
const MAX_QUERY_LIMIT: u64 = 1000;
const MAX_LOGS: usize = 1000;

struct Prepared {
    bound: Bound,
    preconditions: Vec<Predicate>,
    fuel: u64,
    input: Vec<u8>,
}

pub(crate) struct Host<S, E> {
    world: World<S, E>,
    decl: aos_action::ActionDecl,
    token: Token,
    now: Timestamp,
    tx: Tx,
    /// Every object version the action read: what everything it writes derives from.
    reads: BTreeSet<ObjectRef>,
    read_sensitivity: Option<Sensitivity>,
    violation: Option<Violation>,
    outputs: Option<Vec<u8>>,
    logs: Vec<(u32, String)>,
    intents: Vec<Ulid>,
}

enum Fail {
    Code(i32),
    Violation(Violation),
}

const BAD: Fail = Fail::Code(abi::ERR_BAD_ARGUMENT);

type HostFn<S, E> = fn(&mut Host<S, E>, &[u8]) -> Result<Vec<u8>, Fail>;
type Invoked<S, E> = (World<S, E>, Result<Outcome, InvokeError<<S as LogStorage>::Error>>);

// Short-lived and moved once; boxing the large variant would only add an allocation.
#[allow(clippy::large_enum_variant)]
enum Exec<E> {
    Store(StoreError<E>),
    Ran {
        result: Result<i32, wasmi::Error>,
        fuel_used: u64,
        tx: Tx,
        violation: Option<Violation>,
        outputs: Option<Vec<u8>>,
        logs: Vec<(u32, String)>,
        intents: Vec<Ulid>,
    },
}

pub(crate) fn run<S: LogStorage + 'static, E: Env + 'static>(
    engine: &Engine,
    mut world: World<S, E>,
    action: &Action,
    inv: Invocation,
) -> Invoked<S, E> {
    let prepared = match prepare(&mut world, action, &inv) {
        Ok(p) => p,
        Err(e) => return (world, Err(e)),
    };
    let (mut world, exec) = execute(engine, world, action, &inv, prepared);
    let result = finish(&mut world, action, &inv, exec);
    (world, result)
}

fn ceil_ms(seconds: f64) -> u64 {
    let ms = seconds * 1000.0;
    let whole = ms as u64;
    if (whole as f64) < ms { whole + 1 } else { whole }
}

fn prepare<S: LogStorage, E: Env>(
    world: &mut World<S, E>,
    action: &Action,
    inv: &Invocation,
) -> Result<Prepared, InvokeError<S::Error>> {
    let decl = &action.decl;
    let bound = decl.bind(&inv.inputs).map_err(InvokeError::Inputs)?;
    let objects: Vec<_> = decl.input_objects(&bound).into_iter().map(|(t, r)| (t, r.id)).collect();
    world.authority.authorize(&inv.token, inv.now, &decl.capability, &objects).map_err(InvokeError::Capability)?;
    if let Some(import) = &action.forbidden_import {
        let violation = Violation::ForbiddenImport(import.clone());
        let record = record_violation(world, decl, inv, &violation)?;
        return Err(InvokeError::Violation { violation, record });
    }
    let preconditions =
        decl.compile_preconditions(&bound).map_err(|e| InvokeError::Failed(format!("precondition: {}", e.0)))?;
    let view = world.store.view(inv.branch).ok_or(StoreError::UnknownBranch(inv.branch))?;
    if let Some(i) = preconditions.iter().position(|p| !p.eval(&view)) {
        return Err(InvokeError::Precondition(i as u32));
    }
    let estimate = decl.estimate_cost(&bound, &view).map_or(0, ceil_ms);
    let available = world.authority.available(inv.token.id).unwrap_or_default();
    if available.steps == 0 || available.cpu_ms == 0 || available.cpu_ms < estimate {
        return Err(InvokeError::Budget);
    }
    let input = cbor_map(&bound.values);
    Ok(Prepared { bound, preconditions, fuel: available.cpu_ms.saturating_mul(FUEL_PER_CPU_MS), input })
}

fn execute<S: LogStorage + 'static, E: Env + 'static>(
    engine: &Engine,
    mut world: World<S, E>,
    action: &Action,
    inv: &Invocation,
    prepared: Prepared,
) -> (World<S, E>, Exec<S::Error>) {
    let meta = TxMeta {
        capability: Some(inv.token.id.0),
        action: Some(action.decl.id()),
        inputs: prepared.bound.values.clone(),
        preconditions: prepared.preconditions,
    };
    let tx = match world.store.begin(inv.branch, inv.actor.clone(), meta) {
        Ok(tx) => tx,
        Err(e) => return (world, Exec::Store(e)),
    };
    let host = Host {
        world,
        decl: action.decl.clone(),
        token: inv.token.clone(),
        now: inv.now,
        tx,
        reads: BTreeSet::new(),
        read_sensitivity: None,
        violation: None,
        outputs: None,
        logs: Vec::new(),
        intents: Vec::new(),
    };
    let mut store = wasmi::Store::new(engine, host);
    // Fuel metering is enabled on the engine, so this cannot fail.
    let _ = store.set_fuel(prepared.fuel);
    let result = (|| -> Result<i32, wasmi::Error> {
        let instance = linker::<S, E>(engine)?.instantiate(&mut store, &action.module)?.start(&mut store)?;
        let alloc = instance.get_typed_func::<i32, i32>(&store, "aos_alloc")?;
        let run = instance.get_typed_func::<(i32, i32), i32>(&store, "run")?;
        let memory = instance.get_memory(&store, "memory").ok_or_else(|| wasmi::Error::new("no memory export"))?;
        let len = i32::try_from(prepared.input.len()).map_err(|_| wasmi::Error::new("inputs too large"))?;
        let ptr = alloc.call(&mut store, len)?;
        memory
            .write(&mut store, ptr as u32 as usize, &prepared.input)
            .map_err(|_| wasmi::Error::new("aos_alloc returned an invalid pointer"))?;
        run.call(&mut store, (ptr, len))
    })();
    let fuel_used = prepared.fuel - store.get_fuel().unwrap_or(0);
    let host = store.into_data();
    let exec = Exec::Ran {
        result,
        fuel_used,
        tx: host.tx,
        violation: host.violation,
        outputs: host.outputs,
        logs: host.logs,
        intents: host.intents,
    };
    (host.world, exec)
}

fn finish<S: LogStorage, E: Env>(
    world: &mut World<S, E>,
    action: &Action,
    inv: &Invocation,
    exec: Exec<S::Error>,
) -> Result<Outcome, InvokeError<S::Error>> {
    let Exec::Ran { result, fuel_used, tx, violation, outputs, logs, intents } = exec else {
        let Exec::Store(e) = exec else { unreachable!() };
        return Err(InvokeError::Store(e));
    };
    let cpu_ms = fuel_used.div_ceil(FUEL_PER_CPU_MS);
    charge(&mut world.authority, &inv.token, cpu_ms)?;
    let violate = |world: &mut World<S, E>, violation: Violation| -> InvokeError<S::Error> {
        match record_violation(world, &action.decl, inv, &violation) {
            Ok(record) => InvokeError::Violation { violation, record },
            Err(e) => InvokeError::Store(e),
        }
    };
    if let Some(v) = violation {
        drop(tx);
        return Err(violate(world, v));
    }
    let code = match result {
        Ok(code) => code,
        Err(e) if e.as_trap_code() == Some(TrapCode::OutOfFuel) => return Err(InvokeError::OutOfFuel),
        Err(e) => return Err(InvokeError::Failed(format!("{e}"))),
    };
    if code != 0 {
        return Err(InvokeError::Failed(format!("run returned {code}")));
    }
    let outputs = match check_outputs(&action.decl, outputs.as_deref()) {
        Ok(o) => o,
        Err(detail) => return Err(violate(world, Violation::BadOutput(detail))),
    };
    let receipt = world.store.apply(tx)?;
    Ok(Outcome { receipt, outputs, logs, intents, cpu_ms })
}

/// Every declared output must be present with its declared kind, and nothing else.
fn check_outputs(decl: &aos_action::ActionDecl, bytes: Option<&[u8]>) -> Result<BTreeMap<String, Value>, String> {
    let values = match bytes {
        None => BTreeMap::new(),
        Some(b) => match cbor::decode(b).ok().and_then(|c| Value::from_cbor(&c).ok()) {
            Some(Value::Map(m)) => m,
            _ => return Err("outputs are not a CBOR map".into()),
        },
    };
    if let Some(extra) = values.keys().find(|k| !decl.outputs.contains_key(*k)) {
        return Err(format!("undeclared output {extra}"));
    }
    for (name, kind) in &decl.outputs {
        let v = values.get(name).ok_or_else(|| format!("missing output {name}"))?;
        kind.check(name, v).map_err(|e| format!("{e:?}"))?;
    }
    Ok(values)
}

fn linker<S: LogStorage + 'static, E: Env + 'static>(engine: &Engine) -> Result<Linker<Host<S, E>>, wasmi::Error> {
    let mut l = Linker::<Host<S, E>>::new(engine);
    macro_rules! io {
        ($name:expr, $f:path, $effect:expr) => {
            l.func_wrap(abi::MODULE, $name, |c: Caller<'_, Host<S, E>>, a: i32, b: i32, o: i32, n: i32| {
                io_call(c, a, b, o, n, $f, $effect)
            })?;
        };
    }
    io!(abi::READ, Host::read, false);
    io!(abi::WRITE, Host::write, true);
    io!(abi::DELETE, Host::delete, true);
    io!(abi::CREATE, Host::create, true);
    io!(abi::QUERY, Host::query, false);
    io!(abi::BLOB_WRITE, Host::blob_write, true);
    io!(abi::BLOB_READ, Host::blob_read, false);
    io!(abi::INTENT_CREATE, Host::intent, true);
    io!(abi::JOB_SUBMIT, Host::job, true);
    l.func_wrap(abi::MODULE, abi::LOG, |mut c: Caller<'_, Host<S, E>>, level: i32, ptr: i32, len: i32| {
        let text = read_guest(&mut c, ptr, len).map(|b| String::from_utf8_lossy(&b).into_owned());
        let host = c.data_mut();
        if let Some(t) = text
            && host.logs.len() < MAX_LOGS
        {
            host.logs.push((level as u32, t));
        }
        0i32
    })?;
    l.func_wrap(abi::MODULE, abi::OUTPUT, |mut c: Caller<'_, Host<S, E>>, ptr: i32, len: i32| {
        match read_guest(&mut c, ptr, len) {
            Some(b) => {
                c.data_mut().outputs = Some(b);
                0i32
            }
            None => abi::ERR_BAD_ARGUMENT,
        }
    })?;
    Ok(l)
}

fn read_guest<S, E>(c: &mut Caller<'_, Host<S, E>>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let memory = c.get_export("memory").and_then(Extern::into_memory)?;
    let (ptr, len) = (usize::try_from(ptr).ok()?, usize::try_from(len).ok()?);
    if len > memory.data_size(&*c) {
        return None;
    }
    let mut buf = vec![0u8; len];
    memory.read(&*c, ptr, &mut buf).ok()?;
    Some(buf)
}

fn io_call<S, E>(
    mut c: Caller<'_, Host<S, E>>,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
    out_cap: i32,
    f: HostFn<S, E>,
    effect: bool,
) -> Result<i32, wasmi::Error> {
    if out_cap < 0 || (effect && out_cap < MIN_EFFECT_OUT) {
        return Ok(abi::ERR_BAD_ARGUMENT);
    }
    let Some(input) = read_guest(&mut c, in_ptr, in_len) else { return Ok(abi::ERR_BAD_ARGUMENT) };
    match f(c.data_mut(), &input) {
        Ok(out) => {
            if out.len() <= out_cap as usize {
                let memory = c.get_export("memory").and_then(Extern::into_memory);
                let Ok(ptr) = usize::try_from(out_ptr) else { return Ok(abi::ERR_BAD_ARGUMENT) };
                if memory.is_none_or(|m| m.write(&mut c, ptr, &out).is_err()) {
                    return Ok(abi::ERR_BAD_ARGUMENT);
                }
            }
            Ok(out.len() as i32)
        }
        Err(Fail::Code(code)) => Ok(code),
        Err(Fail::Violation(v)) => {
            c.data_mut().violation = Some(v);
            Err(wasmi::Error::new("action violated its declaration"))
        }
    }
}

fn field<'a>(m: &'a CborMap, key: &str) -> Result<&'a Cbor, Fail> {
    m.get_str(key).ok_or(BAD)
}

fn id_of(m: &CborMap) -> Result<Ulid, Fail> {
    ulid_from_cbor(field(m, "id")?).map_err(|_| BAD)
}

fn single(key: &str, value: Cbor) -> Vec<u8> {
    let mut m = CborMap::new();
    m.insert(Cbor::text(key), value);
    cbor::encode(&Cbor::Map(m))
}

fn fields_of(v: &Cbor) -> Result<BTreeMap<String, Option<Value>>, Fail> {
    let m = v.as_map().ok_or(BAD)?;
    let mut out = BTreeMap::new();
    for (k, v) in m.iter() {
        let k = String::from(k.as_text().ok_or(BAD)?);
        let v = if *v == Cbor::Null { None } else { Some(Value::from_cbor(v).map_err(|_| BAD)?) };
        out.insert(k, v);
    }
    Ok(out)
}

impl<S: LogStorage, E: Env> Host<S, E> {
    fn check_scope(&self, object: &Object) -> Result<(), Fail> {
        match self.token.spec.scope.get(&object.type_id.name) {
            Some(allowed) if !allowed.contains(&object.id) => Err(Fail::Violation(Violation::OutOfScope(object.id))),
            _ => Ok(()),
        }
    }

    fn check_read(&self, object: &Object) -> Result<(), Fail> {
        if !self.decl.effects.may_read(&object.type_id.name) {
            return Err(Fail::Violation(Violation::UndeclaredRead(object.type_id.name.clone())));
        }
        self.check_scope(object)
    }

    fn check_write(&self, object: &Object) -> Result<(), Fail> {
        if !self.decl.effects.may_write(&object.type_id.name) {
            return Err(Fail::Violation(Violation::UndeclaredWrite(object.type_id.name.clone())));
        }
        self.check_scope(object)
    }

    fn note_read(&mut self, object: &Object) {
        self.reads.insert(object.object_ref());
        self.read_sensitivity = self.read_sensitivity.max(Some(object.sensitivity));
    }

    /// New data is at least as sensitive as anything it was computed from; with no inputs it
    /// gets the default for user data.
    fn derived_sensitivity(&self) -> Sensitivity {
        self.read_sensitivity.unwrap_or(Sensitivity::USER_DEFAULT)
    }

    fn current(&mut self, m: &CborMap) -> Result<Object, Fail> {
        let id = id_of(m)?;
        let object = self.world.store.read(&mut self.tx, id).ok_or(Fail::Code(abi::ERR_NOT_FOUND))?;
        let expected = field(m, "expected_version")?.as_u64().ok_or(BAD)?;
        self.check_write(&object)?;
        if object.version != expected {
            return Err(Fail::Code(abi::ERR_CONFLICT));
        }
        Ok(object)
    }

    fn read(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let id = id_of(&m)?;
        let object = self.world.store.read(&mut self.tx, id).ok_or(Fail::Code(abi::ERR_NOT_FOUND))?;
        self.check_read(&object)?;
        self.note_read(&object);
        Ok(cbor::encode(&object.to_cbor()))
    }

    fn write(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let mut object = self.current(&m)?;
        for (k, v) in fields_of(field(&m, "fields")?)? {
            match v {
                Some(v) => object.fields.insert(k, v),
                None => object.fields.remove(&k),
            };
        }
        self.note_read(&object);
        object.provenance.derived_from = self.reads.clone();
        object.sensitivity = object.sensitivity.max(self.derived_sensitivity());
        let version = object.version + 1;
        self.world.store.put(&mut self.tx, object).map_err(|_| BAD)?;
        Ok(single("version", Cbor::Unsigned(version)))
    }

    fn delete(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let object = self.current(&m)?;
        self.world.store.delete(&mut self.tx, object.id).map_err(|_| Fail::Code(abi::ERR_NOT_FOUND))?;
        Ok(single("version", Cbor::Unsigned(object.version + 1)))
    }

    fn new_object(&mut self, type_id: TypeId, fields: BTreeMap<String, Value>) -> Result<Object, Fail> {
        let id = self.world.store.new_id().map_err(|_| BAD)?;
        Ok(Object {
            id,
            type_id,
            version: 0,
            fields,
            blobs: BTreeSet::new(),
            provenance: Provenance {
                actor: aos_types::Actor::System,
                origin: Origin::Internal,
                taint: Taint::Clean,
                derived_from: self.reads.clone(),
                tx: Ulid::from_u128(0),
            },
            sensitivity: self.derived_sensitivity(),
            extra: BTreeMap::new(),
        })
    }

    fn create(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let type_id: TypeId = field(&m, "type")?.as_text().ok_or(BAD)?.parse().map_err(|_| BAD)?;
        if !self.decl.effects.may_write(&type_id.name) {
            return Err(Fail::Violation(Violation::UndeclaredWrite(type_id.name)));
        }
        let fields = fields_of(field(&m, "fields")?)?.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect();
        let object = self.new_object(type_id, fields)?;
        let id = object.id;
        self.world.store.put(&mut self.tx, object).map_err(|_| BAD)?;
        Ok(single("id", ulid_to_cbor(id)))
    }

    fn query(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let type_id: TypeId = field(&m, "from")?.as_text().ok_or(BAD)?.parse().map_err(|_| BAD)?;
        if !self.decl.effects.may_read(&type_id.name) {
            return Err(Fail::Violation(Violation::UndeclaredRead(type_id.name)));
        }
        let filter = match m.get_str("where") {
            Some(w) => fields_of(w)?,
            None => BTreeMap::new(),
        };
        let limit = m.get_str("limit").map_or(Some(DEFAULT_QUERY_LIMIT), Cbor::as_u64).ok_or(BAD)?.min(MAX_QUERY_LIMIT);
        let scope = self.token.spec.scope.get(&type_id.name).cloned();
        let mut ids = Vec::new();
        for id in self.world.store.scan(&mut self.tx, &type_id) {
            if ids.len() as u64 == limit {
                break;
            }
            if scope.as_ref().is_some_and(|s| !s.contains(&id)) {
                continue; // out-of-scope objects are invisible
            }
            let Some(object) = self.world.store.read(&mut self.tx, id) else { continue };
            if filter.iter().all(|(k, v)| object.fields.get(k) == v.as_ref()) {
                ids.push(ulid_to_cbor(id));
            }
        }
        Ok(cbor::encode(&Cbor::Array(ids)))
    }

    fn blob_write(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        Ok(crate::BlobStore::put(&mut self.world.blobs, input).0.to_vec())
    }

    fn blob_read(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let hash: Hash256 = hash_from_cbor(field(&m, "hash")?).map_err(|_| BAD)?;
        let offset = field(&m, "offset")?.as_u64().ok_or(BAD)? as usize;
        let len = field(&m, "len")?.as_u64().ok_or(BAD)? as usize;
        let blob = crate::BlobStore::get(&self.world.blobs, &hash).ok_or(Fail::Code(abi::ERR_NOT_FOUND))?;
        let end = offset.checked_add(len).filter(|e| *e <= blob.len()).ok_or(BAD)?;
        Ok(cbor::encode(&Cbor::Bytes(blob[offset..end].to_vec())))
    }

    fn intent(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        self.create_intent(input, "intent")
    }

    fn job(&mut self, input: &[u8]) -> Result<Vec<u8>, Fail> {
        self.create_intent(input, "job")
    }

    /// An `EgressIntent` object (SPEC §11.1); executing it is the egress gateway's job.
    fn create_intent(&mut self, input: &[u8], kind: &str) -> Result<Vec<u8>, Fail> {
        let m = decode_map(input).ok_or(BAD)?;
        let channel = String::from(field(&m, "channel")?.as_text().ok_or(BAD)?);
        if kind == "job" && !channel.starts_with("compute:") {
            return Err(BAD);
        }
        let target = String::from(field(&m, "target")?.as_text().ok_or(BAD)?);
        let summary = String::from(field(&m, "summary")?.as_text().ok_or(BAD)?);
        let hashes: Vec<Hash256> = match m.get_str("blobs") {
            Some(b) => {
                b.as_array().ok_or(BAD)?.iter().map(|h| hash_from_cbor(h).map_err(|_| BAD)).collect::<Result<_, _>>()?
            }
            None => Vec::new(),
        };
        let payload_hash = aos_egress::payload_hash(&hashes);
        let blobs: Vec<Value> = hashes.into_iter().map(Value::Blob).collect();
        if !self.decl.effects.may_egress(&channel)
            || self.world.authority.authorize_egress(&self.token, self.now, &channel).is_err()
        {
            return Err(Fail::Violation(Violation::UndeclaredEgress(channel)));
        }
        let reversibility = match self.decl.reversibility {
            aos_action::Reversibility::Undo => "undo",
            aos_action::Reversibility::Compensate => "compensate",
            aos_action::Reversibility::Irreversible => "irreversible",
        };
        let mut fields = BTreeMap::new();
        fields.insert("kind".into(), Value::text(kind));
        fields.insert("channel".into(), Value::Text(channel));
        fields.insert("target".into(), Value::Text(target));
        fields.insert("summary".into(), Value::Text(summary));
        fields.insert("blobs".into(), Value::List(blobs));
        fields.insert("payload_hash".into(), Value::Bytes(payload_hash.0.to_vec()));
        fields.insert("action".into(), Value::Text(self.decl.id()));
        fields.insert("external_reversibility".into(), Value::text(reversibility));
        fields.insert("status".into(), Value::text("pending"));
        let object = self.new_object(INTENT_TYPE.parse().expect("valid"), fields)?;
        let id = object.id;
        self.world.store.put(&mut self.tx, object).map_err(|_| BAD)?;
        self.intents.push(id);
        Ok(single("id", ulid_to_cbor(id)))
    }
}
