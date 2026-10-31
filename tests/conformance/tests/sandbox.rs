//! §16.1 动作沙箱：读写未声明类型 → 中止；尝试直接 I/O → 中止并记录违规。
//! Plus the runtime half of §16.1 能力 (越权调用被拒) and §8.3 enforcement.

use std::collections::{BTreeMap, BTreeSet};

use aos_action::{ActionDecl, Effects, InputSpec, Reversibility};
use aos_branch::{BranchId, Rejection, StoreError, TxMeta};
use aos_cap::{Authority, CapError, Limits, Pattern, Spec, Token};
use aos_conformance::{TestEnv, item, n_of, new_store, set};
use aos_log::MemStorage;
use aos_runtime::{Action, Invocation, InvokeError, MemBlobs, Sandbox, VIOLATION_TYPE, Violation, World};
use aos_types::{Actor, FieldKind, Taint, Timestamp, TypeName, Ulid, Value};

static SCRIPT: &[u8] = include_bytes!(env!("AOS_TEST_SCRIPT_WASM"));
const MAIN: BranchId = BranchId::Main;
const NOW: Timestamp = Timestamp(2_000_000_000_000);
const AGENT: Actor = Actor::Agent { task: Ulid::from_u128(77) };

fn item_type() -> TypeName {
    "test/Item".parse().unwrap()
}

struct Fixture {
    sandbox: Sandbox<MemStorage, TestEnv>,
    root: Token,
    item: Ulid,
}

fn fixture() -> Fixture {
    let mut store = new_store();
    let item = store.new_id().unwrap();
    set(&mut store, MAIN, item, 5);
    let mut authority = Authority::new([3; 32]).unwrap();
    let root = authority
        .issue_root(
            Ulid::from_u128(1),
            Spec {
                subject: Actor::User,
                rights: BTreeSet::from([Pattern::new("*").unwrap()]),
                scope: BTreeMap::new(),
                limits: Limits { cpu_ms: 1_000_000, gpu_ms: 0, money_fen: 0, steps: 1000 },
                egress: BTreeSet::from([Pattern::new("*").unwrap()]),
                expires_at: Timestamp(u64::MAX),
            },
            NOW,
        )
        .unwrap();
    Fixture { sandbox: Sandbox::new(World { store, authority, blobs: MemBlobs::default() }), root, item }
}

impl Fixture {
    fn token(&mut self, rights: &str, egress: &[&str], cpu_ms: u64, scope: Option<Vec<Ulid>>) -> Token {
        let id = self.sandbox.world_mut().store.new_id().unwrap();
        let mut spec = Spec {
            subject: AGENT,
            rights: BTreeSet::from([Pattern::new(rights).unwrap()]),
            scope: BTreeMap::new(),
            limits: Limits { cpu_ms, gpu_ms: 0, money_fen: 0, steps: 10 },
            egress: egress.iter().map(|e| Pattern::new(e).unwrap()).collect(),
            expires_at: Timestamp(u64::MAX),
        };
        if let Some(ids) = scope {
            spec.scope.insert(item_type(), ids.into_iter().collect());
        }
        self.sandbox.world_mut().authority.derive(&Actor::User, self.root.id, id, spec, NOW).unwrap()
    }

    fn load(&self, reads: &[&str], writes: &[&str], egress: &[&str], tweak: impl FnOnce(&mut ActionDecl)) -> Action {
        let types = |ts: &[&str]| ts.iter().map(|t| t.parse().unwrap()).collect();
        let mut inputs = BTreeMap::new();
        inputs.insert("script".into(), InputSpec { kind: FieldKind::Any, default: None });
        let mut decl = ActionDecl {
            name: "test.script".into(),
            version: 1,
            provider: "test".into(),
            summary: "scripted".into(),
            inputs,
            outputs: BTreeMap::new(),
            effects: Effects {
                reads: types(reads),
                writes: types(writes),
                egress: egress.iter().map(|e| e.to_string()).collect(),
            },
            reversibility: if egress.is_empty() { Reversibility::Undo } else { Reversibility::Irreversible },
            preconditions: vec![],
            cost: None,
            capability: "test.script".into(),
        };
        tweak(&mut decl);
        self.sandbox.load(decl, SCRIPT).unwrap()
    }

    fn invoke(
        &mut self,
        action: &Action,
        token: &Token,
        branch: BranchId,
        script: Vec<Value>,
    ) -> Result<aos_runtime::Outcome, InvokeError<aos_log::OutOfRange>> {
        self.invoke_with(action, token, branch, script, BTreeMap::new())
    }

    fn invoke_with(
        &mut self,
        action: &Action,
        token: &Token,
        branch: BranchId,
        script: Vec<Value>,
        mut inputs: BTreeMap<String, Value>,
    ) -> Result<aos_runtime::Outcome, InvokeError<aos_log::OutOfRange>> {
        inputs.insert("script".into(), Value::List(script));
        self.sandbox.invoke(action, Invocation { token: token.clone(), branch, actor: AGENT, inputs, now: NOW })
    }

    fn n(&self, branch: BranchId) -> i64 {
        n_of(self.sandbox.world().store.get(branch, self.item).unwrap())
    }

    fn violations(&self, branch: BranchId) -> Vec<String> {
        let t: aos_types::TypeId = VIOLATION_TYPE.parse().unwrap();
        self.sandbox
            .world()
            .store
            .objects(branch)
            .values()
            .filter(|o| o.type_id == t)
            .map(|o| match o.fields.get("kind") {
                Some(Value::Text(k)) => k.clone(),
                _ => String::new(),
            })
            .collect()
    }
}

fn op(fields: &[(&str, Value)]) -> Value {
    Value::Map(fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
}

fn id(u: Ulid) -> Value {
    Value::Bytes(u.to_bytes().to_vec())
}

fn write(u: Ulid, n: i64) -> Value {
    op(&[("op", Value::text("write")), ("id", id(u)), ("n", Value::Int(n))])
}

fn read(u: Ulid) -> Value {
    op(&[("op", Value::text("read")), ("id", id(u))])
}

fn create(n: i64) -> Value {
    op(&[("op", Value::text("create")), ("type", Value::text("test/Item@1")), ("n", Value::Int(n))])
}

#[test]
fn a_well_behaved_action_runs_in_one_transaction() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 10_000, None);
    let action = f.load(&["test/Item"], &["test/Item"], &[], |d| {
        d.outputs.insert("created".into(), FieldKind::Bytes { max_len: Some(16) });
    });
    let log_len = f.sandbox.world().store.log().len();
    let script = vec![
        write(f.item, 42),
        create(7),
        op(&[("op", Value::text("query")), ("type", Value::text("test/Item@1")), ("expect", Value::Int(2))]),
        op(&[("op", Value::text("blob")), ("data", Value::Bytes(b"weights".to_vec()))]),
        op(&[("op", Value::text("log")), ("message", Value::text("done"))]),
    ];
    let out = f.invoke(&action, &token, MAIN, script).unwrap();
    assert_eq!(f.sandbox.world().store.log().len(), log_len + 1, "one transaction");
    assert_eq!(f.n(MAIN), 42);
    let Some(Value::Bytes(created)) = out.outputs.get("created") else { panic!("outputs {:?}", out.outputs) };
    let created = Ulid::from_bytes(created.as_slice().try_into().unwrap());
    let c = f.sandbox.world().store.get(MAIN, created).unwrap();
    assert_eq!(n_of(c), 7);
    assert!(c.provenance.derived_from.iter().any(|r| r.id == f.item), "writes derive from what was read");
    assert_eq!(c.provenance.actor, AGENT);
    assert_eq!(out.logs, vec![(1, "done".to_string())]);
    let spent = f.sandbox.world().authority.spent(token.id).unwrap();
    assert_eq!(spent.steps, 1);
    assert_eq!(spent.cpu_ms, out.cpu_ms);
    let (_, record) = (0, f.sandbox.world().store.log().read(log_len).unwrap().record);
    let record: aos_branch::Record = aos_types::FromCbor::from_cbor(&record).unwrap();
    assert_eq!(record.action.as_deref(), Some("test.script@1"));
    assert_eq!(record.capability, Some(token.id.0));
}

#[test]
fn undeclared_reads_and_writes_abort_and_are_recorded() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 10_000, None);
    for (reads, writes, script, expected) in [
        (&[][..], &[][..], vec![read(f.item)], Violation::UndeclaredRead(item_type())),
        (&["test/Item"][..], &[][..], vec![write(f.item, 1)], Violation::UndeclaredWrite(item_type())),
        (&["test/Item"][..], &[][..], vec![create(1)], Violation::UndeclaredWrite(item_type())),
    ] {
        let action = f.load(reads, writes, &[], |_| {});
        match f.invoke(&action, &token, MAIN, script) {
            Err(InvokeError::Violation { violation, .. }) => assert_eq!(violation, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
        assert_eq!(f.n(MAIN), 5, "nothing the action did survives");
    }
    assert_eq!(f.violations(MAIN), vec!["undeclared_read", "undeclared_write", "undeclared_write"]);
}

#[test]
fn ambient_io_imports_are_a_recorded_violation() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 10_000, None);
    let wasm = wat::parse_str(
        r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "aos_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "run") (param i32 i32) (result i32) i32.const 0))"#,
    )
    .unwrap();
    let decl = f.load(&[], &[], &[], |_| {}).decl().clone();
    let action = f.sandbox.load(decl, &wasm).unwrap();
    match f.invoke(&action, &token, MAIN, vec![]) {
        Err(InvokeError::Violation { violation: Violation::ForbiddenImport(name), .. }) => {
            assert_eq!(name, "wasi_snapshot_preview1::fd_write")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.violations(MAIN), vec!["forbidden_import"]);
}

#[test]
fn egress_needs_both_the_declaration_and_the_capability() {
    let mut f = fixture();
    let intent = |ch: &str| op(&[("op", Value::text("intent")), ("channel", Value::text(ch))]);
    let token = f.token("test.*", &["model:*"], 10_000, None);
    let undeclared = f.load(&["test/Item"], &[], &[], |_| {});
    assert!(matches!(
        f.invoke(&undeclared, &token, MAIN, vec![intent("model:default")]),
        Err(InvokeError::Violation { violation: Violation::UndeclaredEgress(_), .. })
    ));
    let declared = f.load(&["test/Item"], &[], &["model:*", "deliver:*"], |_| {});
    assert!(
        matches!(
            f.invoke(&declared, &token, MAIN, vec![intent("deliver:acme")]),
            Err(InvokeError::Violation { violation: Violation::UndeclaredEgress(_), .. })
        ),
        "declared by the action but not granted by the capability"
    );
    let out = f.invoke(&declared, &token, MAIN, vec![read(f.item), intent("model:default")]).unwrap();
    let i = f.sandbox.world().store.get(MAIN, out.intents[0]).unwrap();
    assert_eq!(i.fields.get("status"), Some(&Value::text("pending")));
    assert_eq!(i.fields.get("channel"), Some(&Value::text("model:default")));
    assert!(i.provenance.derived_from.iter().any(|r| r.id == f.item), "lineage of the payload");

    let job = |ch: &str| op(&[("op", Value::text("job")), ("channel", Value::text(ch))]);
    let jobs = f.load(&[], &[], &["compute:*", "model:*"], |_| {});
    let compute = f.token("test.*", &["compute:*", "model:*"], 10_000, None);
    f.invoke(&jobs, &compute, MAIN, vec![job("compute:worker")]).unwrap();
    assert!(
        matches!(f.invoke(&jobs, &compute, MAIN, vec![job("model:default")]), Err(InvokeError::Failed(_))),
        "jobs go to compute:*"
    );
}

#[test]
fn capability_checks_happen_before_and_during_the_run() {
    let mut f = fixture();
    let action = f.load(&["test/Item"], &["test/Item"], &[], |d| {
        d.inputs.insert("item".into(), InputSpec { kind: FieldKind::Ref { target: item_type() }, default: None });
    });
    let with_item =
        |f: &Fixture| BTreeMap::from([("item".to_string(), Value::Ref(aos_types::ObjectRef::latest(f.item)))]);

    let wrong_right = f.token("ml.*", &[], 10_000, None);
    assert!(matches!(
        f.invoke_with(&action, &wrong_right, MAIN, vec![], with_item(&f)),
        Err(InvokeError::Capability(CapError::NoRight))
    ));

    let other = Ulid::from_u128(424242);
    let scoped_elsewhere = f.token("test.*", &[], 10_000, Some(vec![other]));
    assert!(matches!(
        f.invoke_with(&action, &scoped_elsewhere, MAIN, vec![], with_item(&f)),
        Err(InvokeError::Capability(CapError::OutOfScope(_)))
    ));
    // Not an input, but read inside the run: still out of scope.
    let unrelated = f.load(&["test/Item"], &[], &[], |_| {});
    assert!(matches!(
        f.invoke(&unrelated, &scoped_elsewhere, MAIN, vec![read(f.item)]),
        Err(InvokeError::Violation { violation: Violation::OutOfScope(_), .. })
    ));

    let revoked = f.token("test.*", &[], 10_000, None);
    f.sandbox.world_mut().authority.revoke(revoked.id).unwrap();
    assert!(matches!(f.invoke(&unrelated, &revoked, MAIN, vec![]), Err(InvokeError::Capability(CapError::Revoked(_)))));

    let mut forged = f.token("test.*", &[], 10_000, None);
    forged.spec.limits.cpu_ms = u64::MAX;
    assert!(matches!(
        f.invoke(&unrelated, &forged, MAIN, vec![]),
        Err(InvokeError::Capability(CapError::BadSignature))
    ));
}

#[test]
fn fuel_is_bounded_by_the_cpu_budget() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 20, None);
    let action = f.load(&[], &[], &[], |_| {});
    let r = f.invoke(&action, &token, MAIN, vec![op(&[("op", Value::text("spin"))])]);
    assert!(matches!(r, Err(InvokeError::OutOfFuel)), "{r:?}");
    let spent = f.sandbox.world().authority.spent(token.id).unwrap();
    assert_eq!(spent.cpu_ms, 20, "the whole budget was used, and no more");
    assert!(matches!(f.invoke(&action, &token, MAIN, vec![]), Err(InvokeError::Budget)), "nothing left");
}

#[test]
fn failures_and_traps_write_nothing() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 10_000, None);
    let action = f.load(&["test/Item"], &["test/Item"], &[], |_| {});
    for last in ["fail", "trap"] {
        let r = f.invoke(&action, &token, MAIN, vec![write(f.item, 99), op(&[("op", Value::text(last))])]);
        assert!(matches!(r, Err(InvokeError::Failed(_))), "{r:?}");
        assert_eq!(f.n(MAIN), 5);
    }
    let promised = f.load(&[], &[], &[], |d| {
        d.outputs.insert("result".into(), FieldKind::Int { min: None, max: None });
    });
    assert!(matches!(
        f.invoke(&promised, &token, MAIN, vec![]),
        Err(InvokeError::Violation { violation: Violation::BadOutput(_), .. })
    ));
}

#[test]
fn preconditions_gate_the_call_and_the_commit() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 10_000, None);
    let action = f.load(&["test/Item"], &["test/Item"], &[], |d| {
        d.inputs.insert("item".into(), InputSpec { kind: FieldKind::Ref { target: item_type() }, default: None });
        d.outputs.insert("created".into(), FieldKind::Bytes { max_len: Some(16) });
        d.preconditions = vec!["item.n > 10".into()];
        d.cost = Some("0.001 * item.n".into());
    });
    let inputs = BTreeMap::from([("item".to_string(), Value::Ref(aos_types::ObjectRef::latest(f.item)))]);
    assert!(matches!(f.invoke_with(&action, &token, MAIN, vec![], inputs.clone()), Err(InvokeError::Precondition(0))));

    set(&mut f.sandbox.world_mut().store, MAIN, f.item, 20);
    let fork = f.sandbox.world_mut().store.fork(Actor::User).unwrap();
    f.invoke_with(&action, &token, fork, vec![create(1)], inputs).unwrap();
    // main changes what the precondition read: the commit is refused (SPEC §7.5.3).
    set(&mut f.sandbox.world_mut().store, MAIN, f.item, 3);
    let BranchId::Fork(fid) = fork else { unreachable!() };
    let store = &mut f.sandbox.world_mut().store;
    store.submit(fid, Actor::System).unwrap();
    assert!(matches!(
        store.commit(fid, Actor::User),
        Err(StoreError::Rejected(Rejection::Precondition { index: 0, .. }))
    ));
}

#[test]
fn taint_flows_from_inputs_to_outputs() {
    let mut f = fixture();
    let token = f.token("test.*", &[], 10_000, None);
    let ext = {
        let store = &mut f.sandbox.world_mut().store;
        let ext = store.new_id().unwrap();
        let mut tx = store.begin(MAIN, Actor::System, TxMeta::default()).unwrap();
        let mut o = item(ext, 1);
        o.provenance.taint = Taint::External;
        store.put(&mut tx, o).unwrap();
        store.apply(tx).unwrap();
        ext
    };
    let action = f.load(&["test/Item"], &["test/Item"], &[], |d| {
        d.outputs.insert("created".into(), FieldKind::Bytes { max_len: Some(16) });
    });
    let out = f.invoke(&action, &token, MAIN, vec![read(ext), create(2)]).unwrap();
    let Some(Value::Bytes(created)) = out.outputs.get("created") else { panic!() };
    let created = Ulid::from_bytes(created.as_slice().try_into().unwrap());
    assert_eq!(f.sandbox.world().store.get(MAIN, created).unwrap().provenance.taint, Taint::External);
}
