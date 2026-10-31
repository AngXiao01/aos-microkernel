//! §16.1 出口：没有放行就不执行；载荷篡改被拒；签名重放被拒；过期签名被拒。
//! §16.1 策略：deny > confirm > allow 的优先级；默认走 confirm。
//! §16.1 污点：收件方来自外部内容时触发 confirm。
//! Plus an end-to-end flow: action → intent → policy → gate, and confirm → approval → gate.

use std::collections::{BTreeMap, BTreeSet};

use aos_confirm::{
    ApprovalRequest, ConfirmError, ConfirmService, Decision as Answer, DevConfirmer, Item, Kind, verify_os_signature,
};
use aos_egress::{Authorization, Gate, GateError, Intent, Transport, payload_hash};
use aos_policy::{Decision, Facts, Policy, Rule, evaluate};
use aos_types::{Hash256, Sensitivity, Timestamp, Ulid};
use proptest::prelude::*;

#[derive(Default)]
struct Recorder {
    sent: Vec<(String, String, Vec<u8>)>,
}

impl Transport for Recorder {
    fn send(&mut self, channel: &str, target: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sent.push((channel.into(), target.into(), payload.to_vec()));
        Ok(b"accepted".to_vec())
    }
}

const NOW: Timestamp = Timestamp(1_000_000);

fn intent(target: &str, blobs: &[Hash256]) -> Intent {
    Intent {
        id: Ulid::from_u128(target.len() as u128 + 7),
        channel: "deliver:acme".into(),
        target: target.into(),
        payload_hash: payload_hash(blobs),
    }
}

fn request(items: Vec<Item>, expires: u64) -> ApprovalRequest {
    ApprovalRequest {
        request_id: Ulid::from_u128(99),
        created_at: NOW,
        expires_at: Timestamp(expires),
        nonce: [7; 16],
        kind: Kind::Egress,
        summary: vec![("交付".into(), "量化模型 int8".into())],
        items,
        branch: "branch/x".into(),
        diff_hash: Hash256::digest(b"diff"),
    }
}

fn item_for(i: &Intent) -> Item {
    Item {
        channel: i.channel.clone(),
        target: i.target.clone(),
        payload_hash: i.payload_hash,
        cost_fen: 0,
        external_reversibility: "irreversible".into(),
        tainted: false,
    }
}

fn confirmer() -> (DevConfirmer, ConfirmService) {
    let phone = DevConfirmer::new([5; 32]).unwrap();
    let service = ConfirmService::new([6; 32], phone.public_key()).unwrap();
    (phone, service)
}

#[test]
fn nothing_executes_without_an_allow_or_an_approval() {
    let blobs = [Hash256::digest(b"model")];
    let i = intent("s3://acme/", &blobs);
    let payload = aos_egress::payload_bytes(&blobs);
    let mut gate = Gate::new(Recorder::default());
    let confirm = aos_policy::Verdict { decision: Decision::Confirm, basis: aos_policy::Basis::Default };
    let deny = aos_policy::Verdict { decision: Decision::Deny, basis: aos_policy::Basis::Default };
    assert_eq!(gate.execute(&i, &payload, Authorization::Policy(confirm)), Err(GateError::NotAuthorized));
    assert_eq!(gate.execute(&i, &payload, Authorization::Policy(deny)), Err(GateError::Denied));

    let (phone, mut service) = confirmer();
    let (bytes, _) = service.issue(request(vec![item_for(&i)], 2_000_000)).unwrap();
    let refused = service.verify(&phone.decide(&bytes, Ulid::from_u128(99), Answer::Deny), NOW).unwrap();
    assert_eq!(gate.execute(&i, &payload, Authorization::Approval(&refused)), Err(GateError::Denied));
    assert!(gate.transport().sent.is_empty());
}

#[test]
fn a_swapped_payload_is_refused() {
    let approved = [Hash256::digest(b"model-v1")];
    let i = intent("s3://acme/", &approved);
    let (phone, mut service) = confirmer();
    let (bytes, _) = service.issue(request(vec![item_for(&i)], 2_000_000)).unwrap();
    let ok = service.verify(&phone.decide(&bytes, Ulid::from_u128(99), Answer::Approve), NOW).unwrap();
    let mut gate = Gate::new(Recorder::default());
    // The intent object is rewritten after approval to point at another blob (BS8).
    let swapped = [Hash256::digest(b"model-v2")];
    let tampered = Intent { payload_hash: payload_hash(&swapped), ..i.clone() };
    assert_eq!(
        gate.execute(&tampered, &aos_egress::payload_bytes(&swapped), Authorization::Approval(&ok)),
        Err(GateError::PayloadMismatch)
    );
    // Or only the bytes handed to the gate differ from the intent.
    assert_eq!(
        gate.execute(&i, &aos_egress::payload_bytes(&swapped), Authorization::Approval(&ok)),
        Err(GateError::PayloadMismatch)
    );
    // An approval covers only the items it lists.
    let other = Intent { target: "s3://evil/".into(), ..i.clone() };
    assert_eq!(
        gate.execute(&other, &aos_egress::payload_bytes(&approved), Authorization::Approval(&ok)),
        Err(GateError::NotApproved)
    );
    assert!(gate.transport().sent.is_empty());
    let receipt = gate.execute(&i, &aos_egress::payload_bytes(&approved), Authorization::Approval(&ok)).unwrap();
    assert_eq!(receipt.payload_hash, i.payload_hash);
    assert_eq!(
        gate.execute(&i, &aos_egress::payload_bytes(&approved), Authorization::Approval(&ok)),
        Err(GateError::AlreadyExecuted)
    );
    assert_eq!(gate.transport().sent.len(), 1);
}

#[test]
fn approvals_are_single_use_bound_and_expire() {
    let i = intent("s3://acme/", &[Hash256::digest(b"x")]);
    let (phone, mut service) = confirmer();
    let (bytes, os_sig) = service.issue(request(vec![item_for(&i)], 2_000_000)).unwrap();
    assert!(
        verify_os_signature(&service.os_key(), &bytes, &os_sig),
        "the phone can check the request came from the OS"
    );
    let approval = phone.decide(&bytes, Ulid::from_u128(99), Answer::Approve);

    // A signature over "deny" does not pass as "approve".
    let flipped =
        aos_confirm::Approval { decision: Answer::Approve, ..phone.decide(&bytes, Ulid::from_u128(99), Answer::Deny) };
    assert_eq!(service.verify(&flipped, NOW), Err(ConfirmError::BadSignature));
    // Another key cannot sign for the paired phone.
    let impostor = DevConfirmer::new([8; 32]).unwrap();
    assert_eq!(
        service.verify(&impostor.decide(&bytes, Ulid::from_u128(99), Answer::Approve), NOW),
        Err(ConfirmError::BadSignature)
    );
    // Expired.
    assert_eq!(service.verify(&approval, Timestamp(2_000_000)), Err(ConfirmError::Expired));

    service.verify(&approval, NOW).unwrap();
    assert_eq!(service.verify(&approval, NOW), Err(ConfirmError::Replayed), "single use");
    // A different request with the same content has a different id and nonce: no reuse.
    let mut again = request(vec![item_for(&i)], 2_000_000);
    again.request_id = Ulid::from_u128(100);
    again.nonce = [9; 16];
    let (bytes2, _) = service.issue(again).unwrap();
    let reused = aos_confirm::Approval { request_id: Ulid::from_u128(100), ..approval.clone() };
    assert_eq!(service.verify(&reused, NOW), Err(ConfirmError::BadSignature), "bound to the request bytes");
    service.verify(&phone.decide(&bytes2, Ulid::from_u128(100), Answer::Approve), NOW).unwrap();
}

fn arb_rule() -> impl Strategy<Value = Rule> {
    let decision = prop_oneof![Just(Decision::Allow), Just(Decision::Confirm), Just(Decision::Deny)];
    let channel = prop_oneof![Just("*"), Just("a:*"), Just("a:x"), Just("b:*"), Just("b:y")];
    let sens = proptest::option::of(prop_oneof![
        Just(Sensitivity::Public),
        Just(Sensitivity::Internal),
        Just(Sensitivity::Secret)
    ]);
    (decision, channel, sens.clone(), sens, proptest::option::of(0u64..100), any::<bool>()).prop_map(
        |(d, c, at_most, at_least, cost, tainted)| Rule {
            decision: d,
            channel: c.into(),
            sensitivity_at_most: at_most,
            sensitivity_at_least: at_least,
            max_cost_fen_per_day: cost,
            when_recipient_tainted: tainted,
        },
    )
}

fn arb_facts() -> impl Strategy<Value = Facts> {
    let channel = prop_oneof![Just("a:x"), Just("a:z"), Just("b:y"), Just("c:q")];
    let sens = prop_oneof![
        Just(Sensitivity::Public),
        Just(Sensitivity::Internal),
        Just(Sensitivity::Private),
        Just(Sensitivity::Secret)
    ];
    (channel, sens, 0u64..60, 0u64..60, any::<bool>()).prop_map(|(c, s, cost, spent, t)| Facts {
        channel: c.into(),
        sensitivity: s,
        cost_fen: cost,
        spent_today_fen: spent,
        recipient_tainted: t,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// The verdict is the strongest applying rule (deny > confirm > allow), the default
    /// (confirm) when none applies, and never allow for a tainted recipient.
    #[test]
    fn policy_precedence(rules in proptest::collection::vec(arb_rule(), 0..8), facts in arb_facts()) {
        let p = Policy { name: "p".into(), rules: rules.clone(), default: Decision::Confirm };
        let v = evaluate(&[p], &facts).decision;
        let applying: Vec<Decision> = rules.iter().filter(|r| r.applies(&facts)).map(|r| r.decision).collect();
        let expected = applying.iter().copied().max().unwrap_or(Decision::Confirm);
        let expected = if expected == Decision::Allow && facts.recipient_tainted { Decision::Confirm } else { expected };
        prop_assert_eq!(v, expected);
        if applying.contains(&Decision::Deny) { prop_assert_eq!(v, Decision::Deny); }
        if facts.recipient_tainted { prop_assert_ne!(v, Decision::Allow); }
    }
}

/// From an action's intent to an executed effect, through the policy or the confirmer.
#[test]
fn intents_flow_through_policy_confirmer_and_gate() {
    use aos_branch::{BranchId, TxMeta};
    use aos_types::{Actor, Value};

    // An intent object as the action runtime creates it (§11.1).
    let mut store = aos_conformance::new_store();
    let blobs = [Hash256::digest(b"weights")];
    let make = |store: &mut aos_conformance::MemStore, channel: &str, tainted: bool| {
        let id = store.new_id().unwrap();
        let mut o = aos_conformance::item(id, 0);
        o.type_id = "sys/EgressIntent@1".parse().unwrap();
        o.fields = BTreeMap::from([
            ("channel".to_string(), Value::text(channel)),
            ("target".to_string(), Value::text("s3://acme/models/")),
            ("payload_hash".to_string(), Value::Bytes(payload_hash(&blobs).0.to_vec())),
            ("status".to_string(), Value::text("pending")),
        ]);
        if tainted {
            o.provenance.taint = aos_types::Taint::External;
        }
        let mut tx = store.begin(BranchId::Main, Actor::System, TxMeta::default()).unwrap();
        store.put(&mut tx, o).unwrap();
        store.apply(tx).unwrap();
        id
    };
    let model = make(&mut store, "model:default", false);
    let delivery = make(&mut store, "deliver:minio-acme", false);
    let tainted_compute = make(&mut store, "compute:worker", true);

    let mut model_rule = Rule::new(Decision::Allow, "model:default");
    model_rule.sensitivity_at_most = Some(Sensitivity::Internal);
    let policy = Policy {
        name: "nightly".into(),
        rules: vec![
            model_rule,
            Rule::new(Decision::Allow, "compute:worker"),
            Rule::new(Decision::Confirm, "deliver:*"),
        ],
        default: Decision::Confirm,
    };
    let facts = |store: &aos_conformance::MemStore, id: Ulid| {
        let o = store.get(BranchId::Main, id).unwrap();
        let Some(Value::Text(channel)) = o.fields.get("channel") else { panic!() };
        Facts {
            channel: channel.clone(),
            sensitivity: o.sensitivity,
            cost_fen: 0,
            spent_today_fen: 0,
            // Conservative: anything tainted in the intent's lineage counts (see DECISIONS).
            recipient_tainted: o.provenance.taint == aos_types::Taint::External,
        }
    };
    let as_intent = |store: &aos_conformance::MemStore, id: Ulid| {
        let o = store.get(BranchId::Main, id).unwrap();
        let text = |k: &str| match o.fields.get(k) {
            Some(Value::Text(t)) => t.clone(),
            _ => panic!(),
        };
        let Some(Value::Bytes(h)) = o.fields.get("payload_hash") else { panic!() };
        Intent {
            id,
            channel: text("channel"),
            target: text("target"),
            payload_hash: Hash256(h.as_slice().try_into().unwrap()),
        }
    };
    let payload = aos_egress::payload_bytes(&blobs);
    let mut gate = Gate::new(Recorder::default());

    // allow: executes at once.
    let v = evaluate(std::slice::from_ref(&policy), &facts(&store, model));
    assert_eq!(v.decision, Decision::Allow);
    gate.execute(&as_intent(&store, model), &payload, Authorization::Policy(v)).unwrap();
    // A tainted recipient is held for confirmation even though a rule allows the channel.
    let v = evaluate(std::slice::from_ref(&policy), &facts(&store, tainted_compute));
    assert_eq!(v.decision, Decision::Confirm);
    assert_eq!(
        gate.execute(&as_intent(&store, tainted_compute), &payload, Authorization::Policy(v)),
        Err(GateError::NotAuthorized)
    );
    // confirm: the user approves on the confirmer, then the gate executes.
    let v = evaluate(&[policy], &facts(&store, delivery));
    assert_eq!(v.decision, Decision::Confirm);
    let held = as_intent(&store, delivery);
    let (phone, mut service) = confirmer();
    let (bytes, _) = service.issue(request(vec![item_for(&held)], 2_000_000)).unwrap();
    let ok = service.verify(&phone.decide(&bytes, Ulid::from_u128(99), Answer::Approve), NOW).unwrap();
    gate.execute(&held, &payload, Authorization::Approval(&ok)).unwrap();

    let channels: BTreeSet<String> = gate.transport().sent.iter().map(|(c, _, _)| c.clone()).collect();
    assert_eq!(channels, BTreeSet::from(["model:default".to_string(), "deliver:minio-acme".to_string()]));
}
