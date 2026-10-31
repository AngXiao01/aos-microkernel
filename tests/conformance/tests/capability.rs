//! §16.1 能力：衰减不变量；越权调用被拒；额度扣减准确。

use std::collections::{BTreeMap, BTreeSet};

use aos_cap::{Authority, CapError, CapId, Limits, Pattern, Spec, Token};
use aos_types::{Actor, Timestamp, Ulid};
use proptest::prelude::*;

const NOW: Timestamp = Timestamp(1_000);

fn p(s: &str) -> Pattern {
    Pattern::new(s).unwrap()
}

fn spec(rights: &[&str], egress: &[&str], cpu: u64, expires: u64) -> Spec {
    Spec {
        subject: Actor::Agent { task: Ulid::from_u128(1) },
        rights: rights.iter().map(|r| p(r)).collect(),
        scope: BTreeMap::new(),
        limits: Limits { cpu_ms: cpu, gpu_ms: 0, money_fen: 0, steps: 100 },
        egress: egress.iter().map(|r| p(r)).collect(),
        expires_at: Timestamp(expires),
    }
}

fn authority() -> Authority {
    Authority::new([7; 32]).unwrap()
}

fn root(a: &mut Authority) -> Token {
    a.issue_root(Ulid::from_u128(100), spec(&["*"], &["*"], 1_000_000, 10_000), NOW).unwrap()
}

#[test]
fn patterns() {
    assert!(p("ml.dataset.*").matches("ml.dataset.dedupe"));
    assert!(!p("ml.dataset.*").matches("ml.experiment.create"));
    assert!(p("ml.*").covers(&p("ml.dataset.*")));
    assert!(p("ml.*").covers(&p("ml.dataset.dedupe")));
    assert!(!p("ml.dataset.*").covers(&p("ml.*")));
    assert!(!p("ml.dataset.dedupe").covers(&p("ml.dataset.*")));
    assert!(p("deliver:*").matches("deliver:minio-acme"));
    assert!(Pattern::new("ml.*.x").is_none());
    assert!(Pattern::new("").is_none());
}

#[test]
fn derivation_only_attenuates() {
    let mut a = authority();
    let r = root(&mut a);
    let user = Actor::User;
    let child = a.derive(&user, r.id, Ulid::from_u128(101), spec(&["ml.*"], &["model:*"], 1000, 5000), NOW).unwrap();
    for (rights, egress, cpu, expires) in [
        (&["*"][..], &["model:*"][..], 1000u64, 5000u64), // broader rights
        (&["ml.*"][..], &["*"][..], 1000, 5000),          // broader egress
        (&["ml.*"][..], &["model:*"][..], 1001, 5000),    // larger budget
        (&["ml.*"][..], &["model:*"][..], 1000, 5001),    // later expiry
    ] {
        assert_eq!(
            a.derive(
                &user,
                child.id,
                Ulid::from_u128(u128::from(200 + cpu + expires)),
                spec(rights, egress, cpu, expires),
                NOW
            ),
            Err(CapError::NotAttenuated)
        );
    }
    let grandchild = a
        .derive(
            &Actor::System,
            child.id,
            Ulid::from_u128(102),
            spec(&["ml.dataset.*"], &["model:default"], 10, 4000),
            NOW,
        )
        .unwrap();
    assert!(grandchild.spec.within(&child.spec) && child.spec.within(&r.spec));

    // A scoped parent forces the child to stay inside the scope.
    let mut scoped = spec(&["ml.*"], &[], 10, 4000);
    let ty: aos_types::TypeName = "ml/Dataset".parse().unwrap();
    scoped.scope.insert(ty.clone(), BTreeSet::from([Ulid::from_u128(9)]));
    let s = a.derive(&user, child.id, Ulid::from_u128(103), scoped.clone(), NOW).unwrap();
    let mut unscoped = scoped.clone();
    unscoped.scope.clear();
    assert_eq!(a.derive(&user, s.id, Ulid::from_u128(104), unscoped, NOW), Err(CapError::NotAttenuated));
    let mut wider = scoped;
    wider.scope.get_mut(&ty).unwrap().insert(Ulid::from_u128(10));
    assert_eq!(a.derive(&user, s.id, Ulid::from_u128(105), wider, NOW), Err(CapError::NotAttenuated));
}

#[test]
fn agents_cannot_issue_tokens() {
    let mut a = authority();
    let r = root(&mut a);
    let agent = Actor::Agent { task: Ulid::from_u128(1) };
    assert_eq!(
        a.derive(&agent, r.id, Ulid::from_u128(101), spec(&["ml.*"], &[], 1, 2000), NOW),
        Err(CapError::IssuerNotAllowed)
    );
}

#[test]
fn verification_rejects_forgery_tampering_expiry_and_revocation() {
    let mut a = authority();
    let r = root(&mut a);
    let child = a.derive(&Actor::User, r.id, Ulid::from_u128(101), spec(&["ml.*"], &[], 100, 2000), NOW).unwrap();
    a.verify(&child, NOW).unwrap();

    let mut tampered = child.clone();
    tampered.spec.limits.cpu_ms = 1_000_000;
    assert_eq!(a.verify(&tampered, NOW), Err(CapError::BadSignature));
    let mut tampered = child.clone();
    tampered.spec.rights.insert(p("*"));
    assert_eq!(a.verify(&tampered, NOW), Err(CapError::BadSignature));

    // Signed by a different authority: same structure, wrong key.
    let mut other = Authority::new([9; 32]).unwrap();
    let forged = other.issue_root(child.id.0, child.spec.clone(), NOW).unwrap();
    assert_eq!(a.verify(&forged, NOW), Err(CapError::BadSignature));

    assert_eq!(a.verify(&child, Timestamp(2000)), Err(CapError::Expired));
    a.revoke(r.id).unwrap();
    assert_eq!(a.verify(&child, NOW), Err(CapError::Revoked(r.id)), "revoking a parent revokes the subtree");
}

#[test]
fn authorization_checks_rights_scope_and_egress() {
    let mut a = authority();
    let r = root(&mut a);
    let ty: aos_types::TypeName = "ml/Dataset".parse().unwrap();
    let mut s = spec(&["ml.dataset.*"], &["model:*"], 100, 2000);
    s.scope.insert(ty.clone(), BTreeSet::from([Ulid::from_u128(9)]));
    let t = a.derive(&Actor::User, r.id, Ulid::from_u128(101), s, NOW).unwrap();
    a.authorize(&t, NOW, "ml.dataset.dedupe", &[(ty.clone(), Ulid::from_u128(9))]).unwrap();
    assert_eq!(a.authorize(&t, NOW, "ml.job.submit", &[]), Err(CapError::NoRight));
    assert_eq!(
        a.authorize(&t, NOW, "ml.dataset.dedupe", &[(ty, Ulid::from_u128(8))]),
        Err(CapError::OutOfScope(Ulid::from_u128(8)))
    );
    a.authorize_egress(&t, NOW, "model:default").unwrap();
    assert_eq!(a.authorize_egress(&t, NOW, "deliver:acme"), Err(CapError::EgressNotAllowed));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Random charges against a three-level tree: each succeeds exactly when it fits every
    /// budget on its path, and every node's spent amount equals the sum of the successful
    /// charges in its subtree.
    #[test]
    fn budgets_are_charged_exactly(
        limits in proptest::collection::vec(1u64..100, 4),
        charges in proptest::collection::vec((0usize..4, 0u64..40), 0..40),
    ) {
        let mut a = authority();
        let r = a.issue_root(Ulid::from_u128(1), spec(&["*"], &[], limits[0], 10_000), NOW).unwrap();
        let mk = |a: &mut Authority, parent: CapId, n: u128, cpu: u64| {
            a.derive(&Actor::User, parent, Ulid::from_u128(n), spec(&["*"], &[], cpu, 10_000), NOW)
        };
        // root → b → c, root → d (children may ask for at most their parent's limit).
        let b = mk(&mut a, r.id, 2, limits[1].min(limits[0])).unwrap();
        let c = mk(&mut a, b.id, 3, limits[2].min(b.spec.limits.cpu_ms)).unwrap();
        let d = mk(&mut a, r.id, 4, limits[3].min(limits[0])).unwrap();
        let nodes = [r.id, b.id, c.id, d.id];
        let parent: [Option<usize>; 4] = [None, Some(0), Some(1), Some(0)];
        let limit: Vec<u64> = [&r, &b, &c, &d].iter().map(|t| t.spec.limits.cpu_ms).collect();
        let mut spent = [0u64; 4];
        for (node, cpu) in charges {
            let mut path = vec![node];
            while let Some(p) = parent[*path.last().unwrap()] { path.push(p); }
            let fits = path.iter().all(|&n| spent[n] + cpu <= limit[n]);
            let result = a.charge(nodes[node], Limits { cpu_ms: cpu, ..Limits::default() });
            prop_assert_eq!(result.is_ok(), fits);
            if fits { for &n in &path { spent[n] += cpu; } }
        }
        for (i, id) in nodes.iter().enumerate() {
            prop_assert_eq!(a.spent(*id).unwrap().cpu_ms, spent[i]);
            prop_assert!(spent[i] <= limit[i]);
        }
    }

}

proptest! {
    // Each case signs up to 20 tokens.
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Whatever children are requested, every issued token stays within all its ancestors.
    #[test]
    fn issued_tokens_never_exceed_their_ancestors(
        requests in proptest::collection::vec((0usize..8, 0u64..200, 0u64..12_000, 0usize..4), 1..20),
    ) {
        let rights = ["*", "ml.*", "ml.dataset.*", "ml.dataset.dedupe"];
        let mut a = authority();
        let r = root(&mut a);
        let mut issued: Vec<Token> = vec![r];
        for (i, (parent, cpu, expires, right)) in requests.into_iter().enumerate() {
            let parent = issued[parent % issued.len()].clone();
            let s = spec(&[rights[right]], &[], cpu, expires);
            match a.derive(&Actor::User, parent.id, Ulid::from_u128(1000 + i as u128), s.clone(), NOW) {
                Ok(t) => {
                    prop_assert!(t.spec.within(&parent.spec));
                    issued.push(t);
                }
                Err(e) => {
                    prop_assert!(!s.within(&parent.spec) || parent.spec.expires_at <= NOW, "refused {e:?} although attenuated");
                }
            }
        }
        for t in &issued {
            let mut cur = t.parent;
            while let Some(p) = cur {
                let ancestor = issued.iter().find(|x| x.id == p).unwrap();
                prop_assert!(t.spec.within(&ancestor.spec));
                cur = ancestor.parent;
            }
        }
    }
}
