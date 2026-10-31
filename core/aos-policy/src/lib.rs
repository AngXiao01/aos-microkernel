//! Standing policies (SPEC §9.3): signed once by the user's confirmer, they decide each
//! egress intent as allow, confirm or deny.
//!
//! - A rule applies when its channel pattern matches and all its conditions hold.
//! - Among applying rules, deny beats confirm beats allow; with none, the policy's default
//!   (confirm unless the user said otherwise) applies.
//! - An intent whose recipient came from tainted data is never allowed without
//!   confirmation, whatever the rules say (SPEC §10).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use aos_types::Sensitivity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    // Ordered by precedence: the maximum over the applying rules wins.
    Allow,
    Confirm,
    Deny,
}

/// The facts about an intent that rules look at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub channel: String,
    /// The most sensitive data in the payload.
    pub sensitivity: Sensitivity,
    pub cost_fen: u64,
    /// Already spent on this channel today.
    pub spent_today_fen: u64,
    /// The recipient (channel or target) was derived from external content.
    pub recipient_tainted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub decision: Decision,
    /// Exact channel or a prefix ending in `*` (`deliver:*`, `*`).
    pub channel: String,
    /// Applies only to payloads at most this sensitive (`max_sensitivity` on allow/confirm).
    pub sensitivity_at_most: Option<Sensitivity>,
    /// Applies only to payloads at least this sensitive (`max_sensitivity` on deny in the
    /// SPEC example, see QUESTIONS Q7).
    pub sensitivity_at_least: Option<Sensitivity>,
    /// Applies only while today's spending including this intent stays within the limit.
    pub max_cost_fen_per_day: Option<u64>,
    /// Applies only when the recipient came from tainted data.
    pub when_recipient_tainted: bool,
}

impl Rule {
    pub fn new(decision: Decision, channel: &str) -> Rule {
        Rule {
            decision,
            channel: String::from(channel),
            sensitivity_at_most: None,
            sensitivity_at_least: None,
            max_cost_fen_per_day: None,
            when_recipient_tainted: false,
        }
    }

    fn channel_matches(&self, channel: &str) -> bool {
        match self.channel.strip_suffix('*') {
            Some(prefix) => channel.starts_with(prefix),
            None => self.channel == channel,
        }
    }

    pub fn applies(&self, f: &Facts) -> bool {
        self.channel_matches(&f.channel)
            && self.sensitivity_at_most.is_none_or(|max| f.sensitivity <= max)
            && self.sensitivity_at_least.is_none_or(|min| f.sensitivity >= min)
            && self.max_cost_fen_per_day.is_none_or(|max| f.spent_today_fen.saturating_add(f.cost_fen) <= max)
            && (!self.when_recipient_tainted || f.recipient_tainted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<Rule>,
    pub default: Decision,
}

/// Which rule (policy index, rule index) decided, or the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    Rule {
        policy: usize,
        rule: usize,
    },
    Default,
    /// Escalated to confirm because the recipient is tainted.
    TaintedRecipient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub basis: Basis,
}

/// Decides `facts` under all active `policies`. With no applying rule, the strictest
/// default among the policies applies (confirm when there are no policies at all).
pub fn evaluate(policies: &[Policy], facts: &Facts) -> Verdict {
    let mut best: Option<Verdict> = None;
    for (pi, p) in policies.iter().enumerate() {
        for (ri, r) in p.rules.iter().enumerate() {
            if r.applies(facts) && best.is_none_or(|b| r.decision > b.decision) {
                best = Some(Verdict { decision: r.decision, basis: Basis::Rule { policy: pi, rule: ri } });
            }
        }
    }
    let verdict = best.unwrap_or_else(|| Verdict {
        decision: policies.iter().map(|p| p.default).max().unwrap_or(Decision::Confirm),
        basis: Basis::Default,
    });
    if verdict.decision == Decision::Allow && facts.recipient_tainted {
        return Verdict { decision: Decision::Confirm, basis: Basis::TaintedRecipient };
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// The `nightly-ml` policy from SPEC §9.3.
    pub(crate) fn nightly_ml() -> Policy {
        let mut model = Rule::new(Decision::Allow, "model:default");
        model.sensitivity_at_most = Some(Sensitivity::Internal);
        let mut gpu = Rule::new(Decision::Allow, "compute:remote-gpu");
        gpu.max_cost_fen_per_day = Some(20_000);
        let mut notify = Rule::new(Decision::Confirm, "notify:*");
        notify.when_recipient_tainted = true;
        let mut secret = Rule::new(Decision::Deny, "*");
        secret.sensitivity_at_least = Some(Sensitivity::Secret);
        Policy {
            name: "nightly-ml".into(),
            rules: vec![
                Rule::new(Decision::Allow, "fetch:registered-sources"),
                model,
                Rule::new(Decision::Allow, "compute:worker"),
                gpu,
                Rule::new(Decision::Confirm, "deliver:*"),
                notify,
                secret,
            ],
            default: Decision::Confirm,
        }
    }

    fn facts(channel: &str) -> Facts {
        Facts {
            channel: channel.into(),
            sensitivity: Sensitivity::Internal,
            cost_fen: 0,
            spent_today_fen: 0,
            recipient_tainted: false,
        }
    }

    fn decide(f: Facts) -> Decision {
        evaluate(&[nightly_ml()], &f).decision
    }

    #[test]
    fn the_spec_policy() {
        assert_eq!(decide(facts("model:default")), Decision::Allow);
        assert_eq!(decide(Facts { sensitivity: Sensitivity::Private, ..facts("model:default") }), Decision::Confirm);
        assert_eq!(decide(Facts { sensitivity: Sensitivity::Secret, ..facts("model:default") }), Decision::Deny);
        assert_eq!(decide(facts("compute:worker")), Decision::Allow);
        assert_eq!(
            decide(Facts { cost_fen: 15_000, spent_today_fen: 6_000, ..facts("compute:remote-gpu") }),
            Decision::Confirm,
            "over the daily budget"
        );
        assert_eq!(decide(Facts { cost_fen: 15_000, ..facts("compute:remote-gpu") }), Decision::Allow);
        assert_eq!(decide(facts("deliver:minio-acme")), Decision::Confirm);
        assert_eq!(decide(facts("notify:feishu")), Decision::Confirm, "no rule applies: the default");
        assert_eq!(decide(facts("upload:somewhere")), Decision::Confirm, "unknown channels default to confirm");
    }

    #[test]
    fn deny_beats_confirm_beats_allow() {
        let p = Policy {
            name: "p".into(),
            rules: vec![
                Rule::new(Decision::Allow, "x:*"),
                Rule::new(Decision::Confirm, "x:y"),
                Rule::new(Decision::Deny, "x:y"),
            ],
            default: Decision::Allow,
        };
        assert_eq!(evaluate(std::slice::from_ref(&p), &facts("x:y")).decision, Decision::Deny);
        let mut q = p.clone();
        q.rules.pop();
        assert_eq!(evaluate(&[q.clone()], &facts("x:y")).decision, Decision::Confirm);
        assert_eq!(evaluate(&[q], &facts("x:z")).decision, Decision::Allow);
        assert_eq!(evaluate(&[], &facts("x:y")).decision, Decision::Confirm, "no policy: confirm");
    }

    #[test]
    fn tainted_recipients_always_need_confirmation() {
        let v = evaluate(&[nightly_ml()], &Facts { recipient_tainted: true, ..facts("compute:worker") });
        assert_eq!(v, Verdict { decision: Decision::Confirm, basis: Basis::TaintedRecipient });
        let deny = Facts { recipient_tainted: true, sensitivity: Sensitivity::Secret, ..facts("compute:worker") };
        assert_eq!(evaluate(&[nightly_ml()], &deny).decision, Decision::Deny, "taint never relaxes a deny");
    }
}
