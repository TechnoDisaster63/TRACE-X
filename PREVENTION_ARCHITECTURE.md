# TRACE-X Prevention Architecture

Date: 2026-09-20

## Status legend

- **IMPLEMENTED**: executable code with tests in this repository
- **PARTIALLY IMPLEMENTED**: bounded prototype behavior, with limits stated
- **DESIGNED BUT NOT IMPLEMENTED**: architecture only
- **FUTURE ROADMAP**: deferred dependency
- **NOT SUPPORTED**: intentionally absent from this build

## Current boundary

M01-M10 produce forensic observations, normalized evidence, deterministic risk, a threat graph, and a report. M11 now adds one structured, explainable prevention recommendation after M09 and before final M10 serialization.

```text
M01-M06 observations
  -> M07 normalized evidence
  -> M08 forensic risk + prevention constraints
  -> M09 threat class
  -> M11 advisory-only recommendation
  -> M10 backward-compatible JSON/text report section
```

## M11 Prevention Recommendation Engine - IMPLEMENTED

`modules/m11_prevention_recommendation/engine.py` provides:

- frozen typed `PreventionRecommendation`
- deterministic recommendation ID derived from investigation, action, and evidence IDs
- advisory and approval-required modes only
- traceable evidence references and rule IDs
- explanation per risk factor
- counterfactual statements
- explicit impact, reversibility, limits, approval requirement, and pending status
- a hard invariant that M11 recommendations are never executable
- propagation of M08's authentication automation constraints

M11 can return only:

- `ALLOW_WITH_NOTICE`
- `FLAG_FOR_REVIEW`
- `REQUIRE_ANALYST_REVIEW`
- `HOLD_FOR_REVIEW`
- `ESCALATE_TO_SOC`
- `REQUEST_ADDITIONAL_ANALYSIS`

The current mapping does not select `ESCALATE_TO_SOC`; it is reserved in the typed vocabulary for a later tested rule. Destructive actions and automated mode are absent.

## Mapping - IMPLEMENTED

| Context | Recommendation | Mode |
|---|---|---|
| Missing/unsupported context or no risk-contributing evidence | `REQUEST_ADDITIONAL_ANALYSIS` | `ADVISORY` |
| LOW risk with traceable risk evidence | `ALLOW_WITH_NOTICE` | `ADVISORY` |
| MEDIUM BEC/phishing/spoofing | `REQUIRE_ANALYST_REVIEW` | `APPROVAL_REQUIRED` |
| Other MEDIUM | `FLAG_FOR_REVIEW` | `APPROVAL_REQUIRED` |
| HIGH/CRITICAL | `HOLD_FOR_REVIEW` | `APPROVAL_REQUIRED` |

`HOLD_FOR_REVIEW` is a recommendation name, not an executed hold. The output states that this offline prototype performs no hold, quarantine, or block.

## Safety properties - IMPLEMENTED

- Risk score alone never enables execution.
- Every approval-required result sets `requires_human_approval=true`.
- `executable` is always false; the dataclass rejects true.
- Untrusted reported authentication may explain analyst review but is marked ineligible for automated prevention.
- Confidence is a label, not a probability.
- No intent is claimed from an anomaly.
- No network request, mailbox mutation, block, quarantine, delete, or external message occurs.

## Report integration - IMPLEMENTED

The existing investigation object gains a top-level `prevention` key. M10 gains `prevention_assessment`, and its text renderer adds a `PREVENTION ASSESSMENT` section. Existing keys and CLI commands remain unchanged.

## M12 Trust and Policy Engine - IMPLEMENTED (local advisory model)

M12 owns typed, versioned policies, deterministic precedence and conflict handling, expiry checks, and advisory decisions. It has no persistent policy service or live execution path.

## M13-M16 status

- M13 is implemented as deterministic offline JSON/CSV IOC review export; automated enforcement stays false.
- M14 is implemented as immutable local analyst-feedback records and review-only summaries; it does not train a model.
- M15 is absent; no live adapter interfaces execute actions.
- M16 is implemented as a local lifecycle/integrity record model; it records supplied outcomes but performs no external action.

## NOT SUPPORTED

Automated quarantine/block/delete, live mailbox control, live SIEM/SOAR/SEG integration, external reputation lookup, ML prioritization, calibrated probabilities, and production enforcement are not supported.

## M12 Trust and Policy Engine - IMPLEMENTED (minimal safe slice)

`modules/m12_trust_policy/engine.py` provides a frozen, versioned
`TrustPolicy`, strict validation, exact all-condition matching, ISO-8601
expiration, deterministic priority and policy-ID ordering, and an explainable
decision record.

Current context signals are derived only from structured pipeline output:
`risk:<LEVEL>`, `threat:<CLASS>`, and evidence source, category, module, and
severity labels. Conditions are exact strings; M12 does not run arbitrary
expressions or code.

Safe precedence:

1. Higher numeric priority wins.
2. At equal priority, a conflict between actions resolves to the stronger
   review action and is recorded explicitly.
3. A policy may strengthen the base forensic recommendation.
4. An allow policy cannot silently weaken an existing forensic recommendation;
   the base result is preserved and the conflict requires review.
5. Disabled, expired, or partially matched policies do not apply.
6. No policies means the base M11 recommendation remains unchanged.

M12 supports only `RECOMMEND` effects. Every decision is `ADVISORY_ONLY`, and
`executable` is always false. Policies cannot quarantine, block, delete, send,
or mutate external state.

Not yet implemented: file-backed policy loading, signatures, access control,
persistent audit history, exceptions, policy migration, department/recipient
attributes, UI/API management, or live enforcement adapters.

## BEC-specific prevention workflow - IMPLEMENTED (advisory prototype)

`modules/m11_prevention_recommendation/bec.py` separates BEC signals into
content, behavioral, identity, authentication, and URL categories. Content is
checked locally with bounded deterministic patterns, while forensic categories
reference existing M07 evidence IDs.

A keyword alone is insufficient. `REVIEW_RECOMMENDED` requires a BEC-related
content indicator plus forensic identity, authentication, or URL corroboration.
Otherwise the result is `INSUFFICIENT_CORROBORATION` or `NOT_INDICATED`.

The assessment copies no raw body text into its output. It provides evidence
references, cautious explanation, financial and out-of-band verification
safeguards, counterfactuals, limitations, and `executable=false`. It sends no
message, initiates no payment, and performs no hold, quarantine, or block.

Relationship-history analysis is not implemented because this offline build
has no mailbox history or persistent trust graph. The assessment states that
limit instead of inventing relationship evidence.

## M16 prevention audit/action lifecycle - IMPLEMENTED (typed model only)

`modules/m16_prevention_audit/lifecycle.py` implements an immutable offline
lifecycle for a non-executable M11 recommendation. Creation stores the original
recommendation SHA-256 and identity. Each legal transition returns a new frozen
object and appends a hash-linked event containing actor, actor role, UTC
timestamp, reason, details, and prior event hash.

States: `PENDING`, `REVIEW_REQUIRED`, `APPROVED`, `REJECTED`, `EXECUTED`,
`FAILED`, `EXPIRED`, `REVERSED`, and `CANCELLED`. A transition table rejects
illegal and terminal-state changes. `EXECUTED` and `FAILED` can only record an
outcome reported by an `ADAPTER`; this model never calls one or executes an
action. Executed records require an external reference. Reversal requires that
the lifecycle was marked reversible and that a reversal reference is recorded.

Integrity verification checks sequence, state chain, hash links, event hashes,
event IDs, monotonic timestamps, current state, and optional linkage to the
original recommendation. This is tamper-evident application logic, not a legal
chain-of-custody or immutable storage claim.

No file persistence is included in this slice. Safe storage, locking, access
control, retention, signatures, encrypted records, and multi-process
concurrency need a separate design before persistence is added.


### M16 lifecycle hardening

Integrity verification independently checks every event hop against the same
legal transition table used when appending events. A correctly re-hashed but
illegal sequence is rejected, and the first event must establish `PENDING`.
Malformed and non-string timestamps fail with `LifecycleError` rather than
leaking parser-specific exceptions.

Equal timestamps are intentionally allowed. Real clocks and serialized inputs
may have coarse resolution, so strict timestamp growth would reject valid
same-tick decisions. Ordering and integrity come from event sequence numbers
and hash links; timestamps must be monotonic non-decreasing, not strictly
increasing.

## M13 prevention intelligence/IOC export - IMPLEMENTED (offline JSON/CSV)

`modules/m13_ioc_export/engine.py` converts only supported, evidence-backed
observables into deterministic TRACE-X JSON or CSV. It is explicitly not STIX.
Each record contains the source investigation and evidence IDs, source module,
ordinal confidence label (not a probability), observation/review/expiration
timestamps, recommended action, reason, verification status, and limitations.

The initial extractor is intentionally narrow: exact HTTP/HTTPS URL evidence,
selected IP evidence, and selected domain fields with known labels. Descriptive
authentication text and arbitrary prose are not guessed into IOCs. Duplicates
are removed deterministically and records are sorted before serialization.

All current records set `safe_for_automated_enforcement=false`. Even a future
independently verified observable would remain non-enforceable here because
this prototype has no reputation, ownership, allowlist, scope, policy, or
false-positive control sufficient to justify automated blocking. The exporter
makes no network call and performs no SIEM, firewall, gateway, mailbox, or
other external action.

## M14 analyst feedback - IMPLEMENTED (immutable offline records)

`modules/m14_analyst_feedback/engine.py` records accepted/rejected action,
false-positive, false-negative, trusted-sender, confirmed-suspicious-sender,
threat-escalated, benign-business-email, and needs-more-evidence decisions.
Each frozen record includes actor/role, timezone-aware time, reason, source
investigation/recommendation IDs, evidence IDs, policy and rule versions,
details, SHA-256 links to the original evidence and full recommendation, and a
content-derived record ID/hash.

Feedback never edits the original evidence or recommendation. Integrity checks
detect changes to either original or the feedback record. Summaries provide
counts by decision/rule/policy version and human review flags only. They do not
change rules, policies, thresholds, or models; they do not train ML; they do
not execute actions.

No persistence is included. Safe identity, authorization, storage, locking,
retention, and privacy controls must be designed before records are stored or
shared. This is a rule-tuning review aid, not adaptive learning.

### M14 nested immutability hardening

Feedback construction deep-copies details into recursively immutable canonical
containers: mappings become read-only mapping proxies, and lists/tuples/sets
become tuples. Unsupported object types fail closed. The record therefore
cannot be changed through a retained input reference or nested in-place
mutation. `to_dict()` returns detached ordinary dictionaries/lists so existing
JSON serialization remains usable without exposing the record's internals.
Integrity hashes use the same thawed canonical representation.
