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

## M12 Trust and Policy Engine - DESIGNED BUT NOT IMPLEMENTED

A future M12 will own versioned policy documents, precedence, trusted identities, exceptions, expiry, approval requirements, and organization context. M11 currently reports an empty `policy_ids` list and does not pretend policy evaluation occurred.

## M13-M16 - FUTURE ROADMAP

- M13 offline IOC/action export with verified-versus-heuristic labels
- M14 analyst feedback stored separately from forensic evidence
- M15 adapter interfaces with no default live execution
- M16 prevention audit and case history

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
