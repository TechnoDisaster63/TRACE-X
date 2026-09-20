# Prevention Engine Specification

## Status

- **IMPLEMENTED:** M11 typed advisory recommendations, explanations, counterfactuals, BEC workflow, M12 policy decisions.
- **IMPLEMENTED:** backward-compatible JSON/text report integration.
- **DESIGNED/FUTURE:** persistent review UI or API.
- **NOT SUPPORTED:** automated execution, quarantine/block/delete, ML probabilities.

## Contract

M11 consumes investigation ID, M07 evidence, M08 risk/constraints, M09 threat class, optional parsed content, and optional M12 policies. It returns one non-executable structured recommendation. Required fields include IDs, risk/threat labels, action/mode, evidence/rules/policies, reason, impact, reversibility, approval, timestamp, status, explanation, counterfactuals, limits, policy decision, and BEC assessment.

Actions are advisory vocabulary only. `executable=false` is invariant. Missing context requests more analysis. LOW may allow with notice; MEDIUM routes to review/flag; HIGH/CRITICAL recommends hold-for-review. Policies may strengthen, never silently weaken.
