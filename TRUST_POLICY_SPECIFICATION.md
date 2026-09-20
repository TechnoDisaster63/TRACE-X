# Trust Policy Specification

- **IMPLEMENTED:** frozen versioned policies; strict validation; exact all-condition matching; priority; expiration; conflicts; safe base default.
- **DESIGNED BUT NOT IMPLEMENTED:** persistent store, signatures, authenticated administration, exceptions, department/recipient context.
- **NOT SUPPORTED:** arbitrary expressions or enforcement.

Fields: policy ID/name/version/enabled/conditions/action/priority/approval/effect/creator/expiry/description/metadata. Conditions match exact risk, threat, source, category, module, or severity signals. Higher priority wins. Equal-priority conflicts select the stronger review action and record the conflict. Allow cannot override forensic risk silently. Every decision remains advisory and non-executable.
