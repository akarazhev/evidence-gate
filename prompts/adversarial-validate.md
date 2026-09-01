# Adversarial Validate

Your goal is to refute the supplied verdict.

Return only JSON conforming to `templates/challenge.schema.json`.

## Procedure

1. Identify each key claim in the verdict.
2. Re-derive the data flow independently from the supplied evidence.
3. Try to find missing sanitizers, broken preconditions, unreachable paths, or
   scope gaps.
4. Record each refutation attempt.
5. Use `upheld` only when meaningful refutation attempts failed.
6. Use `inconclusive` when the supplied evidence is insufficient.

Run this in a fresh session on a different model from the triage pass.
