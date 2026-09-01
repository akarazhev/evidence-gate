# Triage Finding

You are triaging one scanner finding using the supplied packet.

Return only JSON conforming to `templates/verdict.schema.json`.

## Procedure

1. Read the scanner metadata and target code.
2. Treat scanner dataflow as a hypothesis, not evidence.
3. Trace attacker-controlled input to the sink where possible.
4. Stop if the flow requires an excluded path or missing file.
5. Classify evidence as `traced`, `partial`, or `pattern`.
6. Set `verdict` to `needs_human` when evidence is incomplete.
7. Use `policy/severity-policy.yml` for severity and priority.

Do not claim execution, reproduction, or runtime proof.
