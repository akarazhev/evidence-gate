# 7. Graduation

Manual mode is the default. Move toward automation only after the controls have
proven useful and predictable on real findings.

## Minimum evidence

Collect at least one full review cycle with:

- Deterministic scan output.
- Triage verdicts.
- Independent challenge results for medium and higher severity findings.
- Recorded engineer minutes.
- Reviewed SARIF output imported into the findings store.

Run:

```bash
make metrics
```

## Graduation criteria

Do not automate until all of these are true:

- Median triage time is falling or materially lower than the prior process.
- False-positive rate is measured over decided findings, not guessed.
- Confirmed findings are appearing; lower false positives are not just deferrals.
- Challenge disagreement is non-zero or has been investigated.
- Excluded paths are owned, explained, and periodically reviewed.
- The golden set passes for the scanner/prompt/model combination in use.

## What may be automated first

Safe candidates:

- Running deterministic scanners.
- Producing SARIF and SBOM artifacts.
- Importing reviewed SARIF into the findings store.
- Computing metrics.

Keep agent-assisted analysis human-initiated until prompt-injection, credential,
and data-handling controls have explicit owners.

## Runtime proof

Findings marked `awaiting_proof` need a harness or reproduction. Static analysis,
including agent-assisted reasoning, is not sufficient to confirm memory-safety,
race, or environment-dependent classes.
