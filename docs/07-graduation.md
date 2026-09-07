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
- Dismissal rate is measured over decided findings, not guessed.
- Confirmed findings are appearing; a falling dismissal rate is not just
  deferrals.
- Agent accuracy is computed from recorded human decisions, with coverage high
  enough to trust it. A dismissal rate with no accuracy behind it says what the
  pipeline did, not whether it was right.
- Challenge disagreement is non-zero or has been investigated.
- Excluded paths are owned, explained, and periodically reviewed.
- The golden set passes for the scanner/prompt/model combination in use.

The golden-set criterion is **blocked**: `goldenset/run_goldenset.py` is a
placeholder with no cases configured. It stays on the list because it belongs
there, but it cannot be met today.

## Pilot exit criteria

A pilot is narrower than graduation. It runs on one repository and answers one
question: is this worth continuing? Use the graduation list minus the golden
set, plus:

- Human decisions recorded for at least `<coverage threshold>` of decided
  findings.
- Agent accuracy of at least `<accuracy threshold>` on those decisions.

**Fill both thresholds in before the pilot starts.** Choosing them after the
numbers arrive is not measurement, it is fitting the criteria to the result.

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
