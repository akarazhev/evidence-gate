# 6. Controls

Every control in this repository refuses with a non-zero exit and writes nothing
partial. This page lists what each one refuses and which tests prove it, so a
change that weakens a control fails visibly rather than quietly.

Run them all with `make test`: 282 tests, standard library only, no network and
no scanner required.

---

## Scope — `scripts/check_scope.py`

The only control here whose refusal is a security boundary rather than a
convenience.

| Refuses | Because |
|---|---|
| A path matching `policy/excluded-paths.yml` | Excluded content must not reach a review packet |
| A symlink whose target is excluded, or resolves outside the repository | The check must cover the file that is opened, not the name that was typed |
| A policy that parses to zero rules | A policy excluding nothing is a disabled control, not a permissive one |
| A policy line the parser cannot account for | Silently ignoring a typo removes an exclusion while the file still looks populated |

Proven by `TestParsePolicy`, `TestMatches`, `TestResolveWithin`,
`TestResolvedScopeControl`, `TestPolicyProcess`, `TestScopeProcess`.

**Known limits**, documented in `docs/03-data-handling.md`: a hard link from an
allowed name to an excluded file is not detectable by path resolution, and the
check and the subsequent open are not atomic.

## Packet construction — `scripts/build_packet.py`

| Refuses | Because |
|---|---|
| Reading any source file before the scope check has passed | The ordering is the control; `TestScopeCheckOrdering` proves it by pointing at an excluded file that does not exist, and requiring `ScopeViolation` rather than `FileNotFoundError` |
| A finding id that is not canonical | The id names an output file; a model-authored value must not steer a write |
| An output path that resolves outside `--out` | Same reason, checked independently of the schema |

Proven by `TestScopeCheckOrdering`, `TestFindingIdentity`,
`TestChallengeOutputContainment`, `TestQueueTargets`.

## Verdict recording — `scripts/record_verdict.py`

| Refuses | Because |
|---|---|
| `--agent` equal to `--validator` | Independence is the mechanism, not a preference |
| `--validator` without `--challenge` | It would record a validator that validated nothing |
| A supplied challenge that fails its schema, whatever it parses to | Presence of the flag decides validation, never the parsed value |
| A challenge whose `verdict_digest` names a different revision | A challenge refutes one revision, not a finding |
| A second verdict without `--supersede` | Revising is deliberate; the log is append-only |
| A log whose header, rows, identity scheme or numeric fields break the contract | `collapse()` relies on all of them |
| An existing SARIF that cannot be interpreted | Overwriting it would discard the audit trail's current state |
| `--minutes` that is negative, infinite or NaN | One NaN turns the programme's headline metric into NaN and prints it as a result |
| A newline in any log cell | One row per physical line is what makes a swallowed row detectable |

Proven by `TestIndependenceControl`, `TestSupersedeCli`, `TestLogCompatibility`,
`TestLogContractProcess`, `TestSarifAccumulation`, `TestCheckConsistency`,
`TestDecideState`, `TestFallbackValidator`, `TestSchemaDriftGuard`,
`TestChallengeRevisionPacket`, `TestRecordTarget`.

## Human decisions — `scripts/record_human_decision.py`

| Refuses | Because |
|---|---|
| A finding with no recorded verdict | A decision about nothing describes nothing |
| A `--by` that is empty after trimming | An attribution to whitespace is not an attribution |
| An unreadable SARIF, before appending to the log | The log is append-only; a row written ahead of a failure cannot be withdrawn |

Proven by `TestDecisionRecording`.

## Scanner egress — `scripts/scan.sh`

| Refuses | Because |
|---|---|
| An empty or missing `rules/` directory | Someone else's rule set is worse than none, and silence would fall back to the network |
| `make install` without `SEMGREP_VERSION` | Scanner fingerprints feed finding identity |

Telemetry and the version check are disabled unconditionally. Registry access is
possible through an explicit `SEMGREP_CONFIG` and announces itself first.

Proven by `TestScanScript`, `TestInstall`. The tests install a stand-in on
`PATH` that records its arguments and exits 42, so they assert what the scanner
was actually invoked with and can never reach the network.

## Project template — `scripts/check_template.py`

Refuses while `CLAUDE.md` still contains template placeholders, and refuses when
the file is missing or unreadable — reporting success about a file it could not
read is the failure this control exists to avoid.

It proves the absence of placeholders, not that the replacement text describes
the project. Proven by `TestFindPlaceholders`, `TestProcess`.

**This check fails in this repository on purpose.** `CLAUDE.md` here is the
template you copy and fill in per project.

## Metrics — `scripts/metrics.py`

Refuses a log that the recorder would also refuse, rather than reporting a
reassuring zero. Withholds derived rates when their denominator is undefined.

Proven by `TestCollapse`, `TestCollapseSemantics`, `TestAgentAccuracy`,
`TestUndefinedDenominator`, `TestSinceSelectsFindings`,
`TestChronologicalTimestamps`, `TestRenderSafeguards`.
