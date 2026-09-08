# Plan Fixes

## Task 3 file list

- Before: Task 3 listed only `tests/test_check_scope.py` under `Files`.
- After: The list also names the required red-test evidence file and the plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is an unambiguous, local completeness correction and does not change the task intent or behavior.

## Task 5 file list

- Before: Task 5 listed only `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is an unambiguous, local completeness correction and does not change the task intent or behavior.

## Task 8 file list and RED expectation

- Before: Task 8 listed only `scripts/record_verdict.py` and `tests/test_record_verdict.py` under `Files`, despite requiring the Task 5 red-test evidence backfill and this plan-fixes entry. Its RED expectation named only `build_result`, although alphabetical `unittest` execution can encounter another missing helper first.
- After: The file list includes both evidence artifacts, and the RED expectation permits the required missing-helper `AttributeError` regardless of which helper executes first.
- Why: These are unambiguous local completeness and test-runner-order corrections. They preserve Task 8's accumulation behavior, refusal semantics, scope, and interfaces.

## Task 9 file list

- Before: Task 9 listed only `scripts/record_verdict.py` and `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is an unambiguous, local completeness correction and does not change the task intent, validation boundary, refusal behavior, partial-write guarantees, scope, or egress.

## Task 9 top-level object guard

- Before: Task 9's fallback-validator tests and prescribed body did not cover a
  non-object top-level instance. `_fallback_validate([], {"type": "object",
  "properties": {}}, "fixture")` therefore leaked `AttributeError` at
  `instance.items()` instead of raising `ValidationError`.
- After: The task adds a focused regression and an upfront `dict` guard that
  raises `ValidationError` before accessing object members.
- Why: This is an unambiguous local validation-boundary correction. It preserves
  the fallback's refusal behavior, scope, partial-write guarantees, and egress.

## Task 10 file list

- Before: Task 10 listed only `scripts/check_scope.py` and
  `policy/excluded-paths.yml` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is
  an unambiguous, local completeness correction and does not change the task
  intent, platform-independent matching behavior, scope, independence,
  partial-write guarantees, or egress.

## Task 11 file list

- Before: Task 11 listed only `scripts/build_packet.py` and
  `tests/test_build_packet.py` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires the Task 3 green-commit backfill, Task 11
  RED evidence, and this plan-fixes entry in the task commit. This is an
  unambiguous, local completeness correction and does not change the task
  intent, identity behavior, scope ordering, independence, partial-write
  guarantees, or egress.

## Task 12 file list

- Before: Task 12 listed only `scripts/record_verdict.py`, `Makefile`, and
  `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires the Task 11 green-commit backfill, Task 12
  RED evidence, and this plan-fixes entry in the task commit. This is an
  unambiguous, local completeness correction and does not change the task
  intent, independence behavior, refusal ordering, partial-write guarantees,
  scope, or egress.

## Task 13 file list

- Before: Task 13 listed only `scripts/record_verdict.py` and
  `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires the Task 12 green-commit backfill, Task 13
  RED evidence, and this plan-fixes entry in the task commit. This is an
  unambiguous, local completeness correction and does not change the task
  intent, log compatibility, independence, partial-write guarantees, scope, or
  egress.

## Task 13 empty-log invariant

- Before: Task 13 allowed `check_log_compatible` to accept an empty file, while
  `append_log` decided whether to write the header from `path.exists()` alone.
- After: `append_log` treats only a non-empty existing file as having a header;
  a zero-byte file receives exactly one `LOG_FIELDS` header before its first
  row. A focused test and mutation run prove the control.
- Why: A zero-byte file is not yet a log. The previous functions disagreed and
  placed a data row where `csv.DictReader` expects column names, silently
  corrupting the audit trail. The corrected invariant preserves the spec's
  header-compatibility intent without changing policy or scope.

## Task 1 temp-tree lifecycle warning found during Task 12

- Before: Task 1's `temp_tree` docstring explained fixture materialisation but
  did not say that `TemporaryDirectory` deletes the tree when the context exits.
- After: The docstring requires file-absence assertions to run inside the
  context and explains that captured values may still be asserted outside it.
- Why: An `assertFalse(path.exists())` after context teardown passes whether or
  not the code under test created the path, making a no-partial-write control
  vacuous. The warning is a local, unambiguous documentation correction to the
  existing test helper and prevents recurrence of the confirmed Task 12 test
  defect without changing production behavior.

## Task 4 fixture path discovered during Task 11

- Before: Task 4's SARIF fixture used `secrets/prod.env`, and its scope-ordering
  test asserted that path. The path was excluded only by the independent
  fixture policy.
- After: The fixture uses `config/server.pem` with rule
  `generic.secrets.private-key-detected` and message `Private key material`;
  the ordering test asserts the new path and explains the live-policy boundary.
- Why: Task 11's manual listing command uses the live policy, not the fixture
  policy. The `.pem` path is excluded under both, preserving fixture
  independence while making the manual scope-control verification meaningful.

## Task 14 file list

- Before: Task 14 listed only `scripts/scan.sh`, `rules/README.md`,
  `tests/test_scan_sh.py`, and `docs/03-data-handling.md` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This
  is an unambiguous local completeness correction and does not change the
  task's offline-default, refusal ordering, partial-write, scope, or egress
  behavior.

## Task 14 correction found in review

- Before: The scanner tests relied on a stripped `PATH` and assumed that this
  proved Semgrep was absent before exercising the registry branch.
- After: `run_scan` accepts an optional `bindir`; `make_fake_semgrep` installs
  an executable stand-in that records the actual argv and exits 42. The local
  and registry branches now assert their behavioral config and telemetry
  arguments through that stand-in.
- Why: A package-managed system Semgrep could still be found in `/usr/bin`,
  causing a real scan and possible network access. The fake makes both branches
  hermetic and behaviorally proves the config/telemetry arguments without
  changing production behavior or task scope.

## Task 15 file list and Task 14 evidence backfill

- Before: Task 15 listed only its two scripts and queue test file, while Task
  14's RED evidence still named a pending green commit.
- After: Task 15's file list includes the red-test and plan-fixes evidence
  files, and Task 14's green commit is recorded as
  `44b50453aa9fa26677dd9585ae112ae8e6849d01`.
- Why: The execution direction explicitly assigns this final Task 14 evidence
  backfill to Task 15. Both changes are unambiguous documentation completeness
  corrections and do not affect queue behavior, scope, identity, independence,
  partial-write guarantees, or egress.

## Task 15 correction found in review

- Before: Task 15 accepted negative limits through Python slicing, returned
  human text before an empty JSON listing could be serialized, placed the
  human summary before list rows, and lacked regression tests for those cases.
  The empty-selection guard was described only as a new Task 16 behavior even
  though it is needed for Task 15's existing index interface.
- After: Task 15 refuses a negative limit while preserving zero, lets empty
  listings reach the JSON and human-list branches, prints the human summary as
  a footer, tests all three cases, and owns the empty-selection guard. Task 16
  now explicitly preserves that guard while adding id resolution.
- Why: These are unambiguous queue-boundary and output-contract corrections.
  They do not change identity, scope ordering, independence, partial-write
  behavior, egress, policy, or the Task 16 id-addressing intent.

## Task 15 output-order correction found in re-review

- Before: The human list printed finding rows before index guidance and printed
  the guidance after the tally, so a reader saw neither the caveat while using
  an index nor the tally as the final output.
- After: The human list prints index guidance before every row and prints the
  tally last, with no later human-output line. A focused regression asserts
  the first and final non-empty lines.
- Why: The corrected queue-output contract is unambiguous and leaves JSON,
  identity, scope, filtering, empty queues, independence, partial-write
  behavior, policy, and egress unchanged.

## Task 16 file list, RED assertions, and output expectation

- Before: Task 16 omitted this plan-fixes file from its Files list; its two
  prescribed failure assertions also passed on argparse's unsupported-option
  error, and Step 5 still expected the tally in the header and id guidance
  below the list.
- After: The Files list includes this evidence file; the tests require the
  feature-specific unknown-id and mutual-exclusion messages; and Step 5 expects
  index guidance in the header with the tally as the final output.
- Why: The first test form could not produce the required genuine RED because
  argparse independently met its non-zero and argument-echo assertions. The
  current output order is the authoritative Task 15 contract. These are
  unambiguous local test, documentation, and file-list corrections that do not
  alter the intended id-addressing behavior or any control.

## Task 16 review fix round 1: path-glob quoting and filtered-ID coverage

- Before: The `make list` recipe passed `$(PATH_GLOB)` unquoted, allowing the
  invoking shell to expand one requested glob into multiple concrete arguments.
  Task 16 also lacked a Make-level argv regression and positive proof that ID
  selection remains independent of filters that empty `shown`; Step 6 omitted
  the plan and plan-fixes files it already required.
- After: The recipe uses `--path "$(PATH_GLOB)"`; Step 1 describes a temporary
  cwd/argv-recorder regression with two matching files and a hand-derived-ID
  packet test under `--level error --limit 0`; and Step 6 stages the plan and
  plan-fixes files.
- Why: Shell glob expansion changes the CLI argument boundary and can corrupt
  the requested filter. The new regression proves the Make-to-CLI boundary,
  while the characterization test documents the intended filter-independent ID
  path without changing it. These are local corrections that preserve scope,
  identity, empty-queue, JSON, output-order, partial-write, policy, and egress
  controls.

## Task 17 RED evidence, staging, and validation order

- Before: Task 17 had no explicit focused RED step after adding its tests, did
  not list the red-test or plan-fixes evidence files under `Files`, and staged
  only production code and tests. Its prose placed duplicate detection directly
  after log compatibility while accessing `verdict["finding_id"]`, although the
  verdict is loaded and validated later.
- After: Task 17 runs and records the focused `TestVerdictRows` and
  `TestSupersedeCli` RED command before implementation; lists and stages both
  evidence files; and performs duplicate/supersede detection after verdict and
  challenge schema validation, consistency validation, and challenge-ID
  matching, but before warnings, SARIF parsing, `append_log`, or any write.
- Why: The explicit RED run supplies the required causality evidence. Moving
  the check avoids unvalidated access while preserving the intended refusal and
  no-partial-write ordering. Both are local, unambiguous corrections that do
  not change the supersession behavior, scope, independence, policy, or egress.

## Task 17 review fix: behavioral proof and latest-lineage coverage

- Before: The two CLI tests read `verdict_rows` before asserting the subprocess
  result, so the original missing-helper RED could mask missing duplicate and
  `--supersede` behavior. Row filtering lacked a nonmatching verdict case;
  lineage lacked a third verdict and intervening human-decision row; and no test
  proved duplicate refusal precedes warnings and malformed-SARIF parsing.
- After: CLI tests assert subprocess results first; filtering includes an exact
  nonmatching verdict row; lineage covers three verdicts with an intervening
  blank-`initial_verdict` human-decision row; and an ordering test snapshots
  both artefacts while requiring refusal before warnings/SARIF parsing. Three
  controlled mutations prove duplicate refusal, `--supersede`, and ordering
  behavior independently.
- Why: These corrections make the regressions exercise the intended observable
  controls rather than fail at an unrelated helper access. They are local and
  unambiguous, and preserve scope, independence, append-only behavior,
  partial-write guarantees, policy, and egress.

## Task 18 shared compatibility control

- Before: The Task 18 script sketch did not invoke
  `record_verdict.check_log_compatible` before writing its decision row.
- After: It imports and calls `check_log_compatible(args.log, ID_SCHEME)` after
  finding the recorded verdict and before SARIF parsing or `append_log`; a
  readable stale-header regression proves refusal and no log growth.
- Why: The shared log contract is the existing control against writing a row
  under stale column names. Omitting the call leaves a corrupting append path;
  adding it is an unambiguous reuse of Task 13's required interface and
  preserves append-only and no-partial-write behavior.

## Task 18 shared appender control

- Before: The Task 18 sketch carried a duplicated `append_decision` helper with
  the pre-Task-13 `exists = path.exists()` header decision.
- After: The script imports and uses `record_verdict.append_log` directly, with
  no local CSV append implementation.
- Why: The duplicate could drift from the zero-byte-log header invariant that
  Task 13 established. Reusing the shared appender is an unambiguous local
  correction and preserves the authoritative `LOG_FIELDS` order.

## Task 18 sequencing, evidence, and file list

- Before: Task 18 expanded production `LOG_FIELDS` before its tests, omitted an
  explicit focused RED command and mutation-evidence step, and did not list or
  stage the plan and two evidence artifacts.
- After: Tests are authored and run with
  `python3 -m unittest tests.test_human_decision -v` before production changes;
  the plan requires focused/full GREEN plus both restored mutations; and its
  Files and staging lists include the plan, red-tests evidence, and plan-fixes
  evidence.
- Why: This supplies TDD causality and keeps the required evidence with the
  implementation. The correction is local and does not change Task 18's human
  decision, compatibility, SARIF, policy, scope, or egress intent.

## Task 18 invalid-decision test hygiene

- Before: `test_invalid_decision_is_refused` required only a non-zero exit
  status, which a missing script or unsupported invocation could satisfy.
- After: It additionally requires argparse's feature-specific `invalid choice`
  diagnostic for the value `maybe`.
- Why: The strengthened assertion ensures the RED/GREEN cycle proves the
  decision enum rather than an unrelated process failure. This is an
  unambiguous test-hygiene correction with no production behavior change.

## Task 19 files, evidence, and Task 18 backfill

- Before: Task 19 listed only the production module and metrics tests, did not
  stage its plan or evidence artifacts, and Task 18's green hash was pending.
- After: Task 19 lists and stages its original plan, user-authorized spec,
  red-test evidence, and plan-fixes evidence; the Task 18 green hash is
  `79ae57f7e51d0deb25e2b61c8a7f5086bf3b14d7`; and genuine §5.3 RED evidence is
  recorded with its final green hash pending Task 20.
- Why: The execution brief assigns these documentation and staging backfills to
  Task 19. They are unambiguous completeness corrections with no behavior or
  control change.

## Task 19 test responsibility and zero-minute coverage

- Before: Metrics tests passed raw rows directly to `compute`, and no regression
  proved that valid zero triage or decision minutes survived aggregation.
- After: Tests explicitly call `compute(collapse(rows))`, matching the new
  caller responsibility, and prove both zero totals remain recorded and render
  as valid values.
- Why: This is a local test-contract and falsification correction. The event
  semantics themselves are user-authorized specification decisions, not plan
  fixes.

## Task 19 human-decision coverage population

- Before: The Task 19 sketch divided every human decision, including one on a
  `human_review` finding, by the number of decided findings.
- After: Coverage counts only decided findings that carry a human decision,
  while `human_decisions`, the breakdown, and accepted/(accepted+rejected)
  accuracy retain all decisions. A mixed-state regression proves coverage is
  50.0%, not inflated beyond its decided population.
- Why: §5.4 defines coverage among decided findings. This isolates the coverage
  numerator without changing the prescribed decision count, breakdown, or
  accuracy denominator.

## Task 19 metrics summary terminology

- Before: The metrics module introduced four numbers and called its second
  measure false-positive rate; Section 4 referred to the stale false-positive
  number.
- After: The summary presents five measures including dismissal rate and human
  accuracy, and the Section 4 warning refers to the dismissal number.
- Why: This is a local stale-prose correction required by §5.4. It does not
  alter metric computation.

## Task 19 render-preservation fix

- Before: The Task 19 rebuild replaced `render()` broadly and silently removed
  established timing guidance, validation alarms, parked-proof reporting, and
  evidence-quality/footer output.
- After: Task 19 restores every render section not explicitly replaced by the
  dismissal and ground-truth blocks, with output-level regressions for zero and
  high disagreement, same-model validation, and parked runtime proof.
- Why: This is a local preservation correction. It restores existing safeguards
  without changing the user-authored event semantics.

## Task 19 no-timing guidance preservation

- Before: The rebuilt no-timing branch was shortened to `No timings recorded.`
- After: It restores the `--minutes` recording instruction and the warning that
  the programme lacks its primary success measure; an observable regression
  requires both phrases.
- Why: This is an unambiguous preservation of pre-Task-19 reporting behavior.

## Task 20 install-refusal behavioral coverage and file list

- Before: Task 20 prescribed a version-refusing `make install` recipe but no
  behavioral regression, and its file and staging lists omitted that test, the
  corrected plan, the Task 19 green-hash backfill, and this plan-fixes entry.
- After: `tests/test_makefile.py` runs `make install` with a temporary fake
  `pip`, proving that an absent `SEMGREP_VERSION` refuses before invocation and
  that a supplied version passes exactly `install semgrep==<version>`. The
  Task 20 file and staging lists include the test and documentation artifacts;
  detailed Task 20 RED/GREEN output stays in the ignored task report.
- Why: The executable refusal protects finding identity and requires direct,
  network-free process evidence. This is a local TDD and completeness
  correction that does not change the specified pinning behavior, scope,
  validator independence, partial-write guarantees, finding identity, or
  egress.

## Task 20 README scanner prerequisite

- Before: README's prerequisites still recommended the unpinned command
  `pip install semgrep`, contradicting Task 20's pinned Quick start and the
  executable `make install` refusal.
- After: The prerequisite points to the scanner version recorded in
  `docs/02-setup.md`.
- Why: Leaving an unpinned installation path in the primary documentation would
  bypass the identity safeguard this task introduces. This is a local,
  unambiguous documentation correction and does not alter scanner behavior,
  scope, independence, partial writes, identity derivation, or egress.

## Task 20 review fix round 1: fail-closed template control

- Before: The prescribed shell `if grep` recipe treated both "no placeholders"
  and "cannot read CLAUDE.md" as success, so a missing context file passed the
  pre-flight gate. Task 20's file and staging lists also omitted a dedicated
  script and its process-level tests.
- After: `scripts/check_template.py` distinguishes clean, templated, and
  unreadable inputs; the Make target delegates to it; and
  `tests/test_check_template.py` covers all three process outcomes plus focused
  placeholder parsing. The Task 20 file and staging lists name both new files.
- Why: A control that promises repository-specific context must refuse when it
  cannot inspect that context. This is a fail-closed correction that preserves
  the gate's scope and required exit 2 while adding direct process evidence.

## Task 20 pre-flight checklist deduplication

- Before: The corrected Task 20 plan draft repeated the `BY=` privacy
  pre-flight item.
- After: The plan contains exactly one instruction to use a role in `BY=` and
  never a name or email address.
- Why: This is a local documentation deduplication only; it preserves the
  privacy requirement and does not change behavior, scope, identity,
  independence, partial writes, or egress.

## Task 21 evidence and staging completeness

- Before: Task 21 named only its three scripts and three test modules, omitting
  the corrected plan, RED/GREEN evidence, plan-fixes evidence, mutation checks,
  staging, and commit steps. The user's Layer 7 plan extension was uncommitted.
- After: The Task 21 file list includes the plan and both evidence documents;
  explicit steps require RED/GREEN records, a restored mutation check for each
  critical defect, focused verification, one final `make test`, diff review,
  and one commit with subject `fix: close validation and scope bypasses`.
  Staging includes the entire existing user-authored Layer 7 plan extension.
- Why: The controller authorized this local completeness correction. It makes
  the controls' evidence reviewable and preserves the user's work without
  changing the specification, exclusion policy, or the scope of Tasks 22–23.

## Task 21 review round 1: validate every supplied challenge

- Before: Step 1's `if challenge is not None` closed the empty-object bypass
  but skipped validation when an explicitly supplied challenge file contained
  JSON `null`. Both low and high severity reached audit-log and SARIF writes.
- After: The user-authored Step 5 captures `challenge_supplied` before parsing
  and uses that flag to decide schema validation. Process tests cover `null`
  and `{}` at low and high severity, assert write absence inside `temp_tree`,
  and prove that restoring `if challenge:` writes the log for both null cases.
  The Step 5 plan edit is preserved and included in its separate fix commit.
- Why: A supplied document must pass its schema regardless of the parsed
  value. The fallback already rejected non-dict inputs with `ValidationError`;
  that existing guard is preserved and its diagnostic now names the parsed
  type exactly as Step 5 specifies. The correction preserves the specification,
  audit history, exclusion policy, and the scope of Tasks 22–23.

## Task 22 files, evidence, verification, and staging

- Before: Task 22 named only its production files and vague corresponding
  tests, with no explicit evidence, verification, staging, or commit steps.
- After: The controller expanded the list to exactly the five production
  files, five corresponding test files, the plan, and both evidence documents.
  Steps 9–10 require sequential I2/I3/I5/I7 mutations, exact failure/restoration
  evidence, final focused tests, one full `make test` after every mutation is
  restored, diff review, and one commit: `fix: resolve important review findings`.
- Why: This is the authorized local completeness correction. Task 23 and the
  specification are outside the edit scope.

## Task 22 shared-filter glob preservation

- Before: Step 4's common filter sketch dropped the quotes around
  `$(PATH_GLOB)`, although Task 16 already established literal glob forwarding.
- After: The shared `QUEUE_FILTERS` retains `--path "$(PATH_GLOB)"` for list
  and index triage, and ID triage omits all queue filters.
- Why: This preserves the established shell argument boundary and avoids
  regressing glob handling while fixing repository/filter propagation.

## Task 22 suppression-test correction

- Before: Step 5 prescribed `Dismissed after review. {rationale}` while also
  requiring an unchallenged suppression to contain no `adversarial validation`
  substring. Task 7's truthful rationale already says that policy
  `does not require adversarial validation`.
- After: The controller confirmed preserving that rationale and requiring the
  full honest suppression while rejecting the false prefix
  `Dismissed after adversarial validation`. The mutation restores that prefix
  and the real recorder regression fails on the false statement.
- Why: The initial substring prohibition contradicted the exact prescribed
  behavior. This local test correction preserves truthful provenance.

## Task 22 decision ordering and timestamp fixtures

- Before: Step 6 compared only timestamps, leaving a later log row with an
  equal instant unable to supersede an earlier decision. An old merge fixture
  omitted the decision timestamp, and a malformed-timestamp test expected
  order independence instead of log-index tie-breaking.
- After: The plan and implementation compare the full event key
  `(_moment(reviewed_at), log index)`. Equal and equivalent aware instants
  break by log index; missing/malformed values use the explicit UTC minimum.
  The positive merge fixture has a later decision timestamp, and invalid-time
  fixtures assert the final log row wins. I6 and I7 both reached RED before
  their shared timestamp implementation.
- Why: The controller required this unambiguous alignment with Step 7 and the
  specification's tie-breaking rule. No specification edit was made.

## Task 22 historical RED classification and parent snapshots

- Before: Step 8 requested switching to parent commits; Task 8's old RED
  stopped at missing helpers and Task 12's at unsupported future arguments.
  Tasks 11/19 described missing-code errors too broadly as defect proof.
- After: Actual parents `e5a2dd2de21dc8a93bf337d3f0524a724a70b8e0`
  (Task 8) and `ee81d5cb5e154f114f35cfffff0caa491f21dd73` (Task 12)
  were extracted with `git archive` into isolated temporary directories.
  Their original CLIs ran with supported arguments and produced causal
  failures, recorded beside the earlier entries marked insufficient.
  Tasks 11/19 explicitly distinguish honest missing-code `AttributeError`
  RED from causal existing-behavior proof.
- Why: The controller required actual historical execution while preserving
  the shared branch. The snapshots were never used to switch/reset the checkout.

## Task 22 fix round 1: user-authored SARIF control-depth correction

- Before: Step 2 checked only result and properties containers. Null/numeric
  finding IDs reached merge sorting after audit append, while object results
  and unrecognized documents could be silently replaced.
- After: The user's rewritten Step 2 requires a document object with a version
  key, runs and results lists, result and properties objects, and a non-empty
  string `properties.finding_id` before appending. The user's existing plan
  edit is preserved verbatim. Valid empty runs/results remain supported.
  New CLI tests hash the existing SARIF and check absent/unchanged audit logs
  inside the temporary context, including the explicitly required empty ID.
- Why: This is a user-authored control correction, not an inferred local
  relaxation. Validation must reach every field that `merge_result` uses.
  A new mutation restores the old shallow check and proves the deep cases fail
  on actual artifact side effects; restoration, 76 focused tests, and one final
  203-test full suite pass. The change uses a separate follow-up commit named
  `fix: validate existing SARIF before recording`.

## Task 23 files, evidence, verification, and staging

- Before: Task 23 listed five findings only, without its exact file surface,
  causal RED/GREEN procedure, focused and full verification, mode/diff review,
  staging command, or one-commit contract.
- After: The controller-authorized task text names the three production files,
  four corresponding test modules, corrected plan, and this plan-fixes file;
  requires behavior-level RED/GREEN evidence (including direct script
  execution and a same-length schema mutation), focused tests, one final
  `make test`, diff/mode verification, exact staging, and one commit named
  `fix: resolve minor review findings`.
- Why: This is an unambiguous local completeness correction. It preserves all
  established validation, scope, identity, queue, egress, audit, and metrics
  semantics while making the five final-review corrections auditable.
