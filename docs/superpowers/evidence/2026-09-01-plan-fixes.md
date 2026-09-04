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
