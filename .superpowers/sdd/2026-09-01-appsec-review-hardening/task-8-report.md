# Task 8 report

## Status

DONE. Existing SARIF is parsed before the append-only triage-log write, so a
malformed SARIF refusal leaves no new log row.

## Changes prepared

- Added the six required SARIF accumulation tests and their `json` and
  `temp_tree` imports.
- Split `to_sarif` into `build_result` and `sarif_document`.
- Added `load_existing_results` and deterministic `merge_result` helpers.
- Added `--fresh` and connected the CLI to parse reviewed SARIF before
  `append_log`, then merge and write the result without rereading it.
- Backfilled both Task 5 green markers with
  `e5a2dd2de21dc8a93bf337d3f0524a724a70b8e0`.
- Corrected two local source-plan defects: Task 8's missing evidence files and
  its overly specific RED failure expectation. Recorded both in the plan-fixes
  evidence file.

## RED/GREEN evidence

RED command:

```text
python3 -m unittest tests.test_record_verdict.TestSarifAccumulation -v
```

Output: six errors, all expected `AttributeError`s for the missing helper API.
Alphabetical unittest ordering exercised `load_existing_results`,
`merge_result`, and `sarif_document` before a path that calls `build_result`.
The source-plan RED expectation was corrected to match this deterministic
runner behavior.

Focused GREEN command:

```text
python3 -m unittest tests.test_record_verdict.TestSarifAccumulation -v
```

Output: 6 tests ran, `OK`.

Full command:

```text
make test
```

Output: 62 tests ran with exactly these two failures, both the remaining
intentional Task 3 matcher failures:

- `tests.test_check_scope.TestMatches.test_mixed_case_extension_is_refused`
- `tests.test_check_scope.TestMatches.test_uppercase_dotfile_is_refused`

Additional command:

```text
git diff --check
```

Output: exit 0 with no whitespace errors.

## Final failure set

Only `test_mixed_case_extension_is_refused` and
`test_uppercase_dotfile_is_refused` remain red. No Task 3 pending marker was
altered.

## Files prepared

- `scripts/record_verdict.py`
- `tests/test_record_verdict.py`
- `docs/superpowers/evidence/2026-09-01-red-tests.md`
- `docs/superpowers/evidence/2026-09-01-plan-fixes.md`
- `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- `.superpowers/sdd/2026-09-01-appsec-review-hardening/task-8-report.md`

## Self-review

The pure helper behavior is covered: absent reviewed SARIF loads as empty,
malformed reviewed SARIF raises `ValidationError`, merges replace by
`finding_id`, and output is sorted deterministically. `sarif_document` retains
the existing SARIF tool metadata and accepts multiple results. No dependencies,
network calls, or spec edits were introduced. The requested independent review
was not dispatched because the task expressly forbids reviewers.

## Control ordering

The user corrected Task 8 Step 5 after the earlier control finding. The
existing-SARIF parse now occurs immediately before `append_log`, and the merge
uses that already-loaded result afterward. This prevents the refusal path from
creating an irreversible log row. The planned Task 12 CLI regression test for
malformed SARIF/no log write remains deferred, alongside the `--fresh` CLI
test, because `--log` does not exist until Task 12.

## Concerns

None. The only remaining failures are the two documented Task 3 matcher tests.
