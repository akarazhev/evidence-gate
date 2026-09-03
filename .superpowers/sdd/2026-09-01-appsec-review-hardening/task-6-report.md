# Task 6 report

## Changes

- Added `tests.helpers.write_log(path, rows)`, deriving CSV columns from `record_verdict.LOG_FIELDS`.
- Added `tests/test_metrics.py` covering empty and missing logs, state counts, rate denominators, disagreement, model independence, timings, date filtering, and render warning paths.

## Verification

Focused command:

```text
python3 -m unittest tests.test_metrics -v
```

Output: 11 tests ran, `OK`.

Full command:

```text
make test
```

Output: 56 tests ran, exactly 4 failures (the documented intentional red tests):

- `tests.test_check_scope.TestMatches.test_mixed_case_extension_is_refused`
- `tests.test_check_scope.TestMatches.test_uppercase_dotfile_is_refused`
- `tests.test_record_verdict.TestDecideState.test_unchallenged_info_dismissal_says_so_plainly`
- `tests.test_record_verdict.TestDecideState.test_unchallenged_low_says_so_plainly`

`git diff --check` passed. No intentional red test was modified or fixed.

## Files changed

- `tests/helpers.py`
- `tests/test_metrics.py`
- `.superpowers/sdd/2026-09-01-appsec-review-hardening/task-6-report.md`

## Self-review

The helper reads the current production field list and fills missing values with empty strings, so later log columns remain compatible. Tests use temporary logs and exercise the public metrics interfaces. No dependencies, network access, spec edits, or unrelated production changes were made.

## Concerns

None. The required hard-gate state is exact.
