# Task 5 report

## Status

Implemented the consistency and promotion-matrix tests and added the two required intentional rationale failures. No production code was changed.

## Changes

- Created `tests/test_record_verdict.py` with the exact `make_verdict` and `make_challenge` factories and consistency/promotion tests from the Task 5 brief.
- Added `test_unchallenged_low_says_so_plainly` and `test_unchallenged_info_dismissal_says_so_plainly` as intentional red tests.
- Recorded both red cases in `docs/superpowers/evidence/2026-09-01-red-tests.md`, preserving Task 3 evidence and marking both green commits pending Task 7.
- Corrected Task 5's incomplete plan `Files` list to include the two required evidence files and recorded the correction in `docs/superpowers/evidence/2026-09-01-plan-fixes.md`.

## Verification

Command:

```text
make test
```

Result: expected non-zero exit; exactly four failures, with no errors:

```text
FAIL: test_mixed_case_extension_is_refused (tests.test_check_scope.TestMatches.test_mixed_case_extension_is_refused)
AssertionError: ScopeViolation not raised
FAIL: test_uppercase_dotfile_is_refused (tests.test_check_scope.TestMatches.test_uppercase_dotfile_is_refused)
AssertionError: ScopeViolation not raised
FAIL: test_unchallenged_info_dismissal_says_so_plainly (tests.test_record_verdict.TestDecideState.test_unchallenged_info_dismissal_says_so_plainly)
AssertionError: Tuples differ: ('dismissed', 'false positive upheld') != ('dismissed', 'false positive; severity=info does not require adversarial validation under policy')
FAIL: test_unchallenged_low_says_so_plainly (tests.test_record_verdict.TestDecideState.test_unchallenged_low_says_so_plainly)
AssertionError: Tuples differ: ('confirmed', 'true positive upheld under adversarial validation') != ('confirmed', 'true positive; severity=low does not require adversarial validation under policy')
Ran 45 tests in 0.024s
FAILED (failures=4)
make: *** [test] Error 1
```

Exact failure name set:

1. `test_mixed_case_extension_is_refused`
2. `test_uppercase_dotfile_is_refused`
3. `test_unchallenged_low_says_so_plainly`
4. `test_unchallenged_info_dismissal_says_so_plainly`

Additional check: `git diff --check` passed.

## Files changed

- `tests/test_record_verdict.py`
- `docs/superpowers/evidence/2026-09-01-red-tests.md`
- `docs/superpowers/evidence/2026-09-01-plan-fixes.md`
- `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- `.superpowers/sdd/2026-09-01-appsec-review-hardening/task-5-report.md`

## Self-review

- Test module follows the brief verbatim for required literals, test names, factories, and expected tuples.
- The two new tests fail only on rationale text, exposing the stale adversarial-validation claims; their states remain `confirmed` and `dismissed` respectively.
- Existing Task 3 failures remain unchanged, and the total is exactly four.
- No expected-failure annotations or production changes were added.
- No dependencies or network access were used.
- The plan correction is limited to the omitted evidence files and does not alter task intent or scope.

## Concerns

The two rationale tests intentionally remain red until Task 7 updates `record_verdict.decide_state`. The Task 3 matcher failures likewise remain pending their planned implementation task.

## RED evidence

The full evidence entries, including commands, assertion/failure lines, and pending green-commit markers, are in `docs/superpowers/evidence/2026-09-01-red-tests.md`.
