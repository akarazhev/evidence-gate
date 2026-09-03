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
