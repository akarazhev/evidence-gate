# appsec-review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Закрыть разрыв между тем, что документация репозитория утверждает, и тем, что код обеспечивает, и довести проект до состояния, пригодного для пилота на реальном репозитории.

**Architecture:** Семь слоёв, строго по порядку. Слой 0 создаёт тестовую инфраструктуру и фиксирует текущее поведение — часть его тестов намеренно красные, они ведут правки слоя 1. Слои 1–3 чинят корректность, независимость и egress. Слои 4–5 добавляют очередь триажа и запись решения человека. Слой 6 приводит документацию в соответствие с уже работающим кодом.

**Tech Stack:** Python 3.9+, только стандартная библиотека. `unittest` для тестов. `jsonschema` остаётся опциональной зависимостью. POSIX sh для `scan.sh`. GNU make.

**Spec:** `docs/superpowers/specs/2026-09-01-appsec-review-hardening-design.md`

## Global Constraints

- **Язык артефактов:** весь код, комментарии, docstring-и, сообщения об ошибках, README и содержимое `docs/` — на английском. Настоящий план и спека — на русском.
- **Никаких новых зависимостей.** `make test` обязан работать на голом Python 3.9+ без единого `pip install`. `jsonschema` остаётся опциональной.
- **Никакой сети в тестах.** Ни один тест не обращается к сети и не требует установленного `semgrep`.
- **Python 3.9 floor.** `from __future__ import annotations` уже стоит во всех скриптах — сохранять при правках; синтаксис `X | None` в аннотациях допустим только благодаря ему.
- **Аудит-трейл append-only.** `findings/triage-log.csv` никогда не переписывается и не редактируется задним числом. Актуальное состояние отражает `findings/reviewed.sarif`.
- **Контроль — это отказ, а не предупреждение.** Любая проверка, названная контролем, завершается ненулевым кодом возврата и не пишет частичный результат.
- **Стиль коммитов:** `<type>: <imperative summary>` на английском, типы `test`, `fix`, `feat`, `docs`, `refactor`.

---

## File Structure

**Создаются:**

| Путь | Ответственность |
|---|---|
| `tests/__init__.py` | Делает `tests` пакетом и кладёт `scripts/` в `sys.path` |
| `tests/helpers.py` | Общие помощники: фикстуры, временные деревья файлов |
| `tests/fixtures/policy-basic.yml` | Политика исключений для тестов, независимая от боевой |
| `tests/fixtures/sample.sarif` | SARIF с несколькими находками, включая `codeFlows` |
| `tests/test_check_scope.py` | Парсинг политики и матчинг путей |
| `tests/test_build_packet.py` | Идентичность находок, порядок scope-check, фильтры очереди |
| `tests/test_record_verdict.py` | Консистентность, продвижение, SARIF, валидатор |
| `tests/test_metrics.py` | Агрегация лога |
| `tests/test_scan_sh.py` | Путь отказа `scan.sh` без semgrep |
| `tests/test_human_decision.py` | Запись решения человека |
| `scripts/record_human_decision.py` | Запись решения человека, ground truth программы |
| `rules/README.md` | Как заполнить локальный набор правил |
| `templates/threat-model.md` | Шаблон, на который уже ссылаются README и `docs/04` |

**Модифицируются:**

| Путь | Что меняется |
|---|---|
| `scripts/check_scope.py` | Регистронезависимый матчинг (§1.4) |
| `scripts/build_packet.py` | Параметр `exclusions`, стабильный `finding_id`, фильтры `--list`, адресация по id |
| `scripts/record_verdict.py` | Честный rationale, накопление SARIF, валидатор, независимость, миграция лога, `--supersede` |
| `scripts/metrics.py` | Схлопывание по `finding_id`, переименование величины, блок точности |
| `scripts/scan.sh` | Офлайн по умолчанию, `--metrics=off` |
| `policy/excluded-paths.yml` | Паттерн `**/.envrc` |
| `templates/verdict.schema.json`, `templates/challenge.schema.json` | Описания полей `agent` |
| `Makefile` | Цели `test`, `check-template`, переменные `AGENT`, `VALIDATOR`, `ID`, фильтры |
| `README.md`, `docs/03-data-handling.md`, `docs/04-procedures.md`, `docs/07-graduation.md`, `CLAUDE.md` | Слой 6 |

---

# Слой 0 — тестовая инфраструктура

Слой 0 покрывает только существующий код. Тесты на новую функциональность слоёв 4 и 5 пишутся внутри этих слоёв.

Часть тестов здесь **намеренно красная**: они написаны против желаемого поведения и станут зелёными в слое 1. Не использовать `unittest.expectedFailure` — после правки такой тест даёт unexpected success и требует переделки. Сохраняйте вывод упавшего прогона: он является доказательством, что дефект реален.

### Task 1: Тестовая инфраструктура

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/helpers.py`
- Create: `tests/fixtures/policy-basic.yml`
- Create: `tests/test_harness.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: ничего.
- Produces: `tests.helpers.REPO_ROOT: Path`, `tests.helpers.FIXTURES: Path`, `tests.helpers.fixture_exclusions(name: str) -> list[dict]`, `tests.helpers.temp_tree(files: dict[str, str]) -> ContextManager[Path]`. Все последующие задачи импортируют отсюда.

- [ ] **Step 1: Создать пакет тестов с bootstrap путей**

`scripts/` не является пакетом, а `build_packet.py` импортирует `check_scope` как модуль верхнего уровня. Тесты обязаны воспроизвести это, иначе импорты разойдутся.

`tests/__init__.py`:

```python
"""Test package for appsec-review.

`scripts/` is a directory of standalone tools, not an importable package:
`build_packet.py` reaches `check_scope` by putting its own directory on
sys.path. Tests must reproduce that layout or the imports diverge from what
the tools actually do at runtime.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = str(REPO_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
```

- [ ] **Step 2: Написать помощники**

`tests/helpers.py`:

```python
"""Shared test helpers.

Fixtures live under tests/fixtures/ rather than reusing policy/ from the
repository root. A test suite that reads the live policy file breaks every
time the policy is edited, and a suite that breaks on unrelated edits stops
being run.
"""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path

from tests import REPO_ROOT

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture_exclusions(name: str = "policy-basic.yml") -> list[dict]:
    """Load the exclusion rules from a fixture policy file."""
    import check_scope

    exclusions, _ = check_scope.load_policy(FIXTURES / name)
    return exclusions


def fixture_scan_noise(name: str = "policy-basic.yml") -> list[str]:
    import check_scope

    _, scan_noise = check_scope.load_policy(FIXTURES / name)
    return scan_noise


@contextlib.contextmanager
def temp_tree(files: dict[str, str]):
    """Materialise a throwaway file tree and yield its root.

    Keys are repository-relative paths, values are file contents. Parent
    directories are created automatically.

    The tree is deleted when the block exits. Assert the ABSENCE of a file
    inside the block, never after it: `assertFalse(p.exists())` on the outside
    passes whether or not the code under test wrote the file, which turns a
    no-partial-write control into a test that cannot fail. Capturing a value
    inside and asserting on it outside is fine.
    """
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        yield root


__all__ = ["REPO_ROOT", "FIXTURES", "fixture_exclusions", "fixture_scan_noise", "temp_tree"]
```

- [ ] **Step 3: Создать фикстуру политики**

Фикстура намеренно упражняет комментарии, значения в кавычках, паттерн-директорию с завершающим слэшем и обе секции.

`tests/fixtures/policy-basic.yml`:

```yaml
# Fixture policy. Deliberately small and independent of policy/excluded-paths.yml
# so that editing the real policy cannot break the test suite.
exclusions:
  - pattern: "**/.env"
    owner: appsec
    reason: Runtime secrets
  - pattern: "**/*.pem"
    owner: appsec
    reason: Certificate or key material
  - pattern: "secrets/"          # trailing slash means the whole directory
    owner: appsec
    reason: Secret material

scan_noise:
  - "node_modules/"
  - "dist/"
```

- [ ] **Step 4: Написать проверку самой инфраструктуры**

`tests/test_harness.py`:

```python
"""Proves the harness itself works before anything depends on it."""

import unittest
from pathlib import Path

from tests.helpers import FIXTURES, fixture_exclusions, temp_tree


class TestHarness(unittest.TestCase):
    def test_scripts_are_importable(self):
        import check_scope

        self.assertTrue(hasattr(check_scope, "check_path"))

    def test_fixture_policy_is_present(self):
        self.assertTrue((FIXTURES / "policy-basic.yml").exists())

    def test_fixture_exclusions_load(self):
        self.assertEqual(len(fixture_exclusions()), 3)

    def test_temp_tree_materialises_files(self):
        with temp_tree({"a/b.py": "print(1)\n"}) as root:
            self.assertEqual((root / "a" / "b.py").read_text(), "print(1)\n")
        self.assertFalse(Path(root).exists())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 5: Добавить цель `make test`**

В `Makefile` дописать `test` в список `.PHONY` и добавить цель. `-t .` задаёт корень репозитория как top-level directory, иначе `tests` не импортируется как пакет.

```make
test:
	@python3 -m unittest discover -s tests -t . -v
```

Также добавить строку в блок `help`:

```make
	@echo "  make test                 run the test suite (stdlib only)"
```

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: 4 теста, все PASS.

- [ ] **Step 7: Коммит**

```bash
git add tests Makefile
git commit -m "test: add stdlib test harness and policy fixture"
```

---

### Task 2: Тесты парсера политики

**Files:**
- Create: `tests/test_check_scope.py`

**Interfaces:**
- Consumes: `tests.helpers.FIXTURES`, `check_scope.load_policy`, `check_scope._parse_policy`.
- Produces: класс `TestParsePolicy`; следующая задача дописывает в этот же файл класс `TestMatches`.

- [ ] **Step 1: Написать тесты**

`_parse_policy` написан вручную специально, чтобы отсутствие PyYAML не отключало контроль молча. Значит он и есть предмет проверки.

`tests/test_check_scope.py`:

```python
"""Tests for the scope control.

check_scope is the only component in this repository whose refusal is a
security control rather than a convenience, so it is tested first and hardest.
"""

import unittest

import check_scope
from tests.helpers import FIXTURES


class TestParsePolicy(unittest.TestCase):
    def setUp(self):
        self.exclusions, self.scan_noise = check_scope.load_policy(
            FIXTURES / "policy-basic.yml"
        )

    def test_reads_every_exclusion(self):
        patterns = [rule["pattern"] for rule in self.exclusions]
        self.assertEqual(patterns, ["**/.env", "**/*.pem", "secrets/"])

    def test_keeps_owner_and_reason(self):
        first = self.exclusions[0]
        self.assertEqual(first["owner"], "appsec")
        self.assertEqual(first["reason"], "Runtime secrets")

    def test_strips_trailing_comment(self):
        third = self.exclusions[2]
        self.assertEqual(third["pattern"], "secrets/")

    def test_reads_scan_noise_as_bare_strings(self):
        self.assertEqual(self.scan_noise, ["node_modules/", "dist/"])

    def test_missing_policy_refuses_rather_than_defaulting(self):
        with self.assertRaises(FileNotFoundError):
            check_scope.load_policy(FIXTURES / "does-not-exist.yml")

    def test_rules_without_a_pattern_are_dropped(self):
        exclusions, _ = check_scope._parse_policy(
            "exclusions:\n"
            "  - owner: appsec\n"
            "    reason: no pattern key\n"
            '  - pattern: "**/id_rsa"\n'
            "    owner: appsec\n"
        )
        self.assertEqual([r["pattern"] for r in exclusions], ["**/id_rsa"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать**

Run: `make test`
Expected: все PASS. Если `test_strips_trailing_comment` падает — парсер не срезает комментарии, и это находка; зафиксируйте вывод и остановитесь.

- [ ] **Step 3: Коммит**

```bash
git add tests/test_check_scope.py
git commit -m "test: cover the hand-rolled policy parser"
```

---

### Task 3: Тесты матчинга путей, включая красные

**Files:**
- Modify: `tests/test_check_scope.py`
- Create: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Create: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `check_scope._matches`, `check_scope.check_path`, `check_scope.ScopeViolation`.
- Produces: класс `TestMatches`. Два его теста красные до Task 10.

- [ ] **Step 1: Дописать класс матчинга**

Добавить в `tests/test_check_scope.py` перед блоком `if __name__`:

```python
class TestMatches(unittest.TestCase):
    def setUp(self):
        self.exclusions = check_scope.load_policy(FIXTURES / "policy-basic.yml")[0]

    def assertRefused(self, path):
        with self.assertRaises(check_scope.ScopeViolation):
            check_scope.check_path(path, self.exclusions)

    def assertAllowed(self, path):
        check_scope.check_path(path, self.exclusions)

    def test_dotfile_at_root(self):
        self.assertRefused(".env")

    def test_dotfile_nested(self):
        self.assertRefused("services/api/.env")

    def test_dot_slash_prefix_is_stripped_not_lstripped(self):
        # lstrip("./") would eat the leading dot and turn ".env" into "env",
        # defeating every dotfile exclusion in the policy.
        self.assertRefused("./.env")

    def test_extension_glob_at_root_and_at_depth(self):
        self.assertRefused("server.pem")
        self.assertRefused("certs/intermediate/server.pem")

    def test_directory_pattern_covers_contents(self):
        self.assertRefused("secrets/token.txt")
        self.assertRefused("app/secrets/token.txt")

    def test_windows_separators_are_normalised(self):
        self.assertRefused("services\\api\\.env")

    def test_similar_names_are_not_refused(self):
        self.assertAllowed("src/environment.py")
        self.assertAllowed("docs/env-setup.md")
        self.assertAllowed("src/secretsmanager.py")

    # --- Red until Task 10 -------------------------------------------------
    # macOS APFS and Windows NTFS are case-insensitive by default, so `.ENV`
    # and `.env` name the same file with the same contents. fnmatch.fnmatch
    # delegates to os.path.normcase, which is the identity on POSIX, so the
    # glob is case-sensitive there and the second spelling walks straight past
    # the exclusion.

    def test_uppercase_dotfile_is_refused(self):
        self.assertRefused(".ENV")

    def test_mixed_case_extension_is_refused(self):
        self.assertRefused("certs/Server.PEM")
```

- [ ] **Step 2: Прогнать и зафиксировать красные**

Run: `make test`
Expected: FAIL ровно в двух тестах — `test_uppercase_dotfile_is_refused` и `test_mixed_case_extension_is_refused`, оба с `ScopeViolation not raised`. Сохраните вывод: он является доказательством дефекта §1.4.

Если падает что-то ещё — остановитесь и сообщите: спека построена на неверном чтении кода.

- [ ] **Step 3: Коммит**

```bash
git add tests/test_check_scope.py
git commit -m "test: cover path matching; two cases red pending case-folding fix"
```

---

### Task 4: Параметр `exclusions` и проверка порядка scope-check

**Files:**
- Modify: `scripts/build_packet.py:116-130`
- Create: `tests/test_build_packet.py`
- Create: `tests/fixtures/sample.sarif`

**Interfaces:**
- Consumes: `tests.helpers.temp_tree`, `tests.helpers.FIXTURES`.
- Produces: `build_packet.build_triage_packet(result, repo, window, exclusions=None)` — новый четвёртый параметр. Задачи 11, 15 и 16 опираются на него.

- [ ] **Step 1: Добавить параметр**

Сейчас `build_triage_packet` зовёт `load_policy()` без аргументов и жёстко привязан к боевой политике. В `scripts/build_packet.py` заменить сигнатуру и начало тела:

```python
def build_triage_packet(
    result: dict, repo: Path, window: int, exclusions: list[dict] | None = None
) -> dict:
    fid = finding_id(result["rule_id"], result["file"], result["start_line"])

    # Scope check before any file content is read. This ordering is the point.
    if exclusions is None:
        exclusions, _ = load_policy()
```

Остальное тело не трогать.

- [ ] **Step 2: Создать фикстуру SARIF**

`tests/fixtures/sample.sarif`:

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "rules": [
            {
              "id": "python.lang.security.audit.exec-detected",
              "shortDescription": { "text": "exec detected" },
              "fullDescription": { "text": "Detected the use of exec" }
            },
            {
              "id": "python.django.security.injection.sql",
              "shortDescription": { "text": "SQL injection" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.audit.exec-detected",
          "level": "error",
          "message": { "text": "Detected the use of exec" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/handler.py" },
                "region": { "startLine": 5, "endLine": 5 }
              }
            }
          ]
        },
        {
          "ruleId": "python.django.security.injection.sql",
          "level": "warning",
          "message": { "text": "SQL injection" },
          "partialFingerprints": { "semgrep.fingerprint": "abc123def456" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/db.py" },
                "region": { "startLine": 2, "endLine": 2 }
              }
            }
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "app/routes.py" },
                          "region": { "startLine": 3 }
                        },
                        "message": { "text": "source: request parameter" }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        },
        {
          "ruleId": "generic.secrets.private-key-detected",
          "level": "note",
          "message": { "text": "Private key material" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "config/server.pem" },
                "region": { "startLine": 1, "endLine": 1 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 3: Написать тесты**

`tests/test_build_packet.py`:

```python
"""Tests for packet construction.

The ordering test is the important one: docs/03-data-handling.md claims the
scope check runs before any file content is read, and that claim is what makes
the data-handling story true.
"""

import unittest
from pathlib import Path

import build_packet
import check_scope
from tests.helpers import FIXTURES, fixture_exclusions, temp_tree

SARIF = FIXTURES / "sample.sarif"


class TestLoadSarif(unittest.TestCase):
    def setUp(self):
        self.results = build_packet.load_sarif_results(SARIF)

    def test_reads_every_result(self):
        self.assertEqual(len(self.results), 3)

    def test_prefers_full_description_over_message(self):
        self.assertEqual(self.results[0]["rule_description"], "Detected the use of exec")

    def test_falls_back_to_short_description(self):
        self.assertEqual(self.results[1]["rule_description"], "SQL injection")

    def test_extracts_code_flows(self):
        steps = self.results[1]["code_flows"][0]["steps"]
        self.assertEqual(steps[0]["file"], "app/routes.py")
        self.assertEqual(steps[0]["line"], 3)

    def test_result_without_flows_has_empty_list(self):
        self.assertEqual(self.results[0]["code_flows"], [])


class TestScopeCheckOrdering(unittest.TestCase):
    """The scope check must refuse before the file is opened."""

    def test_excluded_path_refuses_even_when_file_is_absent(self):
        results = build_packet.load_sarif_results(SARIF)
        excluded = results[2]
        # Excluded by **/*.pem under BOTH the fixture policy and the live one.
        # The manual check in Task 11 Step 8 runs against the live policy, so a
        # fixture path excluded only by the fixture would look in-scope there.
        self.assertEqual(excluded["file"], "config/server.pem")

        # Empty tree: the file does not exist. If the builder read first and
        # checked second, this would raise FileNotFoundError instead.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.build_triage_packet(
                    excluded, repo, 40, fixture_exclusions()
                )


class TestReadContext(unittest.TestCase):
    def setUp(self):
        self.text = "\n".join(f"line{i}" for i in range(1, 11)) + "\n"

    def test_window_clamps_at_start_of_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 1, 1, 3)
        self.assertTrue(out.splitlines()[0].endswith("| line1"))
        self.assertEqual(len(out.splitlines()), 4)

    def test_window_clamps_at_end_of_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 10, 10, 3)
        self.assertTrue(out.splitlines()[-1].endswith("| line10"))

    def test_window_wider_than_file_returns_whole_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 5, 5, 500)
        self.assertEqual(len(out.splitlines()), 10)

    def test_missing_file_returns_none(self):
        self.assertIsNone(build_packet.read_context(Path("/nope/absent.py"), 1, 1, 3))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Прогнать**

Run: `make test`
Expected: всё PASS, кроме двух известных красных из Task 3.

- [ ] **Step 5: Коммит**

```bash
git add scripts/build_packet.py tests/test_build_packet.py tests/fixtures/sample.sarif
git commit -m "test: prove scope check precedes file reads; inject exclusions for testability"
```

---

### Task 5: Тесты консистентности и продвижения, включая красные

**Files:**
- Create: `tests/test_record_verdict.py`
- Update: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Update: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict.check_consistency`, `record_verdict.decide_state`.
- Produces: `tests.test_record_verdict.make_verdict(**overrides) -> dict` — фабрика валидного вердикта, используется задачами 8, 9, 12, 13, 17.

- [ ] **Step 1: Написать тесты**

`tests/test_record_verdict.py`:

```python
"""Tests for verdict validation and promotion.

decide_state decides what enters the audit trail, and the rationale it returns
is written verbatim into SARIF. A rationale that overstates what was verified
is a defect of the same kind this whole workflow exists to catch.
"""

import unittest

import record_verdict


def make_verdict(**overrides) -> dict:
    """A minimal verdict that passes schema and consistency checks."""
    verdict = {
        "finding_id": "F-000000000001",
        "rule_id": "python.lang.security.audit.exec-detected",
        "verdict": "true_positive",
        "confidence": "medium",
        "evidence_level": "partial",
        "severity": "medium",
        "reasoning": "Read the sink and its immediate callers; path not fully resolved.",
        "reviewer": {"agent": "model-a", "reviewed_at": "2026-09-01T10:00:00+00:00"},
        "location": {"file": "app/handler.py", "start_line": 4, "end_line": 4},
    }
    verdict.update(overrides)
    return verdict


def make_challenge(result: str = "upheld", **overrides) -> dict:
    challenge = {
        "finding_id": "F-000000000001",
        "challenge_result": result,
        "refutation_attempts": [
            {"claim": "input is attacker controlled", "result": "held"}
        ],
        "reasoning": "Re-derived the flow independently; the claim survived.",
        "validator": {"agent": "model-b", "validated_at": "2026-09-01T12:00:00+00:00"},
    }
    challenge.update(overrides)
    return challenge


class TestCheckConsistency(unittest.TestCase):
    def test_clean_verdict_has_no_problems(self):
        self.assertEqual(record_verdict.check_consistency(make_verdict()), [])

    def test_high_confidence_requires_traced(self):
        problems = record_verdict.check_consistency(
            make_verdict(confidence="high", evidence_level="partial")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("evidence_level=traced", problems[0])

    def test_pattern_cannot_be_true_positive(self):
        problems = record_verdict.check_consistency(
            make_verdict(evidence_level="pattern", verdict="true_positive")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("pattern", problems[0])

    def test_traced_requires_data_flow(self):
        problems = record_verdict.check_consistency(
            make_verdict(evidence_level="traced")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("data_flow", problems[0])

    def test_traced_with_data_flow_is_clean(self):
        problems = record_verdict.check_consistency(
            make_verdict(
                evidence_level="traced",
                data_flow=[{"file": "app/handler.py", "description": "sink"}],
            )
        )
        self.assertEqual(problems, [])

    def test_memory_safety_cwe_requires_runtime_proof(self):
        problems = record_verdict.check_consistency(make_verdict(cwe=["CWE-416"]))
        self.assertEqual(len(problems), 1)
        self.assertIn("CWE-416", problems[0])

    def test_blocked_by_scope_forces_needs_human(self):
        problems = record_verdict.check_consistency(
            make_verdict(blocked_by_scope=["policy/secrets/"], verdict="true_positive")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("needs_human", problems[0])


class TestDecideState(unittest.TestCase):
    def test_medium_without_challenge_is_blocked(self):
        state, _ = record_verdict.decide_state(make_verdict(severity="medium"), None)
        self.assertEqual(state, "blocked_needs_challenge")

    def test_refuted_challenge_goes_to_human(self):
        state, rationale = record_verdict.decide_state(
            make_verdict(), make_challenge("refuted")
        )
        self.assertEqual(state, "human_review")
        self.assertIn("refuted", rationale)

    def test_inconclusive_challenge_goes_to_human(self):
        state, _ = record_verdict.decide_state(
            make_verdict(), make_challenge("inconclusive")
        )
        self.assertEqual(state, "human_review")

    def test_runtime_proof_parks_the_finding(self):
        state, _ = record_verdict.decide_state(
            make_verdict(requires_runtime_proof=True), make_challenge()
        )
        self.assertEqual(state, "awaiting_proof")

    def test_pattern_evidence_never_confirms(self):
        state, _ = record_verdict.decide_state(
            make_verdict(verdict="false_positive", evidence_level="pattern"),
            make_challenge(),
        )
        self.assertEqual(state, "dismissed")

    def test_needs_human_verdict_goes_to_human(self):
        state, _ = record_verdict.decide_state(
            make_verdict(verdict="needs_human"), make_challenge()
        )
        self.assertEqual(state, "human_review")

    def test_challenged_true_positive_is_confirmed(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(evidence_level="partial"), make_challenge("upheld")
            ),
            ("confirmed", "true positive upheld under adversarial validation"),
        )

    # --- Red until Task 7 --------------------------------------------------
    # Policy exempts low and info from adversarial validation, so reaching
    # `confirmed` without a challenge is correct. Claiming the finding was
    # "upheld under adversarial validation" when no second pass ran is not:
    # that sentence is written verbatim into reviewed.sarif and the triage log.

    def test_unchallenged_low_says_so_plainly(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(severity="low", evidence_level="partial"), None
            ),
            (
                "confirmed",
                "true positive; severity=low does not require adversarial "
                "validation under policy",
            ),
        )

    def test_unchallenged_info_dismissal_says_so_plainly(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(
                    severity="info", verdict="false_positive", evidence_level="partial"
                ),
                None,
            ),
            (
                "dismissed",
                "false positive; severity=info does not require adversarial "
                "validation under policy",
            ),
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать и зафиксировать красные**

Run: `make test`
Expected: FAIL ровно в `test_unchallenged_low_says_so_plainly` и `test_unchallenged_info_dismissal_says_so_plainly`. Первый покажет фактическое `'true positive upheld under adversarial validation'` — это и есть ложное утверждение §1.1. Сохраните вывод.

Всего красных на этот момент: 4 (два из Task 3, два отсюда).

- [ ] **Step 3: Коммит**

```bash
git add tests/test_record_verdict.py
git commit -m "test: cover consistency rules and promotion matrix; two cases red"
```

---

### Task 6: Тесты метрик

**Files:**
- Create: `tests/test_metrics.py`
- Modify: `tests/helpers.py`

**Interfaces:**
- Consumes: `metrics.load_rows`, `metrics.compute`, `metrics.render`.
- Produces: `tests.helpers.write_log(path: Path, rows: list[dict]) -> None` — пишет CSV по актуальному `record_verdict.LOG_FIELDS`. Задачи 13 и 19 расширяют список колонок; помощник переживает это без правок.

- [ ] **Step 1: Добавить помощник записи лога**

Помощник читает `LOG_FIELDS` из модуля, а не дублирует список. Колонки будут добавляться в задачах 13 и 19, и захардкоженный заголовок сломал бы тесты на ровном месте.

Дописать в `tests/helpers.py` перед `__all__`:

```python
def write_log(path, rows: list[dict]) -> None:
    """Write a triage log using whatever columns record_verdict declares today.

    Reading LOG_FIELDS from the module rather than hardcoding it here means
    later tasks can add columns without breaking every metrics test.
    """
    import csv

    import record_verdict

    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=record_verdict.LOG_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in record_verdict.LOG_FIELDS})
```

И добавить `"write_log"` в `__all__`.

- [ ] **Step 2: Написать тесты**

`tests/test_metrics.py`:

```python
"""Tests for programme metrics.

Metric 4 (disagreement rate) is the one that tells you whether the second pass
is doing any work, so its edge cases matter more than the headline numbers.
"""

import unittest

import metrics
from tests.helpers import temp_tree, write_log


def row(**overrides) -> dict:
    base = {
        "reviewed_at": "2026-09-01T10:00:00+00:00",
        "finding_id": "F-000000000001",
        "severity": "medium",
        "evidence_level": "traced",
        "confidence": "high",
        "initial_verdict": "true_positive",
        "challenge_result": "upheld",
        "final_state": "confirmed",
        "minutes_spent": "10",
        "requires_runtime_proof": "False",
        "agent": "model-a",
        "validator": "model-b",
    }
    base.update(overrides)
    return base


class TestCompute(unittest.TestCase):
    def compute(self, rows):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(log, rows)
            return metrics.compute(metrics.load_rows(log, None))

    def test_empty_log(self):
        self.assertEqual(metrics.compute([]), {"total": 0})

    def test_missing_log_is_not_an_error(self):
        self.assertEqual(metrics.load_rows(metrics.LOG_PATH.parent / "absent.csv", None), [])

    def test_counts_states(self):
        m = self.compute([row(), row(finding_id="F-2", final_state="dismissed")])
        self.assertEqual(m["total"], 2)
        self.assertEqual(m["decided"], 2)
        self.assertEqual(m["undecided"], 0)

    def test_rate_excludes_undecided_findings(self):
        # Parked findings are not evidence of precision, so they must stay out
        # of the denominator.
        m = self.compute(
            [
                row(),
                row(finding_id="F-2", final_state="dismissed"),
                row(finding_id="F-3", final_state="human_review", challenge_result=""),
            ]
        )
        self.assertEqual(m["decided"], 2)
        self.assertEqual(m["undecided"], 1)
        self.assertEqual(m["false_positive_rate_pct"], 50.0)

    def test_disagreement_rate_over_challenged_only(self):
        m = self.compute(
            [
                row(),
                row(finding_id="F-2", challenge_result="refuted", final_state="human_review"),
            ]
        )
        self.assertEqual(m["disagreement_rate_pct"], 50.0)

    def test_same_model_validations_are_counted(self):
        m = self.compute([row(validator="model-a")])
        self.assertEqual(m["same_model_validations"], 1)

    def test_timings(self):
        m = self.compute([row(minutes_spent="10"), row(finding_id="F-2", minutes_spent="20")])
        self.assertEqual(m["median_minutes"], 15.0)
        self.assertEqual(m["timed_findings"], 2)

    def test_unparseable_timing_is_skipped_not_fatal(self):
        m = self.compute([row(minutes_spent=""), row(finding_id="F-2", minutes_spent="8")])
        self.assertEqual(m["timed_findings"], 1)

    def test_since_filter(self):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(
                log,
                [
                    row(reviewed_at="2026-07-01T10:00:00+00:00"),
                    row(finding_id="F-2", reviewed_at="2026-09-01T10:00:00+00:00"),
                ],
            )
            kept = metrics.load_rows(log, "2026-08-01")
        self.assertEqual([r["finding_id"] for r in kept], ["F-2"])


class TestRender(unittest.TestCase):
    def test_empty_render_tells_you_what_to_do(self):
        self.assertIn("No reviews recorded yet", metrics.render({"total": 0}))

    def test_zero_disagreement_raises_the_alarm(self):
        m = metrics.compute(
            [
                dict(row(), final_state="confirmed"),
                dict(row(), finding_id="F-2", final_state="confirmed"),
            ]
        )
        self.assertIn("rubber-stamping", metrics.render(m))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Прогнать**

Run: `make test`
Expected: PASS, кроме четырёх известных красных.

- [ ] **Step 4: Коммит**

```bash
git add tests/test_metrics.py tests/helpers.py
git commit -m "test: cover metric aggregation and its warning paths"
```

**Слой 0 завершён.** Итог: 4 красных теста, каждый соответствует дефекту из спеки. Если красных больше или меньше — остановитесь и сообщите до начала слоя 1.

---

# Слой 1 — корректность контролей

### Task 7: Честный rationale в `decide_state`

**Files:**
- Modify: `scripts/record_verdict.py:152-189`

**Interfaces:**
- Consumes: тесты из Task 5.
- Produces: `record_verdict._unchallenged_note(verdict_label: str, severity: str) -> str`.

- [ ] **Step 1: Подтвердить красноту**

Run: `python3 -m unittest tests.test_record_verdict.TestDecideState -v`
Expected: FAIL в двух тестах `*_says_so_plainly`.

- [ ] **Step 2: Добавить хелпер формулировки**

Вставить в `scripts/record_verdict.py` непосредственно перед `def decide_state`:

```python
def _unchallenged_note(verdict_label: str, severity: str) -> str:
    """Rationale for a finding that policy exempts from adversarial validation.

    Deliberately distinct from the challenged wording. Only critical, high and
    medium require a challenge; reporting a low finding as "upheld under
    adversarial validation" would write a false statement into reviewed.sarif
    and the triage log, where it outlives everyone who remembers the context.
    """
    return (
        f"{verdict_label}; severity={severity} does not require adversarial "
        "validation under policy"
    )
```

- [ ] **Step 3: Развести ветки продвижения**

Заменить обе терминальные ветки в `decide_state`:

```python
    if v == "true_positive":
        if verdict.get("requires_runtime_proof"):
            return (
                "awaiting_proof",
                "static reasoning cannot confirm this class; a runtime harness must reproduce it",
            )
        if verdict.get("evidence_level") == "pattern":
            return ("human_review", "pattern-level evidence is insufficient to confirm")
        if challenge_result == "upheld":
            return ("confirmed", "true positive upheld under adversarial validation")
        return ("confirmed", _unchallenged_note("true positive", severity))

    if v == "false_positive":
        if challenge_result == "upheld":
            return ("dismissed", "false positive upheld")
        if not needs_challenge:
            return ("dismissed", _unchallenged_note("false positive", severity))
        return ("human_review", "dismissal not independently validated")
```

- [ ] **Step 4: Прогнать**

Run: `make test`
Expected: красных осталось 2 (только из Task 3).

- [ ] **Step 5: Коммит**

```bash
git add scripts/record_verdict.py
git commit -m "fix: stop claiming adversarial validation that never ran"
```

---

### Task 8: Накопление SARIF вместо перезаписи

**Files:**
- Modify: `scripts/record_verdict.py:202-269`, `:272-372`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `make_verdict`, `make_challenge` из Task 5.
- Produces: `record_verdict.build_result(verdict, challenge, state, rationale) -> dict`, `record_verdict.sarif_document(results: list[dict]) -> dict`, `record_verdict.load_existing_results(path: Path) -> list[dict]`, `record_verdict.merge_result(existing: list[dict], result: dict) -> list[dict]`. Задача 18 вызывает `load_existing_results` и `sarif_document`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_record_verdict.py` перед блоком `if __name__`:

```python
class TestSarifAccumulation(unittest.TestCase):
    """docs/04 loops record_verdict over many verdicts; each call must keep
    the previous ones. A single-result write silently discards the batch."""

    def result_for(self, fid, state="confirmed"):
        return record_verdict.build_result(
            make_verdict(finding_id=fid), None, state, "rationale text"
        )

    def test_second_finding_does_not_evict_the_first(self):
        merged = record_verdict.merge_result([], self.result_for("F-1"))
        merged = record_verdict.merge_result(merged, self.result_for("F-2"))
        ids = [r["properties"]["finding_id"] for r in merged]
        self.assertEqual(ids, ["F-1", "F-2"])

    def test_rerecording_replaces_rather_than_duplicates(self):
        merged = record_verdict.merge_result([], self.result_for("F-1", "confirmed"))
        merged = record_verdict.merge_result(merged, self.result_for("F-1", "dismissed"))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["properties"]["state"], "dismissed")

    def test_order_is_deterministic(self):
        merged = record_verdict.merge_result([], self.result_for("F-9"))
        merged = record_verdict.merge_result(merged, self.result_for("F-1"))
        ids = [r["properties"]["finding_id"] for r in merged]
        self.assertEqual(ids, sorted(ids))

    def test_absent_file_yields_empty_list(self):
        with temp_tree({}) as root:
            self.assertEqual(
                record_verdict.load_existing_results(root / "reviewed.sarif"), []
            )

    def test_unparseable_file_refuses_rather_than_overwriting(self):
        with temp_tree({"reviewed.sarif": "{ this is not json"}) as root:
            with self.assertRaises(record_verdict.ValidationError):
                record_verdict.load_existing_results(root / "reviewed.sarif")

    # Two CLI-level tests for this task live in Task 12's
    # TestIndependenceControl instead: --fresh, and the refusal on malformed
    # existing SARIF. Both need --log so they do not write into the real
    # findings/ directory, and --log only exists from Task 12 onward.

    def test_round_trip_through_document(self):
        doc = record_verdict.sarif_document([self.result_for("F-1")])
        with temp_tree({}) as root:
            path = root / "reviewed.sarif"
            path.write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(len(record_verdict.load_existing_results(path)), 1)
```

Добавить в шапку файла `import json` и `from tests.helpers import temp_tree`.

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `python3 -m unittest tests.test_record_verdict.TestSarifAccumulation -v`
Expected: FAIL with `AttributeError` for the required new helper API. Test
ordering may expose a missing helper other than `build_result` first.

- [ ] **Step 3: Разделить построение результата и документа**

В `scripts/record_verdict.py` переименовать `to_sarif` в `build_result`, оставив тело до `return {` без изменений, и завершить его возвратом одного результата:

```python
def build_result(verdict: dict, challenge: dict | None, state: str, rationale: str) -> dict:
    """Build one SARIF result for a reviewed finding.

    Dismissed findings carry a SARIF suppression, which is how a findings store
    learns not to re-raise them on the next scan.
    """
```

Тело оставить как есть до формирования `result`, затем:

```python
    if state == "dismissed":
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": f"Dismissed after adversarial validation. {rationale}",
            }
        ]

    return result
```

- [ ] **Step 4: Добавить документ, чтение и слияние**

Дописать следом:

```python
def sarif_document(results: list[dict]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "appsec-review",
                        "informationUri": "https://example.org/appsec-review",
                        "version": "1.0.0",
                    }
                },
                "results": results,
            }
        ],
    }


def load_existing_results(path: Path) -> list[dict]:
    """Read previously recorded results so a new one joins them.

    A file we cannot parse is a refusal, not a licence to overwrite: the
    reviewed SARIF is the audit trail's current-state view, and silently
    discarding it would lose every earlier verdict.
    """
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValidationError(
            f"Cannot read {path}: {exc}. Refusing to overwrite a file that "
            "cannot be parsed. Move it aside, or pass --fresh to start over."
        ) from exc
    runs = data.get("runs") or []
    if not runs:
        return []
    return runs[0].get("results", [])


def merge_result(existing: list[dict], result: dict) -> list[dict]:
    """Replace the result with the same finding_id, or append it."""
    fid = result["properties"]["finding_id"]
    merged = [
        r for r in existing if r.get("properties", {}).get("finding_id") != fid
    ]
    merged.append(result)
    merged.sort(key=lambda r: r.get("properties", {}).get("finding_id", ""))
    return merged
```

- [ ] **Step 5: Подключить в `main`, разбирая SARIF до любой записи**

Добавить флаг рядом с остальными аргументами:

```python
    parser.add_argument("--fresh", action="store_true",
                        help="Discard the existing reviewed SARIF instead of adding to it")
```

**Порядок здесь и есть предмет задачи.** Разбор существующего SARIF обязан идти до `append_log`. Лог append-only: строка, записанная перед отказом, не может быть отозвана, и два артефакта расходятся навсегда. Вставить непосредственно **перед** вызовом `append_log(`:

```python
    # Parse the existing SARIF before writing anything. The triage log is
    # append-only, so a row written ahead of a SARIF failure could never be
    # withdrawn and the two artefacts would disagree permanently.
    try:
        existing = [] if args.fresh else load_existing_results(args.sarif_out)
    except ValidationError as exc:
        print(f"SARIF ERROR: {exc}", file=sys.stderr)
        return 1
```

И заменить прежний блок записи SARIF на слияние и запись, без повторного чтения:

```python
    results = merge_result(existing, build_result(verdict, challenge, state, rationale))
    args.sarif_out.parent.mkdir(parents=True, exist_ok=True)
    args.sarif_out.write_text(json.dumps(sarif_document(results), indent=2), encoding="utf-8")
```

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: PASS, кроме двух красных из Task 3.

- [ ] **Step 7: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "fix: accumulate reviewed SARIF instead of overwriting per finding"
```

---

### Task 9: Укрепление резервного валидатора

**Files:**
- Modify: `scripts/record_verdict.py:71-113`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict._fallback_validate`, `record_verdict.ValidationError`.
- Produces: `record_verdict._JSON_TYPES: dict[str, type | tuple]`, `record_verdict._type_ok(value, expected) -> bool`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_record_verdict.py`:

```python
class TestFallbackValidator(unittest.TestCase):
    """The fallback exists so a missing jsonschema degrades the check rather
    than removing it. It degraded further than advertised."""

    SCHEMA = {
        "required": ["name"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "minLength": 2},
            "count": {"type": "integer"},
            "mode": {"type": "string", "enum": ["a", "b"]},
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {"file": {"type": "string"}},
                },
            },
            "tags": {"type": "array", "items": {"type": "string"}},
        },
    }

    def validate(self, instance):
        record_verdict._fallback_validate(instance, self.SCHEMA, "fixture")

    def test_missing_required_field(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({})

    def test_unknown_field_when_additional_properties_false(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "surprise": 1})

    def test_enum_is_enforced(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "mode": "c"})

    def test_min_length_is_enforced(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "x"})

    def test_valid_instance_passes(self):
        self.validate({"name": "ok", "count": 3, "mode": "a", "tags": ["x"]})

    # --- Gaps closed by this task -----------------------------------------

    def test_boolean_is_not_an_integer(self):
        # bool subclasses int in Python, so isinstance(True, int) is True and
        # `"count": True` slipped through as a valid integer.
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "count": True})

    def test_array_items_are_validated(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "steps": [{"line": 3}]})

    def test_scalar_array_items_are_type_checked(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "tags": [1]})

    def test_unknown_schema_type_is_reported_not_crashed(self):
        with self.assertRaises(record_verdict.ValidationError):
            record_verdict._fallback_validate(
                {"x": 1}, {"properties": {"x": {"type": "int64"}}}, "fixture"
            )

    def test_top_level_non_object_is_reported_not_crashed(self):
        with self.assertRaises(record_verdict.ValidationError):
            record_verdict._fallback_validate(
                [], {"type": "object", "properties": {}}, "fixture"
            )


class TestSchemaDriftGuard(unittest.TestCase):
    """check_consistency compensates for the two conditional rules the
    fallback validator cannot express. If the schema grows a third, this test
    fails and forces someone to decide whether to mirror it."""

    def test_schema_has_exactly_the_conditionals_we_mirror(self):
        schema = json.loads(
            (record_verdict.SCHEMA_DIR / "verdict.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(schema["allOf"]), 2)

    def test_high_confidence_conditional_is_mirrored(self):
        self.assertTrue(
            record_verdict.check_consistency(
                make_verdict(confidence="high", evidence_level="partial")
            )
        )

    def test_pattern_verdict_conditional_is_mirrored(self):
        self.assertTrue(
            record_verdict.check_consistency(
                make_verdict(evidence_level="pattern", verdict="true_positive")
            )
        )
```

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_record_verdict.TestFallbackValidator -v`
Expected: FAIL в `test_boolean_is_not_an_integer`, `test_array_items_are_validated`, `test_scalar_array_items_are_type_checked`, `test_unknown_schema_type_is_reported_not_crashed`, `test_top_level_non_object_is_reported_not_crashed`.

- [ ] **Step 3: Вынести таблицу типов и проверку**

В `scripts/record_verdict.py` добавить перед `_fallback_validate`:

```python
_JSON_TYPES = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def _type_ok(value, expected) -> bool:
    """JSON-schema type check with Python's bool/int overlap accounted for."""
    names = expected if isinstance(expected, list) else [expected]
    for name_ in names:
        if name_ not in _JSON_TYPES:
            raise ValidationError(f"schema uses unknown type {name_!r}")
        # bool is a subclass of int, so True would satisfy "integer" and
        # "number" without this guard.
        if name_ in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, _JSON_TYPES[name_]):
            return True
    return False
```

- [ ] **Step 4: Переписать тело валидатора**

Заменить `_fallback_validate` целиком:

```python
def _fallback_validate(instance: dict, schema: dict, name: str) -> None:
    """Minimal validator covering required keys, enums, types and array items.

    Not a full draft-07 implementation: `allOf`, `oneOf`, `$ref` and pattern
    matching are out of scope. The two conditional rules the verdict schema
    relies on are enforced separately by check_consistency, and a test guards
    against the schema growing a third.
    """
    if not isinstance(instance, dict):
        raise ValidationError(f"{name}: expected an object")

    for key in schema.get("required", []):
        if key not in instance:
            raise ValidationError(f"{name}: missing required field {key!r}")

    props = schema.get("properties", {})
    for key, value in instance.items():
        spec = props.get(key)
        if not spec:
            if schema.get("additionalProperties") is False:
                raise ValidationError(f"{name}: unexpected field {key!r}")
            continue

        if "enum" in spec and value not in spec["enum"]:
            raise ValidationError(f"{name}: {key}={value!r} not in {spec['enum']}")

        if "type" in spec and not _type_ok(value, spec["type"]):
            raise ValidationError(
                f"{name}: {key} should be {spec['type']}, got {type(value).__name__}"
            )

        if spec.get("minLength") and isinstance(value, str):
            if len(value) < spec["minLength"]:
                raise ValidationError(
                    f"{name}: {key} shorter than {spec['minLength']} chars"
                )

        if isinstance(value, dict) and spec.get("properties"):
            _fallback_validate(value, spec, f"{name}.{key}")

        if isinstance(value, list) and isinstance(spec.get("items"), dict):
            item_spec = spec["items"]
            for index, item in enumerate(value):
                label = f"{name}.{key}[{index}]"
                if item_spec.get("properties") or item_spec.get("required"):
                    if not isinstance(item, dict):
                        raise ValidationError(f"{label}: expected an object")
                    _fallback_validate(item, item_spec, label)
                elif "type" in item_spec and not _type_ok(item, item_spec["type"]):
                    raise ValidationError(
                        f"{label}: should be {item_spec['type']}, "
                        f"got {type(item).__name__}"
                    )
```

- [ ] **Step 5: Прогнать**

Run: `make test`
Expected: PASS, кроме двух красных из Task 3.

- [ ] **Step 6: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "fix: close type and array gaps in the fallback validator"
```

---

### Task 10: Регистронезависимый матчинг путей

**Files:**
- Modify: `scripts/check_scope.py:93-125`
- Modify: `policy/excluded-paths.yml`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: красные тесты из Task 3.
- Produces: поведение `_matches` не зависит от ОС.

- [ ] **Step 1: Подтвердить красноту**

Run: `python3 -m unittest tests.test_check_scope.TestMatches -v`
Expected: FAIL в `test_uppercase_dotfile_is_refused` и `test_mixed_case_extension_is_refused`.

- [ ] **Step 2: Свернуть регистр**

В `scripts/check_scope.py` заменить начало `_matches` и три вызова `fnmatch.fnmatch`:

```python
def _matches(path: str, pattern: str) -> bool:
    """gitignore-flavoured glob matching.

    A trailing slash means "this directory and everything under it". A pattern
    without a slash matches at any depth, mirroring gitignore behaviour, so
    `**/.env` and `.env` both catch a nested file.

    Matching is case-insensitive and platform-independent. macOS APFS and
    Windows NTFS are case-insensitive by default, so `.ENV` names the same file
    as `.env`; a case-sensitive glob would let the second spelling walk past
    every dotfile exclusion. fnmatch.fnmatch is not an option here because it
    defers to os.path.normcase, which makes the answer depend on the operating
    system the reviewer happens to be using.
    """
    # Strip a leading "./" as a prefix, not as a character set. lstrip("./")
    # would eat the leading dot of a dotfile and turn ".env" into "env",
    # silently defeating every dotfile exclusion in the policy.
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/").lower()
    pattern = pattern.lower()

    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        cleaned = prefix.replace("**/", "")
        return (
            norm.startswith(prefix + "/")
            or f"/{cleaned}/" in f"/{norm}"
            or norm.startswith(cleaned + "/")
        )

    if fnmatch.fnmatchcase(norm, pattern):
        return True
    # `**/x` should also match a top-level `x`
    if pattern.startswith("**/") and fnmatch.fnmatchcase(norm, pattern[3:]):
        return True
    # A bare pattern matches at any depth
    if "/" not in pattern and fnmatch.fnmatchcase(Path(norm).name, pattern):
        return True
    return False
```

- [ ] **Step 3: Закрыть пробел в политике**

В `policy/excluded-paths.yml` после блока `**/.env.*` добавить:

```yaml
  - pattern: "**/.envrc"
    owner: appsec
    reason: direnv environment, commonly holds secrets
```

- [ ] **Step 4: Прогнать**

Run: `make test`
Expected: **все зелёные.** Красных больше нет.

- [ ] **Step 5: Проверить боевую политику вручную**

Run: `python3 scripts/check_scope.py .ENV ; echo "exit=$?"`
Expected: `REFUSED`, `exit=2`.

Run: `python3 scripts/check_scope.py src/environment.py ; echo "exit=$?"`
Expected: `OK: 1 path(s) within scope`, `exit=0`.

- [ ] **Step 6: Коммит**

```bash
git add scripts/check_scope.py policy/excluded-paths.yml
git commit -m "fix: match exclusions case-insensitively and cover .envrc"
```

---

### Task 11: Стабильная идентичность находки

**Files:**
- Modify: `scripts/build_packet.py:32-35`, `:116-180`, `:200-280`
- Modify: `tests/test_build_packet.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `check_scope.check_path`, `check_scope.ScopeViolation`.
- Produces: `build_packet.ID_SCHEME: str = "content-v1"`, `build_packet.compute_finding_id(result: dict, repo: Path, exclusions: list[dict] | None = None) -> str`, `build_packet.normalize_snippet(text: str) -> str`, `build_packet.scanner_fingerprint(result: dict) -> str | None`, `build_packet.occurrence_index(file_text: str, start_line: int, end_line: int, target: str) -> int`. Задачи 13, 15, 16 и 18 опираются на `ID_SCHEME` и `compute_finding_id`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_build_packet.py` перед блоком `if __name__`:

```python
FILE_BEFORE = "import os\n\n\ndef run(cmd):\n    exec(cmd)\n"
FILE_AFTER = "import os\nimport sys\n\n\ndef run(cmd):\n    exec(cmd)\n"


def result_at(path="app/handler.py", start=5, end=5, **extra):
    base = {
        "rule_id": "python.lang.security.audit.exec-detected",
        "file": path,
        "start_line": start,
        "end_line": end,
    }
    base.update(extra)
    return base


class TestFindingIdentity(unittest.TestCase):
    """The old id hashed the line number, so any edit above a finding gave it a
    new identity: its verdicts were orphaned and dismissed findings came back."""

    def test_line_shift_preserves_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            before = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        with temp_tree({"app/handler.py": FILE_AFTER}) as repo:
            after = build_packet.compute_finding_id(
                result_at(start=6, end=6), repo, fixture_exclusions()
            )
        self.assertEqual(before, after)

    def test_changing_the_fragment_changes_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            original = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        edited = FILE_BEFORE.replace("exec(cmd)", "exec(shlex.quote(cmd))")
        with temp_tree({"app/handler.py": edited}) as repo:
            changed = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        self.assertNotEqual(original, changed)

    def test_identical_fragments_get_distinct_identities(self):
        text = "a = 1\nexec(cmd)\nb = 2\nexec(cmd)\n"
        with temp_tree({"app/handler.py": text}) as repo:
            first = build_packet.compute_finding_id(
                result_at(start=2, end=2), repo, fixture_exclusions()
            )
            second = build_packet.compute_finding_id(
                result_at(start=4, end=4), repo, fixture_exclusions()
            )
        self.assertNotEqual(first, second)

    def test_indentation_change_preserves_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            original = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        reindented = FILE_BEFORE.replace("    exec(cmd)", "        exec(cmd)")
        with temp_tree({"app/handler.py": reindented}) as repo:
            same = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        self.assertEqual(original, same)

    def test_scanner_fingerprint_wins_and_needs_no_file(self):
        result = result_at(partialFingerprints={"semgrep.fingerprint": "abc123"})
        with temp_tree({}) as repo:
            fid = build_packet.compute_finding_id(result, repo, fixture_exclusions())
        self.assertTrue(fid.startswith("F-"))

    def test_fingerprint_key_choice_is_deterministic(self):
        a = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"zeta": "1", "alpha": "2"}}
        )
        b = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"alpha": "2", "zeta": "1"}}
        )
        self.assertEqual(a, b)

    def test_preferred_fingerprint_key_wins_over_alphabetical(self):
        fp = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"aaa": "x", "primaryLocationLineHash": "y"}}
        )
        self.assertIn("primaryLocationLineHash", fp)

    def test_excluded_path_refuses_before_reading(self):
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(
                    result_at(path="secrets/prod.env", start=1, end=1),
                    repo,
                    fixture_exclusions(),
                )

    def test_excluded_path_refuses_even_with_a_fingerprint(self):
        # The fingerprint path needs no file, so nothing would be leaked. It is
        # still refused: an id for a finding that can never become a packet is
        # a loose end, and the listing promises (no id) for excluded paths.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(
                    result_at(
                        path="secrets/prod.env",
                        start=1,
                        end=1,
                        partialFingerprints={"semgrep.fingerprint": "deadbeef"},
                    ),
                    repo,
                    fixture_exclusions(),
                )

    def test_empty_region_is_reported_clearly(self):
        with temp_tree({"app/handler.py": "\n\n\n"}) as repo:
            with self.assertRaises(ValueError):
                build_packet.compute_finding_id(
                    result_at(start=1, end=2), repo, fixture_exclusions()
                )

    def test_packet_records_the_identity_scheme(self):
        results = build_packet.load_sarif_results(SARIF)
        with temp_tree({"app/handler.py": FILE_BEFORE, "app/db.py": "q = f'{x}'\n"}) as repo:
            packet = build_packet.build_triage_packet(
                results[0], repo, 40, fixture_exclusions()
            )
        self.assertEqual(packet["id_scheme"], build_packet.ID_SCHEME)
```

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_build_packet.TestFindingIdentity -v`
Expected: FAIL с `AttributeError: module 'build_packet' has no attribute 'compute_finding_id'`.

- [ ] **Step 3: Заменить генератор идентичности**

В `scripts/build_packet.py` заменить `finding_id` целиком:

```python
ID_SCHEME = "content-v1"

# Keys we trust first when a scanner emits several. Order is significance, not
# preference for its own sake: these are the ones scanners document as stable.
FINGERPRINT_PREFERENCE = ("primaryLocationLineHash", "semgrep.fingerprint")


def _digest(material: str) -> str:
    return f"F-{hashlib.sha256(material.encode()).hexdigest()[:12]}"


def scanner_fingerprint(result: dict) -> str | None:
    """The scanner's own stable identifier for this finding, when it emits one.

    SARIF 2.1.0 defines fingerprints and partialFingerprints for exactly this
    purpose, so preferring them means inheriting the scanner's notion of
    identity rather than inventing a competing one. Key selection is
    deterministic: a preferred key if present, otherwise the first in sorted
    order, so two runs over the same result always agree.
    """
    for container in ("fingerprints", "partialFingerprints"):
        prints = result.get(container)
        if not isinstance(prints, dict) or not prints:
            continue
        for key in FINGERPRINT_PREFERENCE:
            if key in prints:
                return f"{container}:{key}:{prints[key]}"
        key = sorted(prints)[0]
        return f"{container}:{key}:{prints[key]}"
    return None


def normalize_snippet(text: str) -> str:
    """Drop indentation and blank lines so reformatting does not reset identity."""
    stripped = (line.strip() for line in text.splitlines())
    return "\n".join(line for line in stripped if line)


def occurrence_index(file_text: str, start_line: int, end_line: int, target: str) -> int:
    """How many identical normalized snippets appear before this one.

    Without it, two identical fragments in one file would collapse into a
    single id. Stable under line shifts: inserting lines above moves the
    finding and its earlier duplicates by the same amount, so the count holds.
    """
    lines = file_text.splitlines()
    span = max(1, end_line - start_line + 1)
    count = 0
    for i in range(0, max(0, start_line - 1)):
        if normalize_snippet("\n".join(lines[i:i + span])) == target:
            count += 1
    return count


def compute_finding_id(
    result: dict, repo: Path, exclusions: list[dict] | None = None
) -> str:
    """Identity that survives edits elsewhere in the file.

    Guarantee: inserting or deleting lines above the finding does not change
    the id, so verdicts and SARIF suppressions survive ordinary refactoring.

    Non-guarantee, and deliberately so: editing the flagged fragment itself
    changes the id. Changed code deserves a fresh review.

    Known limitation: identity combines the fragment with how many identical
    fragments precede it, so reordering identical fragments within one file
    swaps their ids.

    Raises ScopeViolation for an excluded path, before either identity path
    runs. The content path would otherwise read a file the policy forbids, and
    the fingerprint path — which needs no file — would hand back an id for a
    finding that can never be turned into a packet. One rule for both keeps the
    control uniform and the listing honest.
    """
    rule_id = result["rule_id"]
    path = result["file"]

    check_path(path, exclusions)

    fingerprint = scanner_fingerprint(result)
    if fingerprint:
        return _digest(f"{rule_id}:{path}:{fingerprint}")

    target_file = repo / path
    if not target_file.exists():
        raise FileNotFoundError(
            f"Source file not found: {target_file}. Run the scan from the "
            "repository root."
        )

    text = target_file.read_text(encoding="utf-8", errors="replace")
    start, end = result["start_line"], result["end_line"]
    snippet = normalize_snippet("\n".join(text.splitlines()[start - 1:end]))
    if not snippet:
        raise ValueError(
            f"Cannot derive an identity for {path}:{start}-{end}: the flagged "
            "region is empty or whitespace only."
        )
    index = occurrence_index(text, start, end, snippet)
    return _digest(f"{rule_id}:{path}:{snippet}:{index}")
```

- [ ] **Step 4: Донести фингерпринты до потребителя**

`load_sarif_results` собирает собственный словарь и до сих пор отбрасывал оба
поля с фингерпринтами, поэтому предпочтительный источник идентичности не мог
сработать ни разу на реальном входе. Добавить в словарь, который собирает
`load_sarif_results` (`scripts/build_packet.py:59-75`), два ключа перед
`"code_flows"`:

```python
                    # Verbatim SARIF spelling: these are passed straight to
                    # scanner_fingerprint, and renaming them here would add a
                    # mapping layer whose only job is to be kept in sync.
                    "fingerprints": result.get("fingerprints") or {},
                    "partialFingerprints": result.get("partialFingerprints") or {},
```

И дописать в `TestFindingIdentity` два теста, закрывающих именно этот разрыв:

```python
    def test_fingerprints_survive_sarif_parsing(self):
        results = build_packet.load_sarif_results(SARIF)
        self.assertEqual(
            results[1]["partialFingerprints"],
            {"semgrep.fingerprint": "abc123def456"},
        )

    def test_real_sarif_input_uses_the_scanner_fingerprint(self):
        # An empty repository: the content path would raise FileNotFoundError,
        # so a returned id proves the fingerprint path actually ran on input
        # that came through load_sarif_results rather than a hand-built dict.
        results = build_packet.load_sarif_results(SARIF)
        with temp_tree({}) as repo:
            fid = build_packet.compute_finding_id(
                results[1], repo, fixture_exclusions()
            )
        self.assertTrue(fid.startswith("F-"))
```

- [ ] **Step 5: Переставить порядок в `build_triage_packet`**

Идентичность теперь читает файл, поэтому scope-check обязан идти раньше её вычисления. Заменить начало функции:

```python
def build_triage_packet(
    result: dict, repo: Path, window: int, exclusions: list[dict] | None = None
) -> dict:
    # Scope check before any file content is read, identity included. This
    # ordering is the point: compute_finding_id opens the source file.
    if exclusions is None:
        exclusions, _ = load_policy()
    candidates = [result["file"]] + [
        step["file"] for flow in result["code_flows"] for step in flow["steps"]
    ]
    for path in candidates:
        if path:
            check_path(path, exclusions)

    fid = compute_finding_id(result, repo, exclusions)
```

Удалить прежнюю строку `fid = finding_id(...)` из начала функции.

В возвращаемом словаре добавить поле сразу после `finding_id`:

```python
        "id_scheme": ID_SCHEME,
```

- [ ] **Step 6: Поправить список находок**

В `main` список больше не может считать id для исключённых путей — это означало бы чтение запрещённого файла. Заменить блок `if args.list or args.index is None:`:

```python
    if args.list or args.index is None:
        exclusions, _ = load_policy()
        print(f"{len(results)} finding(s):\n")
        for i, r in enumerate(results):
            try:
                fid = compute_finding_id(r, args.repo, exclusions)
            except (ScopeViolation, FileNotFoundError, ValueError):
                # Out of scope, absent, or unidentifiable. Never read a file the
                # policy excludes just to print a label for it.
                fid = None
            flag = "" if _in_scope(r["file"], exclusions) else "  [OUT OF SCOPE]"
            label = fid or "(no id)"
            print(f"  [{i:>3}] {label}  {r['level']:<8} {r['file']}:{r['start_line']}{flag}")
            print(f"        {r['rule_id']}")
        print("\nBuild a packet with: make triage N=<index>")
        return 0
```

И расширить `_in_scope`:

```python
def _in_scope(path: str, exclusions: list[dict] | None = None) -> bool:
    try:
        check_path(path, exclusions)
        return True
    except ScopeViolation:
        return False
```

- [ ] **Step 7: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 8: Проверить вручную**

Run: `python3 scripts/build_packet.py --sarif tests/fixtures/sample.sarif --list`
Expected: три находки, по одной на каждый путь идентичности. `app/db.py` несёт фингерпринт и получает id, не читая файла. `app/handler.py` идёт по содержимому, файла в рабочем каталоге нет, поэтому `(no id)`. `config/server.pem` помечена `[OUT OF SCOPE]` и тоже без id.

Эта проверка идёт против **живой** `policy/excluded-paths.yml`, а не против фикстуры, поэтому исключённый путь в фикстурном SARIF обязан подпадать под обе политики. Фикстура намеренно независима от живой политики (слой 0), и единственное место, где границы пересекаются, — вот эта ручная проверка.

- [ ] **Step 9: Коммит**

```bash
git add scripts/build_packet.py tests/test_build_packet.py
git commit -m "fix: derive finding identity from content so it survives line shifts"
```

**Слой 1 завершён.**

---

# Слой 2 — контракт независимости

### Task 12: Идентификаторы моделей от человека и отказ при совпадении

**Files:**
- Modify: `scripts/record_verdict.py:272-330`
- Modify: `Makefile`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict.main`.
- Produces: обязательный `--agent`, условно обязательный `--validator`. Задача 13 добавляет колонки самоотчёта.

- [ ] **Step 1: Написать падающий тест**

Тест вызывает `main` через `subprocess`, потому что предмет проверки — код возврата и отсутствие записи. Дописать в `tests/test_record_verdict.py`:

```python
class TestIndependenceControl(unittest.TestCase):
    """docs/04 calls independence the mechanism. A warning is not a mechanism."""

    def run_recorder(self, args, cwd):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "record_verdict.py"), *args],
            capture_output=True,
            text=True,
            cwd=str(cwd),
        )

    def setup_files(self, root):
        verdict = make_verdict(severity="low", evidence_level="partial")
        challenge = make_challenge("upheld")
        (root / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
        (root / "challenge.json").write_text(json.dumps(challenge), encoding="utf-8")

    def test_same_model_is_refused_and_writes_nothing(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                    "--validator", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(log),
                ],
                root,
            )
            # Absence is asserted INSIDE the block. temp_tree deletes the whole
            # tree on exit, so exists() afterwards is False no matter what the
            # process did, and the assertion could never fail.
            self.assertFalse(log.exists(), "a refused run must not write the log")
            self.assertFalse(sarif.exists(), "a refused run must not write SARIF")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("REFUSED", proc.stderr)

    def test_missing_agent_is_refused(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(["--verdict", str(root / "verdict.json")], root)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--agent", proc.stderr)

    def test_challenge_without_validator_is_refused(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                ],
                root,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--validator", proc.stderr)

    def test_fresh_discards_the_existing_sarif(self):
        # Deferred from Task 8: --fresh is only observable through the CLI, and
        # the recorder's argument set settles in this task.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            sarif = root / "reviewed.sarif"
            stale = record_verdict.build_result(
                make_verdict(finding_id="F-stale"), None, "confirmed", "old"
            )
            sarif.write_text(
                json.dumps(record_verdict.sarif_document([stale])), encoding="utf-8"
            )
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(root / "triage-log.csv"),
                    "--fresh",
                ],
                root,
            )
            ids = [
                r["properties"]["finding_id"]
                for r in record_verdict.load_existing_results(sarif)
            ]
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("F-stale", ids)

    def test_single_model_run_without_challenge_is_accepted(self):
        # severity=low needs no challenge, so one model is legitimate here.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(root / "reviewed.sarif"),
                    "--log", str(root / "triage-log.csv"),
                ],
                root,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_malformed_sarif_refuses_before_touching_the_log(self):
        # Deferred from Task 8 alongside the --fresh test. Regression for the
        # ordering requirement: the log is append-only, so a row written ahead
        # of a SARIF failure could never be withdrawn.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            sarif.write_text("{ not json", encoding="utf-8")
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(log),
                ],
                root,
            )
            # Inside the block: see the note in test_same_model_is_refused.
            self.assertFalse(log.exists(), "a refused run must not create the log")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SARIF ERROR", proc.stderr)

    def test_distinct_models_are_accepted(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                    "--validator", "model-b",
                    "--sarif-out", str(root / "reviewed.sarif"),
                    "--log", str(root / "triage-log.csv"),
                ],
                root,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
```

Добавить в шапку файла: `import subprocess`, `import sys`, `from tests import REPO_ROOT`.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_record_verdict.TestIndependenceControl -v`
Expected: FAIL — `--agent` и `--log` пока не существуют.

- [ ] **Step 3: Добавить аргументы**

В `main` рядом с остальными:

```python
    parser.add_argument("--agent", required=True,
                        help="Model identifier for the triage pass, supplied by the engineer")
    parser.add_argument("--validator",
                        help="Model identifier for the validation pass; required with --challenge")
    parser.add_argument("--log", type=Path, default=LOG_PATH,
                        help="Triage log to append to")
```

- [ ] **Step 4: Поставить контроль до любых записей**

Сразу после `args = parser.parse_args()`:

```python
    if args.challenge and not args.validator:
        parser.error("--validator is required when --challenge is given")

    if args.validator and args.agent == args.validator:
        print("REFUSED: triage and validation ran on the same model.\n", file=sys.stderr)
        print(f"  agent:     {args.agent}", file=sys.stderr)
        print(f"  validator: {args.validator}\n", file=sys.stderr)
        print(
            "Independence is the mechanism, not a preference. A second pass on the\n"
            "same model inherits the same blind spots and produces agreement rather\n"
            "than validation. Nothing was written.",
            file=sys.stderr,
        )
        return 2
```

- [ ] **Step 5: Заменить прежнее предупреждение сверкой самоотчёта**

Удалить блок, сравнивающий `verdict["reviewer"]["agent"]` с `challenge["validator"]["agent"]`, и поставить на его место:

```python
    # The model fills reviewer.agent in its own output, and models are
    # unreliable about their own identity. The engineer's value is authoritative;
    # a mismatch is worth surfacing but is not grounds to refuse.
    self_reported = verdict.get("reviewer", {}).get("agent", "")
    if self_reported and self_reported != args.agent:
        print(
            f"WARNING: verdict self-reports agent {self_reported!r}, engineer "
            f"supplied {args.agent!r}.\n",
            file=sys.stderr,
        )
    if challenge:
        validator_self = challenge.get("validator", {}).get("agent", "")
        if validator_self and validator_self != args.validator:
            print(
                f"WARNING: challenge self-reports validator {validator_self!r}, "
                f"engineer supplied {args.validator!r}.\n",
                file=sys.stderr,
            )
        if challenge.get("challenge_result") == "upheld" and not challenge.get(
            "refutation_attempts"
        ):
            print("WARNING: 'upheld' with no recorded refutation attempts is "
                  "agreement, not validation.\n", file=sys.stderr)
```

Заменить в `append_log` и в вызове использование `LOG_PATH` на `args.log`: сделать `append_log(row, path)` с параметром и передавать `args.log`.

```python
def append_log(row: dict, path: Path = LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})
```

И в конце `main` заменить печать пути на `args.log`.

- [ ] **Step 6: Обновить Makefile**

```make
record:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@test -n "$(AGENT)" || (echo "Set AGENT=<model that ran triage>" && exit 1)
	@python3 scripts/record_verdict.py \
		--verdict findings/verdicts/$(ID).json \
		--agent "$(AGENT)" \
		$(if $(VALIDATOR),--validator "$(VALIDATOR)",) \
		$(if $(wildcard findings/challenges/$(ID).json),--challenge findings/challenges/$(ID).json,) \
		$(if $(MINUTES),--minutes $(MINUTES),)
```

И в блоке `help` заменить строку записи:

```make
	@echo "  make record ID=F-abc AGENT=<model> VALIDATOR=<model> MINUTES=12"
```

- [ ] **Step 7: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 8: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py Makefile
git commit -m "feat: refuse same-model validation instead of warning about it"
```

---

### Task 13: Рост лога и проверка совместимости

**Files:**
- Modify: `scripts/record_verdict.py:33-51`, `:192-200`, `:326-352`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `build_packet.ID_SCHEME`.
- Produces: `record_verdict.check_log_compatible(path: Path, id_scheme: str) -> None`. Колонки `agent_self_reported`, `validator_self_reported`, `id_scheme`. Задачи 17 и 18 дополняют `LOG_FIELDS` тем же механизмом.

- [ ] **Step 1: Написать падающий тест**

```python
class TestLogCompatibility(unittest.TestCase):
    """csv.DictWriter appends happily under a stale header, misaligning every
    column. A silently corrupted audit trail is worse than a refusal."""

    def test_absent_log_is_fine(self):
        with temp_tree({}) as root:
            record_verdict.check_log_compatible(root / "triage-log.csv", "content-v1")

    def test_stale_header_is_refused(self):
        with temp_tree({"triage-log.csv": "reviewed_at,finding_id\n2026-01-01,F-1\n"}) as root:
            with self.assertRaises(record_verdict.ValidationError) as ctx:
                record_verdict.check_log_compatible(root / "triage-log.csv", "content-v1")
            self.assertIn("missing columns", str(ctx.exception))

    def test_current_header_is_accepted(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [])
            record_verdict.check_log_compatible(log, "content-v1")

    def test_foreign_id_scheme_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{"finding_id": "F-1", "id_scheme": "line-v0"}])
            with self.assertRaises(record_verdict.ValidationError) as ctx:
                record_verdict.check_log_compatible(log, "content-v1")
            self.assertIn("line-v0", str(ctx.exception))

    def test_log_carries_self_reported_columns(self):
        self.assertIn("agent_self_reported", record_verdict.LOG_FIELDS)
        self.assertIn("validator_self_reported", record_verdict.LOG_FIELDS)
        self.assertIn("id_scheme", record_verdict.LOG_FIELDS)

    def test_empty_log_file_still_gets_a_header(self):
        # A zero-byte file exists but is not yet a log: an interrupted write or
        # a stray touch leaves one behind. Appending without a header would put
        # a data row where csv.DictReader expects column names, and every
        # column would silently take its name from the first finding.
        with temp_tree({"triage-log.csv": ""}) as root:
            log = root / "triage-log.csv"
            record_verdict.check_log_compatible(log, "content-v1")
            record_verdict.append_log({"finding_id": "F-1"}, log)
            with log.open(encoding="utf-8", newline="") as fh:
                first_line = next(csv.reader(fh))
        self.assertEqual(first_line, record_verdict.LOG_FIELDS)
```

Добавить `import csv` и `from tests.helpers import write_log` в шапку.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_record_verdict.TestLogCompatibility -v`
Expected: FAIL — `check_log_compatible` отсутствует.

- [ ] **Step 3: Расширить набор колонок**

В `scripts/record_verdict.py` заменить `LOG_FIELDS`:

```python
LOG_FIELDS = [
    "reviewed_at", "finding_id", "id_scheme", "rule_id", "file", "line",
    "severity", "priority_class", "evidence_level", "confidence",
    "initial_verdict", "challenge_result", "final_state",
    "minutes_spent", "requires_runtime_proof",
    "agent", "validator",
    "agent_self_reported", "validator_self_reported",
    "notes",
]
```

И импортировать схему идентичности рядом с существующими импортами, по образцу `build_packet.py`:

```python
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_packet import ID_SCHEME  # noqa: E402
```

- [ ] **Step 4: Добавить проверку совместимости**

Сначала закрыть расхождение между двумя функциями. `append_log` решает, писать
ли заголовок, по факту существования файла, а `check_log_compatible` считает файл
без заголовка не требующим проверки. Пустой файл проваливается в щель между ними.
Заменить `append_log`:

```python
def append_log(row: dict, path: Path = LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Key the header on content, not on existence. A file that exists but is
    # empty is not a log yet, and appending to it without a header would put a
    # data row in the header position, where csv.DictReader would read it as
    # the column names and corrupt every row that follows.
    has_header = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not has_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})
```

Затем добавить саму проверку:

```python
def check_log_compatible(path: Path, id_scheme: str) -> None:
    """Refuse to append to a log whose shape or identity scheme differs.

    Two separate hazards. A stale header means csv.DictWriter writes new rows
    under old column names and every field lands in the wrong place. A foreign
    id_scheme means the same finding carries a different id in older rows, so
    metrics would count one finding as two and nobody would notice.
    """
    if not path.exists():
        return

    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header is None:
            # Empty file: nothing to compare against, and append_log will lay
            # down the header on the next write. The two functions have to
            # agree about what an empty file means, or a row lands where the
            # header belongs.
            return
        schemes = set()
        if "id_scheme" in header:
            column = header.index("id_scheme")
            for row in reader:
                if len(row) > column and row[column]:
                    schemes.add(row[column])

    if header != LOG_FIELDS:
        missing = [f for f in LOG_FIELDS if f not in header] or ["none"]
        extra = [f for f in header if f not in LOG_FIELDS] or ["none"]
        raise ValidationError(
            f"{path} has an incompatible header.\n"
            f"  missing columns: {', '.join(missing)}\n"
            f"  unexpected columns: {', '.join(extra)}\n"
            "Archive the existing findings/ directory, or migrate the log, "
            "before recording new verdicts."
        )

    foreign = sorted(s for s in schemes if s != id_scheme)
    if foreign:
        raise ValidationError(
            f"{path} contains rows written under identity scheme(s) "
            f"{', '.join(foreign)}, but this run uses {id_scheme}.\n"
            "The same finding carries a different id under each scheme, so the "
            "two cannot share a log. Archive findings/ and re-triage."
        )
```

- [ ] **Step 5: Вызвать проверку и заполнить колонки**

В `main`, сразу после проверки независимости:

```python
    try:
        check_log_compatible(args.log, ID_SCHEME)
    except ValidationError as exc:
        print(f"LOG ERROR: {exc}", file=sys.stderr)
        return 1
```

В словаре `append_log` заменить строки про агентов и добавить схему:

```python
            "id_scheme": ID_SCHEME,
            ...
            "agent": args.agent,
            "validator": args.validator or "",
            "agent_self_reported": verdict.get("reviewer", {}).get("agent", ""),
            "validator_self_reported": (challenge or {}).get("validator", {}).get("agent", ""),
```

И передать путь: `append_log({...}, args.log)`.

В `build_result` добавить в `properties`:

```python
            "id_scheme": ID_SCHEME,
```

- [ ] **Step 6: Обновить тест метрик под авторитетные колонки**

В `tests/test_metrics.py` тест `test_same_model_validations_are_counted` продолжает работать: `metrics.py` читает колонки `agent` и `validator`, которые теперь заполняются из CLI. Изменений не требуется — убедитесь прогоном.

- [ ] **Step 7: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 8: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "feat: record authoritative and self-reported model ids; guard log shape"
```

**Слой 2 завершён.**

---

# Слой 3 — egress

### Task 14: Офлайн-правила по умолчанию

**Files:**
- Modify: `scripts/scan.sh`
- Create: `rules/README.md`
- Create: `tests/test_scan_sh.py`
- Modify: `docs/03-data-handling.md`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: ничего.
- Produces: `SEMGREP_CONFIG` как единственный способ выйти в сеть.

- [ ] **Step 1: Написать падающий тест**

`tests/test_scan_sh.py`:

```python
"""Tests for the scanner entry point.

The refusal path must work without semgrep installed, which is why rule
resolution happens before semgrep is invoked.
"""

import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT
from tests.helpers import temp_tree

SCAN = REPO_ROOT / "scripts" / "scan.sh"


class TestScanScript(unittest.TestCase):
    def run_scan(self, repo, env_config, bindir=None):
        # A stripped PATH is not a guarantee that semgrep is absent: package
        # managers do put it in /usr/bin. Tests that exercise the registry
        # branch must supply a stand-in on PATH, or they can reach the network.
        path = f"{bindir}:/usr/bin:/bin" if bindir else "/usr/bin:/bin"
        env = {"PATH": path, "SEMGREP_CONFIG": env_config}
        return subprocess.run(
            ["/bin/sh", str(SCAN), str(repo)],
            capture_output=True,
            text=True,
            cwd=str(repo),
            env=env,
        )

    def make_fake_semgrep(self, bindir: Path) -> Path:
        """Install a stand-in that records its arguments and exits 42.

        Returns the path it writes those arguments to. The distinctive exit
        code proves the stand-in is what ran, rather than a real semgrep found
        elsewhere on PATH or a silent failure that happens to look similar.
        """
        bindir.mkdir(parents=True, exist_ok=True)
        args_file = bindir / "args.txt"
        fake = bindir / "semgrep"
        fake.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{args_file}"\n'
            "exit 42\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return args_file

    def test_empty_rules_directory_refuses(self):
        with temp_tree({"rules/README.md": "placeholder\n"}) as root:
            proc = self.run_scan(root, str(root / "rules"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)
        self.assertIn("SEMGREP_CONFIG", proc.stderr)

    def test_missing_rules_directory_refuses(self):
        with temp_tree({"placeholder": ""}) as root:
            proc = self.run_scan(root, str(root / "absent"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)

    def test_refusal_leaves_no_state_behind(self):
        with temp_tree({"rules/README.md": "placeholder\n"}) as root:
            self.run_scan(root, str(root / "rules"))
            self.assertFalse((root / "findings").exists())

    def test_local_rules_pass_metrics_off_and_the_local_config(self):
        with temp_tree({"rules/x.yaml": "rules: []\n"}) as root:
            args_file = self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(root, str(root / "rules"), bindir=root / "bin")
            recorded = args_file.read_text(encoding="utf-8").split("\n")
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("--metrics=off", recorded)
        self.assertIn(str(root / "rules"), recorded)
        self.assertNotIn("NETWORK", proc.stderr)

    def test_registry_config_announces_egress_and_still_disables_telemetry(self):
        with temp_tree({"placeholder": ""}) as root:
            args_file = self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(root, "p/security-audit", bindir=root / "bin")
            recorded = args_file.read_text(encoding="utf-8").split("\n")
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("NETWORK", proc.stderr)
        self.assertIn("docs/03-data-handling.md", proc.stderr)
        self.assertIn("--metrics=off", recorded)
        self.assertIn("p/security-audit", recorded)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_scan_sh -v`
Expected: FAIL — скрипт сейчас сразу зовёт semgrep с `--config auto`.

- [ ] **Step 3: Переписать `scan.sh`**

```sh
#!/usr/bin/env sh
set -eu

# Rules come from a local directory by default. docs/03-data-handling.md
# claims exactly one channel out of the perimeter — the review packet — and
# `--config auto` quietly opened a second one by fetching rules from the
# Semgrep registry and reporting telemetry. Going to the registry is still
# possible, but it is now a decision someone makes out loud.

repo="${1:-.}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config="${SEMGREP_CONFIG:-$root/rules}"

# Resolution happens before semgrep is invoked so the refusal path works on a
# machine without semgrep, and so it can be tested there too. Nothing is
# created on disk until the configuration is known to be usable: a refusal
# that leaves state behind is not a clean refusal.
case "$config" in
  p/*|r/*|https://*)
    printf 'NETWORK: fetching rules from the Semgrep registry (%s).\n' "$config" >&2
    printf 'This is a second channel out of the perimeter.\n' >&2
    printf 'See docs/03-data-handling.md.\n\n' >&2
    ;;
  *)
    if [ ! -d "$config" ] || [ -z "$(ls -A "$config" 2>/dev/null | grep -v '^README.md$' || true)" ]; then
      printf 'REFUSED: no local rules in %s\n\n' "$config" >&2
      printf 'Add Semgrep rule files for this repository, or opt into the\n' >&2
      printf 'registry explicitly:\n\n' >&2
      printf '    SEMGREP_CONFIG=p/security-audit make scan REPO=%s\n\n' "$repo" >&2
      printf 'docs/03-data-handling.md explains why the default is offline.\n' >&2
      exit 2
    fi
    ;;
esac

mkdir -p findings

printf 'Rules:  %s\n' "$config"
printf 'Target: %s\n\n' "$repo"

semgrep scan --config "$config" --metrics=off --sarif \
  --output findings/raw.sarif "$repo"
```

- [ ] **Step 4: Создать каталог правил**

`rules/README.md`:

```markdown
# Local Semgrep rules

`scan.sh` reads rules from this directory by default. It is empty on purpose:
a rule set is specific to the languages and frameworks of the repository under
review, and shipping someone else's is worse than shipping none.

Populate it with `.yaml` rule files before the first scan.

To use the Semgrep registry instead, opt in explicitly:

    SEMGREP_CONFIG=p/security-audit make scan REPO=../myapp

That reaches the network, which is a second channel out of the perimeter.
`docs/03-data-handling.md` explains what that means and when it is acceptable.
```

- [ ] **Step 5: Задокументировать канал**

В `docs/03-data-handling.md`, сразу после раздела «The one channel», вставить:

```markdown
## The scanner is also a channel

`semgrep --config auto`, the previous default, fetched rules from the Semgrep
registry and reported telemetry on every run. That was a second path out of the
perimeter, undocumented and not covered by `check_scope.py`.

The default is now a local rule directory, `rules/`, and telemetry is disabled
unconditionally. `scan.sh` refuses to run against an empty `rules/` rather than
silently falling back to the network.

Reaching the registry is still supported and sometimes correct, but it is
explicit:

```bash
SEMGREP_CONFIG=p/security-audit make scan REPO=../myapp
```

That prints a banner naming the egress before it happens. What leaves the
perimeter on that path is the rule request itself, not your source; the source
still leaves only in a review packet.
```

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 7: Коммит**

```bash
git add scripts/scan.sh rules tests/test_scan_sh.py docs/03-data-handling.md
git commit -m "fix: default the scanner to local rules and disable telemetry"
```

**Слой 3 завершён.**

---

# Слой 4 — очередь триажа

### Task 15: Фильтры списка находок

**Files:**
- Modify: `scripts/check_scope.py`
- Modify: `scripts/build_packet.py:200-280`
- Modify: `tests/test_build_packet.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `build_packet.compute_finding_id`, `build_packet._in_scope`.
- Produces: `check_scope.matches(path: str, pattern: str) -> bool`; `build_packet.LEVEL_ORDER: dict[str, int]`, `build_packet.annotate(results, repo, exclusions) -> list[dict]`, `build_packet.apply_filters(items, levels=None, rule=None, path_glob=None, reviewed_ids=None, limit=None) -> list[dict]`, `build_packet.reviewed_finding_ids(verdict_dir: Path) -> set[str]`. Задача 16 адресует находки по id из этих же структур.

- [ ] **Step 1: Открыть матчер**

`apply_filters` нуждается в том же глоб-матчере, что и политика. Импортировать приватное имя было бы хрупко. В `scripts/check_scope.py` дописать после `_matches`:

```python
def matches(path: str, pattern: str) -> bool:
    """Public entry point for the policy's glob matcher.

    Exposed so the triage queue can filter paths with exactly the semantics the
    exclusion policy uses, rather than growing a second, subtly different one.
    """
    return _matches(path, pattern)
```

- [ ] **Step 2: Написать падающие тесты**

Дописать в `tests/test_build_packet.py`, добавив в шапку `import json`, `import subprocess`, `import sys` и `from tests import REPO_ROOT`:

```python
class TestTriageQueue(unittest.TestCase):
    def items(self):
        results = build_packet.load_sarif_results(SARIF)
        # Annotate without a repo so ids come back None; the filters under test
        # do not depend on identity except through reviewed_ids.
        with temp_tree({}) as repo:
            return build_packet.annotate(results, repo, fixture_exclusions())

    def test_level_filter(self):
        out = build_packet.apply_filters(self.items(), levels=["error"])
        self.assertEqual([i["level"] for i in out], ["error"])

    def test_level_filter_accepts_several(self):
        out = build_packet.apply_filters(self.items(), levels=["error", "note"])
        self.assertEqual(len(out), 2)

    def test_rule_substring_filter(self):
        out = build_packet.apply_filters(self.items(), rule="injection")
        self.assertEqual(len(out), 1)
        self.assertIn("injection", out[0]["rule_id"])

    def test_path_glob_filter(self):
        out = build_packet.apply_filters(self.items(), path_glob="app/*.py")
        self.assertEqual({i["file"] for i in out}, {"app/handler.py", "app/db.py"})

    def test_filters_combine(self):
        out = build_packet.apply_filters(
            self.items(), levels=["error", "warning"], path_glob="app/*.py", limit=1
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["level"], "error")

    def test_sort_is_deterministic_and_severity_first(self):
        out = build_packet.apply_filters(self.items())
        self.assertEqual([i["level"] for i in out], ["error", "warning", "note"])

    def test_unreviewed_filter_hides_findings_with_verdicts(self):
        items = self.items()
        items[0]["finding_id"] = "F-aaaaaaaaaaaa"
        items[1]["finding_id"] = "F-bbbbbbbbbbbb"
        out = build_packet.apply_filters(items, reviewed_ids={"F-aaaaaaaaaaaa"})
        self.assertNotIn("F-aaaaaaaaaaaa", [i["finding_id"] for i in out])

    def test_reviewed_ids_are_read_from_verdict_filenames(self):
        with temp_tree(
            {"verdicts/F-aaaaaaaaaaaa.json": "{}", "verdicts/F-bbbbbbbbbbbb.json": "{}"}
        ) as root:
            found = build_packet.reviewed_finding_ids(root / "verdicts")
        self.assertEqual(found, {"F-aaaaaaaaaaaa", "F-bbbbbbbbbbbb"})

    def test_absent_verdict_directory_is_empty_not_an_error(self):
        with temp_tree({}) as root:
            self.assertEqual(build_packet.reviewed_finding_ids(root / "nope"), set())

    def test_index_caveat_leads_and_the_tally_ends_the_output(self):
        # This block has been reordered twice. The order is a requirement, not
        # a formatting preference, so it gets an assertion of its own.
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build_packet.py"),
                "--sarif", str(SARIF), "--list",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertIn("Indices are positions", lines[0])
        self.assertTrue(lines[-1].endswith("shown"), lines[-1])

    def test_json_output_is_machine_readable(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build_packet.py"),
                "--sarif", str(SARIF), "--list", "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload), 3)
        for item in payload:
            self.assertIn("finding_id", item)
            self.assertIn("in_scope", item)
            self.assertIn("level", item)
            self.assertIn("rule_id", item)

    def test_empty_sarif_list_json_is_an_empty_array(self):
        with temp_tree({"empty.sarif": '{"version": "2.1.0", "runs": []}'}) as root:
            sarif = root / "empty.sarif"
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "build_packet.py"),
                 "--sarif", str(sarif), "--list", "--json"],
                capture_output=True, text=True,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), [])

    def test_negative_limit_refuses_and_zero_is_empty(self):
        self.assertEqual(build_packet.apply_filters(self.items(), limit=0), [])
        with self.assertRaisesRegex(ValueError, r"--limit must not be negative, got -1"):
            build_packet.apply_filters(self.items(), limit=-1)

    def test_empty_sarif_selection_refuses_with_scan_guidance(self):
        with temp_tree({"empty.sarif": '{"version": "2.1.0", "runs": []}'}) as root:
            sarif = root / "empty.sarif"
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "build_packet.py"),
                 "--sarif", str(sarif), "--index", "0"],
                capture_output=True, text=True,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, f"No findings in {sarif}. Run `make scan` first.\n")
```

- [ ] **Step 3: Прогнать**

Run: `python3 -m unittest tests.test_build_packet.TestTriageQueue -v`
Expected: FAIL — `annotate` отсутствует.

- [ ] **Step 4: Реализовать очередь**

В `scripts/build_packet.py` добавить перед `def main`:

```python
# error first, because that is the order a reviewer wants to work in.
LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}


def annotate(results: list[dict], repo: Path, exclusions: list[dict]) -> list[dict]:
    """Attach identity and scope status to each result."""
    annotated = []
    for result in results:
        item = dict(result)
        try:
            item["finding_id"] = compute_finding_id(result, repo, exclusions)
        except (ScopeViolation, FileNotFoundError, ValueError):
            # Excluded, absent, or unidentifiable. Never read an excluded file
            # just to print a label for it.
            item["finding_id"] = None
        item["in_scope"] = _in_scope(result["file"], exclusions)
        annotated.append(item)
    return annotated


def reviewed_finding_ids(verdict_dir: Path) -> set[str]:
    """Ids that already have a verdict on disk, taken from filenames."""
    if not verdict_dir.exists():
        return set()
    return {path.stem for path in verdict_dir.glob("*.json")}


def apply_filters(
    items: list[dict],
    levels: list[str] | None = None,
    rule: str | None = None,
    path_glob: str | None = None,
    reviewed_ids: set[str] | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Narrow the queue using what the SARIF actually carries.

    Filtering is on scanner `level`, rule id and path — never on policy
    severity or priority class. Those are assigned by the agent during triage
    and do not exist yet at listing time; mapping SARIF levels onto them here
    would manufacture a confidence nobody earned.
    """
    out = list(items)
    if levels:
        wanted = {level.strip().lower() for level in levels if level.strip()}
        out = [i for i in out if i["level"].lower() in wanted]
    if rule:
        out = [i for i in out if rule.lower() in i["rule_id"].lower()]
    if path_glob:
        out = [i for i in out if check_scope_matches(i["file"], path_glob)]
    if reviewed_ids is not None:
        out = [i for i in out if i["finding_id"] not in reviewed_ids]
    out.sort(
        key=lambda i: (LEVEL_ORDER.get(i["level"].lower(), 9), i["file"], i["start_line"])
    )
    if limit is not None:
        # A negative limit would slice from the end and silently return a
        # different set than asked for. Refuse rather than guess.
        if limit < 0:
            raise ValueError(f"--limit must not be negative, got {limit}")
        out = out[:limit]
    return out
```

И расширить импорт в шапке файла:

```python
from check_scope import (  # noqa: E402
    ScopeViolation,
    check_path,
    load_policy,
    matches as check_scope_matches,
)
```

- [ ] **Step 5: Подключить к CLI**

Добавить аргументы в `main`:

```python
    parser.add_argument("--level", help="Comma-separated SARIF levels, e.g. error,warning")
    parser.add_argument("--rule", help="Substring match on the rule id")
    parser.add_argument("--path", dest="path_glob", help="Glob on the file path")
    parser.add_argument("--unreviewed", action="store_true",
                        help="Hide findings that already have a verdict on disk")
    parser.add_argument("--limit", type=int, help="Show at most N findings")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="Machine-readable output")
    parser.add_argument("--verdicts", type=Path,
                        default=REPO_ROOT / "findings" / "verdicts",
                        help="Where recorded verdicts live, for --unreviewed")
```

Сначала убрать ранний возврат, который перехватывает `--json`. Существующий блок

```python
    results = load_sarif_results(args.sarif)
    if not results:
        print("No findings in SARIF.")
        return 0
```

печатает человеческий текст раньше, чем ветка листинга успевает решить, что вывод
машинный, поэтому `--list --json` на пустом SARIF отдаёт не разбираемую строку
вместо `[]`. Заменить на

```python
    results = load_sarif_results(args.sarif)
```

Пустой список дальше обрабатывается сам собой: `annotate` и `apply_filters`
вернут пустое, `--json` напечатает `[]`, человеческий вывод — нули в сводке.
Сообщение остаётся нужным только для выбора конкретной находки, поэтому
переезжает в ветку выбора (шаг ниже).

Заменить блок листинга целиком:

```python
    if args.list or args.index is None:
        exclusions, _ = load_policy()
        items = annotate(results, args.repo, exclusions)
        shown = apply_filters(
            items,
            levels=args.level.split(",") if args.level else None,
            rule=args.rule,
            path_glob=args.path_glob,
            reviewed_ids=reviewed_finding_ids(args.verdicts) if args.unreviewed else None,
            limit=args.limit,
        )

        if args.as_json:
            print(json.dumps(shown, indent=2))
            return 0

        # "already reviewed" must be a subset of what this SARIF contains.
        # Counting every file in the verdict directory would fold in findings
        # from other scans and report a number nobody can reconcile.
        # How to read the list comes before the list. The reader needs the
        # caveat about indices while looking at them, not after scrolling past
        # everything they were meant to qualify.
        print("Indices are positions in this filtered list and change when the")
        print("filters change. Use the id for anything you want to reproduce:")
        print("  make triage ID=<finding-id>   or   make triage N=<index>\n")

        for i, item in enumerate(shown):
            flag = "" if item["in_scope"] else "  [OUT OF SCOPE]"
            label = item["finding_id"] or "(no id)"
            print(f"  [{i:>3}] {label}  {item['level']:<8} "
                  f"{item['file']}:{item['start_line']}{flag}")
            print(f"        {item['rule_id']}")

        # The tally is the last thing printed, with nothing after it. On a real
        # repository the list runs to hundreds of lines and anything above it
        # scrolls away unread. "already reviewed" is the intersection with this
        # SARIF: counting every file in the verdict directory would fold in
        # findings from other scans and report a number nobody can reconcile.
        on_disk = reviewed_finding_ids(args.verdicts)
        present = {i["finding_id"] for i in items if i["finding_id"]}
        reviewed = len(present & on_disk)
        print(f"\n{len(results)} finding(s) in SARIF, {reviewed} already "
              f"reviewed, {len(shown)} shown")
        return 0
```

Индексация в дальнейшем должна брать элемент из `shown`, а не из `results`. Заменить блок выбора:

```python
    exclusions, _ = load_policy()
    items = annotate(results, args.repo, exclusions)
    shown = apply_filters(
        items,
        levels=args.level.split(",") if args.level else None,
        rule=args.rule,
        path_glob=args.path_glob,
        reviewed_ids=reviewed_finding_ids(args.verdicts) if args.unreviewed else None,
        limit=args.limit,
    )

    if not results:
        print(f"No findings in {args.sarif}. Run `make scan` first.", file=sys.stderr)
        return 1

    if not 0 <= args.index < len(shown):
        print(f"Index out of range (0..{len(shown) - 1})", file=sys.stderr)
        return 1
    chosen = shown[args.index]
```

и передавать `chosen` в `build_triage_packet(chosen, args.repo, args.context_lines, exclusions)`.

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 7: Коммит**

```bash
git add scripts/build_packet.py scripts/check_scope.py tests/test_build_packet.py
git commit -m "feat: filter the triage queue by level, rule, path and review state"
```

---

### Task 16: Адресация находок по идентификатору

**Files:**
- Modify: `scripts/build_packet.py:200-280`
- Modify: `Makefile`
- Modify: `tests/test_build_packet.py`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `build_packet.annotate`.
- Produces: `--finding-id` в CLI, `make triage ID=`, `make list LEVEL= RULE= PATH= UNREVIEWED= LIMIT=`.

- [ ] **Step 1: Написать падающий тест**

```python
class TestFindingIdAddressing(unittest.TestCase):
    def run_builder(self, args):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "build_packet.py"), *args],
            capture_output=True,
            text=True,
        )

    def test_unknown_id_is_reported_and_non_zero(self):
        proc = self.run_builder(
            ["--sarif", str(SARIF), "--finding-id", "F-doesnotexist"]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("No finding with id F-doesnotexist", proc.stderr)

    def test_id_and_index_together_are_refused(self):
        proc = self.run_builder(
            ["--sarif", str(SARIF), "--finding-id", "F-x", "--index", "0"]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("pass either --finding-id or --index, not both", proc.stderr)
```

(`subprocess`, `sys` и `REPO_ROOT` уже импортированы в Task 15.)

Review correction: also add a Make-level regression that runs the real
`Makefile` from a temporary cwd containing two matching `app/*.py` files and a
temporary `scripts/build_packet.py` argv recorder. Assert that `make list
PATH_GLOB=app/*.py` supplies exactly one literal `app/*.py` value after
`--path`; this is red until the recipe quotes the value. Add a positive CLI
test with a hand-derived fixture id, a temporary source and output directory,
and `--level error --limit 0`; it must still build and write the identified
packet even though the filters make `shown` empty. This is characterization
coverage for existing filter-independent id selection and should pass before
the Makefile correction.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_build_packet.TestFindingIdAddressing -v`
Expected: FAIL — feature-specific id resolution and mutual-exclusion behavior are unavailable.

- [ ] **Step 3: Добавить аргумент и разрешение**

```python
    parser.add_argument("--finding-id",
                        help="Address a finding by id; survives filter changes")
```

Расширить условие листинга — до этой задачи оно не знало про id, и без правки
`--finding-id` без `--index` провалился бы в печать списка:

```python
    if args.list or (args.index is None and not args.finding_id):
```

Сразу после `args = parser.parse_args()`:

```python
    if args.finding_id and args.index is not None:
        parser.error("pass either --finding-id or --index, not both")
```

Task 15 already refuses an empty queue before index access. Preserve that
guard before adding id resolution; Task 16 must not move or replace it.
The remaining selection logic is:

```python
    if args.finding_id:
        matching = [i for i in items if i["finding_id"] == args.finding_id]
        if not matching:
            print(f"No finding with id {args.finding_id} in {args.sarif}.",
                  file=sys.stderr)
            print("Run --list to see the current ids. An id changes only when "
                  "the flagged code itself changes.", file=sys.stderr)
            return 1
        chosen = matching[0]
    else:
        if not 0 <= args.index < len(shown):
            print(f"Index out of range (0..{len(shown) - 1})", file=sys.stderr)
            return 1
        chosen = shown[args.index]
```

- [ ] **Step 4: Обновить Makefile**

```make
list:
	@python3 scripts/build_packet.py --sarif $(SARIF) --list \
		$(if $(LEVEL),--level $(LEVEL),) \
		$(if $(RULE),--rule $(RULE),) \
		$(if $(PATH_GLOB),--path "$(PATH_GLOB)",) \
		$(if $(UNREVIEWED),--unreviewed,) \
		$(if $(LIMIT),--limit $(LIMIT),)

triage:
	@python3 scripts/build_packet.py --sarif $(SARIF) --repo $(REPO) \
		$(if $(ID),--finding-id $(ID),--index $(N))
```

В блоке `help`:

```make
	@echo "  make list LEVEL=error UNREVIEWED=1   filtered triage queue"
	@echo "  make triage ID=F-abc      build a packet by finding id"
```

`PATH_GLOB`, а не `PATH`: `PATH` в make наследует переменную окружения и переопределять её нельзя. Quote `$(PATH_GLOB)` so the recipe passes one literal glob to the CLI instead of letting the shell expand it in the caller's cwd.

- [ ] **Step 5: Прогнать**

Run: `make test`
Expected: всё зелёное.

Run: `make list SARIF=tests/fixtures/sample.sarif LEVEL=error`
Expected: одна находка, подсказка про индекс в шапке, сводка последней строкой вывода.

- [ ] **Step 6: Коммит**

```bash
git add scripts/build_packet.py tests/test_build_packet.py Makefile \
  docs/superpowers/plans/2026-09-01-appsec-review-hardening.md \
  docs/superpowers/evidence/2026-09-01-plan-fixes.md
git commit -m "feat: address findings by id so filters cannot change what N means"
```

**Слой 4 завершён.**

---

# Слой 5 — решение человека и пересмотр вердиктов

### Task 17: Явный пересмотр вердикта

**Files:**
- Modify: `scripts/record_verdict.py`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Produces: `record_verdict.verdict_rows(path: Path, finding_id: str) -> list[dict]`, флаг `--supersede`, колонка `supersedes`.

- [ ] **Step 1: Написать падающий тест**

```python
class TestVerdictRows(unittest.TestCase):
    def test_verdict_rows_are_found(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{
                "finding_id": "F-000000000001",
                "id_scheme": "content-v1",
                "initial_verdict": "true_positive",
                "reviewed_at": "2026-09-01T10:00:00+00:00",
            }, {
                "finding_id": "F-000000000002",
                "id_scheme": "content-v1",
                "initial_verdict": "false_positive",
                "reviewed_at": "2026-09-01T11:00:00+00:00",
            }])
            rows = record_verdict.verdict_rows(log, "F-000000000001")
        self.assertEqual(
            [row["finding_id"] for row in rows], ["F-000000000001"]
        )

    def test_rows_without_a_verdict_are_not_counted(self):
        # Human-decision rows share the finding_id but decide on a verdict
        # rather than being one, so superseding must not see them.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{
                "finding_id": "F-000000000001",
                "human_decision": "accepted",
            }])
            self.assertEqual(record_verdict.verdict_rows(log, "F-000000000001"), [])

    def test_absent_log_has_no_rows(self):
        with temp_tree({}) as root:
            self.assertEqual(
                record_verdict.verdict_rows(root / "absent.csv", "F-1"), []
            )


class TestSupersedeCli(unittest.TestCase):
    """Re-recording must be a deliberate act. The log is append-only, so a
    silent second row would let metrics count one finding as two."""

    def write_verdict(self, root, **overrides):
        verdict = make_verdict(severity="low", evidence_level="partial", **overrides)
        (root / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    def run_recorder(self, root, extra=()):
        return subprocess.run(
            [
                sys.executable, str(REPO_ROOT / "scripts" / "record_verdict.py"),
                "--verdict", str(root / "verdict.json"),
                "--agent", "model-a",
                "--log", str(root / "triage-log.csv"),
                "--sarif-out", str(root / "reviewed.sarif"),
                *extra,
            ],
            capture_output=True,
            text=True,
        )

    def test_first_recording_succeeds(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            proc = self.run_recorder(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_second_recording_without_the_flag_is_refused(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)
            proc = self.run_recorder(root)
            rows = record_verdict.verdict_rows(
                root / "triage-log.csv", "F-000000000001"
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--supersede", proc.stderr)
        self.assertEqual(len(rows), 1, "a refused run must not append")

    def test_supersede_appends_and_points_back(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)

            revised = make_verdict(
                severity="low", evidence_level="partial", verdict="false_positive"
            )
            revised["reviewer"]["reviewed_at"] = "2026-09-02T10:00:00+00:00"
            (root / "verdict.json").write_text(json.dumps(revised), encoding="utf-8")

            proc = self.run_recorder(root, ["--supersede"])
            rows = record_verdict.verdict_rows(
                root / "triage-log.csv", "F-000000000001"
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["supersedes"], "2026-09-01T10:00:00+00:00")
        self.assertEqual(rows[1]["initial_verdict"], "false_positive")
```

Strengthen the CLI regressions as follows:

- Assert each subprocess return code and feature-specific stderr before calling
  `verdict_rows`, so a missing helper cannot mask the CLI assertion.
- In the supersede test, append a row with the same `finding_id` and blank
  `initial_verdict` between the second and third recordings. Assert that the
  third verdict supersedes the second verdict's `reviewed_at`, not the first
  verdict or the human-decision row.
- Add a duplicate-refusal ordering test. After a valid first recording, replace
  SARIF with malformed bytes and change the verdict's self-reported agent.
  Snapshot both artefacts and assert inside `temp_tree` that an unflagged
  duplicate is `REFUSED`, emits neither `WARNING` nor `SARIF ERROR`, and leaves
  both byte-for-byte unchanged.

- [ ] **Step 2: Прогнать focused RED и сохранить доказательство**

Run:

```bash
python3 -m unittest tests.test_record_verdict.TestVerdictRows tests.test_record_verdict.TestSupersedeCli -v
```

Expected: the new tests fail because `verdict_rows` and `--supersede` do not
exist yet. Record the genuine failure output in
`docs/superpowers/evidence/2026-09-01-red-tests.md`.

Mutation proof after the implementation is restored:

```bash
python3 -m unittest \
  tests.test_record_verdict.TestSupersedeCli.test_second_recording_without_the_flag_is_refused -v
python3 -m unittest \
  tests.test_record_verdict.TestSupersedeCli.test_supersede_appends_and_points_back -v
python3 -m unittest \
  tests.test_record_verdict.TestSupersedeCli.test_duplicate_refusal_precedes_warnings_and_sarif_parsing -v
```

Temporarily disable duplicate refusal, disable `--supersede`, and move duplicate
detection after warnings and SARIF parsing, respectively. Each command must
fail at its subprocess/output assertion; restore production code after each
mutation and record the outputs in RED evidence.

- [ ] **Step 3: Реализовать**

Дописать в `scripts/record_verdict.py`:

```python
def verdict_rows(path: Path, finding_id: str) -> list[dict]:
    """Previously recorded verdicts for one finding.

    Human-decision rows share the finding_id but carry no initial_verdict, so
    they are excluded here: superseding a verdict is a different act from
    deciding on one.
    """
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [
            row
            for row in csv.DictReader(fh)
            if row.get("finding_id") == finding_id and row.get("initial_verdict")
        ]
```

Добавить `"supersedes"` в `LOG_FIELDS` (перед `"notes"`), флаг и проверку:

```python
    parser.add_argument("--supersede", action="store_true",
                        help="Record a revision of a verdict already in the log")
```

After log compatibility, verdict and challenge schema validation, consistency
validation, and challenge-ID matching, but before warnings, SARIF parsing,
`append_log`, or any write:

```python
    prior = verdict_rows(args.log, verdict["finding_id"])
    if prior and not args.supersede:
        print(f"REFUSED: {verdict['finding_id']} already has a verdict recorded "
              f"at {prior[-1].get('reviewed_at', 'an unknown time')}.\n",
              file=sys.stderr)
        print("Pass --supersede to record a revision. The log stays append-only:\n"
              "the earlier row remains and the new one points back at it.",
              file=sys.stderr)
        return 2
```

И в словарь строки лога:

```python
            "supersedes": prior[-1].get("reviewed_at", "") if prior else "",
```

- [ ] **Step 4: Прогнать и закоммитить**

Run: `make test`
Expected: всё зелёное.

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py \
  docs/superpowers/plans/2026-09-01-appsec-review-hardening.md \
  docs/superpowers/evidence/2026-09-01-red-tests.md \
  docs/superpowers/evidence/2026-09-01-plan-fixes.md
git commit -m "feat: require --supersede to revise a recorded verdict"
```

---

### Task 18: Запись решения человека

**Files:**
- Create: `scripts/record_human_decision.py`
- Create: `tests/test_human_decision.py`
- Modify: `scripts/record_verdict.py` (`LOG_FIELDS`)
- Modify: `Makefile`
- Modify: `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict.append_log`, `record_verdict.check_log_compatible`, `record_verdict.verdict_rows`, `record_verdict.load_existing_results`, `record_verdict.sarif_document`, `record_verdict.ID_SCHEME`.
- Produces: колонки `human_decision`, `human_decision_at`, `human_decision_by`, `human_rationale`; цель `make decide`.

- [ ] **Step 1: Написать падающие тесты и зафиксировать RED**

Сначала создать `tests/test_human_decision.py` и выполнить:

```text
python3 -m unittest tests.test_human_decision -v
```

Записать настоящий RED в `docs/superpowers/evidence/2026-09-01-red-tests.md`.
В частности, `test_invalid_decision_is_refused` обязан требовать
feature-specific сообщение argparse `invalid choice`, чтобы отсутствующий скрипт
не мог удовлетворить тест только non-zero кодом.

`tests/test_human_decision.py`:

```python
"""Tests for the ground-truth record.

Without a human decision the programme can describe what the pipeline did but
not whether it was right, and that is the question a pilot exists to answer.
"""

import csv
import json
import subprocess
import sys
import unittest

import record_verdict
from tests import REPO_ROOT
from tests.helpers import temp_tree, write_log

SCRIPT = REPO_ROOT / "scripts" / "record_human_decision.py"


def verdict_row(fid="F-000000000001"):
    return {
        "reviewed_at": "2026-09-01T10:00:00+00:00",
        "finding_id": fid,
        "id_scheme": "content-v1",
        "initial_verdict": "true_positive",
        "final_state": "confirmed",
        "severity": "high",
        "agent": "model-a",
        "validator": "model-b",
    }


class TestDecisionRecording(unittest.TestCase):
    def run_script(self, args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
        )

    def test_unknown_finding_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-nope", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("F-nope", proc.stderr)

    def test_invalid_decision_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "maybe",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
        ])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr)

    def test_decision_is_appended_to_the_log(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "rejected",
                "--by", "appsec-oncall", "--rationale", "sanitiser upstream",
                "--log", str(log), "--sarif", str(root / "reviewed.sarif"),
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with log.open(encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["human_decision"], "rejected")
        self.assertEqual(rows[-1]["human_decision_by"], "appsec-oncall")
        self.assertEqual(rows[-1]["finding_id"], "F-000000000001")

    def test_stale_log_header_is_refused_and_nothing_is_written(self):
        # A log written before a column existed. Its verdict row is still
        # readable, so the run gets past the "no verdict" check and reaches the
        # log contract, which must refuse rather than append under old names.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            stale_fields = [f for f in record_verdict.LOG_FIELDS if f != "notes"]
            values = {
                "finding_id": "F-000000000001",
                "initial_verdict": "true_positive",
                "final_state": "confirmed",
                "reviewed_at": "2026-09-01T10:00:00+00:00",
            }
            with log.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=stale_fields)
                writer.writeheader()
                writer.writerow({k: values.get(k, "") for k in stale_fields})
            before = log.read_text(encoding="utf-8")
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
            after = log.read_text(encoding="utf-8")
            self.assertEqual(before, after, "a refused run must not append")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("LOG ERROR", proc.stderr)

    def test_malformed_sarif_refuses_and_leaves_the_log_untouched(self):
        # Regression for the ordering fix: the SARIF is parsed before anything
        # is written, because the triage log is append-only and a row added
        # ahead of a SARIF failure could never be withdrawn.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            write_log(log, [verdict_row()])
            sarif.write_text("{ not json", encoding="utf-8")
            before = log.read_text(encoding="utf-8")
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log), "--sarif", str(sarif),
            ])
            after = log.read_text(encoding="utf-8")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SARIF ERROR", proc.stderr)
        self.assertEqual(before, after, "a refused run must not append to the log")

    def test_sarif_properties_are_updated(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            write_log(log, [verdict_row()])
            result = record_verdict.build_result(
                {
                    "finding_id": "F-000000000001",
                    "severity": "high",
                    "reasoning": "text",
                    "location": {"file": "app/handler.py", "start_line": 4},
                },
                None,
                "confirmed",
                "rationale",
            )
            sarif.write_text(
                json.dumps(record_verdict.sarif_document([result])), encoding="utf-8"
            )
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log), "--sarif", str(sarif),
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            results = record_verdict.load_existing_results(sarif)
        self.assertEqual(results[0]["properties"]["human_decision"], "accepted")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Расширить набор колонок**

В `scripts/record_verdict.py` добавить в `LOG_FIELDS` перед `"supersedes"`:

```python
    "human_decision", "human_decision_at", "human_decision_by", "human_rationale",
```

- [ ] **Step 3: Написать скрипт**

`scripts/record_human_decision.py`:

```python
#!/usr/bin/env python3
"""Record the human's decision on a reviewed finding.

CLAUDE.md opens by saying every verdict is a recommendation that a human
accepts, rejects, or escalates. Nothing recorded that decision, so the
programme had no ground truth: metrics could describe what the pipeline did,
but never whether it was right.

The subject of the decision is the pipeline's final_state, not the agent's
original verdict. Two people reading this field differently would make the
number meaningless, so it is stated here and in docs/04.

There is deliberately no JSON schema for this input. The schemas in templates/
are output contracts for a model. A human typing at a terminal is validated by
argparse and an enum; adding a schema here would blur a line worth keeping.

Do not put personal data in --by. The triage log is committed (docs/03), so a
name or an email address becomes a permanent part of repository history. Use a
role or a work handle.

Usage:
    record_human_decision.py --finding-id F-abc --decision rejected \\
                             --by appsec-oncall --rationale "sanitiser upstream"
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_verdict import (  # noqa: E402
    ID_SCHEME,
    LOG_PATH,
    SARIF_OUT,
    ValidationError,
    append_log,
    check_log_compatible,
    load_existing_results,
    sarif_document,
    verdict_rows,
)

DECISIONS = ("accepted", "rejected", "escalated")


def latest_verdict_row(path: Path, finding_id: str) -> dict | None:
    """The most recent recorded verdict for a finding, if there is one.

    Delegates to record_verdict.verdict_rows so that "what counts as a verdict
    row" is defined once. Two copies of that predicate would drift the moment
    a new row type appears.
    """
    rows = verdict_rows(path, finding_id)
    return rows[-1] if rows else None


def find_sarif_result(results: list[dict], finding_id: str) -> dict | None:
    for result in results:
        if result.get("properties", {}).get("finding_id") == finding_id:
            return result
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--decision", required=True, choices=DECISIONS,
                        help="Whether the human accepts the pipeline's final state")
    parser.add_argument("--by", required=True,
                        help="Role or work handle. Not a name or an email address: "
                             "the triage log is committed.")
    parser.add_argument("--rationale", default="")
    parser.add_argument("--minutes", type=float)
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--sarif", type=Path, default=SARIF_OUT)
    args = parser.parse_args()

    verdict_row = latest_verdict_row(args.log, args.finding_id)
    if verdict_row is None:
        print(f"REFUSED: no recorded verdict for {args.finding_id} in {args.log}.",
              file=sys.stderr)
        print("\nRecord the verdict first. A decision with nothing to decide on "
              "would sit in the log describing nothing.", file=sys.stderr)
        return 2

    # Same log contract as record_verdict, invoked rather than reimplemented.
    # A stale header would file this row's values under old column names, and a
    # foreign identity scheme means the ids already in the log do not mean what
    # this row's id means.
    try:
        check_log_compatible(args.log, ID_SCHEME)
    except ValidationError as exc:
        print(f"LOG ERROR: {exc}", file=sys.stderr)
        return 1

    # Parse the SARIF before writing anything. The triage log is append-only,
    # so a row written before a SARIF failure could never be taken back and the
    # two artefacts would disagree permanently.
    try:
        results = load_existing_results(args.sarif)
    except ValidationError as exc:
        print(f"SARIF ERROR: {exc}", file=sys.stderr)
        return 1
    target = find_sarif_result(results, args.finding_id)

    decided_at = datetime.now(timezone.utc).isoformat()
    append_log(
        {
            "reviewed_at": decided_at,
            "finding_id": args.finding_id,
            "id_scheme": verdict_row.get("id_scheme", ""),
            "rule_id": verdict_row.get("rule_id", ""),
            "file": verdict_row.get("file", ""),
            "line": verdict_row.get("line", ""),
            "severity": verdict_row.get("severity", ""),
            "final_state": verdict_row.get("final_state", ""),
            "minutes_spent": args.minutes if args.minutes is not None else "",
            "human_decision": args.decision,
            "human_decision_at": decided_at,
            "human_decision_by": args.by,
            "human_rationale": args.rationale,
        },
        args.log,
    )

    if target is not None:
        target["properties"].update(
            {
                "human_decision": args.decision,
                "human_decision_at": decided_at,
                "human_decision_by": args.by,
                "human_rationale": args.rationale,
            }
        )
        args.sarif.write_text(
            json.dumps(sarif_document(results), indent=2), encoding="utf-8"
        )

    print(f"{args.finding_id}: {args.decision} by {args.by}")
    print(f"  logged -> {args.log}")
    if target is not None:
        print(f"  sarif  -> {args.sarif}")
    else:
        print(f"  note: {args.finding_id} is not in {args.sarif}; log updated only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Добавить цель make**

```make
decide:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@test -n "$(DECISION)" || (echo "Set DECISION=accepted|rejected|escalated" && exit 1)
	@test -n "$(BY)" || (echo "Set BY=<role or work handle, not a name>" && exit 1)
	@python3 scripts/record_human_decision.py --finding-id $(ID) \
		--decision $(DECISION) --by "$(BY)" \
		$(if $(RATIONALE),--rationale "$(RATIONALE)",)
```

Дописать `decide` в `.PHONY` и строку в `help`:

```make
	@echo "  make decide ID=F-abc DECISION=rejected BY=appsec-oncall"
```

- [ ] **Step 5: Проверить GREEN и доказать контролы мутациями**

Выполнить focused GREEN:

```text
python3 -m unittest tests.test_human_decision -v
```

После GREEN, до коммита, выполнить и восстановить обе мутации, записав команды,
релевантный вывод и восстановление в `red-tests.md` и отчёте:

1. Временно убрать или обойти `check_log_compatible`, затем выполнить
   `test_stale_log_header_is_refused_and_nothing_is_written`; он должен стать RED
   именно потому, что лог вырос. Восстановить shared compatibility call.
2. Временно заменить импортированный shared `append_log` локальным appender с
   прежним `exists = path.exists()` решением заголовка. Напрямую вызвать этот
   exact Task 18 appender symbol на существующем zero-byte temp log с
   representative decision row (или equally direct behavioural probe) и
   подтвердить, что его первая/единственная строка -- data row, а не
   `LOG_FIELDS` header. Восстановить imported shared appender.

После каждого восстановления вновь выполнить focused тесты, затем full suite.

- [ ] **Step 6: Прогнать и закоммитить**

Run: `make test`
Expected: всё зелёное.

```bash
git add scripts/record_human_decision.py scripts/record_verdict.py tests/test_human_decision.py Makefile \
  docs/superpowers/plans/2026-09-01-appsec-review-hardening.md \
  docs/superpowers/evidence/2026-09-01-red-tests.md \
  docs/superpowers/evidence/2026-09-01-plan-fixes.md
git commit -m "feat: record the human decision as programme ground truth"
```

---

### Task 19: Метрики считают находки и знают точность

**Files:**
- Modify: `scripts/metrics.py:56-211`
- Modify: `tests/test_metrics.py`
- Modify: `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`
- Modify: `docs/superpowers/specs/2026-09-01-appsec-review-hardening-design.md`

**Interfaces:**
- Consumes: колонки из задач 13, 17, 18.
- Produces: `metrics.collapse(rows) -> list[dict]`; ключи `dismissal_rate_pct`, `human_decisions`, `human_decision_coverage_pct`, `agent_accuracy_pct`, `revisions`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_metrics.py`, и заменить обращения к `false_positive_rate_pct` на `dismissal_rate_pct` в существующем `test_rate_excludes_undecided_findings`:

```python
class TestCollapse(unittest.TestCase):
    """The log is append-only, so one finding can occupy several rows. Counting
    rows would report a revised finding as two findings."""

    def test_superseded_verdict_counts_once(self):
        rows = [
            row(final_state="confirmed"),
            row(final_state="dismissed", reviewed_at="2026-09-02T10:00:00+00:00",
                supersedes="2026-09-01T10:00:00+00:00"),
        ]
        collapsed = metrics.collapse(rows)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["final_state"], "dismissed")

    def test_human_decision_row_merges_into_the_finding(self):
        rows = [
            row(final_state="confirmed"),
            {"finding_id": "F-000000000001", "human_decision": "rejected",
             "human_decision_by": "appsec-oncall", "initial_verdict": ""},
        ]
        collapsed = metrics.collapse(rows)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["final_state"], "confirmed")
        self.assertEqual(collapsed[0]["human_decision"], "rejected")

    def test_latest_wins_regardless_of_input_order(self):
        newer = row(final_state="dismissed", reviewed_at="2026-09-02T10:00:00+00:00",
                    supersedes="2026-09-01T10:00:00+00:00")
        older = row(final_state="confirmed")
        collapsed = metrics.collapse([newer, older])
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["final_state"], "dismissed")

    def test_missing_or_malformed_timestamps_have_a_stable_fallback(self):
        rows = [
            row(final_state="confirmed", reviewed_at="not-a-timestamp"),
            row(final_state="dismissed", reviewed_at=""),
        ]
        self.assertEqual(metrics.collapse(rows),
                         metrics.collapse(list(reversed(rows))))

    def test_revisions_are_counted_before_collapse(self):
        rows = [
            row(),
            row(reviewed_at="2026-09-02T10:00:00+00:00", supersedes="2026-09-01T10:00:00+00:00"),
        ]
        self.assertEqual(metrics.compute(rows)["revisions"], 1)


class TestAgentAccuracy(unittest.TestCase):
    def compute(self, rows):
        return metrics.compute(rows)

    def test_accuracy_uses_only_rows_with_a_decision(self):
        m = self.compute([
            row(finding_id="F-1", human_decision="accepted"),
            row(finding_id="F-2", human_decision="accepted"),
            row(finding_id="F-3", human_decision="rejected"),
            row(finding_id="F-4"),
        ])
        self.assertEqual(m["human_decisions"], 3)
        self.assertAlmostEqual(m["agent_accuracy_pct"], 66.7, places=1)

    def test_escalated_is_not_counted_as_right_or_wrong(self):
        m = self.compute([
            row(finding_id="F-1", human_decision="accepted"),
            row(finding_id="F-2", human_decision="escalated"),
        ])
        self.assertEqual(m["agent_accuracy_pct"], 100.0)

    def test_no_decisions_leaves_accuracy_undefined(self):
        self.assertIsNone(self.compute([row()])["agent_accuracy_pct"])

    def test_human_review_decisions_do_not_inflate_decided_coverage(self):
        m = self.compute([
            row(finding_id="F-1", human_decision="accepted"),
            row(finding_id="F-2", final_state="dismissed"),
            row(finding_id="F-3", final_state="human_review",
                human_decision="rejected"),
        ])
        self.assertEqual(m["human_decisions"], 2)
        self.assertEqual(m["human_decision_coverage_pct"], 50.0)
        self.assertLessEqual(m["human_decision_coverage_pct"], 100.0)
        self.assertEqual(m["agent_accuracy_pct"], 50.0)

    def test_low_coverage_warns_in_the_render(self):
        m = self.compute([
            row(finding_id=f"F-{i}", human_decision="accepted" if i == 0 else "")
            for i in range(10)
        ])
        self.assertIn("biased subset", metrics.render(m))

    def test_dismissal_rate_is_no_longer_called_accuracy(self):
        m = self.compute([row(final_state="dismissed")])
        self.assertIn("dismissal_rate_pct", m)
        self.assertNotIn("false_positive_rate_pct", m)
```

Расширить фабрику `row()`, добавив ключи по умолчанию: `"human_decision": ""`, `"supersedes": ""`.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_metrics -v`
Expected: FAIL — `collapse` отсутствует, ключ переименован.

- [ ] **Step 3: Схлопнуть строки в находки**

Два типа строк означают разное и сливаются по-разному. Строка вердикта замещает
вердикт целиком; строка решения накладывает на него поля решения. Ничья по
времени разрешается позицией в логе.

В `scripts/metrics.py` добавить перед `compute`:

```python
DECISION_FIELDS = (
    "human_decision", "human_decision_at", "human_decision_by", "human_rationale",
)


def _is_verdict_row(row: dict) -> bool:
    return bool(row.get("initial_verdict"))


def _minutes(row: dict) -> float | None:
    try:
        return float(row["minutes_spent"])
    except (KeyError, TypeError, ValueError):
        return None


def collapse(rows: list[dict]) -> list[dict]:
    """One record per finding.

    Two row types with different merge rules, because they mean different
    things. A verdict row REPLACES the verdict wholesale, empty fields
    included: re-triaging without a challenge must not inherit the previous
    run's challenge_result, or the log would assert a second pass that never
    ran. A human-decision row PATCHES the decision fields onto whichever
    verdict stands.

    Ties on reviewed_at fall back to position in the log. Ties are ordinary,
    not exotic: reviewed_at comes from the verdict JSON, so re-recording the
    same file repeats it. The log is append-only and written in order, which
    makes position the only surviving evidence of sequence.
    """
    ordered = sorted(
        enumerate(rows),
        key=lambda pair: (pair[1].get("reviewed_at", ""), pair[0]),
    )

    verdicts: dict[str, dict] = {}
    decisions: dict[str, dict] = {}
    triage_minutes: dict[str, list] = {}
    decision_minutes: dict[str, list] = {}
    last_event: dict[str, str] = {}

    for _, row in ordered:
        fid = row.get("finding_id")
        if not fid:
            continue

        stamp = row.get("reviewed_at", "")
        if stamp > last_event.get(fid, ""):
            last_event[fid] = stamp

        minutes = _minutes(row)
        if _is_verdict_row(row):
            verdicts[fid] = {
                k: v for k, v in row.items() if k not in DECISION_FIELDS
            }
            if minutes is not None:
                triage_minutes.setdefault(fid, []).append(minutes)
        elif row.get("human_decision"):
            decisions[fid] = {k: row.get(k, "") for k in DECISION_FIELDS}
            if minutes is not None:
                decision_minutes.setdefault(fid, []).append(minutes)

    collapsed = []
    for fid in sorted(verdicts.keys() | decisions.keys()):
        record = dict(verdicts.get(fid, {}))
        record.update(decisions.get(fid, {}))
        record["finding_id"] = fid
        record["last_event_at"] = last_event.get(fid, "")
        triage = triage_minutes.get(fid, [])
        decided = decision_minutes.get(fid, [])
        record["triage_minutes_total"] = sum(triage) if triage else None
        record["decision_minutes_total"] = sum(decided) if decided else None
        collapsed.append(record)
    return collapsed
```

- [ ] **Step 4: Перенести `--since` за схлопывание**

Отсев строк до схлопывания оставляет свежую строку решения без её вердикта, и
находка входит в метрики без состояния, уровня доказательности и времени.
Фильтровать надо находки, а не строки.

Убрать блок `if since:` из `load_rows` целиком, оставив чтение:

```python
def load_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
```

И добавить фильтр по находкам:

```python
def filter_since(records: list[dict], since: str | None) -> list[dict]:
    """Keep findings whose most recent event falls in the window.

    Applied after collapse, never before. Filtering raw rows would strand a
    recent decision row without the older verdict row it describes, and that
    finding would reach the metrics with no state and no timing - counted, but
    counted as nothing.

    A finding enters whole or not at all: if its latest event is in the window,
    its entire history comes with it, because "decided in August" is
    meaningless without the July verdict it decided on.
    """
    if not since:
        return records
    cutoff = datetime.fromisoformat(since)
    kept = []
    for record in records:
        stamp = (record.get("last_event_at") or "").replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(stamp)
        except ValueError:
            continue
        if moment.replace(tzinfo=None) >= cutoff:
            kept.append(record)
    return kept
```

В `main` заменить получение строк:

```python
    records = filter_since(collapse(load_rows(args.log)), args.since)
    m = compute(records)
```

`compute` теперь принимает уже схлопнутые записи, поэтому убрать из него вызов
`collapse` и считать `revisions` до схлопывания — перенести подсчёт в `collapse`,
записывая в каждую запись `revision_count`, и суммировать в `compute`.

```python
        record["revision_count"] = max(0, len(triage_minutes.get(fid, [])) - 1)
```

Это приблизительная величина: она считает только пересмотры с указанным
временем. Точнее — считать строки вердикта; для этого вести отдельный счётчик
`verdict_rows_seen[fid]` и записывать `len - 1`.

- [ ] **Step 5: Пересчитать величины**

В `compute` заменить блок расчёта:

```python
    total = len(rows)
    if total == 0:
        return {"total": 0}

    revisions = sum(r.get("revision_count", 0) for r in rows)
    ...
    dismissal_rate = (states["dismissed"] / decided * 100) if decided else None

    decisions = Counter(
        r.get("human_decision") for r in rows if r.get("human_decision")
    )
    judged = decisions["accepted"] + decisions["rejected"]
    covered_decided = sum(
        1 for r in rows if r.get("human_decision") and r["final_state"] in ("confirmed", "dismissed")
    )
    coverage = (covered_decided / decided * 100) if decided else None
    # No decided findings means no denominator, so no rate. The counts below
    # are facts and still print; the derived share does not, because there is
    # nothing to divide by. Same rule as evidence_level: report what was
    # established, withhold the rest.
    accuracy = (decisions["accepted"] / judged * 100) if (judged and decided) else None
```

Времена берутся из схлопнутых записей:

```python
    times = [
        r["triage_minutes_total"]
        for r in rows
        if r.get("triage_minutes_total") is not None
    ]
    decision_times = [
        r["decision_minutes_total"]
        for r in rows
        if r.get("decision_minutes_total") is not None
    ]
```

В возвращаемый словарь добавить `"decision_minutes_total"` рядом с остальными
временами и `"revisions": revisions`.

- [ ] **Step 5b: Переписать вывод**

Блок 2 переименовать в `DISMISSAL RATE` с пояснением, что это действие
конвейера, а не его правота, и ссылкой на блок 5.

Блок 5 `AGENT ACCURACY (ground truth)` печатает счётчики всегда, а долю — только
когда она определена:

```python
    if m["human_decisions"]:
        add(f"  Human decisions recorded {m['human_decisions']}")
        for name in ("accepted", "rejected", "escalated"):
            if name in m["human_decision_breakdown"]:
                add(f"  {name:<24} {m['human_decision_breakdown'][name]}")
        coverage = m["human_decision_coverage_pct"]
        if coverage is None:
            add("")
            add("  ! No findings have reached a decided state, so coverage and")
            add("    accuracy have no denominator. The counts above stand; the")
            add("    rates are not computed rather than guessed.")
        else:
            add(f"  Coverage                 {coverage}%")
            if m["agent_accuracy_pct"] is not None:
                add(f"  Agent accuracy           {m['agent_accuracy_pct']}%")
            if coverage < 50:
                add("")
                add("  ! Fewer than half the decided findings carry a human")
                add("    decision, so the accuracy above rests on a biased")
                add("    subset. Record decisions before quoting it.")
    else:
        add("  No human decisions recorded. Without them the programme can")
        add("  describe what the pipeline did but not whether it was right,")
        add("  which is the question a pilot exists to answer.")
        add("  Record them with: make decide ID=<id> DECISION=<d> BY=<role>")
    if m["revisions"]:
        add("")
        add(f"  Verdicts revised         {m['revisions']}")
```

Отдельной строкой в блоке 1 — время решений, чтобы его не путали с триажем:

```python
    if m["decision_minutes_total"] is not None:
        add(f"  Human decision time      {m['decision_minutes_total']} min "
            "(separate from triage)")
```

All render sections not explicitly replaced above remain intact. Preserve the
full timing guidance, confirmed severity and parked-proof reporting, validation
independence alarms (including same-model and high-disagreement warnings),
evidence-quality percentages/guidance, and the header/totals/footer. Add
observable regressions for zero/high disagreement, same-model validation, and
parked runtime proof rendering. The no-timing regression must retain both the
`--minutes` instruction and the primary-success-measure warning.

- [ ] **Step 5c: Тесты на принятые решения**

Дописать в `tests/test_metrics.py`:

```python
class TestCollapseSemantics(unittest.TestCase):
    def test_new_verdict_does_not_inherit_the_old_challenge(self):
        first = row(challenge_result="upheld", validator="model-b")
        second = row(
            reviewed_at="2026-09-02T10:00:00+00:00",
            challenge_result="",
            validator="",
            supersedes="2026-09-01T10:00:00+00:00",
        )
        collapsed = metrics.collapse([first, second])
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["challenge_result"], "")
        self.assertEqual(collapsed[0]["validator"], "")

    def test_decision_survives_a_later_verdict_revision(self):
        collapsed = metrics.collapse([
            row(),
            {"finding_id": "F-000000000001", "human_decision": "rejected",
             "reviewed_at": "2026-09-02T10:00:00+00:00"},
            row(reviewed_at="2026-09-03T10:00:00+00:00", final_state="dismissed"),
        ])
        self.assertEqual(collapsed[0]["human_decision"], "rejected")
        self.assertEqual(collapsed[0]["final_state"], "dismissed")

    def test_equal_timestamps_break_by_log_position(self):
        first = row(final_state="confirmed")
        second = row(final_state="dismissed")
        self.assertEqual(
            metrics.collapse([first, second])[0]["final_state"], "dismissed"
        )
        self.assertEqual(
            metrics.collapse([second, first])[0]["final_state"], "confirmed"
        )

    def test_triage_minutes_sum_across_revisions(self):
        collapsed = metrics.collapse([
            row(minutes_spent="10"),
            row(reviewed_at="2026-09-02T10:00:00+00:00", minutes_spent="4"),
        ])
        self.assertEqual(collapsed[0]["triage_minutes_total"], 14.0)

    def test_decision_minutes_stay_separate(self):
        collapsed = metrics.collapse([
            row(minutes_spent="10"),
            {"finding_id": "F-000000000001", "human_decision": "accepted",
             "minutes_spent": "3", "reviewed_at": "2026-09-02T10:00:00+00:00"},
        ])
        self.assertEqual(collapsed[0]["triage_minutes_total"], 10.0)
        self.assertEqual(collapsed[0]["decision_minutes_total"], 3.0)


class TestSinceSelectsFindings(unittest.TestCase):
    def test_a_finding_enters_whole_or_not_at_all(self):
        # Verdict in July, decision in September. Filtering rows would keep the
        # decision and drop the verdict, leaving a stateless finding.
        records = metrics.collapse([
            row(reviewed_at="2026-07-01T10:00:00+00:00", final_state="confirmed"),
            {"finding_id": "F-000000000001", "human_decision": "accepted",
             "reviewed_at": "2026-09-01T10:00:00+00:00"},
        ])
        kept = metrics.filter_since(records, "2026-08-01")
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["final_state"], "confirmed")
        self.assertEqual(kept[0]["human_decision"], "accepted")

    def test_untouched_findings_fall_outside_the_window(self):
        records = metrics.collapse([row(reviewed_at="2026-07-01T10:00:00+00:00")])
        self.assertEqual(metrics.filter_since(records, "2026-08-01"), [])


class TestUndefinedDenominator(unittest.TestCase):
    def test_accuracy_is_withheld_when_nothing_is_decided(self):
        m = metrics.compute(metrics.collapse([
            row(final_state="human_review", challenge_result="refuted"),
            {"finding_id": "F-000000000001", "human_decision": "accepted",
             "reviewed_at": "2026-09-02T10:00:00+00:00"},
        ]))
        self.assertEqual(m["decided"], 0)
        self.assertIsNone(m["human_decision_coverage_pct"])
        self.assertIsNone(m["agent_accuracy_pct"])
        self.assertEqual(m["human_decisions"], 1)
        self.assertIn("not computed rather than guessed", metrics.render(m))
```

Существующие тесты, вызывающие `metrics.compute(rows)` на сырых строках, теперь
обязаны передавать `metrics.collapse(rows)`. Обновить их — это не смена
поведения, а перенос ответственности за схлопывание из `compute` в вызывающего.

- [ ] **Step 6: Прогнать и закоммитить**

Run: `make test`
Expected: всё зелёное.

```bash
git add scripts/metrics.py tests/test_metrics.py \
  docs/superpowers/plans/2026-09-01-appsec-review-hardening.md \
  docs/superpowers/specs/2026-09-01-appsec-review-hardening-design.md \
  docs/superpowers/evidence/2026-09-01-red-tests.md \
  docs/superpowers/evidence/2026-09-01-plan-fixes.md
git commit -m "feat: collapse rows into findings and report agent accuracy"
```

**Слой 5 завершён.**

---

# Слой 6 — доки против кода

### Task 20: Привести документацию в соответствие

**Files:**
- Modify: `README.md`, `docs/02-setup.md`, `docs/03-data-handling.md`, `docs/04-procedures.md`, `docs/07-graduation.md`, `CLAUDE.md`, `Makefile`
- Modify: `templates/verdict.schema.json`, `templates/challenge.schema.json`, `prompts/adversarial-validate.md`
- Modify: `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`, `docs/superpowers/evidence/2026-09-01-red-tests.md`, `docs/superpowers/evidence/2026-09-01-plan-fixes.md`
- Create: `scripts/check_template.py`, `tests/test_check_template.py`
- Create: `tests/test_makefile.py`
- Create: `templates/threat-model.md`

**Interfaces:**
- Consumes: всё построенное выше.
- Produces: цель `make check-template`.

- [ ] **Step 1: README**

Заменить таблицу Layout — строка `templates/` описывает несуществующие файлы:

```markdown
| `templates/` | Verdict and challenge schemas, threat-model template |
```

Добавить раздел после Quick start:

```markdown
## Status

Working: scan, triage queue, packet builder, scope enforcement, verdict
recording, human decisions, metrics, tests.

**Not implemented.** These are placeholders and will tell you so when run:

- `goldenset/run_goldenset.py` — no regression cases are configured. Until they
  are, the graduation criterion that depends on them cannot be met; see
  `docs/07-graduation.md`.
- `scripts/import_defectdojo.py` — no DefectDojo credentials or import settings.
  Reviewed findings are in `findings/reviewed.sarif` and can be imported by hand.

## Tests

```bash
make test
```

Standard library only, no network, no scanner required. If it needs a
`pip install` to run, that is a bug.

## The triage queue

`make list` shows every finding. On a real repository that is hundreds, so it
filters:

```bash
make list LEVEL=error UNREVIEWED=1
make list RULE=injection LIMIT=20
make triage ID=F-abc123
```

Filters work on what the SARIF carries — scanner `level`, rule id, path. They
deliberately do not filter on policy severity or priority class: those are
assigned by the agent during triage and do not exist yet at listing time.

Indices shift when filters change, so use `ID=` for anything you want to
reproduce or put in a ticket.
```

Добавить в конце секции про нумерацию:

```markdown
Documentation files follow an internal series, so the numbering has gaps.
```

**Привести Quick start в соответствие с обязательными аргументами.** Сейчас он
учит `make record ID=<finding-id>`, что после слоя 2 не работает и выводит
читателя прямо на контроль независимости без объяснения. Заменить второй блок
команд:

```bash
make validate ID=F-abc123   # build the adversarial challenge packet
make record ID=F-abc123 AGENT=<triage model> VALIDATOR=<validation model> MINUTES=12
make decide ID=F-abc123 DECISION=accepted BY=appsec-oncall
make metrics                # how the programme is actually performing
```

Следом абзац: `make record` отказывает, когда `AGENT` и `VALIDATOR` совпадают.
Это механизм, а не пожелание — второй проход на той же модели наследует те же
слепые пятна. В первом блоке заменить `make install` на
`make install SEMGREP_VERSION=1.2.3`.

Добавить раздел известных ограничений:

```markdown
## Known limitations

- `findings/reviewed.sarif` accumulates and is never pruned. Over a long
  programme it grows without bound; rotate it yourself if that becomes a
  problem.
- `make check-template` fails in this repository on purpose: `CLAUDE.md` here is
  the template you copy and fill in per project.
- A scanner upgrade can change finding ids. See `docs/02-setup.md`.
```

- [ ] **Step 1b: `docs/02-setup.md` и закрепление версии сканера**

Фингерпринты сканера питают идентичность: `compute_finding_id` предпочитает
`partialFingerprints` содержимому. Апгрейд semgrep может их изменить, а значит
перевыдать ключи всем находкам, осиротить вердикты и воскресить всё ранее
отклонённое. Сейчас `make install` ставит `semgrep` без версии, а `docs/02`
называет его без номера.

Требовать версию так же, как набор правил: отказом, а не просьбой. В `Makefile`:

```make
SEMGREP_VERSION ?=

install:
	@test -n "$(SEMGREP_VERSION)" || ( \
	  echo "Set SEMGREP_VERSION=<version>."; \
	  echo ""; \
	  echo "Scanner fingerprints feed finding identity, so an unpinned"; \
	  echo "upgrade silently re-keys every finding and orphans its verdicts."; \
	  echo "See docs/02-setup.md."; \
	  exit 1)
	pip install "semgrep==$(SEMGREP_VERSION)"
	@echo ""
	@echo "Record $(SEMGREP_VERSION) in docs/02-setup.md before the first scan."
	@echo "Optional: syft, grype or trivy, and jsonschema for strict validation."
```

В `docs/02-setup.md` заменить `- Semgrep` на `- Semgrep, at a pinned version
(see below)` и добавить раздел:

```markdown
### Pin the scanner version

Semgrep's fingerprints feed finding identity: the packet builder prefers
`partialFingerprints` over file content when deriving a finding id. An upgrade
can change those fingerprints, which re-keys every finding, which orphans its
verdicts and resurrects everything previously dismissed.

So the version is pinned, and `make install` refuses without one:

    make install SEMGREP_VERSION=1.2.3

Record the version in use here, before the first scan:

**Scanner version:** `<fill in>`

Treat an upgrade the way you would an identity-scheme change: archive
`findings/` and re-triage. `record_verdict.py` refuses to mix identity schemes
in one log, but it cannot detect a scanner upgrade for you. That one is on the
engineer, which is why the version is written down rather than inferred.
```

И строка в пре-флайт чек-лист `docs/03`:

```markdown
- [ ] Scanner version pinned and recorded in `docs/02-setup.md`
```

- [ ] **Step 2: `docs/07-graduation.md`**

Дописать после списка критериев:

```markdown
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
```

Терминология в существующем списке устарела после §5.4: строки про
«False-positive rate» и «lower false positives» называют величину, которая
теперь зовётся dismissal rate и означает действие конвейера, а не его правоту.
Заменить их на:

```markdown
- Dismissal rate is measured over decided findings, not guessed.
- Confirmed findings are appearing; a falling dismissal rate is not just
  deferrals.
- Agent accuracy is computed from recorded human decisions, with coverage high
  enough to trust it. A dismissal rate with no accuracy behind it says what the
  pipeline did, not whether it was right.
```

- [ ] **Step 3: `docs/04-procedures.md`**

Обновить команды сценария 1:

```bash
make record ID=F-abc123 AGENT=<triage model> VALIDATOR=<validation model> MINUTES=12
make decide ID=F-abc123 DECISION=accepted BY=appsec-oncall
```

И дописать в конце сценария 1:

```markdown
`make record` refuses when AGENT and VALIDATOR name the same model. That is the
independence mechanism, not a preference — a second pass on the same model
inherits the same blind spots.

`make decide` records what you decided about the pipeline's final state, not
about the agent's original verdict. That distinction is what makes the accuracy
number in `make metrics` mean anything. Use a role or a work handle for `BY=`:
the triage log is committed.
```

Обновить цикл сценария 2:

```bash
for f in findings/verdicts/audit-*.json; do
  python3 scripts/record_verdict.py --verdict "$f" --agent "<triage model>"
done
```

- [ ] **Step 4: Схемы и промпт**

В `templates/verdict.schema.json` заменить описание:

```json
      "agent": { "type": "string", "description": "Tool and model identifier, self-reported by the model and therefore not authoritative. The engineer supplies the authoritative value via record_verdict.py --agent." },
```

В `templates/challenge.schema.json` — то же для `validator.agent`, со ссылкой на `--validator`.

В `prompts/adversarial-validate.md` дописать:

```markdown
The engineer records which models actually ran the two passes. `make record`
refuses when they match, so state your identity honestly and do not guess.
```

- [ ] **Step 5: Шаблон модели угроз**

`templates/threat-model.md`:

```markdown
# Threat model: <component>

- **Date:**
- **Author:**
- **Trigger:** <new feature | architecture change | incident follow-up>
- **Review again when:** <the architectural change that invalidates this>

## Component and scope

What is in scope, and explicitly what is not.

## Assets

What an attacker would want. Data, capability, availability, trust.

## Actors

Who interacts with this, and what each is trusted to do.

## Trust boundaries

Where data crosses from less trusted to more trusted. For systems with an
agent, every tool it can call is a boundary and every retrieval source is
untrusted input.

## Entry points

Concrete: handlers, consumers, uploads, webhooks, CLI arguments.

## Threats

| # | Threat | Boundary | Impact | Likelihood |
|---|---|---|---|---|

For AI systems also cover: prompt injection including the indirect variety,
retrieval poisoning, context and memory poisoning, unsafe tool use, output
handling into interpreters, training and data supply chain, excessive agency.

## Controls

What exists today. Separate implemented from planned.

## Residual risks

What remains after the controls, and who accepted it.

## Review triggers

What change would make this document wrong.
```

- [ ] **Step 6: `CLAUDE.md` и `make check-template`**

Заменить первый пункт «What not to do»:

```markdown
- Do not modify files **in the repository under review**. Analysis is read-only.
  This does not restrict maintenance of the review tooling itself, which is
  ordinary development work with its own tests.
```

Контроль реализуется скриптом, а не рецептом с шеллом. `if grep; then …; else …`
объединяет два разных исхода: «совпадений нет» (статус 1) и «файл не прочитан»
(статус 2) — и на отсутствующем `CLAUDE.md` печатает успех с кодом 0. Это
fail-open ровно в том месте, где `docs/03` обещает обратное. Кроме того, каждый
другой контроль здесь — Python-скрипт со своим тестовым файлом, и этот не должен
быть исключением: тесты процесса нужны на все три исхода.

Создать `scripts/check_template.py`:

```python
#!/usr/bin/env python3
"""Refuse to proceed while CLAUDE.md is still the shipped template.

The evidence standard rests on CLAUDE.md naming this repository's entry points
and trust boundaries. Until it does, "traced" means nothing, because the agent
cannot know what an attacker controls.

Same shape as check_scope refusing without a policy file: a control that cannot
read its input refuses, rather than reporting success. A shell `if grep` cannot
express that - it folds "no matches" and "no such file" into one branch - which
is why this is a script.

Exit codes:
    0  no placeholders remain
    2  placeholders remain, or the file is missing or unreadable
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / "CLAUDE.md"
PLACEHOLDER = re.compile(r"<[A-Za-z][^>]*>")


def find_placeholders(text: str) -> list[tuple[int, str]]:
    """Line numbers and contents of every line still carrying a placeholder."""
    return [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), start=1)
        if PLACEHOLDER.search(line)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=TEMPLATE_PATH)
    args = parser.parse_args()

    try:
        text = args.path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"REFUSED: cannot read {args.path}: {exc}", file=sys.stderr)
        print(
            "\nThis check exists to prove the file describes this repository. "
            "It cannot prove that about a file it cannot read.",
            file=sys.stderr,
        )
        return 2

    placeholders = find_placeholders(text)
    if placeholders:
        print(f"REFUSED: {args.path} still has template placeholders:\n", file=sys.stderr)
        for number, line in placeholders:
            print(f"  {number:>4}  {line}", file=sys.stderr)
        print(
            "\nFill in trust boundaries, entry points and accepted patterns for "
            "this repository. Until then the evidence standard is hollow: the "
            "agent cannot know what an attacker controls.",
            file=sys.stderr,
        )
        return 2

    print(f"{args.path}: no unfilled placeholders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Цель в `Makefile`, с `check-template` в `.PHONY`:

```make
check-template:
	@python3 scripts/check_template.py
```

Тесты `tests/test_check_template.py` — три исхода, все через процесс:

```python
"""Tests for the template control.

docs/03 tells the reader that a passing check-template proves CLAUDE.md
describes this repository. The shell version reported success when the file was
absent, so the claim was false in exactly the case that matters most.
"""

import subprocess
import sys
import unittest

import check_template
from tests import REPO_ROOT
from tests.helpers import temp_tree

SCRIPT = REPO_ROOT / "scripts" / "check_template.py"

FILLED = (
    "# Project context\n\n"
    "- Attacker-controlled input enters at: HTTP handlers in app/routes.py\n"
    "- Security-critical modules: app/auth.py, app/crypto.py\n"
)
TEMPLATED = (
    "# Project context\n\n"
    "- Attacker-controlled input enters at: `<HTTP handlers, queue consumers>`\n"
    "- Security-critical modules requiring extra scrutiny: `<auth, crypto>`\n"
)


class TestFindPlaceholders(unittest.TestCase):
    def test_reports_line_numbers(self):
        found = check_template.find_placeholders(TEMPLATED)
        self.assertEqual([number for number, _ in found], [3, 4])

    def test_filled_file_has_none(self):
        self.assertEqual(check_template.find_placeholders(FILLED), [])

    def test_prose_angle_brackets_do_not_count(self):
        # "less than" in prose must not be mistaken for a placeholder.
        self.assertEqual(check_template.find_placeholders("if a < b and c > d\n"), [])


class TestProcess(unittest.TestCase):
    def run_check(self, path):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(path)],
            capture_output=True,
            text=True,
        )

    def test_placeholders_are_refused(self):
        with temp_tree({"CLAUDE.md": TEMPLATED}) as root:
            proc = self.run_check(root / "CLAUDE.md")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)

    def test_filled_file_passes(self):
        with temp_tree({"CLAUDE.md": FILLED}) as root:
            proc = self.run_check(root / "CLAUDE.md")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no unfilled placeholders", proc.stdout)

    def test_missing_file_is_refused_not_reported_clean(self):
        # The shell version printed "no unfilled placeholders" and exited 0
        # here, which is the fail-open this control exists to avoid.
        with temp_tree({}) as root:
            proc = self.run_check(root / "CLAUDE.md")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)
        self.assertNotIn("no unfilled placeholders", proc.stdout)


if __name__ == "__main__":
    unittest.main()
```

В `help`:

```make
	@echo "  make check-template       refuse while CLAUDE.md is unfilled"
```

Дописать в `docs/03-data-handling.md` новый подраздел перед пре-флайт чек-листом:

```markdown
## Human decisions carry no schema, deliberately

The contracts in `templates/` are output contracts for a model: they exist
because model output needs validating before it enters the findings store. A
human decision is typed at a terminal by a person and is validated by argparse
and an enum instead.

Do not add a schema for it out of a sense of symmetry. The distinction between
"a model asserted this" and "a person decided this" is the one that makes the
accuracy metric mean anything, and a shared schema would blur it.

`--by` takes a role or a work handle. Not a name, not an email address: this
log is committed, so whatever goes there becomes permanent repository history.
```

И дописать в пре-флайт чек-лист:

```markdown
- [ ] `make check-template` passes, so `CLAUDE.md` describes this repository
      rather than the template
- [ ] Whoever records human decisions knows to use a role in `BY=`, never a
      name or an email address
```

Ожидаемое поведение в этом репозитории: `make check-template` **падает**, потому что `CLAUDE.md` здесь остаётся шаблоном. Это правильно и должно быть отражено в README:

```markdown
`make check-template` fails in this repository on purpose: `CLAUDE.md` here is
the template you copy and fill in per project.
```

- [ ] **Step 7: Финальная проверка**

Run: `make test`
Expected: всё зелёное.

Run: `make check-scope`
Expected: печатает исключения, включая `**/.envrc`.

Run: `make metrics`
Expected: `No reviews recorded yet.`

Run: `make check-template`
Expected: exit 2 со списком плейсхолдеров — ожидаемо для этого репозитория.

Run: `make list SARIF=tests/fixtures/sample.sarif`
Expected: три находки со сводкой и подсказкой про id.

- [ ] **Step 8: Коммит**

```bash
git add README.md docs CLAUDE.md Makefile templates prompts scripts/check_template.py tests/test_check_template.py tests/test_makefile.py
git commit -m "docs: reconcile documentation with the code that ships"
```

**Слой 6 завершён.**

---

---

# Слой 7 — правки финального ревью ветки

Все пункты проверены исполнением, а не чтением. Два критических касаются
контролей и подтверждены воспроизведением.

### Task 21: Критические — обход валидации и обход области

**Files:**
- Modify: `scripts/record_verdict.py`, `scripts/check_scope.py`, `scripts/build_packet.py`
- Modify: `tests/test_record_verdict.py`, `tests/test_check_scope.py`, `tests/test_build_packet.py`
- Modify: `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

- [ ] **Step 1: Пустой челлендж обходит валидацию**

Проверено: `decide_state(high true_positive, {})` возвращает
`('confirmed', 'true positive; severity=high does not require adversarial validation under policy')`.
Тот же вердикт с `None` даёт правильное `blocked_needs_challenge`.

Два дефекта в одном. `{}` достаточно ложно, чтобы `if challenge:` в `main`
пропустил проверку по схеме, и недостаточно `None`, чтобы сработала ветка
блокировки. А формулировка утверждает, что политика не требует валидации для
`high` — что просто неправда.

Причина в том, что ветвление идёт по контейнеру, а не по результату. Заменить
начало `decide_state`:

```python
    v = verdict["verdict"]
    severity = verdict.get("severity", "info")
    needs_challenge = severity in CHALLENGE_REQUIRED

    # Drive off the result, not the container. An empty challenge object is not
    # a challenge: it is falsy enough to skip schema validation in main, yet not
    # None enough to reach the blocked branch, so a high finding was promoted to
    # confirmed under a rationale claiming policy did not require validation.
    challenge_result = (challenge or {}).get("challenge_result")

    if needs_challenge and challenge_result is None:
        return (
            "blocked_needs_challenge",
            f"severity={severity} requires adversarial validation before promotion",
        )

    if challenge_result in ("refuted", "inconclusive"):
        return (
            "human_review",
            f"the two passes disagree (challenge={challenge_result}); a human decides",
        )
```

После этой перестановки `_unchallenged_note` недостижима для severities,
требующих челленджа: они уже вернулись выше. Формулировка становится истинной по
построению, а не по внимательности. Отметить это в её docstring.

В `main` заменить `if challenge:` на `if challenge is not None:`, чтобы `{}`
доходило до схемы и отвергалось на отсутствующих обязательных полях.

Тесты: `{}` даёт `blocked_needs_challenge` для high; челлендж без
`challenge_result` — то же; `--challenge` на файл с `{}` отвергается по схеме и
ничего не пишет.

- [ ] **Step 2: Символьные ссылки обходят область**

Проверено: ссылка `app/handler.py -> ../secrets/token.txt` проходит лексическую
проверку и отдаёт содержимое в пакет. В прогоне вернулось `1 | TOP-SECRET`.

Это обход центрального контроля репозитория. Лексической проверки недостаточно:
проверяется имя, а читается то, куда оно ведёт.

Решение — проверять и то, что открывается. Добавить в `scripts/check_scope.py`:

```python
def resolve_within(
    repo: Path, relative: str, exclusions: list[dict] | None = None
) -> Path:
    """Resolve a repository-relative path, refusing what the policy excludes.

    The lexical check alone is not enough. A symlink sitting at an allowed path
    can point at an excluded file, and reading it puts exactly the content the
    policy forbids into a packet: a link at app/handler.py pointing to
    ../secrets/token.txt produced a packet containing the secret.

    So the resolved target is checked as well, and a target outside the
    repository is refused outright. The policy describes paths within the
    repository and cannot speak for anything beyond it.
    """
    check_path(relative, exclusions)

    root = repo.resolve()
    target = (root / relative).resolve()
    try:
        inside = target.relative_to(root)
    except ValueError:
        raise ScopeViolation(
            relative,
            "<outside repository>",
            f"resolves to {target}, which is outside {root}",
        )

    check_path(str(inside), exclusions)
    return target
```

В `build_packet.py` каждое чтение исходника идёт через него: в
`build_triage_packet` для целевого файла и каждого шага dataflow, и в
`compute_finding_id` на пути по содержимому. `read_context` получает уже
разрешённый путь.

Тесты: ссылка на исключённый файл внутри репозитория — `ScopeViolation`; ссылка
наружу — `ScopeViolation` с указанием, куда она ведёт; обычный файл работает как
прежде; каталог-ссылка в середине пути тоже отвергается.

- [ ] **Step 3: Доказательства RED/GREEN и проверки мутациями**

Сначала добавить регрессионные тесты и сохранить команды, коды выхода и
фактический вывод RED в `docs/superpowers/evidence/2026-09-01-red-tests.md`.
После исправления сохранить GREEN для затронутых модулей.

Для каждого критического дефекта отдельно выполнить проверку мутацией:
временно вернуть обход пустого челленджа и показать, что регрессия обнаруживает
неправомерное продвижение и пропуск схемы; восстановить исправление. Затем
временно отключить проверку разрешённой цели в `resolve_within` и показать,
что регрессия обнаруживает принятие или раскрытие исключённого либо внешнего
содержимого; восстановить исправление. Сохранить точные команды и существенный
вывод обеих мутаций в том же файле доказательств.

Убедиться, что обе мутации полностью удалены, повторить затронутые тесты и
один раз выполнить `make test` перед коммитом. Просмотреть итоговый diff.
Исправление неполного списка файлов и шагов этого задания зафиксировать в
`docs/superpowers/evidence/2026-09-01-plan-fixes.md`.

- [ ] **Step 4: Индексация и единый коммит**

Включить в коммит всё уже написанное пользователем расширение плана «Слой 7»,
сохранив его содержание; реализацию Task 22 и Task 23 сюда не добавлять.

```bash
git add scripts/record_verdict.py scripts/check_scope.py scripts/build_packet.py tests/test_record_verdict.py tests/test_check_scope.py tests/test_build_packet.py docs/superpowers/plans/2026-09-01-appsec-review-hardening.md docs/superpowers/evidence/2026-09-01-red-tests.md docs/superpowers/evidence/2026-09-01-plan-fixes.md
git diff --cached --check
git commit -m "fix: close validation and scope bypasses"
```

- [ ] **Step 5: Валидацию решает переданный флаг, а не разобранное значение**

Правка из Step 1 закрыла `{}` и оставила `null`. Проверено: `--challenge` на файл
с содержимым `null` даёт exit 0, пишет лог и SARIF и записывает в строку
`validator=model-b` при пустом `challenge_result` — аудит утверждает валидатора,
которого не было.

Причина та же, что и в Step 1, и она пережила его исправление: ветвление шло по
разобранному документу, а `null` разбирается в `None`. Правильный инвариант
формулируется не про значение, а про намерение: **если инженер передал
`--challenge`, документ обязан пройти схему.** Пустой, нулевой, любой — это
предъявленный челлендж, и он либо валиден, либо отвергнут.

```python
    challenge_supplied = args.challenge is not None
    challenge = (
        json.loads(args.challenge.read_text(encoding="utf-8"))
        if challenge_supplied
        else None
    )
```

и далее:

```python
    try:
        validate(verdict, "verdict.schema.json")
        # Presence of the flag decides this, never the parsed value. A file
        # containing `null` parses to None and `{}` parses to a falsy dict;
        # both looked like "no challenge" and sailed past the schema while the
        # log recorded a validator for a challenge that was never checked.
        if challenge_supplied:
            validate(challenge, "challenge.schema.json")
    except ValidationError as exc:
```

`validate` должна пережить не-словарь. `jsonschema` отвергнет `None` сама, но
резервный валидатор упадёт на `key not in None` с `TypeError`, а не с
`ValidationError`. Добавить первой строкой `_fallback_validate`:

```python
    if not isinstance(instance, dict):
        raise ValidationError(
            f"{name}: expected a JSON object, got {type(instance).__name__}"
        )
```

Тесты — процессные, на обеих severities, потому что путь промотирования у них
различается:

- `--challenge` на файл с `null`, severity low: non-zero, лог не создан, SARIF не
  создан;
- то же для severity high;
- `--challenge` на файл с `{}`: то же, как регрессия к Step 1;
- валидный челлендж по-прежнему принимается.

Проверки отсутствия файлов делать **внутри** блока `temp_tree`.

Мутационная проверка: вернуть `if challenge:`, убедиться что оба теста с `null`
краснеют на записанном логе, восстановить.

Коммит отдельный, поверх Step 4: `fix: validate a supplied challenge whatever it parses to`.

---

### Task 22: Важные

**Files:**
- Modify: `scripts/scan.sh`, `scripts/record_verdict.py`, `scripts/build_packet.py`, `scripts/metrics.py`, `Makefile`
- Modify: `tests/test_scan_sh.py`, `tests/test_record_verdict.py`, `tests/test_build_packet.py`, `tests/test_makefile.py`, `tests/test_metrics.py`
- Modify: `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`, `docs/superpowers/evidence/2026-09-01-red-tests.md`, `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

Для каждого поведения сначала добавить регрессию, получить RED на самом дефекте,
затем внести минимальное исправление и получить GREEN. Steps 6–7 используют
общий ключ события; RED для обоих получить до их общей реализации.

- [ ] **Step 1: `--metrics=off` не закрывает весь egress**

Semgrep по умолчанию делает HTTP-запрос проверки версии, и `--metrics=off` его не
отключает. Флаг `--disable-version-check` установленным semgrep принимается —
проверено. Добавить его в вызов `scan.sh` рядом с `--metrics=off` и в оба
поведенческих теста с подставным semgrep: записанные аргументы обязаны содержать
оба флага.

- [ ] **Step 2: Структурно битый SARIF даёт частичную запись**

`load_existing_results` принимает `results: [null]` без исключения — проверено, —
а падает потом `merge_result`, уже после `append_log`. Порядок был исправлен в
Task 8, но проверка оказалась слишком мелкой: она ловит нечитаемый JSON и не
ловит читаемый мусор.

**Проверка контейнеров недостаточна.** Первая редакция этого шага сверяла только
типы `result` и `properties`. Проверено, что этого мало:

| Существующий SARIF | exit | лог | sarif |
|---|---|---|---|
| `[{"properties":{"finding_id":null}}]` | 1 | записан | нет |
| `[{"properties":{"finding_id":7}}]` | 1 | записан | нет |
| `{}` | 0 | записан | **подменён** |

Первые два падают в сортировке `merge_result`, которая сравнивает `None` или
`int` со строкой, — и падают уже после `append_log`. Третий проходит насквозь:
`data.get("runs") or []` превращает нераспознанный документ в пустой список, и
файл, который мы не смогли истолковать, молча замещается.

**Правило: проверять на ту глубину, на которую полагается потребитель.**
`merge_result` сортирует и сопоставляет по `properties.finding_id`, значит
валидатор обязан гарантировать именно это поле, а не тип контейнера над ним.
Проверка мельче, чем использование, — это и есть форма всех четырёх обходов,
найденных в финальном ревью.

Заменить тело `load_existing_results` после разбора JSON:

```python
    if (
        not isinstance(data, dict)
        or "version" not in data
        or not isinstance(data.get("runs"), list)
    ):
        raise ValidationError(
            f"{path} is not a SARIF document this tool wrote: no version, or "
            "runs is not a list. Refusing to replace a file we cannot "
            "interpret. Move it aside, or pass --fresh."
        )

    if not data["runs"]:
        return []

    results = data["runs"][0].get("results", [])
    if not isinstance(results, list):
        raise ValidationError(f"{path}: runs[0].results is not a list.")

    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValidationError(f"{path}: results[{index}] is not an object.")
        properties = result.get("properties")
        if not isinstance(properties, dict):
            raise ValidationError(
                f"{path}: results[{index}] has no properties object."
            )
        finding_id = properties.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            # Checked to this depth on purpose: merge_result sorts and matches
            # on this field, so anything else crashes the sort - after the log
            # has already been appended to.
            raise ValidationError(
                f"{path}: results[{index}].properties.finding_id is "
                f"{finding_id!r}, not a non-empty string."
            )

    return results
```

Все три исключения возникают до `append_log`, поэтому частичной записи не
остаётся.

Регрессии — процессные, по одной на строку таблицы: non-zero, лог не создан,
существующий SARIF байт в байт прежний. Сверять содержимое хешем **внутри** блока
`temp_tree`, а не фактом существования: третий случай отличается именно подменой
содержимого, а файл при этом на месте.

- [ ] **Step 3: Многострочный подсчёт вхождений склеивает разные находки**

`occurrence_index` скользит окном сырых строк, тогда как цель нормализована с
удалением пустых строк. Окно той же сырой длины нормализуется к другой длине,
настоящий более ранний дубль не засчитывается, и две разные области получают
один id.

Считать по нормализованным строкам файла, а не по сырым окнам:

```python
def occurrence_index(file_text: str, start_line: int, end_line: int, target: str) -> int:
    """How many identical normalized snippets appear before this one.

    Counted over the file's normalized lines, not raw windows. The target has
    had blank lines and indentation removed, so a raw window of the same length
    can normalize to something shorter; a genuine earlier duplicate then goes
    uncounted and two distinct findings collapse onto one id.
    """
    normalized = [
        (number, line.strip())
        for number, line in enumerate(file_text.splitlines(), start=1)
        if line.strip()
    ]
    target_lines = target.split("\n")
    span = len(target_lines)

    count = 0
    for i in range(0, max(0, len(normalized) - span + 1)):
        window = normalized[i:i + span]
        if window[0][0] >= start_line:
            break
        if [text for _, text in window] == target_lines:
            count += 1
    return count
```

Регрессия: две многострочные области, нормализующиеся одинаково, получают разные
id; сдвиг строк выше по-прежнему id не меняет.

- [ ] **Step 4: Makefile теряет контекст очереди**

`make list` не передаёт `REPO`, `make triage N=` не передаёт фильтры. Значит
`make list LEVEL=error` и следом `make triage N=0` берут находку из разных
списков, что прямо противоречит обещанию «индексы относятся к отфильтрованному
списку».

Ввести общую переменную фильтров и использовать её в обеих целях:

```make
QUEUE_FILTERS = $(if $(LEVEL),--level $(LEVEL),) \
	$(if $(RULE),--rule $(RULE),) \
	$(if $(PATH_GLOB),--path "$(PATH_GLOB)",) \
	$(if $(UNREVIEWED),--unreviewed,) \
	$(if $(LIMIT),--limit $(LIMIT),)

list:
	@python3 scripts/build_packet.py --sarif $(SARIF) --repo $(REPO) --list $(QUEUE_FILTERS)

triage:
	@python3 scripts/build_packet.py --sarif $(SARIF) --repo $(REPO) \
		$(if $(ID),--finding-id $(ID),--index $(N) $(QUEUE_FILTERS))
```

Фильтры при `ID=` не передаются намеренно: адресация по id не зависит от того,
что показано.

- [ ] **Step 5: Подавление в SARIF всё ещё утверждает валидацию**

`build_result` жёстко пишет `"Dismissed after adversarial validation. {rationale}"`
даже когда челленджа не было. Тот же дефект, что и §1.1, в месте, до которого
Task 7 не дошёл. Заменить на:

```python
            "justification": f"Dismissed after review. {rationale}",
```

`rationale` уже содержит правду о том, была ли валидация. Тест проверяет полное
честное подавление непроверенной находки и отсутствие ложного утверждения
`Dismissed after adversarial validation`. Запрет всей подстроки
`adversarial validation` неверен: правдивое `does not require adversarial
validation under policy` из Task 7 сохраняется.

- [ ] **Step 6: Решение человека переживает пересмотр вердикта — решение о замысле**

Последовательность confirmed → accepted → superseded-dismissed сейчас оставляет
старое «accepted» как ground truth для нового вердикта. Человек принимал другое
решение о другом состоянии, и такая запись фабрикует согласие.

**Решение: вердикт, записанный позже решения, это решение отменяет.** Находка
возвращается в неразрешённое состояние и снова попадает в знаменатель покрытия —
что корректно сигнализирует «это надо решить заново». Историческая запись не
теряется: лог append-only, отменяется только схлопнутое текущее состояние.

В `collapse` запоминать полный ключ решения и вердикта
`(_moment(reviewed_at), индекс строки журнала)` и отбрасывать решение, если
ключ победившего вердикта больше:

```python
        decision = decisions.get(finding_id)
        if decision and finding_id in verdict_at and decision_at[finding_id] < verdict_at[finding_id]:
            # A verdict recorded after the decision supersedes it: the human
            # accepted a different state than the one that now stands.
            decision = None
```

Сравнение моментов — через `_moment` из Step 7, не лексическое. При равных
или эквивалентных моментах поздняя строка вердикта отменяет решение, а поздняя
строка решения применяется к текущему вердикту, как предписывает Step 7.

Тест `test_decision_survives_a_later_verdict_revision` из Task 19 переписать:
решение переживает пересмотр, записанный **раньше** него, и отменяется
пересмотром, записанным позже.

- [ ] **Step 7: Сортировка по времени лексическая, а не хронологическая**

Проверено: `2026-09-01T12:00:00+03:00` лексически больше
`2026-09-01T10:00:00+00:00`, хронологически — раньше. Спека предписывает пару
`(reviewed_at, индекс)`, но подразумевала сравнение моментов, а не строк.

```python
def _moment(value: str) -> datetime:
    """Parse a log timestamp into an aware datetime, UTC when unqualified.

    Sorting these as strings is wrong: 12:00+03:00 sorts after 10:00+00:00 yet
    happens an hour earlier. The log mixes offsets as soon as two reviewers work
    in different zones.
    """
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
```

Ключ сортировки становится `(_moment(row.get("reviewed_at", "")), index)`.
`filter_since` разбирает и границу через `_moment`, сравнивая осведомлённые
моменты, — это заодно убирает `TypeError` на смешанных смещениях.

Тест: вердикт `12:00+03:00` проигрывает вердикту `10:00+00:00`; `--since` с
границей в другом часовом поясе не падает и отбирает верно.

- [ ] **Step 8: Красные доказательства не доказывают заявленный дефект**

В Tasks 8, 11, 12 и 19 красный прогон падал на отсутствующем хелпере или
неизвестном аргументе, а не через сам дефект. Для новой функции это честная
краснота — дефект нельзя показать через функцию, которой нет. Но для дефектов в
**существующем** поведении красный прогон обязан показывать неправильное
поведение, а не отсутствие кода.

Задним числом достроить для Tasks 8 и 12: извлечь `git archive` родительских
коммитов в отдельные каталоги `mktemp`, не переключая и не сбрасывая общую ветку.
Task 8: `e5a2dd2de21dc8a93bf337d3f0524a724a70b8e0`;
Task 12: `ee81d5cb5e154f114f35cfffff0caa491f21dd73`.
Запустить существующий CLI каждого снимка с поддерживаемыми им аргументами,
показать перезапись SARIF второй находкой и принятие совпадающих моделей
соответственно. Записать точные команды, SHA и фактический вывод рядом с
прежними записями, явно пометив прежние RED как недостаточные.

Для Tasks 11 и 19 записать явно, что дефект относился к отсутствующему коду и
красный прогон по нему возможен только как `AttributeError`. Это не оправдание, а
разграничение: два разных класса краснот, и файл доказательств должен их
различать.

- [ ] **Step 9: Доказательства мутаций и восстановление**

После GREEN по очереди временно отменить каждое исправление I2, I3, I5, I7,
запустить его регрессию через реальное поведение, получить падение на исходном
дефекте, восстановить исправление и тем же запуском подтвердить GREEN.
В `red-tests.md` сохранить точную мутацию, команды и фактический вывод каждого
падения и восстановления. Одновременно активна только одна мутация.

- [ ] **Step 10: Проверка, доказательства и один коммит**

Сохранить RED/GREEN и исправления плана в двух файлах доказательств. После
восстановления всех мутаций выполнить профильные наборы и один полный
`make test`, проверить итоговый diff. Spec и Task 23 не менять.

```bash
git add scripts/scan.sh scripts/record_verdict.py scripts/build_packet.py scripts/metrics.py Makefile tests/test_scan_sh.py tests/test_record_verdict.py tests/test_build_packet.py tests/test_makefile.py tests/test_metrics.py docs/superpowers/plans/2026-09-01-appsec-review-hardening.md docs/superpowers/evidence/2026-09-01-red-tests.md docs/superpowers/evidence/2026-09-01-plan-fixes.md
git commit -m "fix: resolve important review findings"
```

---

### Task 23: Мелкие

**Files:**
- Modify: `scripts/build_packet.py`
- Modify mode: `scripts/record_human_decision.py`
- Modify: `scripts/scan.sh`
- Modify: `tests/test_build_packet.py`
- Modify: `tests/test_human_decision.py`
- Modify: `tests/test_record_verdict.py`
- Modify: `tests/test_scan_sh.py`
- Modify: `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

- [ ] **Step 1: Написать поведенческие регрессии и зафиксировать RED**

Добавить профильные тесты, которые проверяют наблюдаемое поведение:

- пустое значение `--finding-id` явно отвергается с non-zero кодом, а не
  превращается в другой режим CLI;
- `scripts/record_human_decision.py --help` запускается непосредственно, без
  `python3` перед путём к скрипту;
- страж схемы проверяет не только два элемента `allOf`, но и точные поля их
  условий: `confidence` и `evidence_level`;
- произвольная конфигурация `https://` описывается как `remote rules`, без
  утверждения, что это Semgrep registry. Использовать локальный stand-in
  Semgrep; сеть в тесте не нужна.

Выполнить отдельные профильные тесты. Для стража схемы временно заменить один
из двух охраняемых ключей при неизменной длине `allOf`, получить RED на точной
идентичности условия и сразу восстановить схему. Фактический вывод RED и GREEN
сохранить в отчёте задачи.

- [ ] **Step 2: Внести минимальные исправления**

- Отличать переданный пустой `--finding-id` от отсутствующего аргумента и
  вызвать `parser.error("--finding-id must not be empty")` до выбора режима.
- Сделать `scripts/record_human_decision.py` исполняемым (`chmod +x`), как
  остальные скрипты.
- Усилить существующий страж схемы точным сравнением условных полей
  `confidence` и `evidence_level`, сохранив проверку длины `allOf`.
- В сетевом сообщении `scan.sh` использовать общее выражение `remote rules`.
- В примере Task 19 сохранять нулевые минуты предикатом `is not None` как для
  времени триажа, так и для времени решения человека.

- [ ] **Step 3: Проверить профильные и полные наборы**

```bash
python3 -m unittest tests.test_build_packet tests.test_human_decision tests.test_record_verdict tests.test_scan_sh -v
make test
git diff --check
git diff --summary
git diff -- scripts/build_packet.py scripts/record_human_decision.py scripts/scan.sh tests/test_build_packet.py tests/test_human_decision.py tests/test_record_verdict.py tests/test_scan_sh.py docs/superpowers/plans/2026-09-01-appsec-review-hardening.md docs/superpowers/evidence/2026-09-01-plan-fixes.md
```

Проверить, что в diff ровно перечисленные файлы, изменение режима
`record_human_decision.py` равно `100644 => 100755`, а временная мутация схемы
полностью восстановлена.

- [ ] **Step 4: Создать один коммит**

```bash
git add scripts/build_packet.py scripts/record_human_decision.py scripts/scan.sh tests/test_build_packet.py tests/test_human_decision.py tests/test_record_verdict.py tests/test_scan_sh.py docs/superpowers/plans/2026-09-01-appsec-review-hardening.md docs/superpowers/evidence/2026-09-01-plan-fixes.md
git commit -m "fix: resolve minor review findings"
```

---
### Task 24: Правки финального ревью ветки

#### Контракт исполнения контроллера

- Сохранить и закоммитить существующие пользовательские правки плана и спеки.
  Шаги 1–7 выполнять строго по порядку: в шагах 1–6 сначала поведенческий RED,
  затем минимальный производственный GREEN. Точные команды, коды возврата и
  существенный вывод записать в
  `docs/superpowers/evidence/2026-09-01-red-tests.md`.
- Файлы: `scripts/check_scope.py`, `scripts/check_template.py`,
  `scripts/record_verdict.py`, `scripts/record_human_decision.py`,
  `scripts/metrics.py`, `scripts/build_packet.py`, `Makefile`,
  `templates/challenge.schema.json`, `README.md`, семь соответствующих
  тестовых модулей (`test_check_scope`, `test_check_template`, `test_record_verdict`,
  `test_human_decision`, `test_metrics`, `test_build_packet`, `test_makefile`),
  этот план, проектную спеку и файлы доказательств red-tests и plan-fixes.
- Выполнить и восстановить по одной пять мутаций: прямой лексический вызов CLI
  проверки области (оба процессных отказа краснеют); старый построчный поиск
  плейсхолдеров (краснеет процессный отказ для многострочного плейсхолдера);
  возврат ключа сортировки и последнего события метрик к `reviewed_at`
  (реальный писатель и SARIF расходятся с метриками); снятие обратного отказа
  validator/challenge (записывается строка аудита); обход проверки равенства
  verdict-digest (устаревший челлендж записывает или меняет артефакты).
  Сохранить `re.DOTALL`: его удаление ничего не меняет, потому что `[^>]` уже
  совпадает с переводами строк.
- Тесты отказа проверяют отсутствие или неизменность артефактов внутри времени
  жизни временных деревьев. Интеграция порядка записи сравнивает реальные
  писатель/SARIF и метрики для одной последовательности событий.
- Шаг 7 последний: записать в файл доказательств таблицу глубины ровно для его
  пяти контролей и не исправлять найденное. После таблицы не менять продукт и
  тесты: только проверки, просмотр разницы и коммит.
- Перед коммитом выполнить `python3 -m unittest tests.test_check_scope
  tests.test_check_template tests.test_record_verdict tests.test_human_decision
  tests.test_metrics tests.test_build_packet tests.test_makefile -v`, затем один
  полный `make test` и `git diff --check`. Без сети и установок.
- Добавить в индекс каждый изменённый файл из списка; создать один коммит
  `git commit -m "fix: close final review control gaps"`.

Все пять проверены исполнением. Пункты 3 и 5 меняли замысел, решения приняты и
записаны в спеку.

- [x] **Step 1: Ручной шлюз области тоже лексический**

Проверено: `check_scope.py app/handler.py` возвращает `OK` для ссылки на
`../secrets/token.txt`, и `check_scope.py /etc/hosts` тоже возвращает `OK`.
`docs/03` документирует ровно этот путь как способ безопасно расширить контекст:
`check_scope.py <file> && sed -n '1,120p' <file>`. То есть задокументированный
человеческий обходной путь обходит контроль.

`resolve_within` был добавлен в Task 21, но подключён только к `build_packet`.
Подключить и к CLI: аргумент `--repo` со значением по умолчанию `Path.cwd()`,
каждый путь проверяется через `resolve_within(args.repo, path, exclusions)`.
Абсолютный путь вне репозитория отвергается той же веткой «outside repository».

Тесты: ссылка на исключённое — exit 2; абсолютный путь наружу — exit 2; обычный
файл — exit 0. Через процесс, потому что предмет проверки — код возврата CLI.

- [x] **Step 2: Шлюз шаблона не видит многострочные плейсхолдеры**

Проверено на живом `CLAUDE.md`: построчный поиск находит 2 плейсхолдера, поиск по
всему тексту — 8. Заполнив видимые два, инженер получил бы exit 0 при шести
оставшихся, и `docs/03` подтвердил бы ему, что файл описывает его репозиторий.

Причина: `<[A-Za-z][^>]*>` применяется к строке, а плейсхолдеры переносятся.
Искать по всему тексту, номер строки вычислять по смещению совпадения:

```python
PLACEHOLDER = re.compile(r"<[A-Za-z][^>]*>", re.DOTALL)


def find_placeholders(text: str) -> list[tuple[int, str]]:
    """Line numbers and first lines of every placeholder still in the file.

    Searched over the whole text, not line by line: the template wraps its
    placeholders across lines, and a per-line pattern never closes on them. The
    line-by-line version reported two of the eight in CLAUDE.md.
    """
    found = []
    for match in PLACEHOLDER.finditer(text):
        line_number = text.count("\n", 0, match.start()) + 1
        first_line = match.group(0).splitlines()[0]
        found.append((line_number, first_line.strip()))
    return found
```

Тест: фикстура с переносом внутри плейсхолдера даёт отказ. Мутационная проверка —
вернуть построчный поиск, убедиться что процессный тест краснеет. `re.DOTALL`
сохраняется: удаление флага ничего не меняет, потому что `[^>]` включает перенос.

- [x] **Step 3: Писатель и метрики расходятся в том, какая ревизия текущая**

Проверено обеими сторонами: вердикт 09:00, записанный после вердикта 10:00, даёт
`dismissed` в SARIF и `confirmed` в метриках; ревизия 11:00 после решения 12:00
очищает решение в SARIF, но метрики применяют старое решение к новому вердикту и
рапортуют 100% покрытия.

**Решение принято и внесено в спеку: очерёдность определяет момент записи.**
`reviewed_at` — самоотчёт модели, и опирать на него управляющее решение нельзя по
той же причине, по которой `--agent` переехал в CLI.

- `LOG_FIELDS` получает `recorded_at` сразу после `reviewed_at`. Рекордер и
  `record_human_decision` проставляют `datetime.now(timezone.utc).isoformat()`.
- `collapse` сортирует по `(_moment(row["recorded_at"]), индекс)`.
- Отмена решения более поздним вердиктом сравнивает `recorded_at`.
- `filter_since` считает по `recorded_at`.
- `reviewed_at` остаётся в логе как факт и нигде не управляет.

Миграция колонки — существующим механизмом `check_log_compatible`.

Тесты: вердикт с более ранним `reviewed_at`, записанный позже, выигрывает;
решение, записанное до ревизии, отменяется ею; SARIF и метрики называют одно и то
же состояние на одной последовательности записей.

- [x] **Step 4: Валидатор записывается без челленджа**

Проверено: `--validator model-b` без `--challenge` даёт exit 0 и строку
`model-a,model-b` при пустом `challenge_result`. Спека говорит «тогда и только
тогда», обеспечена была одна половина.

В `main`, рядом с существующей проверкой:

```python
    if args.validator and args.challenge is None:
        parser.error(
            "--validator without --challenge would record a validator that "
            "validated nothing"
        )
```

В `Makefile` цель `record` передаёт `--validator` только вместе с `--challenge`:
обе подстановки ставятся под один `$(if $(wildcard findings/challenges/$(ID).json),...)`.

Тест: комбинация отвергается с non-zero, лог не создан.

- [x] **Step 5: Устаревший челлендж авторизует противоположную ревизию**

Челлендж, подтвердивший `true_positive`, принимается при замещении вердикта на
`false_positive`. Привязка идёт по `finding_id`, который у ревизий общий.

**Решение принято и внесено в спеку: челлендж привязывается к ревизии вердикта
каноническим хешем.**

В `build_packet.py`:

```python
def verdict_digest(verdict: dict) -> str:
    """Canonical hash of a verdict, binding a challenge to the revision it read.

    finding_id is shared by every revision of a finding, so it cannot express
    "this challenge refuted that verdict". Without a tighter binding an upheld
    challenge for a true positive was accepted when superseding it with a false
    positive - authorising the opposite claim.
    """
    canonical = json.dumps(verdict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
```

`build_challenge_packet` кладёт его в пакет и в инструкции требует скопировать
дословно. `templates/challenge.schema.json` получает обязательное
`verdict_digest` (строка, 16 hex). `record_verdict` пересчитывает хеш переданного
вердикта и отказывает при несовпадении, до любой записи:

```python
    if challenge_supplied:
        expected = verdict_digest(verdict)
        supplied = challenge.get("verdict_digest")
        if supplied != expected:
            print(f"REFUSED: challenge was built for a different verdict.\n",
                  file=sys.stderr)
            print(f"  challenge carries: {supplied}", file=sys.stderr)
            print(f"  this verdict is:   {expected}\n", file=sys.stderr)
            print("A challenge refutes one revision, not a finding. Re-run the "
                  "validation pass against the verdict you are recording.",
                  file=sys.stderr)
            return 2
```

Ломающее изменение схемы: прежние челленджи не пройдут. Данных нет, цена нулевая
— зафиксировать в README рядом с прочими ломающими.

Тесты: челлендж от прежней ревизии отвергается, ничего не пишется; челлендж от
текущей принимается; отсутствующий `verdict_digest` отвергается схемой.

- [x] **Step 6: Мелкие**

- `annotate` считает `in_scope` лексически, поэтому псевдоним через ссылку
  показывается в области и получает рабочий id. Использовать проверку с
  разрешением пути, ту же что и в Step 1.
- Дописать хеши финальных коммитов в записи GREEN по Tasks 21 и 22.

- [x] **Step 7: Пересмотреть остальные контроли одним вопросом**

Все обходы этого ревью имеют одну форму: проверяется мельче, чем используется.
Контейнер вместо результата, имя вместо открываемого файла, значение вместо
переданного флага, тип контейнера вместо поля сортировки, строка вместо момента
записи.

Пройти оставшиеся контроли — `check_scope`, `check_log_compatible`,
`check_template`, `_fallback_validate`, отказ независимости — и для каждого
ответить письменно: на что опирается потребитель и на ту ли глубину проверяет
контроль. Результат в файл доказательств. Это не поиск багов вслепую, а один
конкретный вопрос к пяти известным местам.

---

### Task 25: Правки второго финального ревью

Шаг 7 задачи 24 отработал: пять новых дефектов, все — в тех пяти контролях,
которые он предписывал перечитать. Все проверены исполнением.

**Контракт исполнения.** Работать от
`231505c3370a80eaa95f12a50681a3b58e6099c1` в `hardening/2026-09`, не
переключая ветку и не меняя спеку. Сохранить незакоммиченный пользовательский
план задачи 25. Точная область отслеживаемых файлов:

- `scripts/check_scope.py`
- `scripts/record_verdict.py`
- `scripts/metrics.py`
- `scripts/build_packet.py`
- `templates/verdict.schema.json`
- `templates/challenge.schema.json`
- `tests/test_check_scope.py`
- `tests/test_record_verdict.py`
- `tests/test_metrics.py`
- `tests/test_build_packet.py`
- `tests/test_human_decision.py`
- `docs/03-data-handling.md`
- `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- `docs/superpowers/evidence/2026-09-01-red-tests.md`
- `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

В каждом из шагов 1–5 сначала добавить тесты и наблюдать причинный RED, затем
внести минимальную производственную правку и получить сфокусированный GREEN.
Каждую предписанную мутацию применять отдельно через `apply_patch`, сохранять
фактическую падающую команду и вывод, восстанавливать через `apply_patch` и до
следующего шага подтверждать восстановленный GREEN. В тестах резервного пути
принудительно делать `jsonschema` недоступным. Мутация испорченного
`recorded_at` на шаге 3 должна доходить до неверного порядка событий, а каждая
проверка отсутствия записи должна выполняться внутри времени жизни временного
дерева. Не обращаться к сети и ничего не устанавливать.

После шага 6 выполнить сфокусированные проверки, один финальный `make test`,
`make check-scope`, `make list SARIF=tests/fixtures/sample.sarif`, `make
metrics`, ожидаемо падающий `make check-template` и `git diff --check`. Вписать
GREEN-коммит задачи 24 `231505c3370a80eaa95f12a50681a3b58e6099c1` в
`red-tests.md`. Добавить в индекс ровно перечисленные выше файлы, проверить
набор в индексе и создать один коммит с темой
`fix: close second-review control gaps`.

- [x] **Step 1: Испорченная политика отключает область молча**

Худший дефект всего ревью. Проверено: политика с ключом `exclusion:` вместо
`exclusions:` разбирается в ноль правил, и `check_scope.py .env` возвращает
`OK, exit 0`. Пустой файл — то же самое.

Docstring `_parse_policy` говорит, что парсер написан вручную, чтобы отсутствие
PyYAML не отключило контроль молча. Опечатку он отрабатывает ровно тем способом,
который этой фразой запрещён: «Anything else is ignored» — и запрет, и дыра в
одном абзаце.

Три отказа вместо трёх умолчаний:

```python
KNOWN_SECTIONS = ("exclusions", "scan_noise")


def _parse_policy(text: str) -> tuple[list[dict], list[str]]:
    """Parse the narrow YAML subset used by excluded-paths.yml.

    Written by hand rather than with PyYAML so a missing dependency cannot
    silently disable the policy. That reasoning applies just as much to a
    typo: `exclusion:` for `exclusions:` used to parse to zero rules and let
    every excluded path through, which is the same failure the hand-rolled
    parser exists to prevent. Unrecognised sections and rules without a
    pattern are refusals now, not omissions.
    """
```

- незнакомый ключ верхнего уровня → `ValidationError`-подобный отказ с перечнем
  допустимых;
- запись в `exclusions` без `pattern` → отказ с номером записи, а не тихое
  выбрасывание через `[e for e in exclusions if e.get("pattern")]`;
- в `load_policy` — отказ, если разобрано ноль правил: «a policy that excludes
  nothing is not a policy, it is a disabled control».

Тесты: каждая из трёх форм порчи даёт non-zero у CLI; корректная политика
работает как прежде. Мутационная проверка: вернуть «ignore unknown», убедиться
что тест с `exclusion:` краснеет.

- [x] **Step 2: Резервный валидатор мельче схемы**

Без `jsonschema`: `"CWE-416 "` с хвостовым пробелом обходит `RUNTIME_PROOF_CWES`,
а `start_line: 0` доходит до SARIF вопреки `minimum: 1`. Фолбэк не знает про
`pattern`, `minimum` и `maxLength`.

Добавить их обработку в `_fallback_validate` — те же ключи, что реально
используются в двух схемах, не больше.

Отдельно `check_consistency` нормализует CWE перед сравнением:

```python
    cwes = {value.strip().upper() for value in verdict.get("cwe", [])}
```

Нормализация здесь дешёвая, а цена промаха — пропуск отказа по классам, которые
статикой не подтверждаются вовсе. Не полагаться на то, что схема поймает пробел:
на машине без `jsonschema` схему исполняет фолбэк.

Тесты гонять с принудительно отключённым `jsonschema`, иначе они проверяют не тот
код: параметризовать через подмену импорта.

- [x] **Step 3: Контракт строки лога, общий для писателя и читателя**

Проверено: лог со старым заголовком `record_verdict` отвергает, а `metrics.py`
на нём же выдаёт успешные `{"total": 0}`. Один файл, два компонента,
противоположные вердикты, и молчаливо-успокаивающий из них неверен.

Первая редакция этого шага предписывала вызвать `check_log_compatible` из
метрик — и была мельче, чем нужно потребителю, ровно как дефекты, которые она
чинит. Эта функция сверяет заголовок и непустые схемы; строки она не проверяет.
После такого «исправления» лог с правильным заголовком и мусором в строках
по-прежнему давал бы успокаивающие цифры.

**Контракт выводится из того, на что опирается `collapse`**, а не из того, что
удобно проверить:

| Поле | Требование | Почему |
|---|---|---|
| `finding_id` | непустая строка без пробелов | ключ группировки; `collapse` молча пропускает строки с пустым, то есть строка есть, а в метриках её нет |
| `recorded_at` | разбирается в осведомлённый момент | ключ очерёдности; сейчас негодное значение становится `datetime.min` и бесшумно выигрывает или проигрывает сортировку |
| `id_scheme` | непустая и равная текущей | сейчас сравниваются только непустые, поэтому пустая проходит |
| тип строки | ровно одно из полей `initial_verdict` и `human_decision` непусто | строка без типа игнорируется молча, а при двух полях `collapse` выбирает ветку вердикта и теряет семантику решения |
| полнота | ни одного `None` среди значений | `csv.DictReader` отдаёт `None` за обрезанную строку |

Реализовать **внутри `check_log_compatible`**, а не рядом. Отдельная функция
разошлась бы с этой при первой же правке — что и произошло между писателем и
читателем. Одна точка входа, один контракт, оба вызывающих получают его целиком.

Docstring обязан назвать глубину и причину:

    Refuse a log whose shape, identity scheme or rows we cannot rely on.

    Checked to the depth collapse() actually uses: it groups by finding_id,
    orders by recorded_at, and tells verdict rows from decision rows by which
    of two fields is populated. A row failing any of those is not skipped and
    not coerced. A metric computed from data the reader had to guess at is
    worse than no metric, because it gets quoted with the same confidence.

Сообщение об отказе называет номер строки и конкретное нарушение — иначе
исправить лог нельзя, а он append-only.

`metrics.py` вызывает её перед чтением, импортируя из `record_verdict`, как это
делает `record_human_decision`. `record_verdict` уже вызывает.

**Строгость осознанная.** Одна негодная строка блокирует дальнейшую запись, пока
её не починят вручную. Для аудит-трейла это верно: альтернатива — продолжать
писать в файл, часть которого мы уже не понимаем.

Тесты: по одному на каждую строку таблицы, плюс валидный лог проходит. У
`make metrics` несовместимый лог даёт non-zero, а не нули. Мутационная проверка:
снять проверку `recorded_at`, убедиться что тест с негодным временем краснеет на
порядке, а не на чём-то ещё.

- [x] **Step 4: Идентификаторы моделей не нормализуются**

Проверено: `--agent ''` доходит до записи с exit 0. `--agent 'model-b '` против
`--validator 'model-b'` расходятся на пробеле, и контроль независимости
пропускает один и тот же движок.

Пробел обходит механизм, который вся программа объявила своим основанием.

```python
def _identity(value: str, flag: str) -> str:
    """Normalise a model identifier supplied by the engineer.

    Independence is decided by comparing these two strings, so a trailing space
    is enough to let one model validate itself. Compared case-folded for the
    same reason: nobody intends Model-B and model-b to be different reviewers.
    """
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{flag} must not be empty")
    return cleaned
```

Хранить очищенное значение, сравнивать `casefold()`. Пустая строка — ошибка
разбора аргументов, а не молчаливое прохождение.

Тесты: пустой `--agent`; совпадение по пробелу; совпадение по регистру. Все три —
non-zero, ни лога, ни SARIF. Проверки отсутствия внутри `temp_tree`.

- [x] **Step 5: Имя выходного файла берётся из поля, написанного моделью**

Проверено: `finding_id: "/virtual/outside"` при `--out /virtual/packets` уводит
запись за пределы каталога. `finding_id` приходит из JSON, который писала модель,
и схема требует от него только `minLength: 1`.

Два уровня, потому что один здесь недостаточен:

- в `templates/verdict.schema.json` и `challenge.schema.json` у `finding_id`
  появляется `"pattern": "^F-[0-9a-f]{12}$"` — ровно то, что порождает
  `_digest`;
- в `build_packet` перед записью проверяется, что разрешённый путь остаётся
  внутри `--out`:

```python
    out_dir = args.out.resolve()
    path = (out_dir / f"{packet['finding_id']}-challenge.json").resolve()
    if out_dir not in path.parents:
        print(f"REFUSED: {packet['finding_id']!r} would write outside {out_dir}.",
              file=sys.stderr)
        return 2
```

Схема одна не спасает: на машине без `jsonschema` её исполняет фолбэк, а
поддержку `pattern` он получает только в Step 2. Проверка пути не зависит ни от
того, ни от другого.

Тесты: `finding_id` с `/` и с `..` отвергаются обеими проверками по отдельности.

- [x] **Step 6: Известные ограничения — записать, не чинить**

Оба минорных пункта реальны и оба остаются:

- `make check-template` доказывает отсутствие плейсхолдеров, а не осмысленность
  содержимого. Заполненный мусором `CLAUDE.md` его пройдёт. Записать в
  `docs/03` рядом с пре-флайт чек-листом: этот шлюз проверяет форму, а
  содержание проверяет человек, который его заполнял.
- Проверка области и последующее открытие файла не атомарны. В рабочем каталоге,
  который кто-то меняет параллельно, между ними есть окно. Закрывается только
  чтением через дескриптор, что несоразмерно ручному процессу с одним инженером.
  Записать в `docs/03` как известное ограничение с явной границей применимости.

Ограничение, записанное честно, лучше контроля, который притворяется полным.

---

### Task 26: Правки третьего финального ревью

Три Important, все проверены исполнением. Первые две — сужающиеся формы уже
закрытых классов, третья нова по виду и касается целостности журнала.

**Контракт исполнения.** Работать от
`6b4284310cba56a6df0fd2ec582b7d779da879e3` в `hardening/2026-09`, не
переключая ветку, не меняя спеку и сохраняя незакоммиченные правки плана и
брифа. Точная область отслеживаемых файлов:

- `scripts/check_scope.py`
- `scripts/build_packet.py`
- `scripts/record_verdict.py`
- `scripts/check_template.py`
- `templates/verdict.schema.json`
- `templates/challenge.schema.json`
- `tests/test_check_scope.py`
- `tests/test_build_packet.py`
- `tests/test_record_verdict.py`
- `tests/test_metrics.py`
- `tests/test_check_template.py`
- `README.md`
- `docs/03-data-handling.md`
- `docs/superpowers/plans/2026-09-01-codex-brief.md`
- `docs/superpowers/plans/2026-09-01-appsec-review-hardening.md`
- `docs/superpowers/evidence/2026-09-01-red-tests.md`
- `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

Шаги 1–3 выполнять через RED/GREEN по одному: сначала регрессия, падающая на
названном дефекте, затем минимальная правка и сфокусированный зелёный прогон.
Каждую из трёх предписанных мутаций применять отдельно через `apply_patch`,
сохранять фактическую команду и вывод, восстанавливать через `apply_patch` и
подтверждать восстановленный GREEN до следующего шага. Для шага 2 отдельными
тестовыми ветками выполнить рекордер при доступном `jsonschema` и при
принудительном `ImportError`; зависимость не устанавливать и в сеть не выходить.
Отказ до записи проверять внутри времени жизни временного дерева.

После шага 4 прогнать сфокусированные тесты, один свежий `make test`, `make
check-scope`, `make list SARIF=tests/fixtures/sample.sarif`, `make metrics`,
ожидаемо падающий `make check-template` и `git diff --check`. Проверить точный
набор в индексе и создать основной коммит `fix: close third-review control gaps`.
Точный хеш коммита не может ссылаться на себя из собственного содержимого,
поэтому после основного коммита вписать его хеш в доказательства задачи 26,
довести весь файл доказательств до самостоятельного формата «дефект — мутация
или честно названный исторический класс — GREEN-коммит» и создать отдельный
документационный коммит `docs: finalize hardening evidence`. Оба коммита входят
в единый пакет ревью задачи 26.

- [x] **Шаг 1: Всё, что парсер политики не смог объяснить, — отказ**

Задача 25 закрыла именованные формы порчи. Остались другие: маркер списка через
табуляцию, шаблон из одних пробелов в кавычках, нераспознанные формы записи.
Каждая убирает исключение, оставляя файл внешне рабочим, — и `.env` снова
проходит с нулевым кодом.

Точечные отказы за каждой формой порчи не угнаться. Принцип обобщается со
секций на строки: **строка внутри `exclusions`, которую парсер не смог отнести
ни к началу записи, ни к продолжению `ключ: значение`, — отказ с её номером.**

- маркером списка считать `-` с любым пробельным символом после, не только `- `;
- `pattern` после снятия кавычек и пробелов не может быть пустым;
- запись обязана нести `pattern`, `owner` и `reason` — `docs/03` уже требует,
  чтобы каждое исключение было владельческим и объяснённым, теперь это
  обеспечено, а не продекларировано;
- всё прочее внутри секции — отказ.

Тесты: по одному на каждую форму, включая табуляцию и пробельный шаблон, плюс
боевая политика по-прежнему разбирается. Мутационная проверка: вернуть тихое
игнорирование нераспознанной строки, убедиться что тест с табуляцией краснеет.

- [x] **Шаг 2: `$` пропускает хвостовой перевод строки**

Проверено: `re.match(r'^F-[0-9a-f]{12}$', 'F-000000000001\n')` истинно,
`re.fullmatch(r'F-[0-9a-f]{12}', ...)` — ложно. Идентификатор с хвостовым
переводом строки проходит канонический шаблон, доходит до обеих записей, и потом
`check_log_compatible` отвергает собственноручно записанную строку. Рекордер
отравляет свой же журнал.

Схема тут не спасает и не может: `jsonschema` применяет `pattern` через
`re.search`, и у Python `$` перед завершающим `\n` совпадает.

**Первая редакция этого шага была неполной.** Она предписывала проверку в
`_fallback_validate`, а он вызывается только при `ImportError`. На машине с
установленным `jsonschema` — то есть на рекомендованной конфигурации — проверка
не выполнялась бы вовсе, и идентификатор с `\n` доходил бы до `append_log`.
Починена была одна ветка развилки.

Поэтому проверка не принадлежит ни одному из бэкендов валидации, а стоит **после
любого из них и до любой записи**.

Канон определяется там же, где порождается, — в `build_packet`, рядом с
`_digest`:

    FINDING_ID = re.compile(r"F-[0-9a-f]{12}")

    def is_canonical_finding_id(value: object) -> bool:
        """Whether a value is exactly an id this tool can have produced.

        fullmatch, not match with an anchored pattern: Python's `$` also
        matches before a terminal newline, so "F-000000000001\n" satisfies
        ^F-[0-9a-f]{12}$ and goes on to poison the log the recorder itself
        writes. jsonschema applies `pattern` with re.search and inherits the
        same `$`, so neither validation backend can carry this check.
        """
        return isinstance(value, str) and bool(FINDING_ID.fullmatch(value))

Применяется в трёх местах, каждое — самостоятельная точка отказа:

- `record_verdict`: после `validate()` и до всякой записи — для вердикта и, если
  передан, для челленджа. Импорт из `build_packet`, как `ID_SCHEME`;
- `build_packet`: перед использованием идентификатора в имени файла;
- `_fallback_validate`: ключ `pattern` вообще проверять через `re.fullmatch` —
  это чинит и остальные шаблоны схемы, не только идентификатор.

В описании поля в обеих схемах отметить, что обеспечение — fullmatch, а `pattern`
в схеме носит документирующий характер.

Тесты: идентификатор с `\n` отвергается рекордером до записи, отвергается
построителем пакета, и отвергается фолбэком. **Рекордерный тест гонять и с
установленным `jsonschema`, и без него** — именно разница между этими двумя
прогонами и была дырой. Мутационная проверка: заменить `fullmatch` на `match`,
убедиться что краснеет рекордерный тест, а не только фолбэковый.

- [x] **Шаг 3: Одна строка журнала — одна физическая строка**

Проверено: незакрытая кавычка в `notes` поглощает следующую строку целиком.
`csv.DictReader` отдаёт одну запись вместо двух, поглощённое событие живёт внутри
поля `notes`, валидация проходит, метрики показывают одну находку вместо двух.
Событие аудита исчезает бесследно — в журнале только с добавлением это худший
из возможных исходов. Лишние ячейки тоже принимаются: они попадают под ключ
`None`.

Инвариант формулируется явно и обеспечивается с обеих сторон: **в журнале одна
запись занимает ровно одну физическую строку.**

Со стороны записи — ни `\n`, ни `\r` ни в одном значении:

    Refuse a newline in any cell. csv writes it as a legal multi-line field,
    but the log's invariant is one row per physical line: it is what makes a
    truncated or swallowed row detectable at all. A note worth keeping is
    worth keeping on one line.

Со стороны чтения, внутри `check_log_compatible`:

- число прочитанных записей равно числу непустых строк файла минус заголовок;
- ключ `None` в записи — лишние ячейки, отказ;
- значение `None` — обрезанная строка, отказ (уже есть).

Первая проверка ловит именно поглощение: съеденная строка уменьшает счётчик
записей, не меняя счётчика строк.

Тесты: незакрытая кавычка — отказ с номером строки; лишняя ячейка — отказ;
попытка записать `--notes` с переводом строки — отказ до всякой записи.
Мутационная проверка: снять сверку счётчиков, убедиться что тест с поглощением
краснеет на числе находок, а не на чём-то попутном.

- [x] **Шаг 4: Мелкие**

- Формулировка вокруг `make check-template` всё ещё обещает больше, чем шлюз
  делает. Привести в соответствие с ограничением, записанным в шаге 6 задачи 25:
  проверяется отсутствие плейсхолдеров, а не осмысленность содержимого.
- Убрать английские вставки исполнения из русского текста плана.
- Оставшиеся исторические записи доказательств пометить их классом, как это
  уже сделано для задач 11 и 19.
- Каждая запись в `red-tests.md` должна читаться без переписки: явно называть
  дефект, мутацию (либо честный исторический класс, если отдельной мутации не
  было) и точный коммит, где проверка стала зелёной.

### Task 26, раунд исправлений 1

- Парсер принимает в продолжении исключения только ключи `pattern`, `owner` и
  `reason`. Любой другой ключ, включая похожий на элемент списка `-pattern`,
  означает отказ с номером физической строки.
- Физические строки CSV ограничены разделителями CR и LF, теми же символами,
  которые запрещает `append_log`; Unicode-разделители вроде U+2028 остаются
  частью одной физической строки. Парсер CSV работает в строгом режиме,
  независимо отвергая незакрытые кавычки, а номер ошибки указывает на реальное
  начало непустой записи после пустых строк.
- Мутационный пример с табуляцией содержит сначала полное независимое
  исключение PEM. Поэтому ослабленный публичный CLI действительно ошибочно
  принимает `.env` с кодом 0, а не останавливается на проверке нулевого числа
  правил.
- Локальный поддельный модуль остаётся проверкой непрозрачности бэкенда, но не
  считается запуском с установленной зависимостью. Отдельная условная
  регрессия использует настоящий `jsonschema`; стандартный Python честно
  пропускает её при отсутствии пакета, а локальный Python Semgrep выполняет её
  с `jsonschema` 4.25.1 без запуска Semgrep и без сети.

### Task 26, раунд исправлений 2

- Строгая граница ошибок CSV распространяется и на заголовок: ошибка
  `csv.Error` при чтении первой записи преобразуется в управляемый
  `ValidationError` с истинным номером строки 1. Публичный рекордер сообщает
  `LOG ERROR` без traceback и не меняет журнал или SARIF.
- Доказательство для установленного `jsonschema` хранит полный сырой вывод
  мутации `fullmatch` → `match` без сокращений путей и строк статуса. Причиной
  RED остаётся создание артефакта append-spy; соседние отказы не используются.
- Границу заголовка проверяет отдельная мутация, удаляющая только перевод
  `csv.Error` заголовка в `ValidationError`; тест обязан показать прежний сырой
  traceback, после чего точная граница восстанавливается через `apply_patch`.

---

### Task 27: Правки перед слиянием

Итог комплексного ревью человеком на `bb0d238`. Прогон подтверждён независимо в
обоих режимах: 268 тестов зелёные без `jsonschema` и с `jsonschema` 4.26.0.
Мутационная методология проверена собственной мутацией — снятие одного контроля
роняет ровно один именованный тест.

Три правки блокируют слияние. Остальные остатки третьего ревью в эту задачу **не
входят** и уходят отдельным тикетом.

- [x] **Step 1: `--minutes` принимает `nan` и уничтожает главную метрику**

Проверено:

    median: 20.0 | mean: nan | total_hours: nan

Одна опечатка в одном вызове превращает `mean_minutes` и `total_hours` в `nan`,
и они **печатаются как результат**, а не вызывают отказ. Это метрика №1 программы
и первый критерий graduation в `docs/07`. Медиана уцелела случайно — на другой
выборке не уцелеет. Отрицательные и `inf` принимаются так же.

Проверка на разборе аргументов, до всякой записи:

    def _minutes(value: str) -> float:
        """Engineer time in minutes: finite and not negative.

        A single nan turns mean_minutes and total_hours into nan for the whole
        programme, and they print as results rather than refusing - destroying
        the one number docs/07 makes the first graduation criterion. float()
        accepts "nan" and "inf" happily, so the check has to follow the parse.
        """
        parsed = float(value)
        if not math.isfinite(parsed) or parsed < 0:
            raise argparse.ArgumentTypeError(
                f"{value!r} is not a finite, non-negative number of minutes"
            )
        return parsed

**Подключить в обоих скриптах**: `record_verdict.py` и
`record_human_decision.py`. Оба принимают `--minutes`, и починка одного из них —
ровно та ошибка, которая в этом проекте повторялась четырежды.

Тот же контракт действует при чтении старого журнала: `minutes_spent` либо пуст,
либо содержит конечное неотрицательное число. `check_log_compatible` отказывает
на отрицательном, `inf`, `nan` и нечисловом значении с указанием физической
строки, прежде чем `metrics.py` сможет напечатать отравленный результат.

Тесты: `-5`, `inf`, `nan`, `abc` — non-zero для обоих скриптов;
`record_verdict.py` не создаёт лог или SARIF, а
`record_human_decision.py` не меняет существующий лог и не создаёт SARIF.
Проверки артефактов находятся внутри `temp_tree`. Мутационная проверка записи:
снять `math.isfinite`, убедиться что краснеют именованные тесты с `nan` для
обоих скриптов, а не только тесты с `inf`. Мутационная проверка чтения: снять
правило `minutes_spent` из контракта строки и убедиться, что отдельный тест с
`nan` в существующем журнале краснеет.

- [x] **Step 2: `--by` принимает строку из пробелов**

Проверено: `--by "   "` даёт exit 0, и решение приписывается пробелам.

Не писать вторую нормализацию. Task 25 Step 4 уже ввёл `_identity` для
`--agent` и `--validator`; переиспользовать её. Две копии одного правила
разойдутся при первой правке — в этом проекте это происходило дважды, оба раза
между `record_verdict.py` и `record_human_decision.py`.

Тест: `--by "   "` и `--by ""` — non-zero, лог не тронут. Мутационная проверка:
убрать обрезку, убедиться что тест краснеет.

- [x] **Step 3: Жёсткие ссылки — записать как ограничение**

Найдено в комплексном ревью, в списке третьего круга отсутствовало. Проверено:

    жёсткая ссылка на исключённый файл    1 | HARDLINK-SECRET

`resolve_within` здесь бессилен принципиально: у файла два равноправных имени, и
разрешать нечего. Все прежние обходы области чинились разрешением пути — этот не
чинится.

**Не чинить проверкой `st_nlink > 1`.** pnpm и часть кэшей CI создают жёсткие
ссылки штатно; ложные отказы приучат отключать контроль, а отключённый контроль
хуже описанной границы.

Записать в `docs/03` рядом с уже записанными ограничениями (осмысленность
`check-template` и неатомарность проверки с открытием), по прецеденту Task 25
Step 6. И в docstring `resolve_within` добавить, чего она не умеет:

    Resolution cannot see through a hard link: the file has two equally real
    names and there is no target to resolve. An excluded file hard-linked to an
    allowed name passes this check. Creating one needs local write access to
    the working tree, so it is recorded as a limitation in docs/03 rather than
    guarded - a st_nlink test would refuse pnpm stores and CI caches, and a
    control that cries wolf gets switched off.

Мутационной проверки нет: шаг текстовый. Требование к нему — граница названа
там, где её будут искать, то есть и в docs, и в коде.

- [x] **Step 4: Остатки — в тикет, не в эту задачу**

Семь Important и четыре Minor из третьего круга плюс всё, что найдётся дальше,
собрать в отдельный тикет со ссылками на воспроизведения из
`final-review-round-5-report.md`. Ни один из них не пробивает основную угрозу —
попадание содержимого исключённого файла в пакет при обычной работе.

В эту задачу их не тянуть: смысл рубежа в том, чтобы слияние состоялось.
Они вынесены в отдельный post-merge тикет:
`https://github.com/akarazhev/evidence-gate/issues/1`.

---

## Критерии готовности

- `make test` зелёный на голом Python 3.9+ без единой установки.
- У каждого дефекта из слоёв 1–3 и §5.3 сохранён вывод падавшего теста.
- `make check-scope`, `make list`, `make metrics` работают.
- В тестах нет обращений к сети.
- `make check-template` падает, и README объясняет почему.

## Что остаётся вне этого плана

Перед пилотом на реальном репозитории требуется работа, которой здесь нет и которая не является кодом:

1. Наполнение `rules/` правилами под языки целевого репозитория.
2. Заполнение `CLAUDE.md` реальными точками входа и границами доверия.
3. Подтверждённый доступ к двум разным моделям. Проверить **до** начала реализации: `make record` теперь отказывает при совпадении, а medium и выше без челленджа не выходят из `blocked_needs_challenge`.
