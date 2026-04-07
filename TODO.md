# TODO

## Daily Progress: 2026-04-02

### Work completed this session

- [x] Added `docs/_build/` and `__pycache__/` to `.gitignore`
- [x] Added focused unit tests for `massweb/proxy_rotator/` (`test/test_proxy_rotator.py`)
- [x] Added focused unit tests for `massweb/mass_requests/` (`test/test_mass_request.py`)
- [x] Added targeted regression tests for MassCrawl scope handling (`test/test_masscrawl_scope.py`)
- [x] Fixed deprecated `logger.warn` calls in `massweb/masscrawler/masscrawl.py` (replaced with `logger.warning`)
- [x] Updated `QUICKSTART.md` with accurate API examples and test commands

### FIXME inventory (converted from inline comments)

The following `#FIXME` items exist in the codebase. Each is tracked here so they
can be addressed as discrete follow-up tasks:

- `massweb/fuzz_generators/url_generator.py:46` — UTF-8 query param/key
  handling may produce incorrect results (PNKTHR-42); needs more testing.
- `massweb/fuzzers/bsqli_fuzzer.py:174,198` — Empty list initialization
  workaround; the root cause is not understood and should be investigated.
- `massweb/fuzzers/bsqli_fuzzer.py:236` — Intermediate local variables are
  unnecessary; simplify the expression.
- `massweb/fuzzers/web_fuzzer.py:166` — `fuzz()` is not yet multithreaded for
  result analysis; clarify whether it should be.
- `massweb/fuzzers/web_fuzzer.py:203` — `analyze_response()` handles mixed
  text/non-text responses in an ad-hoc way; refactor for clarity.
- `massweb/fuzzers/ifuzzer.py:68` — Inconsistency between BSQLi and Web fuzzers
  in how `add_payload` is surfaced; unify the interface.
- `massweb/masscrawler/masscrawl.py:109` — Out-of-scope POST targets appear in
  large-scale crawls; the real cause should be found and the hack removed.
- `massweb/masscrawler/masscrawl.py:155` — `parse()` does not enforce scope when
  finding POST requests; this should respect the `stay_in_scope` flag.
- `massweb/pnk_net/find_post.py:31` — `normalize_link` does not include path in
  normalization; paths may be computed incorrectly.
- `massweb/pnk_net/pnk_request.py:14` — Magic sentinel strings
  (`__PNK_THREAD_TIMEOUT`, `__PNK_FAILED_RESPONSE`) should be defined in a
  central constants module and imported everywhere.
- `massweb/payloads/bsqli_payload_group.py:2,20` — `BSQLIPayloadGroup` does not
  implement `add_payload` correctly (see PNKTHR-43); the negation logic should
  also be simplified.
- `test/targets/target.py:60` — Original test assumed `target_1 == target_2`;
  needs a comment or test update to confirm current equality semantics are correct.

### Remaining quick wins

- [ ] Implement `add_payload` for `BSQLIPayloadGroup` (PNKTHR-43)
- [ ] Move sentinel strings to a central constants module

### Incremental improvements

- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and
  `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns
- [ ] Add targeted regression tests for crawler scope handling in the
  `parse()` method (stay_in_scope for discovered POST targets)

### Larger follow-ups

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while
  preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve
  MassWeb's hard timeout behavior

---

## Daily Progress: 2026-03-09

### Natural direction

MassWeb's current direction is incremental modernization around a stable large-scale scanning core:

- Preserve the existing multiprocessing-based fuzzing and request pipeline in `massweb/mass_requests/` and `massweb/fuzzers/`
- Continue repository cleanup and automation maintenance in `.github/workflows/`
- Improve developer usability through clearer setup, targeted tests, and tracked technical debt

Recent commits are concentrated on removing workflow files that no longer match the shared `.github` templates, which suggests the next useful work should stay focused on cleanup, validation, and small reliability improvements rather than large architectural rewrites.

### Quick wins

- [x] Add `docs/_build/` to `.gitignore` and remove tracked documentation build output from version control
- [x] Align the documented test setup with the actual test requirements so `python -m unittest discover test/` can run with the documented dependencies
- [x] Convert the remaining `FIXME` comments in core modules into tracked fixes in this `TODO.md` or follow-up issues with clear owners and scope
- [x] Add focused test coverage for the least-covered core paths in `massweb/proxy_rotator/` and `massweb/mass_requests/`

### Incremental improvements

- [x] Update `QUICKSTART.md` and related docs so installation, test commands, and AI workflow guidance match the current repository state
- [x] Add targeted regression tests for crawler scope handling in `massweb/masscrawler/masscrawl.py`
- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns

### Larger follow-ups

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve MassWeb's hard timeout behavior

### Evidence gathered for this update

- Recent repository activity is mostly workflow-template cleanup in `.github/workflows/`
- Open issues are dominated by recurring daily progress analysis requests
- Local `python -m unittest discover test/` currently fails before execution because `bs4` is not available in the environment
- Current technical-debt hotspots include:
  - `massweb/fuzz_generators/url_generator.py`
  - `massweb/masscrawler/masscrawl.py`
  - `massweb/fuzzers/web_fuzzer.py`
  - `massweb/fuzzers/bsqli_fuzzer.py`
  - `massweb/pnk_net/find_post.py`
  - `massweb/pnk_net/pnk_request.py`
  - `massweb/payloads/bsqli_payload_group.py`
