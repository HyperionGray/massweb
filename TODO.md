# TODO

## Daily Progress: 2026-04-07

### Natural direction

MassWeb's current direction is incremental modernization around a stable large-scale scanning core:

- Preserve the existing multiprocessing-based fuzzing and request pipeline in `massweb/mass_requests/` and `massweb/fuzzers/`
- Continue repository cleanup and automation maintenance in `.github/workflows/`
- Improve developer usability through clearer setup, targeted tests, and tracked technical debt

Recent commits added SSRF and SSTI vuln checks, offline WebFuzzer tests, and minor test-quality improvements.

### Quick wins (completed 2026-04-07)

- [x] Add `docs/_build/` to `.gitignore` — stop tracking Sphinx build output
- [x] Align the documented test setup with the actual test requirements (`QUICKSTART.md` now uses `python -m unittest discover test/`)
- [x] Add focused test coverage for `massweb/proxy_rotator/` (`test/test_proxy_rotator.py`)
- [x] Add focused test coverage for `massweb/mass_requests/response_analysis` (`test/test_response_analysis.py`)
- [x] Correct inaccurate API examples in `QUICKSTART.md` (WebFuzzer, payload, vuln-check usage)

### FIXME items tracked from source code

These FIXME comments exist in the codebase and are tracked here for follow-up:

- [ ] `massweb/fuzz_generators/url_generator.py:46` — PNKTHR-42: UTF-8 query params and keys may be incorrectly generated; needs more testing
- [ ] `massweb/fuzzers/bsqli_fuzzer.py:174,198` — Investigate why an empty list is required in certain bsqli payload processing paths
- [ ] `massweb/fuzzers/bsqli_fuzzer.py:236` — Refactor: local variable assignments are unnecessary; pass values directly
- [ ] `massweb/fuzzers/web_fuzzer.py:166` — Clarify: `_run_checks()` is not yet multiprocessed; decide if it should be
- [ ] `massweb/fuzzers/web_fuzzer.py:203` — Clarify: `fuzz()` return type is not clearly documented; the response object handling is messy
- [ ] `massweb/fuzzers/ifuzzer.py:68` — Unify bsqli and web fuzzer interfaces to reduce code duplication
- [ ] `massweb/masscrawler/masscrawl.py:109` — Out-of-scope POST requests occur in large-scale crawls; investigate and restrict
- [ ] `massweb/masscrawler/masscrawl.py:155` — Crawler does not stay in scope consistently; fix scope enforcement
- [ ] `massweb/pnk_net/find_post.py:31` — URL normalization does not include path; some paths are computed incorrectly
- [ ] `massweb/pnk_net/pnk_request.py:14` — Define `IDENTIFY_POSTS`, `GET`, `POST` constants in a single central constants module (currently duplicated in `mass_request.py` and `pnk_request.py`)
- [ ] `massweb/payloads/bsqli_payload_group.py:2` — PNKTHR-43: Clarify how `add_payload()` interacts with `BSQLIPayloadGroup`
- [ ] `massweb/payloads/bsqli_payload_group.py:20` — Simplify double-negation logic

### Incremental improvements

- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns
- [ ] Add targeted regression tests for crawler scope handling in `massweb/masscrawler/masscrawl.py`

### Larger follow-ups

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve MassWeb's hard timeout behavior
- [ ] Extract `IDENTIFY_POSTS`/`GET`/`POST` constants into a shared `massweb/constants.py` to eliminate duplication

### Evidence gathered for this update

- `python -m unittest discover test/` now runs successfully with the standard `pip install -e .` setup (15 tests, 2 integration skips)
- `docs/_build/` was tracked in git despite being a generated Sphinx output directory — now excluded via `.gitignore`
- `QUICKSTART.md` contained fabricated API examples (`PayloadGenerator.from_file`, `FuzzyTarget` with keyword args, `Check.scan()`) that don't exist in the codebase — corrected to match the real API
- FIXME comments are now all captured above; none require immediate structural changes but several touch scope and interface consistency
