# TODO

## Daily Progress: 2026-04-07

### Completed from 2026-04-04 plan

- [x] Add `docs/_build/` to `.gitignore` (also added `__pycache__/`)
- [x] Add focused unit tests for `massweb/proxy_rotator/` (`test/test_proxy_rotator.py`)
- [x] Add focused unit tests for `massweb/mass_requests/` (`test/test_mass_request.py`)
- [x] Fix `QUICKSTART.md`: corrected broken API examples, removed non-existent classes
  (`FuzzyTarget` constructor, `PayloadGenerator`, `SQLICheck(target).scan()`),
  aligned test command with actual tooling (`unittest` not `pytest`)

### FIXME inventory (tracked from source, not yet resolved)

These are the current FIXME comments in core modules.
Address them in follow-up issues or PRs.

| File | Line | FIXME |
|------|------|-------|
| `massweb/fuzz_generators/url_generator.py` | 46 | PNKTHR-42 — utf-8 query param encoding may produce incorrect keys/values; needs more testing |
| `massweb/fuzzers/bsqli_fuzzer.py` | 174 | Investigate why an empty list must be appended before extending the result list |
| `massweb/fuzzers/bsqli_fuzzer.py` | 198 | Same pattern as line 174 |
| `massweb/fuzzers/bsqli_fuzzer.py` | 236 | No need to hold results in local variables; inline them |
| `massweb/fuzzers/web_fuzzer.py` | 166 | Clarify whether `_run_checks` should be multithreaded |
| `massweb/fuzzers/web_fuzzer.py` | 203 | `_run_checks` return type is messy; clean up response type contract |
| `massweb/fuzzers/ifuzzer.py` | 68 | Remove workaround to make bsqli and web fuzzers share a uniform interface |
| `massweb/masscrawler/masscrawl.py` | 109 | Out-of-scope POST requests observed in large-scale crawls |
| `massweb/masscrawler/masscrawl.py` | 155 | Crawler scope not reliably enforced |
| `massweb/pnk_net/find_post.py` | 31 | URL normalization does not include path; gets paths wrong |
| `massweb/pnk_net/pnk_request.py` | 14 | Constants (`IDENTIFY_POSTS`, `GET`, `POST`) should be defined in a central const module, not duplicated across `pnk_request.py` and `mass_request.py` |
| `massweb/payloads/bsqli_payload_group.py` | 2 | PNKTHR-43 — clarify how `add_payload` interacts with this class |
| `massweb/payloads/bsqli_payload_group.py` | 20 | Negate the condition and remove unnecessary else branch |

## Daily Progress: 2026-04-04

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

- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns
- [ ] Add targeted regression tests for crawler scope handling in `massweb/masscrawler/masscrawl.py`

### Larger follow-ups

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve MassWeb's hard timeout behavior
- [ ] Consolidate the duplicated `GET`/`POST`/`IDENTIFY_POSTS` constants into a central `massweb/const.py` module (see FIXME in `pnk_request.py`)

## Daily Progress: 2026-03-09

### Natural direction

MassWeb's current direction is incremental modernization around a stable large-scale scanning core:

- Preserve the existing multiprocessing-based fuzzing and request pipeline in `massweb/mass_requests/` and `massweb/fuzzers/`
- Continue repository cleanup and automation maintenance in `.github/workflows/`
- Improve developer usability through clearer setup, targeted tests, and tracked technical debt

Recent commits are concentrated on removing workflow files that no longer match the shared `.github` templates, which suggests the next useful work should stay focused on cleanup, validation, and small reliability improvements rather than large architectural rewrites.

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
