# TODO

## Daily Progress: 2026-04-03

### Natural direction

Continuing incremental modernization and cleanup. Recent work focused on:

- Removing stale `docs/_build/` output from version control
- Correcting `QUICKSTART.md` to reflect the real API and test commands
- Adding offline unit tests for previously untested core paths
- Capturing all open FIXME items as tracked debt below

### Quick wins

- [x] Add `docs/_build/` to `.gitignore` and remove tracked documentation build output from version control
- [x] Align the documented test setup with the actual test requirements so `python -m unittest discover test/` can run with the documented dependencies
- [x] Convert the remaining `FIXME` comments in core modules into tracked fixes in this `TODO.md`
- [x] Add focused test coverage for the least-covered core paths in `massweb/proxy_rotator/` and `massweb/mass_requests/`

### Incremental improvements

- [x] Update `QUICKSTART.md` and related docs so installation, test commands, and API examples match the current repository state
- [x] Add targeted regression tests for crawler scope handling in `massweb/masscrawler/masscrawl.py`
- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns

### Larger follow-ups

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve MassWeb's hard timeout behavior

---

## Daily Progress: 2026-03-09

### Natural direction

MassWeb's current direction is incremental modernization around a stable large-scale scanning core:

- Preserve the existing multiprocessing-based fuzzing and request pipeline in `massweb/mass_requests/` and `massweb/fuzzers/`
- Continue repository cleanup and automation maintenance in `.github/workflows/`
- Improve developer usability through clearer setup, targeted tests, and tracked technical debt

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

---

## Open FIXME Items

These were extracted from source comments and are tracked here for follow-up.

### `massweb/fuzz_generators/url_generator.py` line 46
**PNKTHR-42** (ticket referenced in original comment): UTF-8 query params and keys may be encoded incorrectly in some
edge cases. Needs a test harness with non-ASCII input to reproduce and fix.

### `massweb/fuzzers/bsqli_fuzzer.py` lines 174, 198
**Investigation needed**: An empty list must be explicitly passed in two
locations to avoid a crash; the root cause is unknown. Needs a minimized
reproduction case to confirm whether the issue is in the fuzzer or in the
payload-group iteration logic.

### `massweb/fuzzers/bsqli_fuzzer.py` line 236
**Cleanup**: Local variables are used to hold values that could be referenced
directly. Low risk; refactor during next scheduled pass of `bsqli_fuzzer.py`.

### `massweb/fuzzers/web_fuzzer.py` line 166
**Design question**: The `fuzz()` method is not yet parallelized even though
the request layer uses `multiprocessing`. Revisit whether the analysis loop
should become concurrent once the analysis bottleneck has been profiled.

### `massweb/fuzzers/web_fuzzer.py` line 203
**Cleanup**: The `analyze_response` helper is described as a mess internally.
The `response` argument type is inconsistent (can be `Response` or a sentinel
string). Formalize the contract with a type annotation or an explicit early
return for non-`Response` values.

### `massweb/fuzzers/ifuzzer.py` line 68
**Refactor**: Remove the divergence between `bsqli` and `web` fuzzer
initialization so that both share the same constructor signature in
`IFuzzer`.

### `massweb/masscrawler/masscrawl.py` line 109
**FIXME**: Out-of-scope POST targets appear in large crawls despite the scope
filter. The hack in `filter_targets_by_scope` suppresses symptoms but the root
cause — likely in `find_post_requests` returning absolute URLs that bypass
scope checking — has not been confirmed.

### `massweb/masscrawler/masscrawl.py` line 155
**FIXME**: `find_post_requests` is called with a raw URL string as `target`
rather than a `Target` object. Confirm whether the scope of discovered POST
targets is validated before they are added to `self.targets`.

### `massweb/pnk_net/find_post.py` line 31
**FIXME**: `normalize_link` does not include the path component when
normalizing relative URLs, which can produce incorrect absolute URLs for
path-relative links. Add a test case with a path-relative href and fix the
normalization logic.

### `massweb/pnk_net/pnk_request.py` line 14
**FIXME**: The sentinel strings `__PNK_THREAD_TIMEOUT` and
`__PNK_FAILED_RESPONSE` are defined inline in multiple places. Move them to a
central `massweb/constants.py` module and import from there.

### `massweb/payloads/bsqli_payload_group.py` lines 2, 20
**PNKTHR-43** (ticket referenced in original comment): Verify that `BsqliPayloadGroup.add_payload` correctly appends
to the right list. The negation comment on line 20 suggests the conditional
logic may be inverted.
