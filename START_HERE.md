# START_HERE.md

## What is This Repository?

**MassWeb** is a high-performance web application fuzzing and scanning library designed for massive-scale Internet vulnerability assessments. If you're looking at this repo for the first time, think of it as a tool that can test hundreds of millions of websites for security vulnerabilities in just days, not years.

This is a Python 3 library originally built by Hyperion Gray for their PunkSPIDER 3.0 project, which scans the entire Internet for web application vulnerabilities. It handles the complexities of making millions of HTTP requests efficiently while checking for common security issues like SQL injection, XSS, path traversal, and more.

## Why Was This Built? Why Is This Useful?

**The Problem:**
When you need to scan hundreds of millions of web applications for vulnerabilities, you face several critical challenges:

1. **Speed**: You can't request URLs one-by-one. That would take forever.
2. **Variable Response Times**: Some URLs return instantly; others might try to send you gigabytes of data. You need hard timeouts.
3. **Scale**: You need to distribute work across clusters (Hadoop) while keeping individual workers multi-threaded.
4. **Proxy Management**: Large-scale scanning requires rotating through many proxies to avoid rate limiting and blocks.
5. **Simplicity**: Despite all this complexity, the API needs to be simple enough to use in just a few lines of code.

**The Solution:**
MassWeb solves all of these problems in one library. It was used to scan several hundred million URLs in just 3 days during PunkSPIDER scans. It provides:
- Multi-threaded request handling with hard timeouts
- Transparent proxy rotation
- Built-in vulnerability checks for common web exploits
- Hadoop-compatible mappers/reducers for distributed scanning
- Simple, pythonic API

## Who Is This For?

This repository is for:

1. **Security Researchers**: Conducting large-scale web vulnerability assessments
2. **Penetration Testers**: Who need to fuzz web applications efficiently
3. **Academic Researchers**: Studying Internet-wide security trends
4. **Infrastructure Engineers**: Building distributed scanning systems
5. **Anyone**: Who needs to make massive numbers of HTTP requests with timeouts and analysis

**Prerequisites**: You should be a developer comfortable with Python, HTTP requests, and basic security concepts (SQL injection, XSS, etc.). No specific language expertise is required, but you should understand web applications and REST APIs.

## Repository Deep Dive

### Architecture Overview

MassWeb is structured as a modular Python library with several key components that work together:

```
massweb/
├── mass_requests/      # Core request handling with threading and timeouts
├── fuzzers/           # Fuzzing engines that combine payloads with targets
├── masscrawler/       # Web crawler for discovering attack surfaces
├── targets/           # Target representation (URLs, parameters, types)
├── payloads/          # Attack payloads for different vulnerability types
├── vuln_checks/       # Vulnerability detection logic (SQLi, XSS, etc.)
├── proxy_rotator/     # Proxy rotation for distributed requests
├── pnk_net/           # Low-level HTTP request utilities
├── results/           # Result objects for vulnerability findings
└── hadoop-utils/      # Hadoop MapReduce integration
```

### Core Components Explained

#### 1. MassRequest (`mass_requests/mass_request.py`)
This is the workhorse. It handles massive parallel HTTP requests with hard timeouts.

**Key Features:**
- Uses Python's `multiprocessing.Pool` to spawn worker processes
- Each URL gets a configurable timeout (default 10 seconds)
- Transparent handling of GET/POST requests
- Automatic proxy rotation
- Can auto-discover POST forms in HTML

**How it works:**
- You give it a list of `Target` objects (URLs with metadata)
- It spawns N worker processes (configurable, default 10)
- Each worker gets a target and makes the HTTP request
- Results are collected with a hard timeout per URL
- Failed requests are tracked and marked with `__PNK_THREAD_TIMEOUT` or `__PNK_FAILED_RESPONSE`

**Important code:** Lines 98-213 in `mass_request.py` show the core `handle_targets()` and `collect_target_results()` methods.

#### 2. WebFuzzer (`fuzzers/web_fuzzer.py`)
The fuzzing engine that combines payloads with targets and checks for vulnerabilities.

**Key Features:**
- Takes targets (URLs) and payloads (attack strings)
- Generates "fuzzy targets" by injecting payloads into URL parameters or POST data
- Makes requests via MassRequest
- Analyzes responses using vulnerability checkers
- Returns `Result` objects with vulnerability status

**How it works:**
1. `generate_fuzzy_targets()`: For each target and each parameter, create a new target with payload injected
2. `fuzz()`: Send all fuzzy targets via MassRequest
3. `analyze_response()`: For each response, run relevant vulnerability checks
4. Returns list of `Result` objects

**Important code:** Lines 128-148 (fuzzy target generation), Lines 150-212 (fuzzing and analysis)

#### 3. Vulnerability Checks (`vuln_checks/`)
Each check is a separate class that inherits from `Check` base class:

- **SQLi**: SQL Injection detection (pattern matching for error messages)
- **XSS**: Cross-site scripting detection (looks for unescaped payload in response)
- **Trav**: Path traversal detection (checks for `/etc/passwd` or Windows system files)
- **MXI**: MySQL injection specific checks
- **OSCi**: OS Command injection detection
- **XPathI**: XPath injection detection

**How they work:** Each checker has a `check(content)` method that takes response text and returns True/False based on pattern matching for known vulnerability indicators.

**Important code:** Each checker in `vuln_checks/*.py` has regex patterns or string matching logic.

#### 4. Targets (`targets/`)
Target objects represent what to scan:

- **Target**: Base class (URL + request type + optional POST data)
- **FuzzyTarget**: Target with an injected payload (tracks original URL, parameter, payload)
- **CrawlTarget**: Target discovered during crawling
- **FuzzyTargetGroup**: Collection of related fuzzy targets, including bulk insertion via `add_targets(...)`

**Bulk add example:**
```python
from massweb.targets.fuzzy_target_group import FuzzyTargetGroup

group = FuzzyTargetGroup()
group.add_targets([true_fuzzy_target, false_fuzzy_target])
```

#### 5. Payloads (`payloads/`)
Payload objects contain attack strings:

- Each payload has a string value and a list of check types to run
- Example: `'"><ScRipT>alert(31337)</ScrIpT>'` with check_type `["xss"]`
- PayloadGroup can bundle multiple related payloads

#### 6. MassCrawl (`masscrawler/masscrawl.py`)
A web crawler that:
- Starts from seed URLs
- Follows links (optionally staying in-scope by domain)
- Discovers forms and POST endpoints
- Builds a target list for fuzzing

**Key Features:**
- Scope control (stay within certain domains)
- Link extraction from HTML (using BeautifulSoup)
- Form discovery
- Max link limits to prevent explosion

#### 7. Hadoop Integration (`hadoop-utils/`)
MapReduce scripts for distributed scanning:
- **Mapper**: Takes URLs from stdin, fuzzes them, outputs results
- **Reducer**: Aggregates and deduplicates results

**Why this matters:** This allows MassWeb to run on a Hadoop cluster where each mapper node can fuzz thousands of URLs independently, then reducers combine the findings.

### How It All Fits Together

**Typical workflow:**
1. Create a list of URLs or use MassCrawl to discover them
2. Create Target objects from URLs
3. Create Payload objects with attack strings
4. Create a WebFuzzer with targets and payloads
5. Call `fuzzer.generate_fuzzy_targets()` to create all combinations
6. Call `fuzzer.fuzz()` to execute and analyze
7. Process Result objects to find vulnerabilities

**Example (simplified):**
```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target
from massweb.payloads.payload_group import PayloadGroup

# Create targets
targets = [Target("http://example.com/page?id=1", "get")]

# Create payloads
payloads = [...]  # Attack strings

# Fuzz
fuzzer = WebFuzzer(targets=targets, payloads=payloads, num_threads=10)
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Check results
for result in results:
    if True in result.result_dic.values():
        print(f"Vulnerability found: {result}")
```

### Unique Aspects of the Code

1. **Hard Timeouts**: Unlike most HTTP libraries, MassWeb uses process pools with timeouts to guarantee no request takes longer than specified. This is critical for Internet-scale scanning where some hosts might try to send gigabytes of data.

2. **Proxy Rotation**: Built-in proxy cycling is transparent - you just provide a list and it rotates automatically.

3. **Hadoop-Ready**: The mapper/reducer scripts show this was designed from day one to run on distributed clusters.

4. **Multi-Phase**: Separates target generation, request execution, and analysis into distinct phases, making it easier to debug and optimize each part.

5. **Legacy Python 2→3 Migration**: You'll see some legacy code patterns (like unicode handling for Python 2) that have been updated for Python 3. Some comments reference old FIXME items.

### Technical Details

**Dependencies:**
- `requests`: HTTP requests
- `beautifulsoup4` + `html5lib`: HTML parsing
- `multiprocessing`: Parallel request handling
- Python 3.7+ (supports up to 3.12)

**Threading Model:**
- Uses `multiprocessing.Pool`, not threads (avoids GIL)
- Worker processes are separate OS processes
- Timeout enforcement via `AsyncResult.get(timeout=...)`

**Error Handling:**
- Failed requests return special strings: `__PNK_THREAD_TIMEOUT`, `__PNK_FAILED_RESPONSE`
- Exceptions during analysis create "failed" Result objects
- Hadoop reporting mode adds extra logging

**Performance Characteristics:**
- Speed limited by: number of threads, timeout per URL, network latency
- Upper bound calculation: `(num_urls / num_threads) * time_per_url`
- Example: 1M URLs, 100 threads, 10s timeout = ~28 hours max

## How to Build On This

Here are concrete ways to contribute or extend MassWeb, from easy to difficult:

### Easy Tasks (Good First Issues)

1. **Add More Payload Examples** (`massweb/payloads/`)
   - Location: Create new payload files or extend existing ones
   - What: Add modern attack patterns (NoSQL injection, SSTI, etc.)
   - Why: Payload lists are from ~2015 and could use updates

2. **Improve Documentation Strings**
   - Location: Throughout codebase, especially `fuzzers/`, `vuln_checks/`
   - What: Add better docstrings, type hints, examples
   - Why: Many methods have minimal or outdated documentation

3. **Update Vulnerability Check Patterns** (`massweb/vuln_checks/`)
   - Location: Individual check files (sqli.py, xss.py, etc.)
   - What: Add newer error messages, WAF bypass patterns
   - Why: Modern frameworks have different error messages

4. **Add Unit Tests** (`test/`)
   - Location: Create missing test files
   - What: Tests for proxy rotation, payload handling, edge cases
   - Why: Test coverage is sparse

5. **Fix Python 2 Legacy Code**
   - Location: Search for `unicode`, old exception syntax
   - What: Clean up Python 2→3 migration artifacts
   - Why: Code has some legacy patterns that could be modernized

### Moderate Tasks

1. **Add New Vulnerability Checks**
   - Location: `massweb/vuln_checks/` - create new checker class
   - What: Implement checks for: SSRF, XXE, IDOR, subdomain takeover
   - How: Inherit from `Check`, implement `check(content)` method
   - Important: See `check.py` for base class, `xss.py` for simple example

2. **Async/Await Refactor** 
   - Location: `massweb/mass_requests/mass_request.py`
   - What: Replace multiprocessing with asyncio for better performance
   - Why: Modern async I/O is faster and more memory-efficient than process pools
   - Challenge: Need to maintain hard timeout guarantees

3. **Improve Crawler** (`massweb/masscrawler/masscrawl.py`)
   - Location: MassCrawl class
   - What: Add JavaScript rendering (selenium/playwright), better form parsing, API endpoint discovery
   - Why: Modern SPAs aren't well-handled by BeautifulSoup alone

4. **Add Authentication Support**
   - Location: `massweb/pnk_net/pnk_request.py`
   - What: Support OAuth, JWT, session cookies, API keys
   - Why: Many apps require auth to reach attack surface

5. **Build a Results Database**
   - Location: New module `massweb/storage/`
   - What: Store results in SQLite/PostgreSQL instead of just returning them
   - Why: For large scans, you need persistent storage and querying

6. **Add Rate Limiting**
   - Location: `massweb/mass_requests/mass_request.py`
   - What: Configurable requests-per-second limits
   - Why: Avoid overwhelming targets or triggering aggressive WAFs

### Difficult Tasks

1. **Implement Fuzzing Intelligence**
   - Location: New module `massweb/ml/` or extend `fuzzers/`
   - What: Use ML to predict which parameters are vulnerable, prioritize targets
   - Why: Reduce request volume by focusing on likely-vulnerable areas
   - Challenge: Need training data, model selection, integration with existing flow

2. **Distributed Coordination**
   - Location: New module `massweb/distributed/`
   - What: Replace Hadoop with modern distributed system (Celery, Ray, Dask)
   - Why: Hadoop is heavyweight; modern tools are more flexible
   - Challenge: Maintain performance, handle failures, coordinate workers

3. **Advanced WAF Detection & Bypass**
   - Location: New module `massweb/waf/` + integration in `fuzzers/`
   - What: Detect WAFs (Cloudflare, Akamai, AWS WAF) and use evasion techniques
   - Why: Many sites have WAFs that block obvious fuzzing
   - Challenge: WAF fingerprinting, payload encoding/mutation, timing analysis

4. **Real-time Dashboard**
   - Location: New package `massweb-dashboard/`
   - What: Web UI showing scan progress, vulnerability findings, statistics
   - Why: Visibility into long-running scans
   - Challenge: Requires web framework, real-time updates, database

5. **Smart Payload Generation**
   - Location: `massweb/fuzz_generators/` (currently has `url_generator.py`)
   - What: Context-aware payload generation based on parameter names, types, responses
   - Why: Generic payloads miss vulnerabilities; targeted fuzzing is more effective
   - Challenge: Requires heuristics or ML, integration with existing payload system

### Important Code Locations Reference

**Start here to understand the system:**
1. `massweb/fuzzers/web_fuzzer.py` - Main fuzzing logic
2. `massweb/mass_requests/mass_request.py` - Request handling
3. `massweb/targets/target.py` - How targets are represented
4. `massweb/vuln_checks/check.py` - Base vulnerability checker

**To add new vulnerability checks:**
1. Create new file in `massweb/vuln_checks/`
2. Inherit from `Check` class
3. Implement `check(content)` method
4. Add to `WebFuzzer._run_checks()` in `web_fuzzer.py` (lines 214-241)

**To modify request behavior:**
1. `massweb/pnk_net/pnk_request.py` - Low-level request function
2. `massweb/proxy_rotator/proxy_rotate.py` - Proxy selection logic

**To extend crawling:**
1. `massweb/masscrawler/masscrawl.py` - Crawler logic
2. `massweb/pnk_net/find_post.py` - Form discovery

**To change how results are handled:**
1. `massweb/results/result.py` - Result object structure
2. `massweb/fuzzers/web_fuzzer.py` lines 177-212 - Result creation

**For Hadoop/distributed:**
1. `massweb/hadoop-utils/massweb_mapper.py` - Map phase
2. `massweb/hadoop-utils/massweb_reducer.py` - Reduce phase

## Getting Started Checklist

To actually start using and developing with MassWeb:

1. **Install**: `pip install -e .` (development mode) or `pip install massweb`
2. **Read tests**: Check `test/` directory for usage examples
3. **Try examples**: Look at `massweb/hadoop-utils/massweb_mapper.py` for a complete example
4. **Make small changes**: Start with adding a payload or improving a docstring
5. **Run tests**: `python -m pytest test/` (if pytest is installed)
6. **Read the docs**: `docs/` has Sphinx documentation (may be outdated but helpful)

## Final Notes

This is beta software originally built for a specific use case (PunkSPIDER). Some areas are polished, others have FIXMEs and TODOs. The core request handling and fuzzing logic is solid and proven at Internet scale. The vulnerability checks are basic pattern matching - they'll find obvious issues but not sophisticated ones.

If you're building on this, focus on:
- The core MassRequest abstraction is excellent - keep it
- The modular vulnerability checks are easy to extend - add modern checks
- The Hadoop integration is dated - consider modern alternatives
- The payload management could be smarter - good area for ML/AI

This codebase was designed for scanning millions of URLs. If you're scanning 10 URLs, use Burp Suite or OWASP ZAP. If you're scanning 10 million URLs, this is your tool.

**Questions?** Read the code - it's generally well-structured despite some rough edges. The test files also serve as decent examples of how to use each component.
