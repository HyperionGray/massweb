# MassWeb Quick Start Guide

## Installation

1. Clone the repository:
```bash
git clone https://github.com/HyperionGray/massweb.git
cd massweb
```

2. Install dependencies:
```bash
pip install -e .
```

## Basic Usage

### Web Fuzzing

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload

wf = WebFuzzer(num_threads=10, time_per_url=10, request_timeout=10, proxy_list=[{}])

# Add payloads
wf.add_payload(Payload("')--", check_type_list=["sqli", "xpathi"]))
wf.add_payload(Payload('"><ScRipT>alert(1)</ScrIpT>', check_type_list=["xss"]))

# Add targets (unicode strings are supported via u"...")
wf.add_target_from_url(u"http://example.com/vuln.php?id=1")
wf.add_target_from_url(u"http://example.com/search.php?q=test")

# Optional: discover simple POST forms from GET targets
wf.determine_posts_from_targets()

# Build fuzz targets and execute
wf.generate_fuzzy_targets()
results = wf.fuzz()

for result in results[:5]:
    print(result)
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

seeds = [u"http://example.com"]
crawler = MassCrawl(seeds=seeds)
crawler.crawl(
    depth=1,
    num_threads=4,
    time_per_url=5,
    request_timeout=3,
    proxy_list=[{}],
    stay_in_scope=True,
)

for target in crawler.targets[:10]:
    print(target.url, target.status)
```

## Using AI-Powered Workflows (Gemini and Others)

### Quick Test

1. **Issue review**:
   - Create/open an issue
   - Add label `gemini` (default model) or `gemini:gemini-1.5-flash`
2. **PR review**:
   - Create/open a pull request
   - Add label `gemini` (or another provider/model label)

For full label formats and troubleshooting, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md).

## Configuration

### Proxy Settings

Pass proxies directly via `proxy_list`:

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer

proxies = [
    {"http": "http://proxy1.example:8080"},
    {"http": "http://proxy2.example:8080"},
]
wf = WebFuzzer(proxy_list=proxies)
```

### Payload Customization

Use `Payload` objects and add them to a fuzzer:

```python
from massweb.payloads.payload import Payload

custom_payloads = [
    Payload("../../../etc/passwd", check_type_list=["trav"]),
    Payload("' OR 1=1--", check_type_list=["sqli"]),
]

for payload in custom_payloads:
    wf.add_payload(payload)
```

## Common Checks

### SQL Injection Pattern Check
```python
from massweb.vuln_checks.sqli import SQLICheck

checker = SQLICheck()
looks_vulnerable = checker.check(response_text)
```

### Directory Traversal Pattern Check
```python
from massweb.vuln_checks.trav import TravCheck

checker = TravCheck()
looks_vulnerable = checker.check(response_text)
```

## Running Tests

```bash
python -m pytest test/
```

## Documentation

- Full project docs: https://hyperiongray.atlassian.net/wiki/display/PUB/MassWeb
- AI workflow docs: [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## License

Apache 2.0 - see `LICENSE.txt`.
