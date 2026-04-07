# MassWeb Quick Start Guide

## Installation

1. Clone the repository:
```bash
git clone https://github.com/HyperionGray/massweb.git
cd massweb
```

2. Install the library and its dependencies:
```bash
pip install -e .
```

## Basic Usage

### Web Fuzzing

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target
from massweb.payloads.payload import Payload

# Create a target with a URL that has query parameters
target = Target("http://example.com/page?param=value")

# Define payloads to inject
payloads = [
    Payload("'", check_type_list=["sqli"]),
    Payload("<script>alert(1)</script>", check_type_list=["xss"]),
]

# Create fuzzer and run
fuzzer = WebFuzzer(targets=[target], payloads=payloads, num_threads=10)
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for target_obj, response in results:
    print(f"URL: {target_obj.url}, Response: {response}")
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

# Provide seed URLs
seeds = ["http://example.com"]

# Create crawler and run
crawler = MassCrawl(seeds=seeds)
crawler.crawl(depth=2, num_threads=4, time_per_url=10)

# View discovered targets
for target in crawler.targets:
    print(target.url)
```

## Configuration

### Proxy Settings

```python
from massweb.mass_requests.mass_request import MassRequest

# Proxy list entries are dicts of {scheme: URI}
proxy_list = [{"http": "http://proxy1.example.com:8080"},
              {"http": "http://proxy2.example.com:8080"}]

mr = MassRequest(num_threads=10, proxy_list=proxy_list)
```

### Payload Customization

```python
from massweb.payloads.payload import Payload
from massweb.payloads.payload_group import PayloadGroup

# Build payloads manually
payloads = [
    Payload("' OR '1'='1", check_type_list=["sqli"]),
    Payload("../../etc/passwd", check_type_list=["trav"]),
]
group = PayloadGroup(payloads=payloads)
```

## Running Tests

```bash
# Install test dependencies first
pip install -r requirements.txt

# Run all tests using unittest discovery (preferred)
python -m unittest discover test/

# Run a specific test module
python -m unittest test.vuln_checks.test_sqli

# Run via Makefile (creates a local venv in env/)
make test
```

## Vulnerability Checks

Each checker in `massweb/vuln_checks/` inherits from `Check` and implements a
`check(content) -> bool` method. Pass raw response content to check for a match:

```python
from massweb.vuln_checks.sqli import SQLICheck
from massweb.vuln_checks.xss import XSSCheck
from massweb.vuln_checks.trav import TravCheck
from massweb.vuln_checks.ssrf import SSRFCheck
from massweb.vuln_checks.ssti import SSTICheck

sqli_check = SQLICheck()
print(sqli_check.check("you have an error in your sql syntax"))  # True

xss_check = XSSCheck()
print(xss_check.check("<html><script>alert(31337)</script></html>"))  # True
```

## Documentation

- API documentation: Run `make html` in the `docs/` directory
- Architecture deep-dive: [START_HERE.md](START_HERE.md)

## Getting Help

- **Issues**: Open an issue on GitHub
- **Documentation**: Check the `docs/` directory

## License

Apache 2.0 - See LICENSE.txt for details
