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

wf = WebFuzzer(num_threads=10, time_per_url=5, request_timeout=5, proxy_list=[{}])

# Add payloads
wf.add_payload(Payload("')--", check_type_list=["sqli", "xpathi"]))
wf.add_payload(Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"]))

# Add one or more GET targets
wf.add_target_from_url(u"http://example.com/vuln.php?id=1")

# Build fuzz targets and execute
wf.generate_fuzzy_targets()
results = wf.fuzz()

for result in results:
    print(result)
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

seeds = [u"http://example.com"]
crawler = MassCrawl(seeds=seeds)

# depth controls how many fetch/parse rounds run
crawler.crawl(depth=2, num_threads=4, time_per_url=5, request_timeout=5, proxy_list=[{}])

for target in crawler.targets[:20]:
    print(target.url)
```

## Using AI-Powered Workflows (Gemini & Others)

### Quick Test

1. **Test Gemini on an Issue**:
   - Create or open any issue in this repository
   - Add the label: `gemini`
   - Wait for the automated review comment

2. **Test Gemini on a Pull Request**:
   - Create a PR with some code changes
   - Add the label: `gemini:gemini-1.5-flash` (or `gemini` for default model)
   - Review the AI-generated feedback

### Available AI Labels

- `gemini` - Google Gemini default model
- `gpt-5` - OpenAI model
- `claude` - Anthropic default model
- `llm:<provider>:<model>` - Fully explicit form

For more details, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer

proxies = [
    {"http": "http://proxy1.example:8080"},
    {"http": "http://proxy2.example:8080"},
]
fuzzer = WebFuzzer(num_threads=10, proxy_list=proxies)
```

### Payload Customization

```python
from massweb.payloads.payload import Payload

payloads = []
with open("custom_payloads.txt", "r") as handle:
    for line in handle:
        payload = line.strip()
        if not payload:
            continue
        payloads.append(Payload(payload, check_type_list=["xss"]))

for payload in payloads:
    fuzzer.add_payload(payload)
```

## Running Tests

```bash
# Run all tests
python -m pytest test/

# Run specific test module
python -m pytest test/test_fuzzers.py
```

## Documentation

- Full documentation: https://hyperiongray.atlassian.net/wiki/display/PUB/MassWeb
- API documentation: Run `make html` in `docs/` directory
- AI Workflows: [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Getting Help

- **Issues**: Open an issue on GitHub
- **AI Review**: Add `gemini` label to get AI-powered assistance
- **Documentation**: Check the `docs/` directory

## Common Tasks

### Scan for SQL Injection
```python
from massweb.vuln_checks.sqli import SQLICheck

checker = SQLICheck()
response_text = "You have an error in your SQL syntax"
is_vulnerable = checker.check(response_text)
print(is_vulnerable)
```

### Directory Traversal Check
```python
from massweb.vuln_checks.trav import TravCheck

checker = TravCheck()
response_text = "root:x:0:0:root:/root:/bin/bash"
is_vulnerable = checker.check(response_text)
print(is_vulnerable)
```

## Next Steps

1. Read the full documentation
2. Explore usage examples in `docs/_static/usage.rst`
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
