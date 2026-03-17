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

# Configure fuzzer
wf = WebFuzzer(num_threads=10, time_per_url=5, proxy_list=[{}])

# Add payloads
wf.add_payload(Payload("')--", check_type_list=["sqli", "xpathi"]))
wf.add_payload(Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"]))

# Add one or more targets
wf.add_target_from_url(u"http://example.com/page?param=1")

# Generate fuzzed targets, then execute
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

# crawl() updates crawler.targets/results in-place
crawler.crawl(depth=2, num_threads=4, time_per_url=5, request_timeout=3, proxy_list=[{}])

for target in crawler.targets:
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
   - Add the label: `gemini:gemini-1.5-flash`
   - Review the AI-generated feedback

### Available AI Labels

- `gemini` - Google Gemini (uses configured/default Gemini model)
- `gpt-4` - OpenAI GPT-4
- `claude-3.5-sonnet` - Anthropic Claude

For more details, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer

proxy_list = [
    {"http": "http://proxy1.example.com:8080"},
    {"http": "http://proxy2.example.com:8080"},
]
wf = WebFuzzer(proxy_list=proxy_list)
```

### Payload Customization

```python
from massweb.payloads.payload import Payload
from massweb.fuzzers.web_fuzzer import WebFuzzer

wf = WebFuzzer()
wf.add_payload(Payload("')--", check_type_list=["sqli", "xpathi"]))
wf.add_payload(Payload("../../../../etc/passwd", check_type_list=["trav"]))
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

check = SQLICheck()
is_sqli = check.check("database error output text here")
```

### Directory Traversal Check
```python
from massweb.vuln_checks.trav import TravCheck

check = TravCheck()
is_traversal = check.check("response body text here")
```

## Next Steps

1. Read the full documentation
2. Explore example scripts in `examples/` (if available)
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
