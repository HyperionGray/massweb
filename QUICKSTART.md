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
from massweb.targets.target import Target

# Create scan targets and payloads
targets = [Target(u"http://example.com/page?param=FUZZ", ttype="get")]
payloads = [Payload(u"'><script>alert(1)</script>", check_type_list=["xss"])]

# Run fuzzing
fuzzer = WebFuzzer(targets=targets, payloads=payloads)
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for result in results:
    print(f"URL: {result.fuzzy_target.url}, Findings: {result.result_dic}")
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

# Run crawler
crawler = MassCrawl(seeds=[u"http://example.com"])
crawler.crawl(depth=2, stay_in_scope=True)

# View discovered targets
for target in crawler.targets:
    print(target.url)
```

## Using AI-Powered Workflows (Gemini & Others)

### Quick Test

1. **Test Gemini on an Issue**:
   - Create or open any issue in this repository
   - Add the label: `gemini:gemini-1.5-pro`
   - Wait for the automated review comment

2. **Test Gemini on a Pull Request**:
   - Create a PR with some code changes
   - Add the label: `gemini:gemini-1.5-flash`
   - Review the AI-generated feedback

### Available AI Labels

- `gemini:gemini-1.5-pro` - Google Gemini 1.5 Pro (recommended default)
- `gemini:gemini-1.5-flash` - Google Gemini 1.5 Flash (faster, cheaper)
- `gpt-4` - OpenAI GPT-4
- `claude-3.5-sonnet` - Anthropic Claude

For more details, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload
from massweb.targets.target import Target

# Provide a list of proxies directly to the fuzzer
proxies = [
    {"http": "http://proxy1.com:8080"},
    {"http": "http://proxy2.com:8080"},
]
targets = [Target(u"http://example.com/page?param=FUZZ", ttype="get")]
payloads = [Payload(u"test", check_type_list=["xss"])]
fuzzer = WebFuzzer(targets=targets, payloads=payloads, proxy_list=proxies)
```

### Payload Customization

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload
from massweb.targets.target import Target

targets = [Target(u"http://example.com/page?param=FUZZ", ttype="get")]
payloads = [
    Payload(u"'><script>alert(1)</script>", check_type_list=["xss"]),
    Payload(u"')--", check_type_list=["sqli", "xpathi"]),
]
fuzzer = WebFuzzer(targets=targets, payloads=payloads)
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
- **AI Review**: Add `gemini:gemini-1.5-pro` (or bare `gemini`) label
- **Documentation**: Check the `docs/` directory

## Common Tasks

### Scan for SQL Injection
```python
from massweb.vuln_checks.sqli import SQLICheck

response_text = "you have an error in your sql syntax"
check = SQLICheck()
is_vulnerable = check.check(response_text)
```

### Directory Traversal Check
```python
from massweb.vuln_checks.trav import TravCheck

response_text = "root:x:0:0:root:/root:/bin/bash"
check = TravCheck()
is_vulnerable = check.check(response_text)
```

## Next Steps

1. Read the full documentation
2. Explore example scripts in `examples/` (if available)
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
