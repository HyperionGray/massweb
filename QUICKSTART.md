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

# Build base targets and payloads
targets = [Target("http://example.com/page?param=1", ttype="get")]
payloads = [
    Payload("' OR '1'='1", ["sqli"]),
    Payload("<script>alert(1)</script>", ["xss"]),
]

fuzzer = WebFuzzer(targets=targets, payloads=payloads, num_threads=10)
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process vulnerability hits
for result in results:
    if any(result.result_dic.values()):
        print(result.fuzzy_target.url, result.result_dic)
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

# Start from one or more seed URLs
crawler = MassCrawl(seeds=["http://example.com"])

# Crawl two levels deep and stay in-scope
crawler.crawl(depth=2, stay_in_scope=True, max_links=20)

# Inspect discovered targets
for target in crawler.targets:
    print(target.url, target.status)
```

## Using AI-Powered Workflows (Gemini & Others)

### Quick Test

1. **Test Gemini on an Issue**:
   - Create or open any issue in this repository
   - Add the label: `gemini` (alias for the default model) or `gemini:gemini-1.5-pro`
   - Wait for the automated review comment

2. **Test Gemini on a Pull Request**:
   - Create a PR with some code changes
   - Add the label: `gemini:gemini-1.5-flash`
   - Review the AI-generated feedback

### Available AI Labels

- `gemini` - Google Gemini default model (`gemini-1.5-pro`)
- `gemini:gemini-1.5-pro` - Google Gemini 1.5 Pro (explicit default)
- `gemini:gemini-1.5-flash` - Google Gemini 1.5 Flash (faster, cheaper)
- `gpt-4` - OpenAI GPT-4
- `claude-3.5-sonnet` - Anthropic Claude

For more details, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer

# Provide proxies as request dictionaries
proxies = [
    {"http": "http://proxy1.com:8080", "https": "http://proxy1.com:8080"},
    {"http": "http://proxy2.com:8080", "https": "http://proxy2.com:8080"},
]
fuzzer = WebFuzzer(targets=targets, payloads=payloads, proxy_list=proxies)
```

### Payload Customization

```python
from massweb.payloads.payload import Payload

# Define custom payload objects with the checks they should trigger
custom_payloads = [
    Payload("' OR 1=1--", ["sqli"]),
    Payload("../../../../etc/passwd", ["trav"]),
]
fuzzer = WebFuzzer(targets=targets, payloads=custom_payloads)
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
if check.check(response_text):
    print("Possible SQL injection signal found")
```

### Directory Traversal Check
```python
from massweb.vuln_checks.trav import TravCheck

check = TravCheck()
if check.check(response_text):
    print("Possible traversal signal found")
```

## Next Steps

1. Read the full documentation
2. Explore example scripts in `examples/` (if available)
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
