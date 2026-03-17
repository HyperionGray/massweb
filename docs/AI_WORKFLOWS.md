# AI-Powered Workflow Documentation

## Overview

This document covers the label-driven LLM workflows used in this repository:

- `auto-llm-issue-review.yml`
- `auto-llm-pr-review.yml`
- `auto-advance-ball.yml`

It also lists related AI workflows so scope is explicit (for example, `auto-tag-based-review.yml` and `auto-amazonq-review.yml`).

## Supported LLM Providers

### OpenAI (GPT Models)
- Typical models: `gpt-4`, `gpt-5`, `o1`, `o3`
- Accepted label patterns: `openai`, `gpt`, `gpt-*`, `openai:*`, `llm:openai:*`
- Required secret: `OPENAI_API_KEY`
- Default model: `gpt-5` (override with `OPENAI_DEFAULT_MODEL`)

### Gemini (Google AI)
- Typical models: `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-2.0-flash`
- Accepted label patterns: `gemini`, `gemini-*`, `gemini:*`, `llm:gemini:*`
- Required secret: `GEMINI_API_KEY`
- Default model: `gemini-1.5-pro` (override with `GEMINI_DEFAULT_MODEL`)

### Anthropic (Claude)
- Typical models: `claude-3`, `claude-3.5-sonnet`, `claude-3-5-sonnet-latest`
- Accepted label patterns: `anthropic`, `claude`, `claude-*`, `anthropic:*`, `llm:anthropic:*`
- Required secret: `ANTHROPIC_API_KEY`
- Default model: `claude-3-5-sonnet-latest` (override with `ANTHROPIC_DEFAULT_MODEL`)

## Core Workflows

### LLM Issue Review (`auto-llm-issue-review.yml`)

Purpose:
- Reviews issues when model/provider labels are added

How provider/model are selected:
1. Explicit label wins (`llm:<provider>:<model>` or `<provider>:<model>`)
2. Short model labels are inferred by prefix (`gpt-*`, `gemini-*`, `claude-*`)
3. Bare provider alias labels (`gemini`, `openai`, `anthropic`, `claude`) resolve to provider defaults
4. Manual dispatch inputs can override label-derived values

### LLM PR Review (`auto-llm-pr-review.yml`)

Purpose:
- Reviews pull requests and posts/updates a single bot review comment

How it is triggered:
- PR label events for recognized LLM labels
- PR synchronize events when recognized LLM labels are present
- Manual dispatch

The provider/model resolution logic matches the issue workflow, including bare provider aliases.

### Advance Ball (`auto-advance-ball.yml`)

Purpose:
- Runs an autonomous implementation loop to move work forward on open tasks/issues

## Other AI-Related Workflows in This Repo

These are AI-enabled but are outside the two label-driven LLM review workflows above:

- `auto-tag-based-review.yml`
- `auto-amazonq-review.yml`
- `auto-gpt5-implementation.yml`
- `auto-copilot-functionality-docs-review.yml`
- `auto-copilot-code-cleanliness-review.yml`

## Setup Requirements

### Required Secrets

Set in GitHub Settings > Secrets and variables > Actions:

```
OPENAI_API_KEY
GEMINI_API_KEY
ANTHROPIC_API_KEY
```

### Optional Repository Variables

```
LLM_PROVIDER             # Global default provider (used in PR workflow/manual runs)
LLM_MODEL                # Global model override for PR workflow/manual runs
OPENAI_BASE_URL          # Custom OpenAI-compatible endpoint
OPENAI_DEFAULT_MODEL     # Default used for bare "openai"/"gpt" labels
GEMINI_DEFAULT_MODEL     # Default used for bare "gemini" labels
ANTHROPIC_DEFAULT_MODEL  # Default used for bare "anthropic"/"claude" labels
```

## Label Examples

### Gemini
```
gemini                         # Alias -> GEMINI_DEFAULT_MODEL (or gemini-1.5-pro)
gemini:gemini-1.5-flash        # Explicit provider:model
gemini-2.0-flash               # Direct model label
llm:gemini:gemini-1.5-pro      # Fully explicit format
```

### OpenAI
```
openai                         # Alias -> OPENAI_DEFAULT_MODEL (or gpt-5)
gpt-5                          # Direct model label
openai:gpt-4.1                 # Explicit provider:model
llm:openai:gpt-5               # Fully explicit format
```

### Anthropic
```
claude                         # Alias -> ANTHROPIC_DEFAULT_MODEL
claude-3.5-sonnet              # Direct model label
anthropic:claude-3-opus        # Explicit provider:model
llm:anthropic:claude-3-5-sonnet-latest
```

## Testing

1. Create an issue and add label `gemini` (or `gemini:gemini-1.5-flash`).
2. Create a PR and add label `gpt-5` or `claude`.
3. Confirm workflow runs in the Actions tab and check generated comments.
4. Optionally run manual dispatch with explicit `llm_provider` and `llm_model`.

## Concurrency Behavior

Both label-triggered review workflows use `cancel-in-progress: true` per issue/PR.
This means rapid label changes can cancel earlier runs. For clean comparisons:

- run one provider label at a time, wait for completion, then switch labels, or
- use manual dispatch for controlled repeated runs.

## Troubleshooting

### Label Accepted but No Useful Output
- Verify the relevant provider API key is configured.
- Check that the resolved model exists for that provider.
- For bare provider labels, verify your default model variable values.

### API Error Responses
- `401 Unauthorized`: missing/invalid API key
- `429 Rate Limited`: provider throttling
- `400 Bad Request`: invalid model name or payload
