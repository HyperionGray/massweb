# AI Workflow Documentation

## Scope

This document covers the label-driven LLM review workflows and related AI automation in this repository:

- `auto-llm-issue-review.yml`
- `auto-llm-pr-review.yml`
- `auto-advance-ball.yml`

Additional AI workflows are available and intentionally use different trigger models, including:

- `auto-tag-based-review.yml` (tag/scheduled review flows)
- `auto-amazonq-review.yml` (Amazon Q follow-up review workflow)

## Supported LLM Providers (Label-Driven Review Workflows)

### OpenAI
- Requires secret: `OPENAI_API_KEY`
- Common labels: `gpt-4`, `gpt-5`, `openai:gpt-5`, `llm:openai:gpt-5`
- Bare label alias: `openai` (maps to the default OpenAI model)

### Gemini
- Requires secret: `GEMINI_API_KEY`
- Common labels: `gemini-1.5-pro`, `gemini:gemini-1.5-pro`, `llm:gemini:gemini-1.5-pro`
- Bare label alias: `gemini` (maps to the default Gemini model)

### Anthropic
- Requires secret: `ANTHROPIC_API_KEY`
- Common labels: `claude-3-5-sonnet-latest`, `anthropic:claude-3-5-sonnet-latest`
- Bare label alias: `anthropic` (maps to the default Anthropic model)

## Label Parsing Rules

The label-driven review workflows support:

1. `llm:<provider>:<model>` (explicit provider + model)
2. `<provider>:<model>` (provider-specific shorthand)
3. Model-like labels (for example `gpt-5`, `gemini-1.5-pro`, `claude-3-5-sonnet-latest`)
4. Bare provider aliases (`openai`, `gemini`, `anthropic`) that resolve to default models

## Default Model Resolution

When a model is not explicitly provided by label, the workflows use:

- OpenAI: `OPENAI_DEFAULT_MODEL` repo variable, fallback `gpt-5`
- Gemini: `GEMINI_DEFAULT_MODEL` repo variable, fallback `gemini-1.5-pro`
- Anthropic: `ANTHROPIC_DEFAULT_MODEL` repo variable, fallback `claude-3-5-sonnet-latest`

You can also set `LLM_MODEL` as a repo variable for a global default override.

## Core Workflows

### LLM Issue Review (`auto-llm-issue-review.yml`)

- Triggered when an issue is labeled with a recognized model/provider label
- Can also be run manually using `workflow_dispatch`
- Posts AI analysis as an issue comment

### LLM PR Review (`auto-llm-pr-review.yml`)

- Triggered when a pull request is labeled with a recognized review/model label
- Re-runs on `synchronize` when a matching label is present
- Posts or updates a PR review comment

### Advance Ball (`auto-advance-ball.yml`)

- Autonomous workflow for advancing issue/task work
- Separate from label-driven LLM review workflows

## Setup Requirements

### Required Secrets

Set these under GitHub Settings -> Secrets and variables -> Actions:

```
OPENAI_API_KEY
GEMINI_API_KEY
ANTHROPIC_API_KEY
```

### Optional Repository Variables

```
LLM_PROVIDER
LLM_MODEL
OPENAI_DEFAULT_MODEL
GEMINI_DEFAULT_MODEL
ANTHROPIC_DEFAULT_MODEL
OPENAI_BASE_URL
```

## Testing

1. Add label `gemini` to an issue and confirm an AI issue-review comment appears.
2. Add label `gemini:gemini-1.5-flash` to a PR and confirm a PR review comment appears.
3. Manually run either workflow from the Actions tab using `workflow_dispatch`.

## Concurrency Note

Both label-driven review workflows use `cancel-in-progress: true` per issue/PR. If multiple labels are applied in quick succession, newer runs can cancel older ones. For provider comparisons, apply labels sequentially and wait for each run to complete.

## Troubleshooting

- **401 Unauthorized**: Missing or invalid provider API key.
- **400 Bad Request**: Invalid model name format.
- **No run started**: Label did not match supported formats.
- **No comment generated**: Review run failed; inspect workflow logs in the Actions tab.
