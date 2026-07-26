# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Model roles for feature work

Any new feature or modification to an existing feature must follow this model split:

1. **Plan with Fable** (fall back to Opus only if Fable is unavailable). Enter plan mode, design the implementation, and present the plan to the user for approval or modification. Do not start implementing until the user approves the plan. Once the plan is approved, enter auto mode for the implementation and review.
2. **Implement with Sonnet by default; use Opus for large or complex work.** Once the plan is approved, carry out the implementation by delegating the implementation steps to subagents via the Agent tool. Use `model: "sonnet"` for routine, well-scoped changes (single-module edits, bug fixes, small features). Use `model: "opus"` when the approved plan is a large multi-file feature or refactor — e.g. a new output integration, or an RFC-level parser change touching `parsedmarc/__init__.py` plus types, tests, and docs. When in doubt, decide at planning time and note the choice in the plan.
3. **Review with Fable** (fall back to Opus only if Fable is unavailable). After implementation, all work must be reviewed by Fable before it is considered done.

**PR reviews** must also use Fable, with Opus as the fallback if Fable is unavailable.

@AGENTS.md
