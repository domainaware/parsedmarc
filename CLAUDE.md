# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Model roles for feature work

Any new feature or modification to an existing feature must follow this model split:

1. **Plan with Fable** (fall back to Opus only if Fable is unavailable). Enter plan mode, design the implementation, and present the plan to the user for approval or modification. Do not start implementing until the user approves the plan.
2. **Implement with Sonnet by default; use Opus for large or complex work.** Once the plan is approved, carry out the implementation by delegating the implementation steps to subagents via the Agent tool. Use `model: "sonnet"` for routine, well-scoped changes (single-module edits, bug fixes, small features). Use `model: "opus"` when the approved plan is a large multi-file feature or refactor (e.g. a new output integration, or an RFC-level parser change touching `parsedmarc/__init__.py` plus types, tests, and docs), or when the change is complex even if contained — subtle parsing or encoding logic, concurrency, or a paired protocol (`__getstate__`/`__setstate__`, save/load, encode/decode) where one side is easy to get silently wrong. When in doubt, decide at planning time and note the choice in the plan.
3. **Review with Fable** (fall back to Opus only if Fable is unavailable). After implementation, all work must be reviewed by Fable before it is considered done.

**PR reviews** must also use Fable, with Opus as the fallback if Fable is unavailable.

## Every PR gets a second reviewer before it merges

The Fable review above is the author's side. Before a PR merges, a second, independent reviewer must also have read its final head, and every finding must be fixed or declined with a reason on its thread.

- **Public PRs: request a Copilot review** when the PR is opened, and re-request it after every push that answers a finding (the `address-copilot-review` skill covers the loop). A review of an earlier commit does not count for a later head.
- **Temporary private advisory forks (`domainaware/parsedmarc-ghsa-*`): Copilot cannot review there.** The request is accepted and Copilot is listed as a reviewer, but the review fails with "Copilot encountered an error and was unable to review this pull request", on a retry too (tried twice on 2026-11-10). Do not open the diff as a public PR to get a review: that discloses the fix before the advisory is published. Instead run a second fresh-context review with a different model than the first one (Opus if the first was Fable), given only the diff, and make sure it covers commits added after the first review, such as review fixes.

@AGENTS.md
