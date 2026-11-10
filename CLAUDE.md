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
- **Temporary private advisory forks (`domainaware/parsedmarc-ghsa-*`): Copilot cannot review there.** The request is accepted and Copilot is listed as a reviewer, but the review fails with "Copilot encountered an error and was unable to review this pull request", on a retry too (tried twice on 2026-11-10). Do not open the diff as a public PR to get a review: that discloses the fix before the advisory is published. Use the Opus review loop below instead.
- **Anywhere else Copilot cannot produce a review of the current head, use the same loop.** Copilot is unavailable only when *our own* request for the current head ends without a review. Two messages are known:
  - "Copilot encountered an error and was unable to review this pull request. You can try again by re-requesting a review."
  - "Copilot was unable to review this pull request because the user who requested the review has insufficient remaining quota. Try requesting a review at a lower effort level."

  The quota in the second message belongs to whoever made that request, so do not take such a message as an answer to ours: on #951 a contributor's request got it on 2026-11-10 and the maintainer's own request afterwards was reviewed normally. Before falling back, check that the message was posted after our request and names no later head, then re-request once. If our own re-request also ends in one of these messages, or in no review at all, say so to the maintainer and run the Opus loop. Go back to Copilot on that PR if it becomes available again before the merge.

### The Opus review loop, for when Copilot cannot review

This applies to advisory forks and to any other PR where Copilot is unavailable as described above. Treat an Opus reviewer exactly as Copilot is treated on a public PR: review, fix, review the new head, and repeat until a review of the **final head** has no open issues. Only then push and merge. A clean review of an earlier head does not count.

1. **Review.** Start a fresh Opus subagent that has seen nothing but the code: read-only, given the diff that will merge (`git diff origin/master...HEAD`) and `AGENTS.md` as its rubric. Tell it which commits no reviewer has read yet, and to reproduce every suspected bug with a script before reporting it. Ask for findings ranked "must fix", "should fix" and "nit", design preferences under a separate "optional" heading, and a last line that is exactly `VERDICT: no open issues` or `VERDICT: changes recommended`.
2. **Triage** each finding like an external review: fix what is real, decline the rest with a reason. Tell the maintainer what the round found.
3. **Fix** through an implementer subagent, one commit per round, with tests that fail on the old code, then CI's commands and patch coverage.
4. **Review again with a new reviewer**, never the one from the previous round. Point it at the new commit first and tell it to try to break that commit: a fix made during review is the least-reviewed code on the branch.
5. **Stop when** a round on the final head ends `VERDICT: no open issues`.

Work in a separate worktree when master has to be merged in, so a running reviewer's tree does not change under it.

**When a fix has been defeated twice, change the approach.** If the second review of a fix finds another input of the same kind getting past it, stop adding cases. A check that recognises bad inputs one shape at a time will keep losing to the next shape; redesign so the code no longer depends on recognising them (for a credential leak, log and raise nothing derived from the secret-bearing value at all). In the 2026-11-10 round, three reviews in a row each defeated a shape-recognising check before that redesign held.

@AGENTS.md
