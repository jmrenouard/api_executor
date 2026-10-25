---
description: Strict Atomicity Rule for Issues, Branches, Pull Requests, and Merges (1 distinct item = 1 Issue = 1 Branch = 1 PR = 1 Merge).
trigger: always_on
---

# Project Rule: Strict Atomicity of Issues, Branches, Pull Requests, and Merges

Every **GitHub Issue**, **Git Branch**, **Pull Request**, and **Merge** in the **API Executor (`go-admin-tool`)** repository **MUST be strictly atomic**:

1. **One Correction / Feature = One Issue = One Branch = One PR = One Merge**:
   - Each distinct feature, fix, security improvement, or documentation update must have its own dedicated GitHub Issue (`#<id>`), its own dedicated branch (`<type>/issue-<id>-<slug>`), its own Pull Request, and its own Merge commit into `main`.
2. **No Catch-All ("Kitchen-Sink") Issues or PRs**:
   - Never bundle unrelated features or fixes into a single multi-topic Issue or Pull Request.
   - If a user request or an existing Issue spans multiple distinct items, decompose it immediately into separate atomic GitHub Issues and deliver each item through an independent `Issue -> Branch -> Commit -> PR -> Merge -> Close Issue` cycle.
3. **Independent Verification per Atomic PR**:
   - Every atomic branch must compile cleanly and pass `go test -v -cover ./...` before its Pull Request is opened and merged.
