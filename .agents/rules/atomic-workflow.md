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
3. **Complete 8-Step GitHub Lifecycle per Atomic Item**:
   1. **Open an Atomic GitHub Issue** (`gh issue create`) describing the single feature or fix and its acceptance criteria.
   2. **Create a Dedicated Atomic Branch** (`<type>/issue-<id>-<slug>`) from `main` (use `git worktree` if uncommitted files exist in the workspace).
   3. **TDD Implementation & Verification**: implement changes and verify with `go test -v -cover ./...` and `go test -v ./tests/e2e/...` (100% passing tests).
   4. **Update Governance Registers**: record entries in `docs/ACTION_LOGBOOK.md` and `docs/RCA_REGISTER.md`.
   5. **Atomic Commit & Push**: commit using Conventional Commits referencing `Closes #<id>` and push (`git push -u origin <branch>`).
   6. **Open Atomic Pull Request**: create PR targeting `main` via `gh pr create` referencing `Closes #<id>`.
   7. **Merge Pull Request**: merge into `main` via `gh pr merge <pr_id> --merge --delete-branch` and pull updates (`git pull --ff-only origin main`).
   8. **Close Issue with Summary Comment**: post completion comment detailing changes and test results (`gh issue comment <id> --body "..."`), then close the issue (`gh issue close <id>`).
4. **Independent Verification per Atomic PR**:
   - Every atomic branch must compile cleanly and pass `go test -v -cover ./...` and `go test -v ./tests/e2e/...` before its Pull Request is opened and merged.
