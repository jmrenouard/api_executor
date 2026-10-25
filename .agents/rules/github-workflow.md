---
trigger: always_on
description: Mandatory Atomic GitHub workflow: 1 Item = 1 Issue -> 1 Branch -> Tests -> 1 Pull Request -> 1 Merge -> Issue Comment for every request.
---

# Project Rule: Systematic Atomic GitHub Workflow (Issue + Branch + PR + Merge)

For every request made on the **API Executor (`go-admin-tool`)** project, you MUST systematically enforce **strict atomicity** (1 distinct item = 1 Issue = 1 Branch = 1 PR = 1 Merge; never create catch-all issues or PRs):

1. **Open an Atomic GitHub Issue** (`gh issue create`) describing the single feature or fix and its acceptance criteria. Split multi-part requests or catch-all issues into separate atomic issues first.
2. **Create a dedicated atomic branch** (`<type>/issue-<id>-<slug>`) from `main` (use `git worktree` if other files are being modified in the workspace).
3. **Implement and run unit tests** (`go test -v -cover ./...`) until full validation.
4. **Commit (Conventional Commits) and push the branch** to `origin`.
5. **Create an atomic Pull Request** (`gh pr create`) referencing `Closes #<id>`.
6. **Merge the Pull Request** (`gh pr merge --merge --delete-branch`) and update `main`.
7. **Close the Issue with an explicit summary comment** (`gh issue comment <id> --body "..."` then `gh issue close <id>`).
