---
description: Mandatory Atomic Git and GitHub workflow (1 Item = 1 Issue -> 1 Branch -> 1 Pull Request -> 1 Merge -> Close Issue with Comment) for every request in the API Executor project.
trigger: always_on
---

# Project Rule: Systematic Atomic Issue + Branch + Pull Request + Merge

For every user request on this project, you **MUST MANDATORILY** execute the complete GitHub workflow with **strict atomicity** (never bundle multiple distinct items into a single catch-all Issue or PR):

1. **Decompose into Atomic Issues**: Ensure 1 distinct feature/fix = 1 GitHub Issue (`gh issue create --title "..." --body "..."`). If a request or existing issue contains multiple distinct items, split it into individual atomic issues first.
2. **Create a dedicated atomic branch** from `main`: `git checkout -b <type>/issue-<number>-<slug>` (use `git worktree` if other uncommitted changes exist in the workspace).
3. **Implement and test** only the files for that single atomic issue with `go test -v -cover ./...` (100% passing tests).
4. **Update Governance Registers** (`docs/ACTION_LOGBOOK.md` and `docs/RCA_REGISTER.md`).
5. **Commit and push** the atomic branch (`git push -u origin <branch>`) with a Conventional Commits message referencing `Closes #<number>`.
6. **Create an atomic Pull Request** with `gh pr create --base main --head <branch> --title "..." --body "Closes #<number>..."`.
7. **Merge the Pull Request** with `gh pr merge --merge --delete-branch` and update `main`.
8. **Close the Issue with a Comment**: Post a completion comment on the GitHub Issue detailing the changes, verification results, and merge commit (`gh issue comment <number> --body "..."`), then close the issue (`gh issue close <number>`).
