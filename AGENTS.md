# API Executor Project Rules (AGENTS.md)

These rules apply **without exception** to every session and every agent working on the **API Executor (`go-admin-tool`)** repository.

---

## 1. Mandatory Atomic GitHub Workflow (Required for Every Request)

### 1.1 Strict Atomicity Rule (1 Item = 1 Issue = 1 Branch = 1 PR = 1 Merge)

Every **Issue**, **Branch**, **Pull Request**, and **Merge** in this repository **MUST be strictly atomic**:
- **One distinct item/feature/fix = One GitHub Issue = One dedicated Git branch = One Pull Request = One Merge.**
- **NEVER bundle** multiple distinct features, bug fixes, or architectural changes into a single catch-all ("kitchen-sink" / "papa-maman") Issue, Branch, or Pull Request.
- If a user prompt contains multiple distinct items or if an existing Issue bundles several distinct corrections, you **MUST first decompose** it into separate atomic GitHub Issues and execute the full lifecycle below independently for each atomic Issue.

### 1.2 Complete GitHub Lifecycle per Atomic Item

For **every atomic item** (new feature, bug fix, CI/CD, documentation, security hardening, or refactoring), the agent **MUST systematically** execute the complete lifecycle below:

1. **Open an Atomic GitHub Issue**:
   - Create a focused issue for that single item using `gh issue create --title "<type>: <title>" --body "<context, single objective, and acceptance criteria>"` before starting implementation.
   - Retrieve the issue number (`#<id>`).

2. **Create a Dedicated Atomic Branch**:
   - Create a dedicated branch from `main` scoped strictly to that issue: `<type>/issue-<id>-<slug>` (e.g., `feat/issue-3-prometheus-action-metrics-and-timeouts`, `fix/issue-4-...`).
   - When parallel work exists in the main working directory, use `git worktree` to cleanly isolate the branch without disturbing uncommitted files from other tasks.

3. **TDD Implementation & Unit Tests**:
   - Write or update unit and integration tests across `internal/**/*_test.go` covering the atomic change.
   - Verify that the full test suite passes locally (`go test -v -cover ./...`).

4. **Update Governance Registers (`docs/ACTION_LOGBOOK.md` & `docs/RCA_REGISTER.md`)**:
   - Systematically update the Action Logbook (`docs/ACTION_LOGBOOK.md`) and the RCA Register (`docs/RCA_REGISTER.md`) before committing (see Sections 2 and 3 below).

5. **Commit & Push**:
   - Make atomic commits following the Conventional Commits format (`feat:`, `fix:`, `ci:`, `docs:`, `test:`, `chore:`) referencing the single issue (`Refs #<id>` or `Closes #<id>`).
   - Push the branch to the remote repository: `git push -u origin <branch>`.

6. **Create an Atomic Pull Request (PR)**:
   - Open a Pull Request targeting `main` via `gh pr create --base main --head <branch> --title "<type>: <title> (#<id>)" --body "Closes #<id> ..."` containing only the changes for that single issue.

7. **Merge the Pull Request**:
   - Merge the Pull Request into `main` via `gh pr merge <pr-id> --merge --delete-branch` and synchronize the local `main` branch (`git pull --ff-only origin main`).

8. **Close Issue with Summary Comment**:
   - Explicitly close the corresponding GitHub Issue with a summary comment detailing the atomic changes, verification results, and merge commit (`gh issue comment <id> --body "..."` followed by `gh issue close <id>`).

---

## 2. Ongoing / Completed Action Logbook (`docs/ACTION_LOGBOOK.md`)

The agent **MUST systematically update** [`docs/ACTION_LOGBOOK.md`](docs/ACTION_LOGBOOK.md) **on every request, every atomic change, and every result**:

1. **Upon receiving a request (`IN PROGRESS` / `Ongoing Actions`)**:
   - Add an entry in the ongoing actions section with the identifier (`ACT-XXX`), ISO timestamp, atomic GitHub Issue reference (`#<id>`), and exact formulation of the **Request**.
2. **During and after implementation (`CHANGES & RESULT`)**:
   - Document the exact list of created/modified files (**Changes**) as well as verification metrics (**Result**: number of passing unit tests, `go test -cover` coverage, PR number, and merge commit).
3. **Upon completion (`COMPLETED` / `Completed Actions`)**:
   - Move the action to the completed actions section once tests and the atomic Pull Request are validated and merged.

---

## 3. RCA Register of Errors, Dead-Ends, Approximations, and Unimplemented Ideas (`docs/RCA_REGISTER.md`)

The agent **MUST systematically update** [`docs/RCA_REGISTER.md`](docs/RCA_REGISTER.md) **on every request, every change, and every result** whenever any of the following four events occurs:

1. **Errors & Bugs Encountered (`RCA-XXX`)**:
   - Every runtime error, test failure, security flaw, workflow violation, typing issue, or CI/CD conflict must be logged with: *Observed Symptom*, *Root Cause Analysis (5 Whys)*, *Applied Change / Fix*, and *Result / Non-Regression Test*.
2. **Technical Dead-Ends & Abandoned Leads (`IMP-XXX`)**:
   - Every explored and rejected approach (e.g., CGO-only dependencies, unsafe shell interpolation, unbounded Prometheus labels, monolithic catch-all PRs) must be recorded so no subsequent session repeats the same dead-end.
3. **Current Approximations & Simplifying Assumptions (`APP-XXX`)**:
   - Every simplification compared to distributed enterprise production environments must be explicitly declared with its measured impact and removal condition.
4. **Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)**:
   - Every feature, optimization, or extension identified during a request or security review that is outside the immediate scope must be logged with its priority and target module.

---

## 4. Mandatory English-Only Policy for All Documentation and Code

All documentation, governance registers, rules, and source code in the **API Executor** repository **MUST be written exclusively in English** ([`.agents/rules/english-only.md`](.agents/rules/english-only.md)):

1. **Documentation & Registers**: All Markdown and HTML documentation (`README.md`, `docs/**/*.md`, `web/static/index.html`, `docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`, `AGENTS.md`, `.agents/rules/*.md`) must be written in English. Do not include non-English headings, subtitles, or prose sections.
2. **Source Code & Tests**: All Go packages (`cmd/**/*.go`, `internal/**/*.go`), tests (`internal/**/*_test.go`), comments, variable/function/type names, CLI output, and API error messages must be written in English.
3. **Git & GitHub Artifacts**: All commit messages, branch names, GitHub Issues, and Pull Requests must be written in English.
