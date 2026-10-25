---
trigger: always_on
description: Mandatory API Executor language rule — all project documentation, governance registers, rules, source code, comments, and tests must be written exclusively in English.
---

# Project Rule: Mandatory English-Only Policy for Documentation and Code

All artifacts in the **API Executor (`go-admin-tool`)** repository **MUST be written exclusively in English** without exception:

1. **Documentation & Governance Registers**:
   - Root and module documentation (`README.md`, `docs/SECURITY_AND_ARCHITECTURE_ANALYSIS.md`, `docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`).
   - Living governance registers (`docs/ACTION_LOGBOOK.md` and `docs/RCA_REGISTER.md`).
   - Agent instructions and rules (`AGENTS.md` and `.agents/rules/*.md`).

2. **Source Code, Schemas, CLI & Web UI**:
   - All Go packages (`cmd/**/*.go`, `internal/**/*.go`), identifiers, struct tags, comments, error messages, and Web Admin Console UI labels (`web/static/index.html`).

3. **Tests, Docker & CI/CD**:
   - All test suites (`internal/**/*_test.go`), Dockerfiles (`Dockerfile`, `docker/Dockerfile.*`), presets (`configs/*.yaml`), and commit/PR/Issue descriptions.
   - *Permitted Exception*: Verbatim quotes of user prompts in `docs/ACTION_LOGBOOK.md` accompanied by an English translation.
