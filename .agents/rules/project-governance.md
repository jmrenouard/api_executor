---
trigger: always_on
description: Mandatory API Executor project governance — systematic update of the Action Logbook (docs/ACTION_LOGBOOK.md) and RCA Register (docs/RCA_REGISTER.md) on every request, change, and result.
---

# Project Rule: Systematic Update of Action Logbook and RCA Register

For **every user request, every technical/documentation change, and every test or security result** on the **API Executor (`go-admin-tool`)** project, you **MUST MANDATORILY** update the following two living registers before closing the task:

## 1. Action Logbook (`docs/ACTION_LOGBOOK.md`)

Must be updated on **every request**, **every change**, and **every result**:
- **Ongoing Actions (`IN PROGRESS`)**: Record every new request as soon as work begins (`ACT-XXX`, date/time, Issue `#<id>`, branch, **Request**).
- **Completed Actions (`COMPLETED`)**: Once implementation is verified, record:
  - **Request**: Initial objective requested by the user.
  - **Changes**: Created or modified files, impacted architecture or rules.
  - **Result**: Real test suite output (`go test -v -cover ./...`), code coverage, and Git/GitHub references (Issue `#<id>`, PR `#<pr>`, commit).

## 2. RCA & Technical Transparency Register (`docs/RCA_REGISTER.md`)

Must be updated on **every request**, **every change**, and **every result** across its 4 sections:
1. **Errors & Bugs Encountered (`RCA-XXX`)**: Observed Symptom, Root Cause Analysis (RCA), Applied Change / Fix, and Result & Non-Regression Test.
2. **Technical Dead-Ends & Abandoned Leads (`IMP-XXX`)**: Explored and abandoned paths with the technical or security justification preventing re-attempts.
3. **Current Approximations & Simplifying Assumptions (`APP-XXX`)**: Simplifications, heuristics, or in-memory fallbacks present in the code (`internal/`), trade-offs, and removal condition.
4. **Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)**: Engineering and security improvements identified for the roadmap.

> **Strict Prohibition**: Never declare a request finished or merge a Pull Request without updating `docs/ACTION_LOGBOOK.md` (and `docs/RCA_REGISTER.md` whenever an error, dead-end, approximation, or idea is identified during the change).

## 3. Mandatory English-Only Policy for Documentation & Code

All project documentation (`README.md`, `docs/**/*.md`, `web/static/index.html`), governance registers (`docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`), rules (`AGENTS.md`, `.agents/rules/*.md`), and source code/tests (`cmd/**/*.go`, `internal/**/*.go`) **MUST be written exclusively in English** (see `.agents/rules/english-only.md`).
