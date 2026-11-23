"""Self-contained Diataxis 4-quadrant, ASD-STE100 Issue 9, math integrity, and Docs-as-Code validation suite."""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"
MKDOCS_CONFIG_PATH = REPO_ROOT / "mkdocs.yml"
VALE_CONFIG_PATH = REPO_ROOT / ".vale.ini"
MARKDOWNLINT_CONFIG_PATH = REPO_ROOT / ".markdownlint.json"
DOCS_CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "docs-ci.yml"

DOCS_PORTAL_URL = "https://api-executor.lightpath.fr"

REQUIRED_QUADRANTS: tuple[str, ...] = (
    "01-tutorials",
    "02-how-to-guides",
    "03-reference",
    "04-explanation",
)

VIRTUAL_DOCS: dict[str, str] = {
    "overview.md": "README.md",
    "security-audit.md": "SECURITY.md",
    "project-architecture.md": "PROJECT.md",
}

FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\n]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")
LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+\S+")
EXTERNAL_SCHEME_RE = re.compile(r"^(?:https?|mailto|ftp|tel|data):", re.IGNORECASE)
SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")

HOWTO_VALIDATION_RE = re.compile(
    r"\b(?:validat(?:e|es|ed|ing|ion)|verif(?:y|ies|ied|ication)|check)\b",
    re.IGNORECASE,
)
HOWTO_ROLLBACK_RE = re.compile(
    r"\b(?:rollback|revert|backout|back-out|undo)\b",
    re.IGNORECASE,
)
HOWTO_THEORY_HEADING_RE = re.compile(
    r"\b(?:why|architecture|theory|explanation|context|background)\b",
    re.IGNORECASE,
)
REF_TUTORIAL_PHRASING_RE = re.compile(
    r"(?:\bin\s+this\s+tutorial\b|\blet['’]?s\b|\blet\s+us\b|\bstep\s+1\b)",
    re.IGNORECASE,
)
EXPLANATION_PROCEDURAL_HEADING_RE = re.compile(
    r"\b(?:step\s+\d+|rollback|remediation|prerequisites|procedure)\b",
    re.IGNORECASE,
)

# ASD-STE100 Issue 9 structural rules
ING_APPROVED: frozenset[str] = frozenset(
    {
        "mating",
        "missing",
        "remaining",
        "lighting",
        "opening",
        "routing",
        "servicing",
        "something",
        "during",
    }
)
ING_NOT_SUFFIX: frozenset[str] = frozenset(
    {
        "ring",
        "spring",
        "string",
        "king",
        "thing",
        "wing",
        "sing",
        "bring",
        "sting",
        "swing",
        "nothing",
        "anything",
        "everything",
        "something",
        "bearing",
        "ceiling",
        "morning",
        "evening",
    }
)
BANNED_MODALS: frozenset[str] = frozenset(
    {"should", "would", "may", "might", "shall", "ought"}
)
NON_PARTICIPLE_ED_EN: frozenset[str] = frozenset(
    {
        "bed",
        "between",
        "bleed",
        "breed",
        "citizen",
        "creed",
        "deed",
        "even",
        "exceed",
        "feed",
        "fifteen",
        "fourteen",
        "golden",
        "greed",
        "green",
        "heed",
        "hundred",
        "linen",
        "men",
        "naked",
        "need",
        "often",
        "open",
        "proceed",
        "red",
        "reed",
        "screen",
        "seed",
        "seven",
        "seventeen",
        "shed",
        "sixteen",
        "sled",
        "speed",
        "steed",
        "succeed",
        "sudden",
        "ten",
        "then",
        "thirteen",
        "wed",
        "weed",
        "when",
        "wicked",
        "women",
        "wooden",
    }
)

CONTRACTION_RE = re.compile(
    r"\b\w+n['’]t\b|\b\w+['’](?:re|ll|ve|m|d)\b|"
    r"\b(?:it|that|there|what|let|who|here|he|she|where|when|how)['’]s\b",
    re.IGNORECASE,
)
_IRREGULAR_PARTICIPLES = (
    "been|done|made|gone|put|set|cut|kept|held|taken|given|found|left|lost|"
    "meant|sent|shown|told|built|become|begun|broken|brought|come|fallen|"
    "felt|got|gotten|grown|known|read|run|seen|spoken|thrown|worn|written|sold"
)
HAVE_PARTICIPLE_RE = re.compile(
    rf"\b(?:has|have|had)\s+(?:(?:not|never|already|always)\s+)?(?:[a-z]{{2,}}ed|{_IRREGULAR_PARTICIPLES})\b",
    re.IGNORECASE,
)
_PASSIVE_PARTICIPLE = (
    r"(?:[a-z]{2,}(?:ed|en)|done|made|held|kept|sent|built|found|left|lost|"
    r"shown|known|sold|told|put|set|cut|run|broken|taken|given|written|seen|worn)"
)
COMPLEX_PASSIVE_RE = re.compile(
    rf"\b(?:can|will|must|could|would|should|may|might|shall)\s+"
    rf"(?:not\s+)?be\s+{_PASSIVE_PARTICIPLE}\b|"
    rf"\b(?:is|are|was|were)\s+to\s+be\s+{_PASSIVE_PARTICIPLE}\b",
    re.IGNORECASE,
)
PASSIVE_BY_RE = re.compile(
    rf"\b(?:is|are|was|were|be|been|being)\s+(?:\w+\s+)?{_PASSIVE_PARTICIPLE}\s+by\b",
    re.IGNORECASE,
)
BE_ING_RE = re.compile(r"\b(?:is|are|was|were|be|been|am)\s+[a-z]+ing\b", re.IGNORECASE)
LATIN_ABBREV_RE = re.compile(
    r"(?<![A-Za-z])(?:e\.g\.|i\.e\.|etc\.)(?![A-Za-z])",
    re.IGNORECASE,
)
_UNIT_ALT = (
    r"degrees?\s+(?:Celsius|Fahrenheit|Kelvin)"
    r"|°[CFK]|deg[CF]|°"
    r"|a\.m\.|p\.m\.|AM|PM"
    r"|kilograms?|milligrams?|kilometers?|kilometres?|millimeters?|millimetres?"
    r"|centimeters?|centimetres?|meters?|metres?|microseconds?|milliseconds?"
    r"|seconds?|minutes?|hours?|liters?|litres?|gallons?"
    r"|pounds?|ounces?|tonnes?|tons?|inches|inch|feet|foot|yards?|miles?"
    r"|degrees?|percent|ohms?|ohm|psia|psig|psi|mbar|bar|atm|kPa|MPa|GPa|hPa|Pa"
    r"|kN|Nm|N·m|N-m|lbf|VDC|VAC|kVA|VA|kWh|MWh|Wh|kW|MW|GW|mW|kV|mV|kA|mA|uA|µA"
    r"|GHz|MHz|kHz|Hz|kΩ|MΩ|Ω|Ω|mF|uF|µF|nF|pF|mH|kJ|MJ|dBA|dBm|dB"
    r"|KiB|MiB|GiB|TiB|Gbps|Mbps|kbps|bps|KB|MB|GB|TB|PB"
    r"|kg|mg|ug|µg|mm|cm|km|nm|um|µm|ft|yd|mi|mL|ml|cc|gal|rpm|RPM|mph|kph|rad"
    r"|sec|secs|min|mins|hr|hrs|ms|us|µs|ns|deg|ppm|ppb|px|pt|dpi|fps|FPS|lbs|lb|oz"
    r"|A|V|W|J|N|F|H|K|L|B|g|m|s|h|l|%"
)
_RATE_DENOM = r"(?:/(?:s|sec|second|min|minute|h|hr|hour|day|m|cm|mm|kg|L|l))?"
NUMBER_UNIT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])[+-]?\d+(?:[.,:]\d+)*(?:-[+-]?\d+(?:[.,:]\d+)*)?"
    rf"\s*(?:{_UNIT_ALT}){_RATE_DENOM}(?![A-Za-z0-9_])"
)
SENT_SPLIT_RE = re.compile(
    r"(?<!No\.)(?<!e\.g\.)(?<!i\.e\.)(?<!etc\.)(?<!a\.m\.)(?<!p\.m\.)(?<=[.!?:])\s+"
    r"|(?<=(?:a\.m\.|p\.m\.|etc\.))\s+(?=[A-Z0-9])"
    r"|(?<=No\.)\s+(?=[A-Z])"
)
WORDISH_RE = re.compile(r"[A-Za-z0-9]+(?:[.'&/’-][A-Za-z0-9]+)*")


class _MkDocsYamlLoader(yaml.SafeLoader):
    """Safe YAML loader accepting PyMdownx `!!python/name:` tags."""


def _python_name_multi_constructor(
    loader: yaml.Loader,
    tag_suffix: str,
    node: yaml.Node,
) -> str:
    del loader, node
    return f"python/name:{tag_suffix}"


_MkDocsYamlLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/name:",
    _python_name_multi_constructor,
)


def _strip_inline_code(line: str) -> str:
    """Replace inline code spans with spaces."""
    if "`" not in line:
        return line
    out: list[str] = []
    idx = 0
    length = len(line)
    while idx < length:
        if line[idx] != "`":
            out.append(line[idx])
            idx += 1
            continue
        tick_len = 0
        while idx + tick_len < length and line[idx + tick_len] == "`":
            tick_len += 1
        search_pos = idx + tick_len
        close_pos = -1
        while search_pos < length:
            if line[search_pos] != "`":
                search_pos += 1
                continue
            run_len = 0
            while search_pos + run_len < length and line[search_pos + run_len] == "`":
                run_len += 1
            if run_len == tick_len:
                close_pos = search_pos + run_len
                break
            search_pos += run_len
        if close_pos != -1:
            out.append(" ")
            idx = close_pos
        else:
            out.append(line[idx : idx + tick_len])
            idx += tick_len
    return "".join(out)


def _extract_non_code_lines(text: str) -> list[tuple[int, str]]:
    """Return 1-based `(line_no, line_without_inline_code)` outside fenced code blocks."""
    result: list[tuple[int, str]] = []
    fence_char: str | None = None
    fence_len = 0
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        if fence_char is not None:
            if re.match(rf"^\s*{re.escape(fence_char)}{{{fence_len},}}\s*$", raw_line):
                fence_char = None
                fence_len = 0
            continue
        fence_match = FENCE_RE.match(raw_line)
        if fence_match:
            marker = fence_match.group(1)
            fence_char = marker[0]
            fence_len = len(marker)
            continue
        result.append((lineno, _strip_inline_code(raw_line)))
    return result


def _normalize_link_target(raw_target: str) -> str:
    """Extract normalized relative path from a Markdown link destination."""
    target = raw_target.strip()
    if not target:
        return ""
    if target.startswith("<"):
        end_idx = target.find(">")
        if end_idx != -1:
            target = target[1:end_idx].strip()
    else:
        target = target.split()[0]
    if not target or target.startswith("#"):
        return ""
    if EXTERNAL_SCHEME_RE.match(target) or target.startswith("//"):
        return ""
    target = target.split("#", 1)[0].split("?", 1)[0]
    return unquote(target.strip())


def _resolve_relative_links(md_file: Path) -> list[tuple[int, str, Path]]:
    """Return `(lineno, raw_target, resolved_path)` for every relative Markdown link."""
    lines = _extract_non_code_lines(md_file.read_text(encoding="utf-8"))
    resolved_links: list[tuple[int, str, Path]] = []
    for lineno, line in lines:
        for match in LINK_RE.finditer(line):
            target = _normalize_link_target(match.group(1))
            if not target:
                continue
            if target.startswith("/"):
                resolved = (DOCS_DIR / target.lstrip("/")).resolve()
            else:
                resolved = (md_file.parent / target).resolve()
            resolved_links.append((lineno, target, resolved))
    return resolved_links


def _flatten_nav_paths(node: Any) -> list[str]:
    """Flatten all Markdown path strings from a MkDocs `nav` structure."""
    paths: list[str] = []
    if isinstance(node, str):
        paths.append(node)
    elif isinstance(node, list):
        for item in node:
            paths.extend(_flatten_nav_paths(item))
    elif isinstance(node, dict):
        for value in node.values():
            paths.extend(_flatten_nav_paths(value))
    return paths


def _strip_markdown_for_ste(text: str) -> str:
    """Strip non-prose Markdown constructs, math, code blocks, URLs, and link targets."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\A---\n.*?\n---(?:\n|\Z)", "", text, flags=re.DOTALL)
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"~~~.*?~~~", " ", text, flags=re.DOTALL)
    text = re.sub(r"(?<!\\)\$\$.*?(?<!\\)\$\$", " MATH ", text, flags=re.DOTALL)
    text = re.sub(r"(?<!\\)\$(?!\s)(?:[^\n$\\]|\\.)+?(?<!\s)\$", " MATH ", text)
    text = re.sub(r"``[^`\n]+``|`[^`\n]+`", " CODE ", text)
    text = re.sub(r"!\[([^\]]*)\]\((?:[^()]|\([^)]*\))*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\((?:[^()]|\([^)]*\))*\)", r"\1", text)
    text = re.sub(r"https?://\S+?(?=[.,;:!?)]*(?:\s|$))", " URL ", text)
    text = re.sub(r"^[ \t]*>.*$", " ", text, flags=re.MULTILINE)
    text = re.sub(r"\"[^\"\n]*\"|“[^”\n]*”|«[^»\n]*»", " QUOTED ", text)
    return text


def _count_ste_words(sentence: str) -> int:
    """Count words according to ASD-STE100 Issue 9 Section 8 rules."""
    cleaned = sentence
    for _ in range(3):
        updated = re.sub(r"\([^()]*\)", " PAREN ", cleaned)
        if updated == cleaned:
            break
        cleaned = updated
    cleaned = NUMBER_UNIT_RE.sub(" NUMUNIT ", cleaned)
    cleaned = re.sub(r"\*\*|__|#+|\*|(?<!\w)_|_(?!\w)", " ", cleaned)
    return len(WORDISH_RE.findall(cleaned))


def _iter_sentences(block: str) -> list[str]:
    """Split a text block into sentences."""
    return [
        part.strip()
        for part in SENT_SPLIT_RE.split(block)
        if part.strip() and WORDISH_RE.search(part)
    ]


def _check_ste_sentence(sentence: str, loc: str) -> list[str]:
    """Validate one procedural sentence against ASD-STE100 Issue 9 structural rules."""
    violations: list[str] = []
    word_count = _count_ste_words(sentence)
    preview = sentence if len(sentence) <= 64 else sentence[:61] + "..."
    if word_count > 20:
        violations.append(f"{loc} [Rule 5.1]: {word_count} words (> 20): {preview!r}")
    if ";" in sentence:
        violations.append(f"{loc} [Rule 8.1]: semicolon in procedural text: {preview!r}")

    clean = re.sub(r"\*\*|__|(?<!\w)_|_(?!\w)|\*", "", sentence)
    if match := LATIN_ABBREV_RE.search(clean):
        violations.append(f"{loc} [GR-6]: Latin abbreviation {match.group(0)!r}: {preview!r}")
    if match := CONTRACTION_RE.search(clean):
        violations.append(f"{loc} [Rule 4.2]: contraction {match.group(0)!r}: {preview!r}")
    if match := HAVE_PARTICIPLE_RE.search(clean):
        if match.group(0).split()[-1].lower() not in NON_PARTICIPLE_ED_EN:
            violations.append(f"{loc} [Rule 3.4]: perfect tense {match.group(0)!r}: {preview!r}")
    if match := COMPLEX_PASSIVE_RE.search(clean):
        if match.group(0).split()[-1].lower() not in NON_PARTICIPLE_ED_EN:
            violations.append(f"{loc} [Rule 3.4]: complex passive {match.group(0)!r}: {preview!r}")
    if match := PASSIVE_BY_RE.search(clean):
        words = match.group(0).split()
        if len(words) >= 2 and words[-2].lower() not in NON_PARTICIPLE_ED_EN:
            violations.append(f"{loc} [Rule 3.6]: passive voice {match.group(0)!r}: {preview!r}")
    if match := BE_ING_RE.search(clean):
        tail = match.group(0).split()[-1].lower()
        if tail not in ING_APPROVED and tail not in ING_NOT_SUFFIX:
            violations.append(f"{loc} [Rule 3.5]: progressive form {match.group(0)!r}: {preview!r}")
    for word in re.findall(r"[A-Za-z-]+", clean):
        if word.lower() in BANNED_MODALS:
            violations.append(f"{loc} [Rule 3.2]: banned modal {word!r}: {preview!r}")
    return violations


def collect_ste_structural_violations(md_file: Path) -> list[str]:
    """Run ASD-STE100 Issue 9 structural procedural validation on a single Markdown file."""
    text = md_file.read_text(encoding="utf-8")
    stripped = _strip_markdown_for_ste(text)
    stripped = re.sub(
        r"(?m)^[ \t]*(?:#.*|\|.*|---+|\*\*\*+|___+|===+)[ \t]*$",
        "",
        stripped,
    )
    bullet_re = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
    violations: list[str] = []
    rel_name = (
        md_file.relative_to(REPO_ROOT).as_posix()
        if md_file.is_relative_to(REPO_ROOT)
        else md_file.name
    )

    for idx, raw_par in enumerate(re.split(r"\n\s*\n", stripped), start=1):
        par = raw_par.strip()
        if not par or not WORDISH_RE.search(par):
            continue
        items: list[str] = []
        prose: list[str] = []
        for line in par.splitlines():
            if bullet_re.match(line):
                items.append(line)
            elif items and re.match(r"^(?:  |\t)\S", line):
                items[-1] = items[-1] + " " + line.strip()
            else:
                prose.append(line)

        for raw_item in items:
            item = bullet_re.sub("", raw_item, count=1)
            for sent in _iter_sentences(item):
                violations.extend(_check_ste_sentence(sent, f"{rel_name}:list"))

        if prose:
            prose_block = "\n".join(prose)
            sents = _iter_sentences(prose_block)
            if len(sents) > 6:
                violations.append(
                    f"{rel_name}:par{idx} [Rule 6.6]: paragraph has {len(sents)} sentences (max 6)"
                )
            for sent in sents:
                violations.extend(_check_ste_sentence(sent, f"{rel_name}:par{idx}"))
    return violations


def test_diataxis_quadrant_structure_and_indexes_exist() -> None:
    """Verify docs/index.md and all four Diataxis quadrant directories and index.md files exist."""
    assert (DOCS_DIR / "index.md").is_file(), "Missing docs/index.md portal"
    for quadrant in REQUIRED_QUADRANTS:
        quadrant_dir = DOCS_DIR / quadrant
        assert quadrant_dir.is_dir(), f"Missing Diataxis quadrant directory: docs/{quadrant}"
        assert (quadrant_dir / "index.md").is_file(), f"Missing quadrant index: docs/{quadrant}/index.md"
        non_index_docs = [p for p in quadrant_dir.rglob("*.md") if p.name.lower() != "index.md"]
        assert non_index_docs, f"Quadrant docs/{quadrant} must contain at least one content document"


def test_zero_broken_relative_links_across_all_docs() -> None:
    """Verify every relative Markdown link across docs/**/*.md resolves on disk."""
    broken: list[str] = []
    for md_file in sorted(DOCS_DIR.rglob("*.md")):
        for lineno, raw_target, resolved in _resolve_relative_links(md_file):
            exists = resolved.is_file() or (
                resolved.is_dir() and (resolved / "index.md").is_file()
            )
            if not exists:
                rel_doc = md_file.relative_to(REPO_ROOT).as_posix()
                broken.append(f"{rel_doc}:{lineno}: broken link '{raw_target}' -> {resolved}")

    assert not broken, "Broken relative Markdown links detected:\n" + "\n".join(broken)


def test_quadrant_genre_guardrails_prevent_genre_mixing() -> None:
    """Verify 02-how-to-guides, 03-reference, and 04-explanation respect Diataxis genre rules."""
    violations: list[str] = []

    for quadrant in REQUIRED_QUADRANTS:
        quadrant_dir = DOCS_DIR / quadrant
        assert quadrant_dir.is_dir(), f"Missing quadrant directory: docs/{quadrant}"
        for md_file in sorted(quadrant_dir.rglob("*.md")):
            if md_file.name.lower() == "index.md":
                continue
            rel_doc = md_file.relative_to(REPO_ROOT).as_posix()
            non_code = _extract_non_code_lines(md_file.read_text(encoding="utf-8"))
            headings = [
                (lineno, m.group(1))
                for lineno, line in non_code
                if (m := HEADING_RE.match(line))
            ]
            full_text = "\n".join(line for _, line in non_code)

            if quadrant == "02-how-to-guides":
                if not HOWTO_VALIDATION_RE.search(full_text):
                    violations.append(f"{rel_doc}: missing verification/validation section or keyword")
                if not HOWTO_ROLLBACK_RE.search(full_text):
                    violations.append(f"{rel_doc}: missing rollback/revert section or keyword")
                for lineno, heading in headings:
                    if HOWTO_THEORY_HEADING_RE.search(heading):
                        violations.append(
                            f"{rel_doc}:{lineno}: theory heading '## {heading}' forbidden in 02-how-to-guides/"
                        )

            elif quadrant == "03-reference":
                has_table = any(TABLE_ROW_RE.match(line) for _, line in non_code)
                has_list = any(LIST_ITEM_RE.match(line) for _, line in non_code)
                if not (has_table or has_list):
                    violations.append(f"{rel_doc}: reference page lacks Markdown tables or structured lists")
                for lineno, line in non_code:
                    if match := REF_TUTORIAL_PHRASING_RE.search(line):
                        violations.append(
                            f"{rel_doc}:{lineno}: tutorial phrasing '{match.group(0)}' forbidden in 03-reference/"
                        )

            elif quadrant == "04-explanation":
                for lineno, heading in headings:
                    if EXPLANATION_PROCEDURAL_HEADING_RE.search(heading):
                        violations.append(
                            f"{rel_doc}:{lineno}: procedural heading '## {heading}' forbidden in 04-explanation/"
                        )

    assert not violations, "Diataxis genre violations found:\n" + "\n".join(violations)


def test_quadrant_cross_linking_mesh() -> None:
    """Verify predictable cross-links connect Tutorials, How-To Guides, Reference, and Explanation."""

    def linked_quadrants(md_file: Path) -> set[str]:
        quadrants: set[str] = set()
        for _, _, resolved in _resolve_relative_links(md_file):
            try:
                rel_parts = resolved.relative_to(DOCS_DIR).parts
            except ValueError:
                continue
            if rel_parts and rel_parts[0] in REQUIRED_QUADRANTS:
                quadrants.add(rel_parts[0])
        return quadrants

    # 1. Tutorials -> How-To Guides, Reference, and Explanation
    tutorial_docs = sorted(
        p for p in (DOCS_DIR / "01-tutorials").rglob("*.md") if p.name.lower() != "index.md"
    )
    assert tutorial_docs, "Expected tutorial pages under docs/01-tutorials/"
    for doc in tutorial_docs:
        targets = linked_quadrants(doc)
        assert {"02-how-to-guides", "03-reference", "04-explanation"} <= targets, (
            f"{doc.relative_to(REPO_ROOT)} must link to 02-how-to-guides, 03-reference, and 04-explanation (found {targets})"
        )

    # 2. How-To Guides -> Reference and Explanation
    howto_docs = sorted(
        p for p in (DOCS_DIR / "02-how-to-guides").rglob("*.md") if p.name.lower() != "index.md"
    )
    assert howto_docs, "Expected procedural guides under docs/02-how-to-guides/"
    for doc in howto_docs:
        targets = linked_quadrants(doc)
        assert {"03-reference", "04-explanation"} <= targets, (
            f"{doc.relative_to(REPO_ROOT)} must link to 03-reference and 04-explanation (found {targets})"
        )

    # 3. Reference Alert Matrix -> How-To remediation runbooks
    alert_matrix = DOCS_DIR / "03-reference" / "troubleshooting-codes" / "error-and-alert-matrix.md"
    assert alert_matrix.is_file(), "Missing error-and-alert-matrix.md"
    assert "02-how-to-guides" in linked_quadrants(alert_matrix), (
        "error-and-alert-matrix.md must link to runbooks under 02-how-to-guides/"
    )

    # 4. Explanation ADRs -> Reference and How-To Guides
    adr_docs = sorted((DOCS_DIR / "04-explanation" / "design-decisions").glob("adr-*.md"))
    assert adr_docs, "Expected ADR documents under docs/04-explanation/design-decisions/"
    for adr in adr_docs:
        targets = linked_quadrants(adr)
        assert {"03-reference", "02-how-to-guides"} <= targets, (
            f"{adr.relative_to(REPO_ROOT)} must link to 03-reference and 02-how-to-guides (found {targets})"
        )


def test_howto_guides_asd_ste100_structural_compliance() -> None:
    """Verify non-index files under docs/02-how-to-guides/ pass ASD-STE100 Issue 9 structural rules."""
    howto_dir = DOCS_DIR / "02-how-to-guides"
    assert howto_dir.is_dir(), "Missing docs/02-how-to-guides/"
    howto_files = sorted(p for p in howto_dir.rglob("*.md") if p.name.lower() != "index.md")
    assert howto_files, "Expected non-index procedures under docs/02-how-to-guides/"

    all_violations: list[str] = []
    for md_file in howto_files:
        all_violations.extend(collect_ste_structural_violations(md_file))

    assert not all_violations, "ASD-STE100 Issue 9 violations in 02-how-to-guides/:\n" + "\n".join(
        all_violations
    )


def test_docs_as_code_toolchain_configs_valid() -> None:
    """Verify mkdocs.yml, .vale.ini, .markdownlint.json, and docs-ci.yml exist and parse cleanly."""
    # 1. mkdocs.yml
    assert MKDOCS_CONFIG_PATH.is_file(), "Missing mkdocs.yml"
    loader = _MkDocsYamlLoader(MKDOCS_CONFIG_PATH.read_text(encoding="utf-8"))
    try:
        mkdocs_cfg = loader.get_single_data()
    finally:
        loader.dispose()
    assert isinstance(mkdocs_cfg, dict)
    features = mkdocs_cfg.get("theme", {}).get("features", [])
    assert "navigation.tabs" in features
    assert "navigation.indexes" in features
    assert "scripts/mkdocs_hooks.py" in mkdocs_cfg.get("hooks", [])

    nav = mkdocs_cfg.get("nav", [])
    top_tabs = [next(iter(entry.keys())) for entry in nav if isinstance(entry, dict)]
    assert top_tabs == [
        "Home",
        "Tutorials",
        "How-To Guides",
        "Reference",
        "Explanation",
        "Releases & Governance",
    ]
    for nav_path in _flatten_nav_paths(nav):
        if nav_path in VIRTUAL_DOCS:
            assert (REPO_ROOT / VIRTUAL_DOCS[nav_path]).is_file(), (
                f"mkdocs.yml virtual nav target missing at repo root: {VIRTUAL_DOCS[nav_path]}"
            )
        else:
            assert (DOCS_DIR / nav_path).is_file(), (
                f"mkdocs.yml nav target missing on disk: docs/{nav_path}"
            )

    # 2. .vale.ini
    assert VALE_CONFIG_PATH.is_file(), "Missing .vale.ini"
    parser = configparser.ConfigParser()
    parser.optionxform = str  # preserve exact key casing
    parser.read_string("[__root__]\n" + VALE_CONFIG_PATH.read_text(encoding="utf-8"))
    assert parser["__root__"]["StylesPath"] == ".vale/styles"
    assert parser["__root__"]["MinAlertLevel"] == "suggestion"
    for section in (
        "*.md",
        "docs/01-tutorials/**/*.md",
        "docs/02-how-to-guides/**/*.md",
        "docs/03-reference/**/*.md",
        "docs/04-explanation/**/*.md",
    ):
        assert section in parser, f"Missing section [{section}] in .vale.ini"
    howto_vale = parser["docs/02-how-to-guides/**/*.md"]
    assert howto_vale["MinAlertLevel"] == "error"
    for key in (
        "Google.FirstPerson",
        "Google.Passive",
        "Google.Contractions",
        "Google.We",
        "Vale.Spelling",
    ):
        assert howto_vale.get(key) == "YES"
    assert howto_vale.get("Google.Will") == "NO"
    assert "STE-Procedural" in howto_vale.get("BasedOnStyles", "")

    # 3. .markdownlint.json
    assert MARKDOWNLINT_CONFIG_PATH.is_file(), "Missing .markdownlint.json"
    mdlint_cfg = json.loads(MARKDOWNLINT_CONFIG_PATH.read_text(encoding="utf-8"))
    assert mdlint_cfg.get("default") is True
    assert mdlint_cfg.get("MD013", {}).get("line_length") == 120
    assert mdlint_cfg.get("MD013", {}).get("code_blocks") is False
    assert mdlint_cfg.get("MD013", {}).get("tables") is False
    assert mdlint_cfg.get("MD024", {}).get("siblings_only") is True
    assert mdlint_cfg.get("MD033") is False
    assert mdlint_cfg.get("MD041") is False
    assert mdlint_cfg.get("MD046", {}).get("style") == "fenced"

    # 4. .github/workflows/docs-ci.yml
    assert DOCS_CI_WORKFLOW_PATH.is_file(), "Missing .github/workflows/docs-ci.yml"
    wf = yaml.safe_load(DOCS_CI_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(wf, dict)
    assert wf.get("permissions") == {"contents": "read"}
    assert "docs-ci-" in str(wf.get("concurrency", {}).get("group", ""))
    triggers = wf.get("on") if "on" in wf else wf.get(True)
    assert isinstance(triggers, dict)
    assert "push" in triggers and "pull_request" in triggers and "workflow_dispatch" in triggers

    jobs = wf.get("jobs", {})
    assert isinstance(jobs, dict) and jobs, "docs-ci.yml must define at least one job"
    job = jobs.get("docs-quality") or next(iter(jobs.values()))
    assert isinstance(job.get("timeout-minutes"), int) and job["timeout-minutes"] <= 15

    steps = [step for step in job.get("steps", []) if isinstance(step, dict)]
    for idx, step in enumerate(steps):
        uses_val = step.get("uses")
        if isinstance(uses_val, str):
            assert "@" in uses_val, f"docs-ci.yml step #{idx} uses unpinned action '{uses_val}'"
            sha = uses_val.split("@", 1)[1]
            assert SHA40_RE.fullmatch(sha), (
                f"docs-ci.yml step #{idx} must pin action to 40-char SHA, got '{uses_val}'"
            )
        if_val = step.get("if")
        if isinstance(if_val, str):
            assert "secrets." not in if_val
        run_val = step.get("run")
        if isinstance(run_val, str):
            assert "${{" not in run_val, "docs-ci.yml must pass expressions via env:, never ${{ in run:"

    run_text = "\n".join(str(step.get("run", "")) for step in steps)
    assert "tests/test_diataxis_documentation.py" in run_text
    assert "tests/test_mkdocs_publishing.py" in run_text
    assert "mkdocs build --strict" in run_text


def test_portal_and_readme_expose_all_diataxis_quadrants() -> None:
    """Verify docs/index.md and README.md expose all four Diataxis quadrants and live portal URL."""
    portal = (DOCS_DIR / "index.md").read_text(encoding="utf-8")
    for token in (
        "01-tutorials/index.md",
        "02-how-to-guides/index.md",
        "03-reference/index.md",
        "04-explanation/index.md",
        "ACTION_LOGBOOK.md",
        "RCA_REGISTER.md",
        DOCS_PORTAL_URL,
    ):
        assert token in portal, f"docs/index.md missing expected portal link or URL: {token}"

    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/index.md" in readme_text, "README.md must link to docs/index.md"
    assert DOCS_PORTAL_URL in readme_text, f"README.md must reference {DOCS_PORTAL_URL}"
    for quadrant in REQUIRED_QUADRANTS:
        assert f"docs/{quadrant}/index.md" in readme_text, (
            f"README.md must expose docs/{quadrant}/index.md"
        )


def test_markdown_latex_math_syntax_integrity() -> None:
    """Verify LaTeX math across docs/**/*.md bans \\operatorname and keeps $$ at column 0."""
    violations: list[str] = []
    for md_file in sorted(DOCS_DIR.rglob("*.md")):
        rel_doc = md_file.relative_to(REPO_ROOT).as_posix()
        non_code = _extract_non_code_lines(md_file.read_text(encoding="utf-8"))
        display_fence_count = 0
        for lineno, line in non_code:
            if r"\operatorname" in line:
                violations.append(
                    f"{rel_doc}:{lineno}: forbidden \\operatorname; use \\arg\\max, \\arg\\min, or \\text{{...}}"
                )
            if "$$" in line:
                if not line.startswith("$$") or line.rstrip() != "$$":
                    violations.append(
                        f"{rel_doc}:{lineno}: display math $$ must start at column 0 on its own line: {line!r}"
                    )
                else:
                    display_fence_count += 1
        if display_fence_count % 2 != 0:
            violations.append(
                f"{rel_doc}: unbalanced display math $$ delimiters ({display_fence_count})"
            )

    assert not violations, "LaTeX math formatting violations found:\n" + "\n".join(violations)


def test_ste_structural_checker_catches_violations_and_passes_valid_prose(tmp_path: Path) -> None:
    """Verify the built-in ASD-STE100 Issue 9 checker catches violations and accepts compliant procedures."""
    valid_doc = tmp_path / "valid.md"
    valid_doc.write_text(
        "# Procedure\n\n"
        "1. Stop the daemon process.\n"
        "2. Run the configuration validation command.\n\n"
        "The output shows exit code zero.\n",
        encoding="utf-8",
    )
    assert collect_ste_structural_violations(valid_doc) == []

    invalid_doc = tmp_path / "invalid.md"
    invalid_doc.write_text(
        "# Bad Procedure\n\n"
        "1. You should restart the daemon; don't ignore errors.\n"
        "2. The service was stopped by the operator after twenty seconds of continuous polling across every mounted target audit volume on the bastion host.\n",
        encoding="utf-8",
    )
    violations = collect_ste_structural_violations(invalid_doc)
    joined = "\n".join(violations)
    assert "[Rule 3.2]" in joined
    assert "[Rule 8.1]" in joined
    assert "[Rule 4.2]" in joined
    assert "[Rule 3.6]" in joined
    assert "[Rule 5.1]" in joined
