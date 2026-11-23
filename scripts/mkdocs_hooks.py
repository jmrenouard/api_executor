"""MkDocs Material build hooks for API Executor documentation publishing."""

from __future__ import annotations

import os
from pathlib import Path
import posixpath
import re
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from mkdocs.structure.files import Files

DEFAULT_REPO_URL = "https://github.com/jmrenouard/api_executor"
VIRTUAL_DOCS: dict[str, tuple[str, str]] = {
    "overview.md": ("README.md", ""),
    "security-audit.md": ("SECURITY.md", ""),
    "project-architecture.md": ("PROJECT.md", ""),
}
_REPO_DOC_TO_VIRTUAL: dict[str, str] = {
    source_path: virtual_uri for virtual_uri, (source_path, _) in VIRTUAL_DOCS.items()
}
QUADRANT_HISTORICAL_FALLBACKS: dict[str, str] = {
    "01-tutorials": "overview.md",
    "02-how-to-guides": "SECURITY_AND_ARCHITECTURE_ANALYSIS.md",
    "03-reference": "project-architecture.md",
    "04-explanation": "SECURITY_AND_ARCHITECTURE_ANALYSIS.md",
}
ALERT_MAP: dict[str, str] = {
    "NOTE": "note",
    "TIP": "tip",
    "IMPORTANT": "info",
    "WARNING": "warning",
    "CAUTION": "danger",
}

_FENCE_RE = re.compile(r"^([ \t]*)(`{3,}|~{3,})(.*)$")
_ALERT_RE = re.compile(
    r"(?m)^([ \t]*)>[ \t]*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*([^\r\n]*)\r?\n"
    r"((?:[ \t]*>.*(?:\r?\n|$))*)"
)
_RELEASE_NOTES_SEMVER_RE = re.compile(
    r"^(?:release_notes_)?v?(\d+)\.(\d+)\.(\d+)\.md$",
    re.IGNORECASE,
)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_EXCLUDED_TARGET_RE = re.compile(
    r"(?i)(?:(?:^|/)\.env[^/]*$|\.(?:kdbx|keyx|db|sqlite[^/]*|log|key)$|(?:^|/)articles/[^/]+\.fr\.md$)"
)
_HTML_ATTR_RE = re.compile(
    r"""(<(?:img|a|source)\b[^>]*?\b(?:src|href)\s*=\s*)(["'])([^"']+)\2""",
    re.IGNORECASE,
)


def gfm_slugify(value: str, separator: str = "-") -> str:
    """Slugify headings using GitHub Flavored Markdown anchor rules."""
    return "".join(
        separator if ch == " " else ch
        for ch in value.strip().lower()
        if ch.isalnum() or ch in (" ", "-", "_")
    )


def _effective_repo_ref(raw_ref: str | None = None) -> str:
    """Resolve the effective Git ref used for GitHub repository links."""
    ref = (
        raw_ref if raw_ref is not None else os.environ.get("API_EXECUTOR_DOCS_REF", "main")
    ).strip()
    if not ref or ref in {"WORKTREE", "HEAD", "origin/main"}:
        return "main"
    return ref


def _split_fences(markdown: str) -> list[tuple[bool, str]]:
    """Split Markdown into `(is_fence, text)` chunks while preserving newlines."""
    chunks: list[tuple[bool, str]] = []
    buf: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0

    for line in markdown.splitlines(keepends=True):
        stripped_nl = line.rstrip("\r\n")
        if not in_fence:
            match = _FENCE_RE.match(stripped_nl)
            if match:
                if buf:
                    chunks.append((False, "".join(buf)))
                    buf.clear()
                in_fence = True
                fence_char = match.group(2)[0]
                fence_len = len(match.group(2))
        else:
            lead = stripped_nl.lstrip(" \t")
            if (
                lead.startswith(fence_char)
                and len(lead) - len(lead.lstrip(fence_char)) >= fence_len
                and not lead.lstrip(fence_char).strip()
            ):
                buf.append(line)
                chunks.append((True, "".join(buf)))
                buf.clear()
                in_fence = False
                fence_char = ""
                fence_len = 0
                continue
        buf.append(line)

    if buf:
        chunks.append((in_fence, "".join(buf)))
    return chunks


def _format_github_alert(match: re.Match[str]) -> str:
    """Convert a matched GitHub alert blockquote into a Material admonition block."""
    ws = match.group(1)
    kind = ALERT_MAP[match.group(2).upper()]
    title = match.group(3).strip()
    body = match.group(4)
    out = [f'{ws}!!! {kind} "{title}"\n' if title else f"{ws}!!! {kind}\n"]
    for raw_line in body.splitlines(keepends=True):
        stripped = raw_line.rstrip("\r\n")
        inner = re.sub(r"^[ \t]*>[ \t]?", "", stripped)
        nl = raw_line[len(stripped) :] or "\n"
        out.append(nl if not inner.strip() else f"{ws}    {inner}{nl}")
    return "".join(out)


def convert_github_alerts(markdown: str) -> str:
    """Convert GitHub-style blockquote alerts into Material admonitions outside code fences."""
    return "".join(
        chunk if is_fence else _ALERT_RE.sub(_format_github_alert, chunk)
        for is_fence, chunk in _split_fences(markdown)
    )


def _is_escaped(text: str, pos: int) -> bool:
    """Return True if the character at `pos` is preceded by an odd number of backslashes."""
    cursor = pos - 1
    while cursor >= 0 and text[cursor] == "\\":
        cursor -= 1
    return ((pos - 1 - cursor) & 1) == 1


def _match_delimiter(
    text: str,
    start: int,
    open_ch: str,
    close_ch: str,
    skip_inline_code: bool,
) -> int | None:
    """Find matching closing delimiter while respecting escapes and inline code spans."""
    depth = 1
    idx = start + 1
    n = len(text)
    while idx < n:
        ch = text[idx]
        if skip_inline_code and ch == "`":
            tick_len = 1
            while idx + tick_len < n and text[idx + tick_len] == "`":
                tick_len += 1
            end = text.find("`" * tick_len, idx + tick_len)
            if end == -1:
                return None
            idx = end + tick_len
            continue
        if not skip_inline_code and ch == "\n":
            return None
        if ch == open_ch and not _is_escaped(text, idx):
            depth += 1
        elif ch == close_ch and not _is_escaped(text, idx):
            depth -= 1
            if depth == 0:
                return idx
        elif skip_inline_code and ch == "\n" and idx + 1 < n and text[idx + 1] == "\n":
            return None
        idx += 1
    return None


def _split_destination(raw_dest: str) -> tuple[str, str, bool]:
    """Split a Markdown link destination into `(url, title_suffix, had_angle_brackets)`."""
    stripped = raw_dest.strip()
    if stripped.startswith("<") and (end := stripped.find(">")) != -1:
        return stripped[1:end].strip(), stripped[end + 1 :], True
    for idx, ch in enumerate(stripped):
        if ch.isspace():
            return stripped[:idx], stripped[idx:], False
    return stripped, "", False


def _historical_overview_target(
    prefix: str,
    clean_repo: str,
    ref: str,
    available_root_docs: frozenset[str],
    virtual_doc: str = "overview.md",
) -> str:
    """Resolve fallback target for historical tags when a quadrant document is absent."""
    if virtual_doc in available_root_docs:
        return f"{prefix}{virtual_doc}"
    source_path = VIRTUAL_DOCS.get(virtual_doc, ("README.md", ""))[0]
    return f"{clean_repo}/blob/{ref}/{source_path}"


def _resolve_target(
    raw_url: str,
    page_src_path: str,
    prefix: str,
    ref: str,
    repo_url: str,
    available_root_docs: frozenset[str],
    docs_dir: Path | None = None,
) -> tuple[str | None, bool]:
    """Resolve a target URL or return `(None, True)` when excluded/neutralized."""
    if not raw_url or raw_url.startswith(("#", "/", "\\")) or _SCHEME_RE.match(raw_url):
        return raw_url, False

    path_part, sep, frag = raw_url.partition("#")
    anchor = f"{sep}{frag}" if sep else ""
    if not path_part:
        return raw_url, False

    norm_src = page_src_path.replace("\\", "/").lstrip("/")
    src_dir = (
        VIRTUAL_DOCS[norm_src][1]
        if norm_src in VIRTUAL_DOCS
        else posixpath.dirname(f"docs/{norm_src}")
    )
    had_trailing_slash = path_part.endswith("/")
    repo_rel = (
        posixpath.normpath(posixpath.join(src_dir, path_part))
        if src_dir
        else posixpath.normpath(path_part)
    )

    if _EXCLUDED_TARGET_RE.search(repo_rel) or _EXCLUDED_TARGET_RE.search(path_part):
        return None, True

    clean_repo = repo_url.rstrip("/")
    repo_root = docs_dir.parent if docs_dir is not None else None

    if (
        repo_rel.startswith("docs/docs/")
        and docs_dir is not None
        and (docs_dir / repo_rel[len("docs/docs/") :]).is_file()
    ):
        repo_rel = f"docs/{repo_rel[len('docs/docs/') :]}"

    # Excluded Go sources inside docs/ (such as docs.go and branding_test.go) resolve to GitHub.
    if repo_rel.startswith("docs/") and repo_rel.lower().endswith(".go"):
        return f"{clean_repo}/blob/{ref}/{repo_rel}{anchor}", False

    if repo_rel in _REPO_DOC_TO_VIRTUAL:
        virtual_uri = _REPO_DOC_TO_VIRTUAL[repo_rel]
        if virtual_uri in available_root_docs:
            return f"{prefix}{virtual_uri}{anchor}", False
        if (
            norm_src == "index.md"
            and docs_dir is not None
            and not (docs_dir / "01-tutorials").is_dir()
        ):
            if (
                virtual_uri == "security-audit.md"
                and (docs_dir / "SECURITY_AND_ARCHITECTURE_ANALYSIS.md").is_file()
            ):
                return f"{prefix}SECURITY_AND_ARCHITECTURE_ANALYSIS.md{anchor}", False
            return (
                _historical_overview_target(prefix, clean_repo, ref, available_root_docs),
                False,
            )
        return f"{clean_repo}/blob/{ref}/{repo_rel}{anchor}", False

    if repo_rel == "docs/index.md":
        return f"{prefix}index.md{anchor}", False

    if repo_rel.startswith("docs/"):
        doc_subpath = repo_rel[len("docs/") :]
        if doc_subpath in VIRTUAL_DOCS and (
            docs_dir is None or not (docs_dir / doc_subpath).is_file()
        ):
            if doc_subpath in available_root_docs:
                return f"{prefix}{doc_subpath}{anchor}", False
            if (
                norm_src == "index.md"
                and docs_dir is not None
                and not (docs_dir / "01-tutorials").is_dir()
            ):
                if (
                    doc_subpath == "security-audit.md"
                    and (docs_dir / "SECURITY_AND_ARCHITECTURE_ANALYSIS.md").is_file()
                ):
                    return f"{prefix}SECURITY_AND_ARCHITECTURE_ANALYSIS.md{anchor}", False
                return (
                    _historical_overview_target(prefix, clean_repo, ref, available_root_docs),
                    False,
                )
            return f"{clean_repo}/blob/{ref}/{VIRTUAL_DOCS[doc_subpath][0]}{anchor}", False

        if docs_dir is not None:
            top_segment = doc_subpath.split("/", 1)[0]
            if (
                top_segment in QUADRANT_HISTORICAL_FALLBACKS
                and not (docs_dir / top_segment).is_dir()
            ):
                fallback_doc = QUADRANT_HISTORICAL_FALLBACKS[top_segment]
                if (docs_dir / fallback_doc).is_file() or fallback_doc in available_root_docs:
                    return f"{prefix}{fallback_doc}", False
                return (
                    _historical_overview_target(prefix, clean_repo, ref, available_root_docs),
                    False,
                )

            # Historical pre-Diataxis snapshots (e.g., v2.0.0 / v2.1.0) overlay modern docs/index.md
            # whose links to newer release notes or quadrant pages must fall back cleanly.
            if (
                norm_src == "index.md"
                and not (docs_dir / "01-tutorials").is_dir()
                and not (docs_dir / doc_subpath).exists()
                and doc_subpath not in available_root_docs
            ):
                if doc_subpath.startswith(("releases/", "release_notes_", "RELEASE_NOTES_")):
                    discovered_notes = _discover_release_notes_entries(docs_dir)
                    if discovered_notes:
                        newest_note = next(iter(discovered_notes[0].values()))
                        return f"{prefix}{newest_note}", False
                return (
                    _historical_overview_target(prefix, clean_repo, ref, available_root_docs),
                    False,
                )

            candidate = docs_dir / doc_subpath
            if candidate.is_dir() and (candidate / "index.md").is_file():
                index_subpath = posixpath.join(doc_subpath.rstrip("/"), "index.md")
                return f"{prefix}{index_subpath}{anchor}", False

        trailing = "/" if had_trailing_slash and doc_subpath and not doc_subpath.endswith("/") else ""
        return f"{prefix}{doc_subpath}{trailing}{anchor}", False

    if repo_rel in (".", "..") or repo_rel.startswith("../"):
        return clean_repo, False

    is_dir_target = had_trailing_slash or (repo_root is not None and (repo_root / repo_rel).is_dir())
    kind = "tree" if is_dir_target else "blob"
    trailing = "/" if had_trailing_slash and not repo_rel.endswith("/") else ""
    return f"{clean_repo}/{kind}/{ref}/{repo_rel}{trailing}{anchor}", False


def _rewrite_html_attributes(
    segment: str,
    page_src_path: str,
    html_prefix: str,
    ref: str,
    repo_url: str,
    available_root_docs: frozenset[str],
    docs_dir: Path | None,
) -> str:
    """Rewrite relative HTML `src`/`href` attributes outside inline code."""

    def _replace_attr(match: re.Match[str]) -> str:
        resolved, neutralized = _resolve_target(
            match.group(3),
            page_src_path=page_src_path,
            prefix=html_prefix,
            ref=ref,
            repo_url=repo_url,
            available_root_docs=available_root_docs,
            docs_dir=docs_dir,
        )
        new_val = "#" if neutralized else str(resolved)
        return f"{match.group(1)}{match.group(2)}{new_val}{match.group(2)}"

    return _HTML_ATTR_RE.sub(_replace_attr, segment)


def _rewrite_prose_segment(
    text: str,
    page_src_path: str,
    md_prefix: str,
    html_prefix: str,
    ref: str,
    repo_url: str,
    available_root_docs: frozenset[str],
    docs_dir: Path | None = None,
) -> str:
    """Rewrite Markdown links and HTML `src`/`href` outside inline code spans."""
    out: list[str] = []
    prose_start = 0
    idx = 0
    n = len(text)

    def _flush_plain(end_idx: int) -> None:
        if end_idx > prose_start:
            out.append(
                _rewrite_html_attributes(
                    text[prose_start:end_idx],
                    page_src_path=page_src_path,
                    html_prefix=html_prefix,
                    ref=ref,
                    repo_url=repo_url,
                    available_root_docs=available_root_docs,
                    docs_dir=docs_dir,
                )
            )

    while idx < n:
        ch = text[idx]
        if ch == "`":
            _flush_plain(idx)
            tick_len = 1
            while idx + tick_len < n and text[idx + tick_len] == "`":
                tick_len += 1
            close_pos = text.find("`" * tick_len, idx + tick_len)
            if close_pos == -1:
                out.append(text[idx:])
                prose_start = n
                break
            out.append(text[idx : close_pos + tick_len])
            idx = prose_start = close_pos + tick_len
            continue

        is_img = ch == "!" and idx + 1 < n and text[idx + 1] == "[" and not _is_escaped(text, idx)
        bracket_start = idx + 1 if is_img else (idx if ch == "[" and not _is_escaped(text, idx) else -1)
        if bracket_start != -1:
            bracket_end = _match_delimiter(text, bracket_start, "[", "]", skip_inline_code=True)
            if bracket_end is not None and bracket_end + 1 < n and text[bracket_end + 1] == "(":
                paren_end = _match_delimiter(text, bracket_end + 1, "(", ")", skip_inline_code=False)
                if paren_end is not None:
                    _flush_plain(idx)
                    label = _rewrite_prose_segment(
                        text[bracket_start + 1 : bracket_end],
                        page_src_path=page_src_path,
                        md_prefix=md_prefix,
                        html_prefix=html_prefix,
                        ref=ref,
                        repo_url=repo_url,
                        available_root_docs=available_root_docs,
                        docs_dir=docs_dir,
                    )
                    url_part, title_suffix, had_angles = _split_destination(
                        text[bracket_end + 2 : paren_end]
                    )
                    resolved, neutralized = _resolve_target(
                        url_part,
                        page_src_path=page_src_path,
                        prefix=md_prefix,
                        ref=ref,
                        repo_url=repo_url,
                        available_root_docs=available_root_docs,
                        docs_dir=docs_dir,
                    )
                    if neutralized:
                        out.append("" if is_img else label)
                    else:
                        formatted_url = f"<{resolved}>" if had_angles else str(resolved)
                        bang = "!" if is_img else ""
                        out.append(f"{bang}[{label}]({formatted_url}{title_suffix})")
                    idx = prose_start = paren_end + 1
                    continue

        idx += 1

    _flush_plain(n)
    return "".join(out)


def rewrite_relative_links(
    markdown: str,
    page_src_path: str,
    ref: str = "main",
    repo_url: str = DEFAULT_REPO_URL,
    docs_dir: Path | None = None,
    use_directory_urls: bool = True,
    available_root_docs: Iterable[str] | None = None,
) -> str:
    """Rewrite repository-relative Markdown and HTML links outside fenced code blocks."""
    norm = page_src_path.replace("\\", "/").lstrip("/")
    md_depth = norm.count("/")
    html_depth = md_depth + (
        0 if (not use_directory_urls or norm == "index.md" or norm.endswith("/index.md")) else 1
    )
    resolved_ref = _effective_repo_ref(ref)
    resolved_docs = Path(docs_dir) if docs_dir is not None else None
    root_docs = (
        frozenset(VIRTUAL_DOCS) if available_root_docs is None else frozenset(available_root_docs)
    )
    return "".join(
        chunk
        if is_fence
        else _rewrite_prose_segment(
            chunk,
            page_src_path=norm,
            md_prefix="../" * md_depth,
            html_prefix="../" * html_depth,
            ref=resolved_ref,
            repo_url=repo_url,
            available_root_docs=root_docs,
            docs_dir=resolved_docs,
        )
        for is_fence, chunk in _split_fences(markdown)
    )


def _nav_doc_exists(rel_path: str, docs_dir: Path, repo_root: Path) -> bool:
    """Return True if a navigation target exists in `docs_dir` or as a virtual root doc."""
    if (docs_dir / rel_path).is_file():
        return True
    if rel_path in VIRTUAL_DOCS and (repo_root / VIRTUAL_DOCS[rel_path][0]).is_file():
        return True
    return False


def _is_release_note_target(rel_path: str) -> bool:
    """Return True if a nav target points to a release notes document."""
    norm = rel_path.replace("\\", "/").lstrip("/")
    return norm.startswith("releases/") or Path(norm).name.lower().startswith("release_notes_")


def _discover_release_notes_entries(docs_dir: Path) -> list[dict[str, str]]:
    """Discover `releases/v*.md`, `release_notes_v*.md`, and `RELEASE_NOTES_*.md` sorted by semver descending."""
    if not docs_dir.is_dir():
        return []

    candidate_paths: list[tuple[Path, str]] = []
    seen_rel: set[str] = set()

    releases_dir = docs_dir / "releases"
    if releases_dir.is_dir():
        for path in sorted(releases_dir.glob("v*.md")):
            if path.is_file():
                rel = f"releases/{path.name}"
                if rel not in seen_rel:
                    seen_rel.add(rel)
                    candidate_paths.append((path, rel))

    for path in sorted(docs_dir.glob("*.md")):
        if path.is_file() and path.name.lower().startswith("release_notes_"):
            rel = path.name
            if rel not in seen_rel:
                seen_rel.add(rel)
                candidate_paths.append((path, rel))

    semver_entries: list[tuple[tuple[int, int, int], str, str]] = []
    other_entries: list[tuple[str, str]] = []

    for path, rel in candidate_paths:
        match = _RELEASE_NOTES_SEMVER_RE.match(path.name)
        if match:
            ver = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
            semver_entries.append((ver, f"Release Notes v{ver[0]}.{ver[1]}.{ver[2]}", rel))
        else:
            stem_tag = re.sub(r"^release_notes_", "", path.stem, flags=re.IGNORECASE)
            other_entries.append((f"Release Notes {stem_tag}", rel))

    semver_entries.sort(key=lambda item: item[0], reverse=True)
    ordered: list[dict[str, str]] = [{label: rel} for _, label, rel in semver_entries]
    for label, rel in sorted(other_entries, reverse=True):
        ordered.append({label: rel})
    return ordered


def _prune_releases_section(
    children: list[Any],
    docs_dir: Path,
    repo_root: Path,
) -> list[Any]:
    """Prune `Releases & Governance` items and inject discovered release notes entries."""
    discovered_notes = _discover_release_notes_entries(docs_dir)
    notes_inserted = False
    pruned: list[Any] = []

    for child in children:
        if isinstance(child, str):
            if _is_release_note_target(child):
                if not notes_inserted:
                    pruned.extend(discovered_notes)
                    notes_inserted = True
                continue
            if _nav_doc_exists(child, docs_dir, repo_root):
                pruned.append(child)
            continue

        if isinstance(child, dict) and len(child) == 1:
            title, target = next(iter(child.items()))
            if isinstance(target, str):
                if _is_release_note_target(target):
                    if not notes_inserted:
                        pruned.extend(discovered_notes)
                        notes_inserted = True
                    continue
                if _nav_doc_exists(target, docs_dir, repo_root):
                    pruned.append({title: target})
            elif isinstance(target, list):
                nested = _prune_nav_list(target, docs_dir, repo_root)
                if nested:
                    pruned.append({title: nested})

    if not notes_inserted and discovered_notes:
        pruned[0:0] = discovered_notes

    return pruned


def _prune_nav_list(
    items: list[Any],
    docs_dir: Path,
    repo_root: Path,
) -> list[Any]:
    """Recursively prune missing pages and empty sections from a MkDocs navigation list."""
    pruned: list[Any] = []
    for entry in items:
        if isinstance(entry, str):
            if _nav_doc_exists(entry, docs_dir, repo_root):
                pruned.append(entry)
            continue

        if isinstance(entry, dict):
            kept_dict: dict[str, Any] = {}
            for title, target in entry.items():
                if isinstance(target, str):
                    if _nav_doc_exists(target, docs_dir, repo_root):
                        kept_dict[title] = target
                elif isinstance(target, list):
                    nested = (
                        _prune_releases_section(target, docs_dir, repo_root)
                        if title == "Releases & Governance"
                        else _prune_nav_list(target, docs_dir, repo_root)
                    )
                    if nested:
                        kept_dict[title] = nested
                elif isinstance(target, dict):
                    nested_dict = _prune_nav_list([target], docs_dir, repo_root)
                    if nested_dict:
                        kept_dict[title] = nested_dict[0]
            if kept_dict:
                pruned.append(kept_dict)
    return pruned


def prune_nav_for_existing_files(
    nav: list[Any] | None,
    docs_dir: Path,
    repo_root: Path,
) -> list[Any]:
    """Prune missing pages and empty sections while auto-discovering release notes."""
    if not nav:
        return []
    return _prune_nav_list(list(nav), Path(docs_dir), Path(repo_root))


def on_config(config: Any) -> Any:
    """Configure environment-driven `site_url`, `edit_uri`, GFM slugifier, and pruned nav."""
    site_url = os.environ.get("API_EXECUTOR_DOCS_SITE_URL", "").strip()
    if site_url:
        config.site_url = site_url.rstrip("/") + "/"

    config.edit_uri = "edit/main/docs/" if _effective_repo_ref() == "main" else ""

    mdx = getattr(config, "mdx_configs", None)
    if isinstance(mdx, dict):
        toc_cfg = mdx.setdefault("toc", {})
        if isinstance(toc_cfg, dict) and not toc_cfg.get("slugify"):
            toc_cfg["slugify"] = gfm_slugify

    docs_dir = Path(config.docs_dir)
    repo_root = docs_dir.parent
    if getattr(config, "nav", None):
        config.nav = prune_nav_for_existing_files(config.nav, docs_dir=docs_dir, repo_root=repo_root)
    return config


def on_files(files: Files, config: Any) -> Files:
    """Exclude sensitive/non-doc files and inject virtual root documents."""
    from mkdocs.structure.files import File, Files as MkDocsFiles, InclusionLevel

    kept: list[File] = []
    for file_obj in list(files):
        if _EXCLUDED_TARGET_RE.search(file_obj.src_uri):
            file_obj.inclusion = InclusionLevel.EXCLUDED
            continue
        kept.append(file_obj)

    if len(kept) != len(files):
        files = MkDocsFiles(kept)

    repo_root = Path(config.docs_dir).parent
    for virtual_uri, (source_rel, _) in VIRTUAL_DOCS.items():
        src_path = repo_root / source_rel
        if src_path.is_file() and files.get_file_from_path(virtual_uri) is None:
            files.append(File.generated(config, virtual_uri, abs_src_path=str(src_path)))

    return files


def on_page_markdown(markdown: str, page: Any, config: Any, files: Files) -> str:
    """Convert GitHub alerts, rewrite relative links, and adjust virtual doc edit URLs."""
    src = getattr(page.file, "src_uri", None) or str(page.file.src_path).replace("\\", "/")
    ref = _effective_repo_ref()
    repo_url = (getattr(config, "repo_url", None) or DEFAULT_REPO_URL).rstrip("/")
    raw_docs = getattr(config, "docs_dir", None) or (
        config.get("docs_dir") if isinstance(config, dict) else None
    )
    docs_dir = Path(raw_docs) if raw_docs else None

    if src in VIRTUAL_DOCS:
        page.edit_url = f"{repo_url}/edit/main/{VIRTUAL_DOCS[src][0]}" if ref == "main" else None

    available_root_docs: Iterable[str] | None = (
        [name for name in VIRTUAL_DOCS if files.get_file_from_path(name) is not None]
        if files is not None
        else None
    )
    return rewrite_relative_links(
        convert_github_alerts(markdown),
        page_src_path=src,
        ref=ref,
        repo_url=repo_url,
        docs_dir=docs_dir,
        use_directory_urls=bool(getattr(config, "use_directory_urls", True)),
        available_root_docs=available_root_docs,
    )
