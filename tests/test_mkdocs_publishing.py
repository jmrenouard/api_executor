"""Unit and integration tests for versioned MkDocs Material publishing and IONOS deployment."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "docs-publish.yml"
MKDOCS_CONFIG_PATH = REPO_ROOT / "mkdocs.yml"
HOOKS_SCRIPT_PATH = REPO_ROOT / "scripts" / "mkdocs_hooks.py"
BUILD_SCRIPT_PATH = REPO_ROOT / "scripts" / "build_versioned_docs.py"
REQUIREMENTS_DOCS_PATH = REPO_ROOT / "requirements-docs.txt"
GITIGNORE_PATH = REPO_ROOT / ".gitignore"

SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class _MkDocsYamlLoader(yaml.SafeLoader):
    """Safe YAML loader supporting PyMdownx `!!python/name:` tag references as strings."""


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


class _AttrDict(dict[str, Any]):
    """Dictionary exposing keys as attributes to mimic MkDocsConfig in hook unit tests."""

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError as exc:
            raise AttributeError(key) from exc

    def __setattr__(self, key: str, value: Any) -> None:
        self[key] = value


def _load_mkdocs_config() -> dict[str, Any]:
    assert MKDOCS_CONFIG_PATH.is_file(), "mkdocs.yml must exist at repository root"
    loader = _MkDocsYamlLoader(MKDOCS_CONFIG_PATH.read_text(encoding="utf-8"))
    try:
        parsed = loader.get_single_data()
    finally:
        loader.dispose()
    assert isinstance(parsed, dict), "mkdocs.yml must parse into a YAML mapping"
    return parsed


def _load_script_module(module_name: str, script_path: Path) -> ModuleType:
    assert script_path.is_file(), f"Missing script module: {script_path}"
    scripts_dir = str(script_path.parent)
    added_sys_path = False
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
        added_sys_path = True
    try:
        spec = importlib.util.spec_from_file_location(module_name, script_path)
        assert spec is not None and spec.loader is not None, f"Cannot load spec for {script_path}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if added_sys_path and scripts_dir in sys.path:
            sys.path.remove(scripts_dir)


def _flatten_nav_paths(node: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(node, str):
        paths.append(node)
    elif isinstance(node, list):
        for item in node:
            paths.extend(_flatten_nav_paths(item))
    elif isinstance(node, dict):
        for val in node.values():
            paths.extend(_flatten_nav_paths(val))
    return paths


def _find_nav_section(nav: list[Any], section_name: str) -> Any:
    for item in nav:
        if isinstance(item, dict) and section_name in item:
            return item[section_name]
    return None


def _collect_workflow_steps(job_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job_cfg.get("steps", [])
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


# ==============================================================================
# 1. mkdocs.yml and Portal Assets Verification
# ==============================================================================


def test_mkdocs_yml_configuration_and_security_exclusions() -> None:
    """Verify mkdocs.yml Material config, Mermaid, KaTeX, mike switcher, hooks, and privacy exclusions."""
    config = _load_mkdocs_config()

    assert config.get("site_name") == "API Executor Documentation"
    assert config.get("site_url") == "https://api-executor.lightpath.fr/"
    assert config.get("repo_name") == "jmrenouard/api_executor"
    assert config.get("repo_url") == "https://github.com/jmrenouard/api_executor"
    assert config.get("docs_dir") == "docs"
    assert "scripts/mkdocs_hooks.py" in config.get("hooks", [])

    theme = config.get("theme", {})
    assert isinstance(theme, dict)
    assert theme.get("name") == "material"
    assert theme.get("language") == "en"
    assert "navigation.tabs" in theme.get("features", [])
    assert "navigation.indexes" in theme.get("features", [])

    extra = config.get("extra", {})
    assert extra.get("version", {}).get("provider") == "mike"
    assert extra.get("version", {}).get("default") == "latest"

    extra_css = config.get("extra_css", [])
    assert any("katex" in item and item.endswith(".css") for item in extra_css)
    assert "stylesheets/extra.css" in extra_css

    extra_js = config.get("extra_javascript", [])
    assert "javascripts/katex.js" in extra_js
    assert any("katex.min.js" in item for item in extra_js)
    assert any("auto-render.min.js" in item for item in extra_js)

    extensions = config.get("markdown_extensions", [])
    ext_names: set[str] = set()
    superfences_cfg: dict[str, Any] = {}
    for ext in extensions:
        if isinstance(ext, str):
            ext_names.add(ext)
        elif isinstance(ext, dict):
            ext_names.update(ext.keys())
            if "pymdownx.superfences" in ext:
                superfences_cfg = ext["pymdownx.superfences"] or {}

    assert "admonition" in ext_names
    assert "pymdownx.arithmatex" in ext_names
    assert "pymdownx.superfences" in ext_names

    custom_fences = superfences_cfg.get("custom_fences", [])
    mermaid_fences = [
        fence for fence in custom_fences if isinstance(fence, dict) and fence.get("name") == "mermaid"
    ]
    assert len(mermaid_fences) == 1, "pymdownx.superfences must configure a mermaid custom fence"
    assert mermaid_fences[0].get("class") == "mermaid"
    assert "fence_code_format" in str(mermaid_fences[0].get("format", ""))

    raw_exclude = config.get("exclude_docs", "")
    exclude_text = "\n".join(raw_exclude) if isinstance(raw_exclude, list) else str(raw_exclude)
    for pattern in ("*.go", "*.kdbx", "*.keyx", "*.db", "*.sqlite*", "*.log", "*.key", ".env", "articles/*.fr.md"):
        assert pattern in exclude_text, f"exclude_docs must exclude '{pattern}'"

    nav = config.get("nav", [])
    assert isinstance(nav, list) and len(nav) == 6
    tab_names = [next(iter(entry.keys())) for entry in nav if isinstance(entry, dict)]
    assert tab_names == [
        "Home",
        "Tutorials",
        "How-To Guides",
        "Reference",
        "Explanation",
        "Releases & Governance",
    ]

    assert (REPO_ROOT / "docs" / "index.md").is_file()
    assert (REPO_ROOT / "docs" / "stylesheets" / "extra.css").is_file()
    katex_js = REPO_ROOT / "docs" / "javascripts" / "katex.js"
    assert katex_js.is_file()
    katex_js_text = katex_js.read_text(encoding="utf-8")
    assert "document$.subscribe" in katex_js_text
    assert "renderMathInElement" in katex_js_text


# ==============================================================================
# 2. scripts/mkdocs_hooks.py Unit Tests
# ==============================================================================


def test_mkdocs_hooks_convert_github_alerts_and_ignore_code_blocks() -> None:
    """Verify all 5 GitHub alerts convert to Material admonitions while fenced blocks stay untouched."""
    hooks = _load_script_module("mkdocs_hooks", HOOKS_SCRIPT_PATH)

    sample = (
        "Intro paragraph.\n\n"
        "> [!NOTE]\n"
        "> Useful context line.\n\n"
        "> [!TIP]\n"
        "> Helpful optimization.\n\n"
        "> [!IMPORTANT]\n"
        "> Essential requirement.\n\n"
        "> [!WARNING]\n"
        "> Watch out for drift.\n\n"
        "> [!CAUTION]\n"
        "> High risk operation.\n\n"
        "```markdown\n"
        "> [!NOTE]\n"
        "> Literal example inside fenced code.\n"
        "```\n"
    )

    converted = hooks.convert_github_alerts(sample)

    assert "!!! note" in converted
    assert "!!! tip" in converted
    assert "!!! info" in converted
    assert "!!! warning" in converted
    assert "!!! danger" in converted
    assert "Useful context line." in converted
    assert "High risk operation." in converted

    fenced_part = converted.split("```markdown", 1)[1]
    assert "> [!NOTE]" in fenced_part
    outside_fenced = converted.split("```markdown", 1)[0]
    for marker in ("[!" + tag + "]" for tag in ("NOTE", "TIP", "IMPORTANT", "WARNING", "CAUTION")):
        assert marker not in outside_fenced


def test_mkdocs_hooks_gfm_slugify() -> None:
    """Verify gfm_slugify produces GitHub-compatible TOC anchors."""
    hooks = _load_script_module("mkdocs_hooks", HOOKS_SCRIPT_PATH)

    assert hooks.gfm_slugify("Documentation & Governance Hub") == "documentation--governance-hub"
    assert hooks.gfm_slugify("33 REST & MCP Endpoints") == "33-rest--mcp-endpoints"
    assert hooks.gfm_slugify("Why Zero-Trust Execution?") == "why-zero-trust-execution"
    assert hooks.gfm_slugify("cli_flags") == "cli_flags"
    assert hooks.gfm_slugify("Alpha Beta", separator="_") == "alpha_beta"


def test_mkdocs_hooks_rewrite_relative_links_virtual_html_and_exclusions() -> None:
    """Verify virtual doc links, HTML <img src> depth, GitHub blob URLs, docs/*.go rewriting, and neutralized exclusions."""
    hooks = _load_script_module("mkdocs_hooks", HOOKS_SCRIPT_PATH)

    overview_md = (
        '<img src="docs/assets/header-banner.svg" alt="Banner" />\n'
        '<img src="docs/assets/logo.svg" alt="Logo" />\n'
        "- [Overview](README.md)\n"
        "- [Security](SECURITY.md)\n"
        "- [Project](PROJECT.md)\n"
        "- [Portal](docs/index.md)\n"
        "- [Logbook](docs/ACTION_LOGBOOK.md)\n"
        "- [BrandingTest](docs/branding_test.go)\n"
        "- [ConfigSrc](internal/core/config.go)\n"
        "- [Vault](secrets.kdbx)\n"
        "- [Key](vault.keyx)\n"
        "- [History](history.db)\n"
        "- [Sqlite](audit.sqlite3)\n"
        "- [Env](.env)\n"
        "```markdown\n"
        '[Preserved](SECURITY.md)\n'
        '<img src="docs/assets/logo.svg" />\n'
        "```\n"
    )

    rewritten_overview = hooks.rewrite_relative_links(
        overview_md,
        page_src_path="overview.md",
        ref="v2.1.0",
        use_directory_urls=True,
    )
    outside_fence, fenced_part = rewritten_overview.split("```markdown", 1)

    assert '<img src="../assets/header-banner.svg"' in outside_fence
    assert '<img src="../assets/logo.svg"' in outside_fence
    assert "](overview.md)" in outside_fence
    assert "](security-audit.md)" in outside_fence
    assert "](project-architecture.md)" in outside_fence
    assert "](index.md)" in outside_fence
    assert "](ACTION_LOGBOOK.md)" in outside_fence
    assert "](https://github.com/jmrenouard/api_executor/blob/v2.1.0/docs/branding_test.go)" in outside_fence
    assert "](https://github.com/jmrenouard/api_executor/blob/v2.1.0/internal/core/config.go)" in outside_fence

    for forbidden_target in ("secrets.kdbx", "vault.keyx", "history.db", "audit.sqlite3", "(.env)"):
        assert forbidden_target not in outside_fence
    for kept_label in ("Vault", "Key", "History", "Sqlite", "Env"):
        assert kept_label in outside_fence

    assert "[Preserved](SECURITY.md)" in fenced_part
    assert '<img src="docs/assets/logo.svg" />' in fenced_part

    rewritten_flat = hooks.rewrite_relative_links(
        '<img src="docs/assets/header-banner.svg" alt="Banner" />\n',
        page_src_path="overview.md",
        ref="v2.1.0",
        use_directory_urls=False,
    )
    assert '<img src="assets/header-banner.svg"' in rewritten_flat

    logbook_md = (
        "- [README](../README.md)\n"
        "- [Security](../SECURITY.md)\n"
        "- [Project](../PROJECT.md)\n"
        "- [Portal](index.md)\n"
        "- [DocsGo](docs.go)\n"
        "- [BrandingTest](branding_test.go)\n"
        "- [Router](../internal/api/router.go)\n"
    )
    rewritten_logbook = hooks.rewrite_relative_links(
        logbook_md,
        page_src_path="ACTION_LOGBOOK.md",
        ref="v2.1.0",
        use_directory_urls=True,
    )
    assert "](overview.md)" in rewritten_logbook
    assert "](security-audit.md)" in rewritten_logbook
    assert "](project-architecture.md)" in rewritten_logbook
    assert "](index.md)" in rewritten_logbook
    assert "](https://github.com/jmrenouard/api_executor/blob/v2.1.0/docs/docs.go)" in rewritten_logbook
    assert "](https://github.com/jmrenouard/api_executor/blob/v2.1.0/docs/branding_test.go)" in rewritten_logbook
    assert "](https://github.com/jmrenouard/api_executor/blob/v2.1.0/internal/api/router.go)" in rewritten_logbook


def test_mkdocs_hooks_diataxis_depth_links_and_historical_fallbacks(tmp_path: Path) -> None:
    """Verify depth-1/depth-2 Diataxis rewriting and v2.0.0/v2.1.0 historical quadrant fallbacks."""
    hooks = _load_script_module("mkdocs_hooks", HOOKS_SCRIPT_PATH)

    depth1_md = (
        "- [Root](../../README.md)\n"
        "- [Security](../../SECURITY.md)\n"
        "- [Project](../../PROJECT.md)\n"
        "- [Portal](../index.md)\n"
        "- [Config](../../internal/core/config.go)\n"
        "- [Ref](../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)\n"
    )
    rewritten_d1 = hooks.rewrite_relative_links(
        depth1_md,
        page_src_path="01-tutorials/01-local-https-quickstart.md",
        ref="main",
    )
    assert "](../overview.md)" in rewritten_d1
    assert "](../security-audit.md)" in rewritten_d1
    assert "](../project-architecture.md)" in rewritten_d1
    assert "](../index.md)" in rewritten_d1
    assert "](https://github.com/jmrenouard/api_executor/blob/main/internal/core/config.go)" in rewritten_d1
    assert "](../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)" in rewritten_d1

    depth2_md = (
        "- [Root](../../../README.md)\n"
        "- [Security](../../../SECURITY.md)\n"
        "- [Project](../../../PROJECT.md)\n"
        "- [Portal](../../index.md)\n"
        "- [Config](../../../internal/core/config.go)\n"
        "- [Ref](../../03-reference/configuration/config-schema-and-profiles.md)\n"
    )
    rewritten_d2 = hooks.rewrite_relative_links(
        depth2_md,
        page_src_path="02-how-to-guides/deployment/deploy-rootless-docker-and-tls.md",
        ref="main",
    )
    assert "](../../overview.md)" in rewritten_d2
    assert "](../../security-audit.md)" in rewritten_d2
    assert "](../../project-architecture.md)" in rewritten_d2
    assert "](../../index.md)" in rewritten_d2
    assert "](https://github.com/jmrenouard/api_executor/blob/main/internal/core/config.go)" in rewritten_d2
    assert "](../../03-reference/configuration/config-schema-and-profiles.md)" in rewritten_d2

    portal_links = (
        "- [T](01-tutorials/index.md)\n"
        "- [T1](01-tutorials/01-local-https-quickstart.md)\n"
        "- [H](02-how-to-guides/index.md)\n"
        "- [R](03-reference/index.md)\n"
        "- [E](04-explanation/index.md)\n"
        "- [RN210](releases/v2.1.0.md)\n"
        "- [RN200](release_notes_v2.0.0.md)\n"
        "- [Sec](../SECURITY.md)\n"
    )

    # Historical v2.1.0: has SECURITY_AND_ARCHITECTURE_ANALYSIS.md, releases/v2.1.0.md, release_notes_v2.0.0.md;
    # lacks quadrant directories and lacks SECURITY.md.
    v210_docs = tmp_path / "v210_docs"
    (v210_docs / "releases").mkdir(parents=True)
    for rel in (
        "SECURITY_AND_ARCHITECTURE_ANALYSIS.md",
        "release_notes_v2.0.0.md",
        "releases/v2.1.0.md",
    ):
        (v210_docs / rel).write_text(f"# {rel}\n", encoding="utf-8")

    rewritten_v210 = hooks.rewrite_relative_links(
        portal_links,
        page_src_path="index.md",
        ref="v2.1.0",
        docs_dir=v210_docs,
        available_root_docs=("overview.md", "project-architecture.md"),
    )
    assert "- [T](overview.md)" in rewritten_v210
    assert "- [T1](overview.md)" in rewritten_v210
    assert "- [H](SECURITY_AND_ARCHITECTURE_ANALYSIS.md)" in rewritten_v210
    assert "- [R](project-architecture.md)" in rewritten_v210 or "- [R](overview.md)" in rewritten_v210
    assert "- [E](SECURITY_AND_ARCHITECTURE_ANALYSIS.md)" in rewritten_v210
    assert "- [RN210](releases/v2.1.0.md)" in rewritten_v210
    assert "- [RN200](release_notes_v2.0.0.md)" in rewritten_v210
    assert "](security-audit.md)" not in rewritten_v210

    # Historical v2.0.0: also lacks releases/v2.1.0.md -> overlaid index.md must fall back cleanly.
    v200_docs = tmp_path / "v200_docs"
    v200_docs.mkdir(parents=True)
    for rel in ("SECURITY_AND_ARCHITECTURE_ANALYSIS.md", "release_notes_v2.0.0.md"):
        (v200_docs / rel).write_text(f"# {rel}\n", encoding="utf-8")

    rewritten_v200 = hooks.rewrite_relative_links(
        portal_links,
        page_src_path="index.md",
        ref="v2.0.0",
        docs_dir=v200_docs,
        available_root_docs=("overview.md", "project-architecture.md"),
    )
    assert "- [T](overview.md)" in rewritten_v200
    assert "- [H](SECURITY_AND_ARCHITECTURE_ANALYSIS.md)" in rewritten_v200
    assert "- [R](project-architecture.md)" in rewritten_v200 or "- [R](overview.md)" in rewritten_v200
    assert "- [E](SECURITY_AND_ARCHITECTURE_ANALYSIS.md)" in rewritten_v200
    assert "- [RN200](release_notes_v2.0.0.md)" in rewritten_v200
    assert "](releases/v2.1.0.md)" not in rewritten_v200
    assert "](security-audit.md)" not in rewritten_v200

    # Modern docs_dir: preserves quadrant links and resolves directory link to index.md
    modern_docs = tmp_path / "modern_docs"
    for quadrant in ("01-tutorials", "02-how-to-guides", "03-reference", "04-explanation"):
        (modern_docs / quadrant).mkdir(parents=True)
        (modern_docs / quadrant / "index.md").write_text(f"# {quadrant}\n", encoding="utf-8")
    (modern_docs / "01-tutorials" / "01-local-https-quickstart.md").write_text("# Lab\n", encoding="utf-8")

    rewritten_modern = hooks.rewrite_relative_links(
        "- [T](01-tutorials/index.md)\n- [TDir](01-tutorials/)\n- [T1](01-tutorials/01-local-https-quickstart.md)\n",
        page_src_path="index.md",
        ref="main",
        docs_dir=modern_docs,
    )
    assert "- [T](01-tutorials/index.md)" in rewritten_modern
    assert "- [TDir](01-tutorials/index.md)" in rewritten_modern
    assert "- [T1](01-tutorials/01-local-https-quickstart.md)" in rewritten_modern


def test_mkdocs_hooks_prune_nav_for_existing_files_and_discover_release_notes(tmp_path: Path) -> None:
    """Verify nav pruning removes missing entries/sections, keeps virtual docs, and sorts release notes descending."""
    hooks = _load_script_module("mkdocs_hooks", HOOKS_SCRIPT_PATH)

    docs_dir = tmp_path / "docs"
    (docs_dir / "releases").mkdir(parents=True)
    (docs_dir / "index.md").write_text("# Home\n", encoding="utf-8")
    (docs_dir / "ACTION_LOGBOOK.md").write_text("# Logbook\n", encoding="utf-8")
    (docs_dir / "release_notes_v2.0.0.md").write_text("# v2.0.0\n", encoding="utf-8")
    (docs_dir / "releases" / "v2.1.0.md").write_text("# v2.1.0\n", encoding="utf-8")
    (docs_dir / "releases" / "v2.10.0.md").write_text("# v2.10.0\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Overview\n", encoding="utf-8")
    (tmp_path / "PROJECT.md").write_text("# Project\n", encoding="utf-8")
    # Intentionally omit SECURITY.md to verify missing virtual doc is pruned.

    nav = [
        {"Home": "index.md"},
        {
            "How-To Guides": [
                {"Deployment": ["02-how-to-guides/deployment/missing.md"]},
                "MISSING_DOC.md",
            ]
        },
        {
            "Reference": [
                {"API Security Audit (SECURITY.md)": "security-audit.md"},
                {"Project Contracts (PROJECT.md)": "project-architecture.md"},
            ]
        },
        {
            "Explanation": [
                {"Overview (README)": "overview.md"},
            ]
        },
        {
            "Releases & Governance": [
                {"Release Notes v9.9.9": "releases/v9.9.9.md"},
                {"Action Logbook": "ACTION_LOGBOOK.md"},
            ]
        },
    ]

    pruned = hooks.prune_nav_for_existing_files(nav, docs_dir, tmp_path)
    all_paths = _flatten_nav_paths(pruned)

    assert "index.md" in all_paths
    assert "overview.md" in all_paths
    assert "project-architecture.md" in all_paths
    assert "security-audit.md" not in all_paths
    assert "MISSING_DOC.md" not in all_paths
    assert "02-how-to-guides/deployment/missing.md" not in all_paths
    assert "releases/v9.9.9.md" not in all_paths
    assert _find_nav_section(pruned, "How-To Guides") is None

    releases_section = _find_nav_section(pruned, "Releases & Governance")
    assert releases_section is not None
    release_paths = _flatten_nav_paths(releases_section)
    assert "ACTION_LOGBOOK.md" in release_paths
    for note in ("releases/v2.10.0.md", "releases/v2.1.0.md", "release_notes_v2.0.0.md"):
        assert note in release_paths

    assert release_paths.index("releases/v2.10.0.md") < release_paths.index("releases/v2.1.0.md")
    assert release_paths.index("releases/v2.1.0.md") < release_paths.index("release_notes_v2.0.0.md")


def test_mkdocs_hooks_on_config_edit_uri_and_virtual_edit_url(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify on_config sets edit_uri on main/WORKTREE, clears on tags, attaches gfm_slugify, and sets edit_url."""
    hooks = _load_script_module("mkdocs_hooks", HOOKS_SCRIPT_PATH)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "index.md").write_text("# Home\n", encoding="utf-8")

    monkeypatch.setenv("API_EXECUTOR_DOCS_REF", "WORKTREE")
    monkeypatch.setenv("API_EXECUTOR_DOCS_SITE_URL", "https://api-executor.lightpath.fr/main")
    cfg_main = _AttrDict(
        {
            "docs_dir": str(docs_dir),
            "site_url": "",
            "edit_uri": "",
            "repo_url": "https://github.com/jmrenouard/api_executor",
            "mdx_configs": {"toc": {"permalink": True}},
            "nav": [{"Home": "index.md"}],
        }
    )
    hooks.on_config(cfg_main)
    assert cfg_main["edit_uri"] == "edit/main/docs/"
    assert cfg_main["site_url"] == "https://api-executor.lightpath.fr/main/"
    assert cfg_main["mdx_configs"]["toc"]["slugify"] is hooks.gfm_slugify

    class _FakeFile:
        def __init__(self, src_uri: str) -> None:
            self.src_uri = src_uri
            self.src_path = src_uri

    class _FakeFiles:
        def get_file_from_path(self, path: str) -> None:
            del path
            return None

    class _FakePage:
        def __init__(self, src_uri: str, edit_url: str | None) -> None:
            self.file = _FakeFile(src_uri)
            self.edit_url = edit_url

    for virtual_uri, root_target in (
        ("overview.md", "README.md"),
        ("security-audit.md", "SECURITY.md"),
        ("project-architecture.md", "PROJECT.md"),
    ):
        page_main = _FakePage(
            virtual_uri,
            f"https://github.com/jmrenouard/api_executor/edit/main/docs/{virtual_uri}",
        )
        hooks.on_page_markdown("# Doc\n", page_main, cfg_main, _FakeFiles())
        assert page_main.edit_url == f"https://github.com/jmrenouard/api_executor/edit/main/{root_target}"

    monkeypatch.setenv("API_EXECUTOR_DOCS_REF", "v2.1.0")
    cfg_tag = _AttrDict(
        {
            "docs_dir": str(docs_dir),
            "site_url": "",
            "edit_uri": "edit/main/docs/",
            "repo_url": "https://github.com/jmrenouard/api_executor",
            "mdx_configs": {"toc": {}},
            "nav": [],
        }
    )
    hooks.on_config(cfg_tag)
    assert cfg_tag["edit_uri"] == ""

    page_tag = _FakePage(
        "overview.md",
        "https://github.com/jmrenouard/api_executor/edit/main/docs/overview.md",
    )
    hooks.on_page_markdown("# Overview\n", page_tag, cfg_tag, _FakeFiles())
    assert not page_tag.edit_url


def test_mkdocs_hooks_importable_without_mkdocs_or_pathspec(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify scripts/mkdocs_hooks.py imports and runs helper/hook functions without mkdocs or pathspec installed."""
    for blocked in (
        "mkdocs",
        "mkdocs.structure",
        "mkdocs.structure.files",
        "pathspec",
        "pathspec.gitignore",
    ):
        monkeypatch.setitem(sys.modules, blocked, None)

    try:
        hooks = _load_script_module("mkdocs_hooks_no_deps", HOOKS_SCRIPT_PATH)
        assert "!!! note" in hooks.convert_github_alerts("> [!NOTE]\n> Works without mkdocs.")
        assert hooks.gfm_slugify("Zero-Trust Bastion") == "zero-trust-bastion"
        assert "](../overview.md)" in hooks.rewrite_relative_links(
            "[Root](../../README.md)",
            "01-tutorials/01-local-https-quickstart.md",
        )
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "index.md").write_text("# Home\n", encoding="utf-8")
        cfg = _AttrDict(
            {
                "docs_dir": str(docs_dir),
                "site_url": "",
                "edit_uri": "",
                "mdx_configs": {"toc": {}},
                "nav": [{"Home": "index.md"}],
            }
        )
        hooks.on_config(cfg)
        assert cfg["edit_uri"] == "edit/main/docs/"
    finally:
        sys.modules.pop("mkdocs_hooks_no_deps", None)


# ==============================================================================
# 3. scripts/build_versioned_docs.py Unit & Integration Tests
# ==============================================================================


def test_build_versioned_docs_parse_semver_tag_and_manifest_ordering() -> None:
    """Verify semver parsing, numeric descending sorting, alias assignment, and empty fallback."""
    builder = _load_script_module("build_versioned_docs", BUILD_SCRIPT_PATH)

    assert builder.parse_semver_tag("v2.0.0") == (2, 0, 0)
    assert builder.parse_semver_tag("v2.1.0") == (2, 1, 0)
    assert builder.parse_semver_tag("v2.10.0") == (2, 10, 0)
    assert builder.parse_semver_tag("main") is None
    assert builder.parse_semver_tag("latest") is None
    assert builder.parse_semver_tag("v2.0") is None

    manifest = builder.build_versions_manifest(
        ["v2.0.0", "v2.2.0", "v2.10.0", "v2.1.0"],
        include_main=True,
    )
    versions = [entry["version"] for entry in manifest]

    # Numeric semver descending puts v2.10.0 before v2.2.0 before v2.1.0 before v2.0.0
    assert versions.index("v2.10.0") < versions.index("v2.2.0")
    assert versions.index("v2.2.0") < versions.index("v2.1.0")
    assert versions.index("v2.1.0") < versions.index("v2.0.0")

    by_version = {entry["version"]: entry for entry in manifest}
    assert "latest" in by_version["v2.10.0"]["aliases"]
    assert "latest" not in by_version["v2.1.0"]["aliases"]
    assert "main" in by_version
    assert "dev" in by_version["main"]["aliases"]

    fallback_main = builder.build_versions_manifest([], include_main=True)
    assert len(fallback_main) == 1
    assert fallback_main[0]["version"] == "main"
    assert "latest" in fallback_main[0]["aliases"]
    assert "dev" in fallback_main[0]["aliases"]

    assert builder.build_versions_manifest([], include_main=False) == []


def test_build_versioned_site_rejects_protected_or_ancestor_output_dirs(tmp_path: Path) -> None:
    """Verify build_versioned_site refuses to overwrite repo root, ancestors, or protected subdirectories."""
    builder = _load_script_module("build_versioned_docs", BUILD_SCRIPT_PATH)
    repo_dir = tmp_path / "repo"
    docs_dir = repo_dir / "docs"
    cmd_dir = repo_dir / "cmd"
    internal_dir = repo_dir / "internal"
    git_dir = repo_dir / ".git"
    for directory in (docs_dir, cmd_dir, internal_dir, git_dir):
        directory.mkdir(parents=True)
    sentinel = docs_dir / "keep.md"
    sentinel.write_text("# Keep\n", encoding="utf-8")

    for forbidden_out in (
        repo_dir,
        tmp_path,
        git_dir,
        docs_dir,
        docs_dir / "nested",
        cmd_dir,
        internal_dir,
    ):
        with pytest.raises(ValueError, match="protected"):
            builder.build_versioned_site(repo_root=repo_dir, output_dir=forbidden_out, skip_tags=True)
        assert sentinel.is_file()


def test_build_versioned_docs_render_htaccess_and_redirect_html() -> None:
    """Verify .htaccess rules (HTTPS 301, /latest/ & /dev/ 302, no Indexes) and redirect HTML."""
    builder = _load_script_module("build_versioned_docs", BUILD_SCRIPT_PATH)

    htaccess = builder.render_htaccess("v2.1.0", main_version="main")
    assert "Options -Indexes" in htaccess
    assert "DirectoryIndex index.html" in htaccess
    assert "RewriteEngine On" in htaccess
    assert "RewriteBase /" in htaccess
    assert "X-Content-Type-Options" in htaccess
    assert "R=301" in htaccess
    assert "^latest(?:/(.*))?$" in htaccess
    assert "/v2.1.0/$1" in htaccess
    assert "^dev(?:/(.*))?$" in htaccess
    assert "/main/$1" in htaccess
    assert "R=302" in htaccess
    assert "ErrorDocument 404 /v2.1.0/404.html" in htaccess

    redirect_html = builder.render_redirect_html("/v2.1.0/", "API Executor Documentation")
    assert "<!doctype html>" in redirect_html.lower()
    assert "API Executor Documentation" in redirect_html
    assert 'http-equiv="refresh"' in redirect_html.lower()
    assert "/v2.1.0/" in redirect_html


def test_build_versioned_docs_end_to_end_worktree_v210_and_v200(tmp_path: Path) -> None:
    """End-to-end build of WORKTREE + v2.1.0 + v2.0.0 asserting manifest, redirects, assets, and zero leaks."""
    if importlib.util.find_spec("mkdocs") is None:
        pytest.skip("mkdocs optional extra not installed in current test environment")
    if not (REPO_ROOT / ".git").exists() or shutil.which("git") is None:
        pytest.skip("Git repository metadata required for multi-version tag build test")

    tag_probe = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "tag", "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    available_tags = set(tag_probe.stdout.splitlines())
    if tag_probe.returncode != 0 or not {"v2.1.0", "v2.0.0"}.issubset(available_tags):
        pytest.skip("Tags v2.1.0 and v2.0.0 not both available in local Git clone")

    out_dir = tmp_path / "site_dist"
    proc = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT_PATH),
            "--output",
            str(out_dir),
            "--base-url",
            "https://api-executor.lightpath.fr",
            "--main-ref",
            "WORKTREE",
            "--tags",
            "v2.1.0",
            "v2.0.0",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"build_versioned_docs.py failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"

    expected_files = [
        out_dir / "versions.json",
        out_dir / "index.html",
        out_dir / ".htaccess",
        out_dir / "latest" / "index.html",
        out_dir / "dev" / "index.html",
        out_dir / "main" / "index.html",
        out_dir / "main" / "stylesheets" / "extra.css",
        out_dir / "main" / "javascripts" / "katex.js",
        out_dir / "v2.1.0" / "index.html",
        out_dir / "v2.0.0" / "index.html",
    ]
    for path in expected_files:
        assert path.is_file(), f"Expected built artifact missing: {path}"

    manifest = json.loads((out_dir / "versions.json").read_text(encoding="utf-8"))
    assert isinstance(manifest, list)
    versions_order = [entry["version"] for entry in manifest]
    assert versions_order.index("v2.1.0") < versions_order.index("v2.0.0")

    by_version = {entry["version"]: entry for entry in manifest}
    assert "v2.1.0" in by_version
    assert "v2.0.0" in by_version
    assert "latest" in by_version["v2.1.0"]["aliases"]
    assert "latest" not in by_version["v2.0.0"]["aliases"]
    assert "main" in by_version
    assert "dev" in by_version["main"]["aliases"]

    htaccess_text = (out_dir / ".htaccess").read_text(encoding="utf-8")
    assert "/v2.1.0/$1" in htaccess_text
    assert "/main/$1" in htaccess_text

    leaked_sensitive = [
        p.relative_to(out_dir).as_posix()
        for p in out_dir.rglob("*")
        if p.is_file()
        and (
            p.suffix.lower() in {".go", ".kdbx", ".keyx", ".db", ".sqlite", ".sqlite3", ".log", ".key", ".exe"}
            or p.name.lower().endswith(".fr.md")
            or p.name.lower() == ".env"
            or p.name.lower().startswith(".env.")
        )
    ]
    assert not leaked_sensitive, f"Sensitive or source files leaked into built output: {leaked_sensitive}"


# ==============================================================================
# 4. .github/workflows/docs-publish.yml Security & Deployment Tests
# ==============================================================================


def test_docs_publish_workflow_triggers_permissions_build_and_sftp_deploy() -> None:
    """Verify docs-publish.yml triggers, SHA pinning, least-privilege permissions, artifact flags, and SFTP steps."""
    assert WORKFLOW_PATH.is_file(), ".github/workflows/docs-publish.yml must exist"
    raw_yaml = WORKFLOW_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_yaml)
    assert isinstance(data, dict)

    assert data.get("permissions") == {"contents": "read"}

    triggers = data.get("on") if "on" in data else data.get(True)
    assert isinstance(triggers, dict)
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["pull_request"]["branches"] == ["main"]
    assert triggers["push"]["paths"] == triggers["pull_request"]["paths"]
    for required_path in (
        "docs/**",
        "mkdocs.yml",
        "README.md",
        "SECURITY.md",
        "PROJECT.md",
        "requirements-docs.txt",
        ".vale.ini",
        ".markdownlint.json",
        "scripts/mkdocs_hooks.py",
        "scripts/build_versioned_docs.py",
        ".github/workflows/docs-ci.yml",
        ".github/workflows/docs-publish.yml",
        "tests/test_diataxis_documentation.py",
        "tests/test_mkdocs_publishing.py",
    ):
        assert required_path in triggers["push"]["paths"]

    assert triggers["release"] == {"types": ["published"]}
    deploy_input = triggers["workflow_dispatch"]["inputs"]["deploy"]
    assert deploy_input["type"] == "boolean"
    assert deploy_input["default"] is True

    concurrency = data.get("concurrency", {})
    assert "docs-publish-" in str(concurrency.get("group", ""))
    assert "github.ref" in str(concurrency.get("group", ""))
    assert "pull_request" in str(concurrency.get("cancel-in-progress", ""))

    jobs = data.get("jobs", {})
    assert "verify-and-build" in jobs
    assert "deploy-ionos" in jobs

    # Global supply-chain & injection checks across every job and step
    for job_name, job_cfg in jobs.items():
        if isinstance(job_cfg.get("if"), str):
            assert "secrets." not in job_cfg["if"], f"{job_name}.if must not reference secrets."
        for idx, step in enumerate(_collect_workflow_steps(job_cfg)):
            uses_val = step.get("uses")
            if isinstance(uses_val, str):
                assert "@" in uses_val, f"{job_name} step #{idx} must pin action to SHA: {uses_val}"
                sha = uses_val.split("@", 1)[1]
                assert SHA40_RE.fullmatch(sha), (
                    f"{job_name} step #{idx} must use 40-char SHA, got '{uses_val}'"
                )
            if_val = step.get("if")
            if isinstance(if_val, str):
                assert "secrets." not in if_val, f"{job_name} step #{idx} must not use secrets. in if:"
            run_val = step.get("run")
            if isinstance(run_val, str):
                assert "${{" not in run_val, (
                    f"{job_name} step #{idx} must pass GitHub expressions via env:, never ${{ in run:"
                )

    # Job 1: verify-and-build
    build_job = jobs["verify-and-build"]
    assert build_job.get("runs-on") == "ubuntu-latest"
    assert isinstance(build_job.get("timeout-minutes"), int) and build_job["timeout-minutes"] <= 15

    build_steps = _collect_workflow_steps(build_job)
    checkout_steps = [s for s in build_steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkout_steps) == 1
    assert checkout_steps[0].get("with", {}).get("fetch-depth") == 0

    python_steps = [s for s in build_steps if str(s.get("uses", "")).startswith("actions/setup-python@")]
    assert len(python_steps) == 1
    python_with = python_steps[0].get("with", {})
    assert python_with.get("python-version") == "3.12"
    assert python_with.get("cache") == "pip"
    assert python_with.get("cache-dependency-path") == "requirements-docs.txt"

    build_run_script = "\n".join(str(s.get("run", "")) for s in build_steps)
    assert "requirements-docs.txt" in build_run_script
    assert "tests/test_diataxis_documentation.py" in build_run_script
    assert "tests/test_mkdocs_publishing.py" in build_run_script
    assert "scripts/build_versioned_docs.py" in build_run_script
    assert "https://api-executor.lightpath.fr" in build_run_script
    assert "origin/main" in build_run_script
    assert "WORKTREE" in build_run_script
    assert "site_dist/versions.json" in build_run_script
    assert "site_dist/.htaccess" in build_run_script

    upload_steps = [s for s in build_steps if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(upload_steps) == 1
    upload_with = upload_steps[0].get("with", {})
    assert upload_with.get("name") == "mkdocs-site-dist"
    assert upload_with.get("path") == "site_dist/"
    assert upload_with.get("include-hidden-files") is True
    assert upload_with.get("retention-days") == 7

    # Job 2: deploy-ionos
    deploy_job = jobs["deploy-ionos"]
    assert deploy_job.get("needs") == "verify-and-build"
    assert deploy_job.get("runs-on") == "ubuntu-latest"
    assert isinstance(deploy_job.get("timeout-minutes"), int) and deploy_job["timeout-minutes"] <= 15

    deploy_if = str(deploy_job.get("if", ""))
    assert "github.event_name == 'release'" in deploy_if
    assert "refs/heads/main" in deploy_if
    assert "inputs.deploy == true" in deploy_if

    deploy_steps = _collect_workflow_steps(deploy_job)
    assert not any("actions/checkout" in str(s.get("uses", "")) for s in deploy_steps)

    download_steps = [s for s in deploy_steps if str(s.get("uses", "")).startswith("actions/download-artifact@")]
    assert len(download_steps) == 1
    assert download_steps[0].get("with", {}).get("name") == "mkdocs-site-dist"
    assert download_steps[0].get("with", {}).get("path") == "."

    sftp_steps = [s for s in deploy_steps if str(s.get("uses", "")).startswith("wlixcc/SFTP-Deploy-Action@")]
    assert len(sftp_steps) == 2, "Expected site upload step plus explicit .htaccess upload step"

    local_paths = [step.get("with", {}).get("local_path") for step in sftp_steps]
    assert "./" in local_paths
    assert ".htaccess" in local_paths

    for step in sftp_steps:
        step_with = step.get("with", {})
        assert step_with.get("sftp_only") is True
        assert step_with.get("server") == "${{ secrets.IONOS_FTP_SERVER }}"
        assert step_with.get("username") == "${{ secrets.IONOS_FTP_USERNAME }}"
        assert step_with.get("password") == "${{ secrets.IONOS_FTP_PASSWORD }}"
        assert step_with.get("port") == "${{ secrets.IONOS_FTP_PORT || '22' }}"
        assert step_with.get("remote_path") == "${{ secrets.IONOS_REMOTE_PATH }}/"

    deploy_run_script = "\n".join(str(s.get("run", "")) for s in deploy_steps)
    assert ".htaccess" in deploy_run_script
    assert "versions.json" in deploy_run_script
    assert "https://api-executor.lightpath.fr/versions.json" in deploy_run_script
    assert "https://api-executor.lightpath.fr/latest/" in deploy_run_script
    assert "https://api-executor.lightpath.fr/main/" in deploy_run_script

    for unsafe_pattern in (
        "chmod 777",
        "chmod -R 777",
        "chmod a+rwx",
        "sudo",
        "eval ",
        "curl -s | bash",
        "wget -O- | sh",
    ):
        assert unsafe_pattern not in raw_yaml, f"Unsafe shell pattern found in workflow: {unsafe_pattern}"


# ==============================================================================
# 5. Requirements, .gitignore, and Portal Link Consistency
# ==============================================================================


def test_gitignore_and_requirements_docs_configuration() -> None:
    """Verify .gitignore excludes site outputs/caches and requirements-docs.txt pins MkDocs Material."""
    gitignore_lines = {
        line.strip()
        for line in GITIGNORE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    for entry in ("site/", "site_dist/", ".pytest_cache/", "__pycache__/", "*.pyc"):
        assert entry in gitignore_lines, f".gitignore must exclude '{entry}'"

    assert REQUIREMENTS_DOCS_PATH.is_file(), "requirements-docs.txt must exist"
    reqs = REQUIREMENTS_DOCS_PATH.read_text(encoding="utf-8")
    assert "mkdocs>=" in reqs
    assert "mkdocs-material>=" in reqs
    assert "pymdown-extensions>=" in reqs

    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "https://api-executor.lightpath.fr" in readme_text
