"""Build a multi-version MkDocs Material site bundle for IONOS Apache hosting."""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import zipfile

_SEMVER_TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9._/\-]+$")
_PRIVATE_OUTPUT_RE = re.compile(
    r"(?i)(?:(?:^|/)\.env[^/]*$|\.(?:kdbx|keyx|go|db|sqlite[^/]*|log|key|exe|fr\.md)$)"
)

ALWAYS_OVERLAY_FILES: tuple[str, ...] = (
    "mkdocs.yml",
    "scripts/mkdocs_hooks.py",
    "docs/stylesheets/extra.css",
    "docs/javascripts/katex.js",
)

FALLBACK_OVERLAY_FILES: tuple[str, ...] = (
    "docs/index.md",
    "docs/assets/logo.svg",
    "docs/assets/header-banner.svg",
)


def parse_semver_tag(tag: str) -> tuple[int, int, int] | None:
    """Parse a semantic version Git tag such as `v2.1.0` into `(major, minor, patch)`."""
    match = _SEMVER_TAG_RE.fullmatch(tag.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _sort_tags_descending(tags: list[str]) -> list[str]:
    """Sort unique tags newest-first by numeric semver, placing non-semver tags last."""
    unique_tags = list(dict.fromkeys(t.strip() for t in tags if t.strip()))

    def _sort_key(tag: str) -> tuple[int, tuple[int, int, int], str]:
        parsed = parse_semver_tag(tag)
        if parsed is not None:
            return (1, parsed, tag)
        return (0, (0, 0, 0), tag)

    return sorted(unique_tags, key=_sort_key, reverse=True)


def discover_release_tags(repo_root: Path) -> list[str]:
    """Discover semantic-version Git release tags sorted newest-first."""
    proc = subprocess.run(  # nosec B603, B607
        ["git", "-C", str(repo_root), "tag", "--list"],
        capture_output=True,
        text=True,
        check=True,
    )
    semver_tags = [
        line.strip()
        for line in proc.stdout.splitlines()
        if parse_semver_tag(line.strip()) is not None
    ]
    return _sort_tags_descending(semver_tags)


def build_versions_manifest(
    release_tags: list[str],
    include_main: bool = True,
) -> list[dict[str, object]]:
    """Build Material (`provider: mike`) `versions.json` entries ordered newest-first."""
    sorted_tags = _sort_tags_descending(release_tags)
    entries: list[dict[str, object]] = []

    for idx, tag in enumerate(sorted_tags):
        aliases = ["latest"] if idx == 0 else []
        entries.append(
            {
                "version": tag,
                "title": tag,
                "aliases": aliases,
            }
        )

    if include_main:
        main_aliases = ["dev"] if sorted_tags else ["latest", "dev"]
        entries.append(
            {
                "version": "main",
                "title": "main (dev)",
                "aliases": main_aliases,
            }
        )

    return entries


def render_redirect_html(
    target_url: str,
    title: str = "API Executor Documentation",
) -> str:
    """Render a minimal HTML redirect fallback page for static hosting."""
    escaped_target = html.escape(target_url, quote=True)
    escaped_title = html.escape(title, quote=True)
    js_target = json.dumps(target_url)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        f"  <title>{escaped_title}</title>\n"
        f'  <meta http-equiv="refresh" content="0; url={escaped_target}">\n'
        f'  <link rel="canonical" href="{escaped_target}">\n'
        f"  <script>window.location.replace({js_target});</script>\n"
        "</head>\n"
        "<body>\n"
        f'  <p>Redirecting to <a href="{escaped_target}">{escaped_target}</a>...</p>\n'
        "</body>\n"
        "</html>\n"
    )


def render_htaccess(latest_version: str, main_version: str = "main") -> str:
    """Render Apache `.htaccess` for IONOS with HTTPS enforcement, security headers, and version redirects."""
    clean_latest = latest_version.strip("/")
    clean_main = main_version.strip("/")
    return f"""# API Executor Versioned Documentation Apache Configuration (IONOS)
Options -Indexes -MultiViews
DirectoryIndex index.html
ErrorDocument 404 /{clean_latest}/404.html

<IfModule mod_deflate.c>
  AddOutputFilterByType DEFLATE text/html text/plain text/css text/xml
  AddOutputFilterByType DEFLATE application/javascript application/json image/svg+xml
</IfModule>

<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
  Header always set X-Frame-Options "SAMEORIGIN"
  <FilesMatch "versions\\.json$">
    Header set Cache-Control "public, max-age=300, must-revalidate"
  </FilesMatch>
</IfModule>

<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteBase /

  # Enforce HTTPS
  RewriteCond %{{HTTPS}} !=on
  RewriteCond %{{HTTP:X-Forwarded-Proto}} !https [NC]
  RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [R=301,L]

  # Redirect site root to the latest release
  RewriteRule ^$ /{clean_latest}/ [R=302,L]

  # Subpath-preserving version alias redirects
  RewriteRule ^latest(?:/(.*))?$ /{clean_latest}/$1 [R=302,L]
  RewriteRule ^dev(?:/(.*))?$ /{clean_main}/$1 [R=302,L]
</IfModule>
"""


def _validate_git_ref(git_ref: str) -> str:
    """Validate that a Git ref string cannot be interpreted as a CLI flag."""
    cleaned = git_ref.strip()
    if not cleaned or cleaned.startswith("-") or not _SAFE_REF_RE.fullmatch(cleaned):
        raise ValueError(f"Invalid git ref: {git_ref!r}")
    return cleaned


def _safe_extract_zip(archive_path: Path, dest_dir: Path) -> None:
    """Extract a ZIP archive into `dest_dir` while preventing path traversal."""
    resolved_root = dest_dir.resolve()
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            member_path = (resolved_root / info.filename).resolve()
            if not member_path.is_relative_to(resolved_root):
                raise ValueError(f"Unsafe archive member path detected: {info.filename!r}")
            if info.is_dir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue
            member_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src_file, open(member_path, "wb") as dst_file:
                shutil.copyfileobj(src_file, dst_file)


def _overlay_repo_files(repo_root: Path, snapshot_dir: Path) -> None:
    """Overlay current MkDocs config, hooks, theme assets, and missing fallback files."""
    for rel_path in ALWAYS_OVERLAY_FILES:
        src = repo_root / rel_path
        if src.is_file():
            dst = snapshot_dir / rel_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    for rel_path in FALLBACK_OVERLAY_FILES:
        src = repo_root / rel_path
        dst = snapshot_dir / rel_path
        if src.is_file() and not dst.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def assert_no_private_files(output_dir: Path) -> None:
    """Verify that zero vault, runtime DB/key/log, Go/EXE binary, French article, or `.env*` files exist in `output_dir`."""
    offenders: list[str] = []
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(output_dir).as_posix()
        if _PRIVATE_OUTPUT_RE.search(rel):
            offenders.append(rel)
    if offenders:
        raise RuntimeError(
            f"Privacy violation in built documentation output ({output_dir}): {offenders}"
        )


def _run_mkdocs_build(
    project_dir: Path,
    site_output_dir: Path,
    git_ref: str,
    version_slug: str,
    base_url: str,
    strict: bool,
) -> None:
    """Invoke `python -m mkdocs build` for one version directory."""
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["API_EXECUTOR_DOCS_REF"] = (
        "main" if git_ref in {"WORKTREE", "origin/main", "main", "HEAD"} else git_ref
    )
    env["API_EXECUTOR_DOCS_SITE_URL"] = f"{base_url.rstrip('/')}/{version_slug}/"

    cmd = [
        sys.executable,
        "-m",
        "mkdocs",
        "build",
        "-f",
        str(project_dir / "mkdocs.yml"),
        "-d",
        str(site_output_dir),
    ]
    if strict:
        cmd.append("--strict")

    subprocess.run(cmd, cwd=str(project_dir), env=env, check=True)  # nosec B603


def build_single_version(
    repo_root: Path,
    git_ref: str,
    version_slug: str,
    output_dir: Path,
    base_url: str,
    strict: bool = True,
) -> Path:
    """Build a single documentation version (`WORKTREE` or Git archive snapshot)."""
    validated_ref = _validate_git_ref(git_ref)
    version_output_dir = output_dir / version_slug
    version_output_dir.parent.mkdir(parents=True, exist_ok=True)

    if validated_ref == "WORKTREE":
        _run_mkdocs_build(
            project_dir=repo_root,
            site_output_dir=version_output_dir,
            git_ref=validated_ref,
            version_slug=version_slug,
            base_url=base_url,
            strict=strict,
        )
    else:
        with tempfile.TemporaryDirectory(prefix=f"api-executor-docs-{version_slug}-") as tmp:
            tmp_path = Path(tmp)
            archive_path = tmp_path / "snapshot.zip"
            snapshot_dir = tmp_path / "src"
            snapshot_dir.mkdir(parents=True, exist_ok=True)

            subprocess.run(  # nosec B603, B607
                [
                    "git",
                    "-C",
                    str(repo_root),
                    "archive",
                    "--format=zip",
                    "-o",
                    str(archive_path),
                    validated_ref,
                ],
                check=True,
            )
            _safe_extract_zip(archive_path, snapshot_dir)
            _overlay_repo_files(repo_root=repo_root, snapshot_dir=snapshot_dir)
            _run_mkdocs_build(
                project_dir=snapshot_dir,
                site_output_dir=version_output_dir,
                git_ref=validated_ref,
                version_slug=version_slug,
                base_url=base_url,
                strict=strict,
            )

    assert_no_private_files(version_output_dir)
    return version_output_dir


def build_versioned_site(
    repo_root: Path,
    output_dir: Path,
    base_url: str = "https://api-executor.lightpath.fr",
    main_ref: str = "WORKTREE",
    tags: list[str] | None = None,
    skip_tags: bool = False,
    strict: bool = True,
) -> dict[str, object]:
    """Build the complete multi-version site bundle with redirects, `.htaccess`, and `versions.json`."""
    resolved_repo = repo_root.resolve()
    resolved_out = output_dir.resolve()
    protected_roots = {
        resolved_repo / name
        for name in (
            ".git",
            ".github",
            "cmd",
            "internal",
            "configs",
            "docker",
            "docs",
            "plugins",
            "scripts",
            "tests",
            "web",
            ".agents",
        )
    }
    if (
        resolved_out == resolved_repo
        or resolved_repo.is_relative_to(resolved_out)
        or any(
            resolved_out == protected or resolved_out.is_relative_to(protected)
            for protected in protected_roots
        )
    ):
        raise ValueError(
            f"Output directory must not overwrite repository or protected paths: {resolved_out}"
        )

    if resolved_out.exists():
        shutil.rmtree(resolved_out)
    resolved_out.mkdir(parents=True, exist_ok=True)

    if skip_tags:
        release_tags: list[str] = []
    elif tags is not None:
        release_tags = _sort_tags_descending(tags)
    else:
        release_tags = discover_release_tags(resolved_repo)

    versions_manifest = build_versions_manifest(release_tags, include_main=True)
    (resolved_out / "versions.json").write_text(
        json.dumps(versions_manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    build_single_version(
        repo_root=resolved_repo,
        git_ref=main_ref,
        version_slug="main",
        output_dir=resolved_out,
        base_url=base_url,
        strict=strict,
    )

    for tag in release_tags:
        build_single_version(
            repo_root=resolved_repo,
            git_ref=tag,
            version_slug=tag,
            output_dir=resolved_out,
            base_url=base_url,
            strict=strict,
        )

    latest_version = release_tags[0] if release_tags else "main"
    (resolved_out / ".htaccess").write_text(
        render_htaccess(latest_version=latest_version, main_version="main"),
        encoding="utf-8",
    )
    (resolved_out / "index.html").write_text(
        render_redirect_html(f"./{latest_version}/", "API Executor Documentation"),
        encoding="utf-8",
    )

    latest_dir = resolved_out / "latest"
    latest_dir.mkdir(parents=True, exist_ok=True)
    (latest_dir / "index.html").write_text(
        render_redirect_html(
            f"../{latest_version}/",
            f"API Executor Documentation ({latest_version})",
        ),
        encoding="utf-8",
    )

    dev_dir = resolved_out / "dev"
    dev_dir.mkdir(parents=True, exist_ok=True)
    (dev_dir / "index.html").write_text(
        render_redirect_html("../main/", "API Executor Documentation (main / dev)"),
        encoding="utf-8",
    )

    assert_no_private_files(resolved_out)
    return {
        "output_dir": str(resolved_out),
        "latest_version": latest_version,
        "versions": [entry["version"] for entry in versions_manifest],
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for building the versioned documentation bundle."""
    parser = argparse.ArgumentParser(
        description="Build versioned API Executor MkDocs Material documentation for IONOS hosting."
    )
    parser.add_argument(
        "--output",
        default="site_dist",
        help="Target output directory (default: site_dist).",
    )
    parser.add_argument(
        "--base-url",
        default="https://api-executor.lightpath.fr",
        help="Base public documentation URL (default: https://api-executor.lightpath.fr).",
    )
    parser.add_argument(
        "--main-ref",
        default="WORKTREE",
        help="Git ref to build for /main/ (default: WORKTREE; use origin/main on release CI).",
    )
    parser.add_argument(
        "--tags",
        nargs="*",
        default=None,
        help="Explicit release tags to build (space- or comma-separated). Defaults to all semver Git tags.",
    )
    parser.add_argument(
        "--skip-tags",
        action="store_true",
        help="Skip building historical release tags and only build /main/.",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="Disable MkDocs --strict link and navigation validation.",
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for versioned MkDocs Material site generation."""
    args = _parse_args(argv)
    explicit_tags: list[str] | None = None
    if args.tags is not None:
        explicit_tags = [
            item.strip()
            for raw in args.tags
            for item in raw.split(",")
            if item.strip()
        ]

    summary = build_versioned_site(
        repo_root=Path(args.repo_root),
        output_dir=Path(args.output),
        base_url=args.base_url,
        main_ref=args.main_ref,
        tags=explicit_tags,
        skip_tags=args.skip_tags,
        strict=not args.no_strict,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
