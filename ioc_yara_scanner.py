#!/usr/bin/env python3
"""
ioc_yara_scanner.py

Windows-compatible defensive scanner:
  - YARA rules
  - SHA-256 IOC/hash feeds
  - Feed update cache
  - SQLite IOC DB
  - CLI scan/watch modes
  - JSONL audit output

Default behavior is report-only. It does not delete, disinfect, upload, or
download malware samples.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import math
import os
import re
import shutil
import sqlite3
import sys
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

"""
1. scan_extensions empty means scan all files. Do not restrict extensions if you want packed binaries scanned.
2. Packed executable policy:
            "annotate"   = report packed signal, do not alter verdict
            "suspicious" = mark likely-packed PE files as suspicious
            "ignore"     = disable packed-binary verdict logic
"""
DEFAULT_CONFIG: dict[str, Any] = {
    "schema": 1,
    "data_dir": "%LOCALAPPDATA%\\PyIOCScanner",
    "user_agent": "pyioc-scanner/0.1 defensive-research",
    "scan": {
        "max_file_mb": 5124,
        "yara_timeout_sec": 300,
        "hash_chunk_mb": 16,
        
        "scan_extensions": [],

        "packed_binary_policy": "suspicious",

        "inspect_pe_sections": True,
        "packed_entropy_threshold": 7.2,
        "packed_min_section_bytes": 4096,
        "packed_min_high_entropy_sections": 1,

        "exclude_globs": [
            "*\\System Volume Information\\*",
            "*\\$Recycle.Bin\\*",
            "*\\Windows\\WinSxS\\*",
            "*\\Windows\\SoftwareDistribution\\Download\\*",
            "*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*",
        ],
    },
    "yara": {
        "enabled": True,
        "max_match_data": 128,
        "stack_size": 65536,
        "externals": {
            "filename": "",
            "filepath": "",
            "extension": "",
            "filetype": "",
            "md5": "",
            "sha1": "",
            "sha256": "",
            "owner": "",
            "package": "",
            "description": "",
            "product": "",
            "company": "",
        },
    },
    "yara_feeds": [
        {
            "name": "neo23x0_signature_base",
            "enabled": True,
            "type": "github_zip",
            "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
            "include_globs": ["*/yara/*.yar", "*/yara/*.yara"],
            "exclude_globs": [
                "*/yara/deprecated/*",
                "*/yara/external-variable-rules.txt",
            ],
            "min_update_seconds": 3600,
        },
        {
            "name": "yara_rules_community",
            "enabled": False,
            "type": "github_zip",
            "url": "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
            "include_globs": ["*/*.yar", "*/*.yara"],
            "exclude_globs": ["*/deprecated/*", "*/index.yar"],
            "min_update_seconds": 3600,
        },
    ],
    "hash_feeds": [
        {
            "name": "local_sha256",
            "enabled": True,
            "type": "local_file",
            "path": "feeds\\hashes\\local_sha256.txt",
            "format": "regex_sha256",
        },
        {
            "name": "malwarebazaar_recent_sha256",
            "enabled": False,
            "type": "http",
            "url": "https://mb-api.abuse.ch/v2/files/exports/{MALWAREBAZAAR_AUTH_KEY}/recent.txt",
            "format": "regex_sha256",
            "min_update_seconds": 300,
        },
    ],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)


def expand_env_tokens(value: str) -> str:
    """
    Expands:
      - Windows vars: %LOCALAPPDATA%
      - Braced env placeholders: {MALWAREBAZAAR_AUTH_KEY}
    """
    value = os.path.expandvars(value)

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        return os.environ.get(key, "")

    return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", repl, value)


def create_default_config(config_path: Path, overwrite: bool = False) -> None:
    if config_path.exists() and not overwrite:
        print(f"Config already exists: {config_path}")
        return

    write_json(config_path, DEFAULT_CONFIG)

    config = load_json(config_path)
    data_dir = resolve_data_dir(config, config_path)
    local_hash_file = data_dir / "feeds" / "hashes" / "local_sha256.txt"
    local_hash_file.parent.mkdir(parents=True, exist_ok=True)

    if not local_hash_file.exists():
        local_hash_file.write_text(
            "# Add known-malicious SHA-256 hashes here, one per line.\n",
            encoding="utf-8",
        )

    print(f"Wrote config: {config_path}")
    print(f"Data directory: {data_dir}")


def resolve_data_dir(config: dict[str, Any], config_path: Path) -> Path:
    raw = expand_env_tokens(str(config.get("data_dir", "%LOCALAPPDATA%\\PyIOCScanner")))
    data_dir = Path(raw)

    if not data_dir.is_absolute():
        data_dir = config_path.parent / data_dir

    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_state_path(data_dir: Path) -> Path:
    return data_dir / "state.json"


def load_state(data_dir: Path) -> dict[str, Any]:
    path = get_state_path(data_dir)
    if not path.exists():
        return {"feeds": {}}
    try:
        return load_json(path)
    except Exception:
        return {"feeds": {}}


def save_state(data_dir: Path, state: dict[str, Any]) -> None:
    write_json(get_state_path(data_dir), state)


def should_skip_update(
    state: dict[str, Any],
    feed_name: str,
    min_update_seconds: int,
    force: bool,
) -> bool:
    if force:
        return False

    feed_state = state.get("feeds", {}).get(feed_name, {})
    last_epoch = feed_state.get("last_update_epoch")

    if not isinstance(last_epoch, (int, float)):
        return False

    return (time.time() - last_epoch) < min_update_seconds


def mark_feed_updated(
    state: dict[str, Any],
    feed_name: str,
    *,
    ok: bool,
    detail: str,
) -> None:
    state.setdefault("feeds", {})[feed_name] = {
        "last_update_epoch": time.time(),
        "last_update_utc": utc_now(),
        "ok": ok,
        "detail": detail,
    }


def http_get_bytes(url: str, user_agent: str, timeout: int = 90) -> bytes:
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError("Missing dependency: pip install requests") from exc

    response = requests.get(
        url,
        headers={"User-Agent": user_agent},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.content


def glob_any(path_text: str, patterns: Iterable[str]) -> bool:
    normalized = path_text.replace("/", "\\")
    alt = path_text.replace("\\", "/")

    for pattern in patterns:
        if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(alt, pattern):
            return True

    return False


def safe_extract_zip_member(zf: zipfile.ZipFile, member: zipfile.ZipInfo, dest: Path) -> Path:
    raw_name = member.filename.replace("\\", "/")
    parts = [p for p in raw_name.split("/") if p not in ("", ".", "..")]

    if not parts:
        raise ValueError(f"Unsafe ZIP member: {member.filename}")

    # Drop the top-level GitHub repo directory.
    rel_parts = parts[1:] if len(parts) > 1 else parts
    target = dest.joinpath(*rel_parts).resolve()

    dest_resolved = dest.resolve()

    if not str(target).lower().startswith(str(dest_resolved).lower()):
        raise ValueError(f"Blocked ZIP path traversal: {member.filename}")

    target.parent.mkdir(parents=True, exist_ok=True)

    with zf.open(member, "r") as src, target.open("wb") as out:
        shutil.copyfileobj(src, out)

    return target


def update_yara_feed(
    feed: dict[str, Any],
    config: dict[str, Any],
    data_dir: Path,
    state: dict[str, Any],
    force: bool,
) -> dict[str, Any]:
    name = str(feed["name"])
    min_update_seconds = int(feed.get("min_update_seconds", 3600))

    if should_skip_update(state, name, min_update_seconds, force):
        return {"name": name, "status": "skipped_recent"}

    url = expand_env_tokens(str(feed["url"]))

    if "{}" in url or "{MALWARE" in url or url.endswith("/recent.txt") and "//recent" in url:
        mark_feed_updated(state, name, ok=False, detail="missing environment token")
        return {"name": name, "status": "error", "error": "missing environment token"}

    include_globs = list(feed.get("include_globs", ["*.yar", "*.yara"]))
    exclude_globs = list(feed.get("exclude_globs", []))

    feed_dir = data_dir / "feeds" / "yara" / name
    tmp_dir = data_dir / "feeds" / "yara" / f".{name}.tmp"

    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    user_agent = str(config.get("user_agent", DEFAULT_CONFIG["user_agent"]))

    content = http_get_bytes(url, user_agent=user_agent)

    extracted = 0

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue

                member_name = member.filename.replace("\\", "/")

                if not glob_any(member_name, include_globs):
                    continue

                if exclude_globs and glob_any(member_name, exclude_globs):
                    continue

                suffix = Path(member_name).suffix.lower()
                if suffix not in {".yar", ".yara"}:
                    continue

                safe_extract_zip_member(zf, member, tmp_dir)
                extracted += 1
    except zipfile.BadZipFile as exc:
        mark_feed_updated(state, name, ok=False, detail="bad zip")
        return {"name": name, "status": "error", "error": f"bad zip: {exc}"}

    if feed_dir.exists():
        shutil.rmtree(feed_dir)

    tmp_dir.rename(feed_dir)

    detail = f"extracted {extracted} YARA files"
    mark_feed_updated(state, name, ok=True, detail=detail)

    return {"name": name, "status": "updated", "files": extracted}


def parse_sha256_text(text: str) -> list[tuple[str, str]]:
    """
    Returns [(sha256, source_line_excerpt), ...].
    Accepts plain text or CSV-like content. Any SHA-256 token is extracted.
    """
    rows: list[tuple[str, str]] = []

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        match = SHA256_RE.search(stripped)
        if match:
            rows.append((match.group(0).lower(), stripped[:512]))

    return rows


class HashDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.init_schema()

    def close(self) -> None:
        self.conn.close()

    def init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_hashes (
                sha256 TEXT NOT NULL,
                source TEXT NOT NULL,
                meta TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (sha256, source)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ioc_hashes_sha256 ON ioc_hashes(sha256)"
        )
        self.conn.commit()

    def upsert_many(self, source: str, rows: list[tuple[str, str]]) -> int:
        now = utc_now()

        with self.conn:
            self.conn.executemany(
                """
                INSERT INTO ioc_hashes (sha256, source, meta, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sha256, source) DO UPDATE SET
                    meta=excluded.meta,
                    updated_at=excluded.updated_at
                """,
                [(sha256, source, meta, now) for sha256, meta in rows],
            )

        return len(rows)

    def lookup(self, sha256: str) -> list[dict[str, str]]:
        cur = self.conn.execute(
            """
            SELECT sha256, source, meta, updated_at
            FROM ioc_hashes
            WHERE sha256 = ?
            ORDER BY source
            """,
            (sha256.lower(),),
        )

        return [
            {
                "sha256": row[0],
                "source": row[1],
                "meta": row[2],
                "updated_at": row[3],
            }
            for row in cur.fetchall()
        ]

    def count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM ioc_hashes")
        return int(cur.fetchone()[0])


def update_hash_feed(
    feed: dict[str, Any],
    config: dict[str, Any],
    data_dir: Path,
    state: dict[str, Any],
    db: HashDB,
    force: bool,
) -> dict[str, Any]:
    name = str(feed["name"])
    feed_type = str(feed.get("type", "http"))
    min_update_seconds = int(feed.get("min_update_seconds", 3600))

    if should_skip_update(state, name, min_update_seconds, force):
        return {"name": name, "status": "skipped_recent"}

    text: str

    if feed_type == "local_file":
        raw_path = expand_env_tokens(str(feed["path"]))
        path = Path(raw_path)

        if not path.is_absolute():
            path = data_dir / path

        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.exists():
            path.write_text(
                "# Add known-malicious SHA-256 hashes here, one per line.\n",
                encoding="utf-8",
            )

        text = path.read_text(encoding="utf-8", errors="replace")

    elif feed_type == "http":
        url = expand_env_tokens(str(feed["url"]))

        if re.search(r"\{[A-Za-z_][A-Za-z0-9_]*\}", str(feed["url"])) and "{" not in url:
            pass

        if not url or "{}" in url or re.search(r"/\s*/", url):
            mark_feed_updated(state, name, ok=False, detail="missing URL or env token")
            return {"name": name, "status": "error", "error": "missing URL or env token"}

        if "{MALWAREBAZAAR_AUTH_KEY}" in str(feed["url"]) and not os.environ.get("MALWAREBAZAAR_AUTH_KEY"):
            mark_feed_updated(state, name, ok=False, detail="MALWAREBAZAAR_AUTH_KEY is not set")
            return {
                "name": name,
                "status": "error",
                "error": "MALWAREBAZAAR_AUTH_KEY is not set",
            }

        user_agent = str(config.get("user_agent", DEFAULT_CONFIG["user_agent"]))
        raw = http_get_bytes(url, user_agent=user_agent)
        text = raw.decode("utf-8", errors="replace")

    else:
        mark_feed_updated(state, name, ok=False, detail=f"unknown feed type: {feed_type}")
        return {"name": name, "status": "error", "error": f"unknown feed type: {feed_type}"}

    rows = parse_sha256_text(text)
    inserted = db.upsert_many(name, rows)

    detail = f"loaded {inserted} SHA-256 indicators"
    mark_feed_updated(state, name, ok=True, detail=detail)

    return {"name": name, "status": "updated", "hashes": inserted}


def update_all_feeds(config_path: Path, force: bool = False) -> dict[str, Any]:
    config = load_or_create_config(config_path)
    data_dir = resolve_data_dir(config, config_path)
    state = load_state(data_dir)

    db = HashDB(data_dir / "ioc_hashes.sqlite3")

    results: dict[str, Any] = {
        "time_utc": utc_now(),
        "data_dir": str(data_dir),
        "yara_feeds": [],
        "hash_feeds": [],
    }

    try:
        for feed in config.get("yara_feeds", []):
            if not feed.get("enabled", False):
                results["yara_feeds"].append(
                    {"name": feed.get("name", "unnamed"), "status": "disabled"}
                )
                continue

            try:
                results["yara_feeds"].append(
                    update_yara_feed(feed, config, data_dir, state, force)
                )
            except Exception as exc:
                name = str(feed.get("name", "unnamed"))
                mark_feed_updated(state, name, ok=False, detail=str(exc))
                results["yara_feeds"].append(
                    {"name": name, "status": "error", "error": str(exc)}
                )

        for feed in config.get("hash_feeds", []):
            if not feed.get("enabled", False):
                results["hash_feeds"].append(
                    {"name": feed.get("name", "unnamed"), "status": "disabled"}
                )
                continue

            try:
                results["hash_feeds"].append(
                    update_hash_feed(feed, config, data_dir, state, db, force)
                )
            except Exception as exc:
                name = str(feed.get("name", "unnamed"))
                mark_feed_updated(state, name, ok=False, detail=str(exc))
                results["hash_feeds"].append(
                    {"name": name, "status": "error", "error": str(exc)}
                )

        results["hash_db_count"] = db.count()

    finally:
        db.close()
        save_state(data_dir, state)

    return results


def load_or_create_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        create_default_config(config_path)
    return load_json(config_path)


def import_yara_module():
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Missing dependency: pip install yara-python") from exc
    return yara


def clean_meta(meta: dict[Any, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}

    for key, value in meta.items():
        key_text = str(key)

        if isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[key_text] = value
        else:
            cleaned[key_text] = str(value)

    return cleaned


def make_yara_externals(config: dict[str, Any], path: Optional[Path] = None, sha256: str = "") -> dict[str, Any]:
    externals = dict(config.get("yara", {}).get("externals", {}))

    if path is not None:
        suffix = path.suffix.lower().lstrip(".")
        externals.update(
            {
                "filename": path.name,
                "filepath": str(path),
                "extension": suffix,
                "filetype": suffix,
                "sha256": sha256,
            }
        )

    return externals


@dataclass
class YaraCompileReport:
    mode: str
    valid_files: int
    skipped_files: int
    errors: list[dict[str, str]]


class YaraManager:
    def __init__(self, config: dict[str, Any], data_dir: Path) -> None:
        self.config = config
        self.data_dir = data_dir
        self.yara = import_yara_module()
        self.rules: list[Any] = []
        self.report = YaraCompileReport(
            mode="none",
            valid_files=0,
            skipped_files=0,
            errors=[],
        )

    def collect_rule_files(self) -> list[Path]:
        root = self.data_dir / "feeds" / "yara"
        if not root.exists():
            return []

        files: list[Path] = []

        for suffix in ("*.yar", "*.yara"):
            files.extend(root.rglob(suffix))

        return sorted(set(files), key=lambda p: str(p).lower())

    def configure_yara(self) -> None:
        yara_config = self.config.get("yara", {})

        try:
            self.yara.set_config(
                max_match_data=int(yara_config.get("max_match_data", 128)),
                stack_size=int(yara_config.get("stack_size", 65536)),
            )
        except Exception:
            # Older builds may not support all knobs; scanning can continue.
            pass

    def compile(self) -> YaraCompileReport:
        self.configure_yara()

        rule_files = self.collect_rule_files()
        externals = make_yara_externals(self.config)

        valid_files: list[Path] = []
        errors: list[dict[str, str]] = []

        for path in rule_files:
            try:
                self.yara.compile(filepath=str(path), externals=externals)
                valid_files.append(path)
            except Exception as exc:
                errors.append({"file": str(path), "error": str(exc)})

        if not valid_files:
            self.report = YaraCompileReport(
                mode="none",
                valid_files=0,
                skipped_files=len(errors),
                errors=errors[:50],
            )
            return self.report

        filepaths: dict[str, str] = {}
        for idx, path in enumerate(valid_files):
            ns = re.sub(r"[^A-Za-z0-9_]", "_", f"ns_{idx}_{path.stem}")[:128]
            filepaths[ns] = str(path)

        try:
            self.rules = [self.yara.compile(filepaths=filepaths, externals=externals)]
            self.report = YaraCompileReport(
                mode="bundle",
                valid_files=len(valid_files),
                skipped_files=len(errors),
                errors=errors[:50],
            )
            return self.report
        except Exception as bundle_exc:
            errors.append({"file": "<bundle>", "error": str(bundle_exc)})

        compiled: list[Any] = []

        for path in valid_files:
            try:
                compiled.append(self.yara.compile(filepath=str(path), externals=externals))
            except Exception as exc:
                errors.append({"file": str(path), "error": str(exc)})

        self.rules = compiled
        self.report = YaraCompileReport(
            mode="per_file",
            valid_files=len(compiled),
            skipped_files=len(rule_files) - len(compiled),
            errors=errors[:50],
        )
        return self.report

    def match_file(self, path: Path, timeout_sec: int, sha256: str) -> tuple[list[dict[str, Any]], list[str]]:
        matches_out: list[dict[str, Any]] = []
        errors: list[str] = []

        if not self.rules:
            return matches_out, errors

        externals = make_yara_externals(self.config, path, sha256=sha256)

        for rules in self.rules:
            try:
                matches = rules.match(
                    filepath=str(path),
                    timeout=timeout_sec,
                    externals=externals,
                )
            except Exception as exc:
                errors.append(str(exc))
                continue

            for match in matches:
                matches_out.append(
                    {
                        "rule": str(match.rule),
                        "namespace": str(match.namespace),
                        "tags": list(match.tags),
                        "meta": clean_meta(dict(match.meta)),
                    }
                )

        return matches_out, errors


def sha256_file(path: Path, chunk_bytes: int) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_bytes)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()

def sha256_existing_file(path: Path, chunk_bytes: int = 8 * 1024 * 1024) -> str:
    return sha256_file(path, chunk_bytes)


def is_relative_to_path(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def preserve_glob_match(path: Path, project_root: Path, patterns: list[str]) -> bool:
    absolute_text = str(path)
    try:
        relative_text = str(path.resolve().relative_to(project_root.resolve()))
    except ValueError:
        relative_text = path.name

    return glob_any(absolute_text, patterns) or glob_any(relative_text, patterns)


def iter_preserve_files(
    project_root: Path,
    *,
    output_root: Path,
    exclude_globs: list[str],
) -> Iterable[Path]:
    project_root = project_root.resolve()
    output_root = output_root.resolve()

    if project_root.is_file():
        if not preserve_glob_match(project_root, project_root.parent, exclude_globs):
            yield project_root
        return

    for root, dirs, files in os.walk(str(project_root), followlinks=False):
        root_path = Path(root)

        dirs[:] = [
            d for d in dirs
            if not preserve_glob_match(root_path / d, project_root, exclude_globs)
            and not is_relative_to_path(root_path / d, output_root)
        ]

        for name in files:
            path = root_path / name

            if is_relative_to_path(path, output_root):
                continue

            if preserve_glob_match(path, project_root, exclude_globs):
                continue

            if path.is_symlink():
                continue

            yield path


def zip_directory(source_dir: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        allowZip64=True,
    ) as zf:
        for path in source_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir))


def preserve_project_snapshot(
    config_path: Path,
    project_root: Path,
    *,
    label: str = "",
    make_zip: bool = False,
) -> dict[str, Any]:
    config = load_or_create_config(config_path)
    data_dir = resolve_data_dir(config, config_path)
    preserve_config = config.get("preserve", {})

    raw_output_dir = expand_env_tokens(
        str(preserve_config.get("output_dir", "%LOCALAPPDATA%\\PyIOCScanner\\snapshots"))
    )
    output_root = Path(raw_output_dir)

    if not output_root.is_absolute():
        output_root = data_dir / output_root

    output_root.mkdir(parents=True, exist_ok=True)

    project_root = project_root.resolve()

    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label.strip())[:64]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_name = f"{stamp}_{safe_label}" if safe_label else stamp

    snapshot_dir = output_root / snapshot_name
    files_dir = snapshot_dir / "files"
    manifest_path = snapshot_dir / "manifest.json"

    files_dir.mkdir(parents=True, exist_ok=False)

    exclude_globs = list(preserve_config.get("exclude_globs", []))

    manifest: dict[str, Any] = {
        "schema": 1,
        "type": "project_preservation_snapshot",
        "created_utc": utc_now(),
        "project_root": str(project_root),
        "config_path": str(config_path.resolve()),
        "data_dir": str(data_dir),
        "snapshot_dir": str(snapshot_dir),
        "files_dir": str(files_dir),
        "label": label,
        "files": [],
        "errors": [],
    }

    copied = 0
    total_bytes = 0

    for src in iter_preserve_files(
        project_root,
        output_root=output_root,
        exclude_globs=exclude_globs,
    ):
        try:
            relative = src.resolve().relative_to(project_root)
            dst = files_dir / relative
            dst.parent.mkdir(parents=True, exist_ok=True)

            src_hash = sha256_existing_file(src)
            shutil.copy2(src, dst)
            dst_hash = sha256_existing_file(dst)

            stat = src.stat()

            entry = {
                "relative_path": str(relative),
                "source_path": str(src),
                "snapshot_path": str(dst),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": src_hash,
                "copy_sha256": dst_hash,
                "verified": src_hash == dst_hash,
            }

            manifest["files"].append(entry)
            copied += 1
            total_bytes += stat.st_size

            if src_hash != dst_hash:
                manifest["errors"].append(
                    {
                        "path": str(src),
                        "error": "copy hash mismatch",
                    }
                )

        except Exception as exc:
            manifest["errors"].append(
                {
                    "path": str(src),
                    "error": str(exc),
                }
            )

    if bool(preserve_config.get("copy_config", True)) and config_path.exists():
        try:
            config_dst = snapshot_dir / "scanner_config.json"
            shutil.copy2(config_path, config_dst)
            manifest["scanner_config_copy"] = {
                "path": str(config_dst),
                "sha256": sha256_existing_file(config_dst),
            }
        except Exception as exc:
            manifest["errors"].append(
                {
                    "path": str(config_path),
                    "error": f"config copy failed: {exc}",
                }
            )

    if bool(preserve_config.get("copy_data_dir_metadata", True)):
        for metadata_name in ("state.json", "ioc_hashes.sqlite3"):
            src = data_dir / metadata_name

            if not src.exists():
                continue

            try:
                dst = snapshot_dir / "data_dir_metadata" / metadata_name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                manifest.setdefault("data_dir_metadata", []).append(
                    {
                        "name": metadata_name,
                        "path": str(dst),
                        "sha256": sha256_existing_file(dst),
                    }
                )
            except Exception as exc:
                manifest["errors"].append(
                    {
                        "path": str(src),
                        "error": f"metadata copy failed: {exc}",
                    }
                )

    manifest["summary"] = {
        "files_copied": copied,
        "total_bytes": total_bytes,
        "errors": len(manifest["errors"]),
    }

    write_json(manifest_path, manifest)

    manifest_hash = sha256_existing_file(manifest_path)
    manifest["manifest_path"] = str(manifest_path)
    manifest["manifest_sha256"] = manifest_hash

    write_json(manifest_path, manifest)

    if make_zip:
        zip_path = output_root / f"{snapshot_name}.zip"
        zip_directory(snapshot_dir, zip_path)
        manifest["zip_path"] = str(zip_path)
        manifest["zip_sha256"] = sha256_existing_file(zip_path)
        write_json(manifest_path, manifest)

    return manifest

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for b in data:
        counts[b] += 1

    total = len(data)
    entropy = 0.0

    for count in counts:
        if count == 0:
            continue

        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def _read_u16_le(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset:offset + 2], "little", signed=False)


def _read_u32_le(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset:offset + 4], "little", signed=False)


def pe_section_entropies(
    path: Path,
    *,
    max_section_sample_bytes: int = 8 * 1024 * 1024,
) -> list[dict[str, Any]]:
    """
    Minimal Portable Executable (PE) section parser.

    Does not execute, load, emulate, unpack, or modify the file.
    Only reads section table metadata and samples raw section bytes.
    """
    sections: list[dict[str, Any]] = []

    try:
        with path.open("rb") as f:
            dos = f.read(64)

            if len(dos) < 64 or dos[0:2] != b"MZ":
                return sections

            pe_offset = _read_u32_le(dos, 0x3C)

            if pe_offset <= 0 or pe_offset > 256 * 1024 * 1024:
                return sections

            f.seek(pe_offset)
            pe_header = f.read(24)

            if len(pe_header) < 24 or pe_header[0:4] != b"PE\x00\x00":
                return sections

            number_of_sections = _read_u16_le(pe_header, 6)
            size_of_optional_header = _read_u16_le(pe_header, 20)

            if number_of_sections <= 0 or number_of_sections > 128:
                return sections

            section_table_offset = pe_offset + 24 + size_of_optional_header
            f.seek(section_table_offset)

            for _ in range(number_of_sections):
                header = f.read(40)

                if len(header) < 40:
                    break

                raw_name = header[0:8].split(b"\x00", 1)[0]
                name = raw_name.decode("ascii", errors="replace")

                virtual_size = _read_u32_le(header, 8)
                raw_size = _read_u32_le(header, 16)
                raw_ptr = _read_u32_le(header, 20)

                if raw_size == 0:
                    sections.append(
                        {
                            "name": name,
                            "virtual_size": virtual_size,
                            "raw_size": raw_size,
                            "raw_ptr": raw_ptr,
                            "entropy": 0.0,
                        }
                    )
                    continue

                current = f.tell()

                try:
                    f.seek(raw_ptr)
                    sample = f.read(min(raw_size, max_section_sample_bytes))
                    entropy = shannon_entropy(sample)
                finally:
                    f.seek(current)

                sections.append(
                    {
                        "name": name,
                        "virtual_size": virtual_size,
                        "raw_size": raw_size,
                        "raw_ptr": raw_ptr,
                        "entropy": round(entropy, 4),
                    }
                )

    except OSError:
        return sections

    return sections


def detect_packed_binary(path: Path, scan_config: dict[str, Any]) -> dict[str, Any]:
    """
    Packed PE heuristic.

    High entropy does not prove malware. It is a triage signal:
      - packer
      - encrypted payload
      - compressed installer
      - protected commercial software
      - self-extracting archive
    """
    result: dict[str, Any] = {
        "is_pe": False,
        "packed_suspected": False,
        "reason": "",
        "high_entropy_sections": [],
        "sections": [],
    }

    if not bool(scan_config.get("inspect_pe_sections", True)):
        return result

    sections = pe_section_entropies(path)
    result["sections"] = sections

    if not sections:
        return result

    result["is_pe"] = True

    threshold = float(scan_config.get("packed_entropy_threshold", 7.2))
    min_section_bytes = int(scan_config.get("packed_min_section_bytes", 4096))
    min_high_sections = int(scan_config.get("packed_min_high_entropy_sections", 1))

    high_entropy_sections = [
        s for s in sections
        if int(s.get("raw_size", 0)) >= min_section_bytes
        and float(s.get("entropy", 0.0)) >= threshold
    ]

    result["high_entropy_sections"] = high_entropy_sections

    if len(high_entropy_sections) >= min_high_sections:
        result["packed_suspected"] = True
        result["reason"] = (
            f"{len(high_entropy_sections)} PE section(s) have entropy >= {threshold}"
        )

    return result

def file_allowed_by_extension(path: Path, scan_extensions: list[str]) -> bool:
    if not scan_extensions:
        return True

    suffix = path.suffix.lower().lstrip(".")
    normalized = [x.lower().lstrip(".") for x in scan_extensions]
    return suffix in normalized


def is_excluded(path: Path, exclude_globs: list[str]) -> bool:
    text = str(path)
    return glob_any(text, exclude_globs)


@dataclass
class ScanOptions:
    use_yara: bool = True
    use_hashes: bool = True
    print_clean: bool = False
    jsonl_path: Optional[Path] = None


class Scanner:
    def __init__(self, config_path: Path, options: ScanOptions) -> None:
        self.config_path = config_path
        self.config = load_or_create_config(config_path)
        self.data_dir = resolve_data_dir(self.config, config_path)
        self.options = options

        self.scan_config = self.config.get("scan", {})
        self.max_file_bytes = int(self.scan_config.get("max_file_mb", 128)) * 1024 * 1024
        self.chunk_bytes = int(self.scan_config.get("hash_chunk_mb", 4)) * 1024 * 1024
        self.timeout_sec = int(self.scan_config.get("yara_timeout_sec", 30))
        self.scan_extensions = list(self.scan_config.get("scan_extensions", []))
        self.exclude_globs = list(self.scan_config.get("exclude_globs", []))

        self.hash_db = HashDB(self.data_dir / "ioc_hashes.sqlite3")
        self.yara_manager: Optional[YaraManager] = None

        if self.options.use_yara and self.config.get("yara", {}).get("enabled", True):
            self.yara_manager = YaraManager(self.config, self.data_dir)
            report = self.yara_manager.compile()
            eprint(
                f"YARA compile: mode={report.mode} "
                f"valid={report.valid_files} skipped={report.skipped_files}"
            )

    def close(self) -> None:
        self.hash_db.close()

    def iter_files(self, target: Path) -> Iterable[Path]:
        target = target.resolve()

        if target.is_file():
            if self.should_scan_path(target):
                yield target
            return

        if not target.is_dir():
            return

        for root, dirs, files in os.walk(str(target), followlinks=False):
            root_path = Path(root)

            dirs[:] = [
                d for d in dirs
                if not is_excluded(root_path / d, self.exclude_globs)
            ]

            for name in files:
                path = root_path / name

                if self.should_scan_path(path):
                    yield path

    def should_scan_path(self, path: Path) -> bool:
        if is_excluded(path, self.exclude_globs):
            return False

        if not file_allowed_by_extension(path, self.scan_extensions):
            return False

        return True

    def emit_jsonl(self, event: dict[str, Any]) -> None:
        if not self.options.jsonl_path:
            return

        self.options.jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        with self.options.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

    def scan_file(self, path: Path) -> dict[str, Any]:
        event: dict[str, Any] = {
            "time_utc": utc_now(),
            "type": "scan_result",
            "path": str(path),
            "verdict": "unknown",
            "size": None,
            "sha256": None,
            "hash_hits": [],
            "yara_matches": [],
            "packed_binary": {
                "is_pe": False,
                "packed_suspected": False,
                "reason": "",
                "high_entropy_sections": [],
                "sections": [],
            },
            "errors": [],
        }

        try:
            st = path.stat()
            event["size"] = st.st_size

            if st.st_size > self.max_file_bytes:
                event["verdict"] = "skipped"
                event["reason"] = "max_file_size_exceeded"
                self.emit_jsonl(event)
                return event

            sha256 = sha256_file(path, self.chunk_bytes)
            event["sha256"] = sha256

            if self.options.use_hashes:
                event["hash_hits"] = self.hash_db.lookup(sha256)

            event["packed_binary"] = detect_packed_binary(path, self.scan_config)

            if self.yara_manager is not None:
                yara_matches, yara_errors = self.yara_manager.match_file(
                    path,
                    timeout_sec=self.timeout_sec,
                    sha256=sha256,
                )
                event["yara_matches"] = yara_matches
                event["errors"].extend(yara_errors)

            packed_policy = str(
                self.scan_config.get("packed_binary_policy", "annotate")
            ).lower()

            if event["hash_hits"]:
                event["verdict"] = "malicious"
            elif event["yara_matches"]:
                event["verdict"] = "suspicious"
            elif (
                packed_policy == "suspicious"
                and event["packed_binary"].get("packed_suspected")
            ):
                event["verdict"] = "suspicious"
            else:
                event["verdict"] = "clean"

        except PermissionError as exc:
            event["verdict"] = "error"
            event["errors"].append(f"permission: {exc}")
        except OSError as exc:
            event["verdict"] = "error"
            event["errors"].append(f"os: {exc}")
        except Exception as exc:
            event["verdict"] = "error"
            event["errors"].append(f"unexpected: {exc}")

        self.emit_jsonl(event)
        return event

    def scan_path(self, target: Path, print_results: bool = True) -> dict[str, Any]:
        summary = {
            "time_utc": utc_now(),
            "target": str(target),
            "scanned": 0,
            "clean": 0,
            "suspicious": 0,
            "malicious": 0,
            "skipped": 0,
            "errors": 0,
            "findings": [],
        }

        for path in self.iter_files(target):
            event = self.scan_file(path)
            verdict = str(event.get("verdict", "unknown"))
            summary["scanned"] += 1

            if verdict == "clean":
                summary["clean"] += 1
            elif verdict == "suspicious":
                summary["suspicious"] += 1
            elif verdict == "malicious":
                summary["malicious"] += 1
            elif verdict == "skipped":
                summary["skipped"] += 1
            else:
                summary["errors"] += 1

            if verdict != "clean":
                summary["findings"].append(event)

            if print_results and (self.options.print_clean or verdict != "clean"):
                print_event_compact(event)

        return summary


def print_event_compact(event: dict[str, Any]) -> None:
    verdict = event.get("verdict")
    path = event.get("path")

    if verdict == "clean":
        print(f"[clean] {path}")
        return

    print(f"[{verdict}] {path}")

    sha256 = event.get("sha256")
    if sha256:
        print(f"  sha256: {sha256}")

    for hit in event.get("hash_hits", []):
        print(f"  hash-hit: {hit.get('source')}")

    packed = event.get("packed_binary", {})

    if packed.get("packed_suspected"):
        print(f"  packed: {packed.get('reason')}")

        for section in packed.get("high_entropy_sections", []):
            print(
                "    section: "
                f"{section.get('name')} "
                f"entropy={section.get('entropy')} "
                f"raw_size={section.get('raw_size')}"
            )

    for match in event.get("yara_matches", []):
        tags = ",".join(match.get("tags", []))
        rule = match.get("rule")
        namespace = match.get("namespace")
        print(f"  yara: {namespace}:{rule} tags={tags}")

    for err in event.get("errors", []):
        print(f"  error: {err}")


def run_watch(
    config_path: Path,
    target: Path,
    interval: int,
    update_interval_min: int,
    options: ScanOptions,
) -> None:
    """
    Polling watcher. This avoids extra Windows dependencies and works under
    normal user permissions. It rescans files whose mtime or size changes.
    """
    last_update = 0.0
    seen: dict[str, tuple[int, int]] = {}

    scanner = Scanner(config_path, options)

    try:
        print(f"Watching: {target}")
        print("Press Ctrl+C to stop.")

        while True:
            now = time.time()

            if update_interval_min > 0 and now - last_update >= update_interval_min * 60:
                print("[update] refreshing feeds")
                scanner.close()

                result = update_all_feeds(config_path, force=False)
                print(json.dumps(result, indent=2))

                scanner = Scanner(config_path, options)
                last_update = now

            for path in scanner.iter_files(target):
                try:
                    st = path.stat()
                except OSError:
                    continue

                key = str(path)
                fingerprint = (int(st.st_mtime_ns), int(st.st_size))

                if seen.get(key) == fingerprint:
                    continue

                seen[key] = fingerprint
                event = scanner.scan_file(path)

                if options.print_clean or event.get("verdict") != "clean":
                    print_event_compact(event)

            time.sleep(interval)

    except KeyboardInterrupt:
        print("Stopped.")

    finally:
        scanner.close()


def run_self_test(config_path: Path) -> int:
    config = load_or_create_config(config_path)
    data_dir = resolve_data_dir(config, config_path)

    yara_dir = data_dir / "feeds" / "yara" / "self_test"
    yara_dir.mkdir(parents=True, exist_ok=True)

    test_rule = yara_dir / "self_test.yar"
    test_rule.write_text(
        """
rule PyIOC_SelfTest_Marker
{
    meta:
        description = "Benign scanner self-test marker"
        author = "local"
    strings:
        $marker = "PYIOC_SELF_TEST_MARKER_2026"
    condition:
        $marker
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    sample_dir = data_dir / "samples"
    sample_dir.mkdir(parents=True, exist_ok=True)

    sample = sample_dir / "self_test_marker.txt"
    sample.write_text(
        "This is benign test content: PYIOC_SELF_TEST_MARKER_2026\n",
        encoding="utf-8",
    )

    scanner = Scanner(
        config_path,
        ScanOptions(use_yara=True, use_hashes=True, print_clean=True),
    )

    try:
        event = scanner.scan_file(sample)
        print_event_compact(event)
        print(json.dumps(event, indent=2))
        return 0 if event.get("verdict") == "suspicious" else 2
    finally:
        scanner.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Windows-compatible YARA + SHA-256 IOC scanner."
    )

    parser.add_argument(
        "-c",
        "--config",
        default="scanner_config.json",
        help="Path to scanner config JSON.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-config", help="Create default config.")
    p_init.add_argument("--overwrite", action="store_true")

    p_update = sub.add_parser("update", help="Update enabled feeds.")
    p_update.add_argument("--force", action="store_true")

    p_compile = sub.add_parser("compile", help="Compile YARA rules and report status.")

    p_scan = sub.add_parser("scan", help="Scan a file or directory.")
    p_scan.add_argument("target")
    p_scan.add_argument("--no-yara", action="store_true")
    p_scan.add_argument("--no-hash", action="store_true")
    p_scan.add_argument("--print-clean", action="store_true")
    p_scan.add_argument("--jsonl", help="Append full scan events to JSONL file.")

    p_watch = sub.add_parser("watch", help="Watch a directory and scan changed files.")
    p_watch.add_argument("target")
    p_watch.add_argument("--interval", type=int, default=10)
    p_watch.add_argument("--update-interval-min", type=int, default=60)
    p_watch.add_argument("--no-yara", action="store_true")
    p_watch.add_argument("--no-hash", action="store_true")
    p_watch.add_argument("--print-clean", action="store_true")
    p_watch.add_argument("--jsonl", help="Append full scan events to JSONL file.")

    p_preserve = sub.add_parser(
        "preserve",
        help="Create a verified project snapshot before re-enabling security software.",
    )
    p_preserve.add_argument("project_root", help="Project directory or file to preserve.")
    p_preserve.add_argument("--label", default="pre-bitdefender", help="Snapshot label.")
    p_preserve.add_argument("--zip", action="store_true", help="Also create a ZIP copy.")

    sub.add_parser("self-test", help="Create and scan a benign YARA self-test file.")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config_path = Path(args.config).resolve()

    if args.command == "init-config":
        create_default_config(config_path, overwrite=bool(args.overwrite))
        return 0

    if args.command == "update":
        result = update_all_feeds(config_path, force=bool(args.force))
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "compile":
        config = load_or_create_config(config_path)
        data_dir = resolve_data_dir(config, config_path)
        manager = YaraManager(config, data_dir)
        report = manager.compile()
        print(json.dumps(report.__dict__, indent=2))
        return 0 if report.valid_files > 0 else 2

    if args.command == "scan":
        options = ScanOptions(
            use_yara=not bool(args.no_yara),
            use_hashes=not bool(args.no_hash),
            print_clean=bool(args.print_clean),
            jsonl_path=Path(args.jsonl).resolve() if args.jsonl else None,
        )

        scanner = Scanner(config_path, options)

        try:
            summary = scanner.scan_path(Path(args.target).resolve())
            print(json.dumps(summary, indent=2))
            return 1 if summary["malicious"] or summary["suspicious"] else 0
        finally:
            scanner.close()

    if args.command == "watch":
        options = ScanOptions(
            use_yara=not bool(args.no_yara),
            use_hashes=not bool(args.no_hash),
            print_clean=bool(args.print_clean),
            jsonl_path=Path(args.jsonl).resolve() if args.jsonl else None,
        )

        run_watch(
            config_path=config_path,
            target=Path(args.target).resolve(),
            interval=max(1, int(args.interval)),
            update_interval_min=max(0, int(args.update_interval_min)),
            options=options,
        )
        return 0

    if args.command == "preserve":
        manifest = preserve_project_snapshot(
            config_path=config_path,
            project_root=Path(args.project_root).resolve(),
            label=str(args.label),
            make_zip=bool(args.zip),
        )

        print(json.dumps(manifest, indent=2))

        return 1 if manifest.get("summary", {}).get("errors", 0) else 0

    if args.command == "self-test":
        return run_self_test(config_path)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())