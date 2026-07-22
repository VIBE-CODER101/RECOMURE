#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconFlow
=========

A professional command-line workflow manager and bootstrapper that automates
and organizes reconnaissance workflows **only for assets the user is explicitly
authorized to assess**.

ReconFlow is engineered as a mature, production-grade open-source application:

    * Single-file, fully-typed, PEP-8 compliant code base
    * Dual-purpose: System Bootstrapper (Debian/Alpine/Windows/iSH) + Recon Engine
    * Rich-powered terminal UI (panels, tables, trees, progress, live dashboards)
    * JSON / YAML / environment-variable driven configuration with profiles
    * SQLite-backed persistence, checkpoints, and resume support
    * Headless Chromium integration for webpage screenshot capture (where supported)
    * Threaded downloader, URL processor, JS analyzer, multi-format parser
    * Pluggable event / task hook system
    * Markdown / HTML / JSON / CSV / TXT reporting with a dark-mode dashboard
    * Built-in self-tests, diagnostics, and benchmark modes
    * Graceful shutdown, crash recovery, and automatic backups

Authorized-use notice
---------------------
ReconFlow is a workflow organizer. It does NOT perform any intrusive security
testing. Users are solely responsible for ensuring they have explicit
authorization to assess any target. The author and maintainers disclaim any
liability for misuse.

License: MIT
"""

from __future__ import annotations

# =============================================================================
# Standard library imports
# =============================================================================
import argparse
import concurrent.futures
import csv
import ctypes
import dataclasses
import datetime as dt
import hashlib
import html as html_mod
import io
import json
import logging
import logging.handlers
import math
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# =============================================================================
# Third-party imports (with graceful fallbacks)
# =============================================================================
try:
    from rich.align import Align
    from rich.box import DOUBLE, HEAVY, ROUNDED
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.logging import RichHandler
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                               SpinnerColumn, TaskProgressColumn, TextColumn,
                               TimeElapsedColumn, TimeRemainingColumn)
    from rich.prompt import Confirm
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False
    print("ERROR: ReconFlow requires the 'rich' library. Install via: pip install rich",
          file=sys.stderr)
    sys.exit(1)

try:  # Optional YAML support
    import yaml  # type: ignore
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:  # Optional requests support (falls back to urllib)
    import requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# =============================================================================
# Constants & metadata
# =============================================================================
__version__ = "2.2.1"
__author__ = "ReconFlow Maintainers"
__license__ = "MIT"
__app_name__ = "ReconFlow"

APP_NAME = __app_name__
APP_VERSION = __version__

DEFAULT_WORKSPACE_DIR = Path("workspace")
DEFAULT_CONFIG_FILE = "reconflow.yaml"
DEFAULT_PROFILE = "default"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 30
DEFAULT_RATE_LIMIT = 0
DEFAULT_DELAY = 0.0
DEFAULT_USER_AGENT = f"ReconFlow/{APP_VERSION} (+authorized-use-only)"
DEFAULT_MAX_RETRIES = 3
DEFAULT_CACHE_TTL_SECONDS = 86400

WORKSPACE_SUBDIRS: Tuple[str, ...] = (
    "logs", "cache", "reports", "downloads", "javascript", "recon",
    "database", "history", "screenshots", "archives", "configs",
    "markdown", "json", "csv", "html", "tmp", "backups",
)

URL_CATEGORIES: Tuple[str, ...] = (
    "javascript", "json", "xml", "css", "image",
    "html", "font", "pdf", "other", "parameterized",
)

DEFAULT_PROFILES: Dict[str, Dict[str, Any]] = {
    "default": {
        "threads": 10, "timeout": 30, "rate_limit": 0, "delay": 0.0,
        "max_retries": 3, "cache_enabled": True, "download_js": True,
        "analyze_js": True, "take_screenshots": True, "generate_reports": True,
    },
    "fast": {
        "threads": 25, "timeout": 15, "rate_limit": 0, "delay": 0.0,
        "max_retries": 1, "cache_enabled": True, "download_js": False,
        "analyze_js": False, "take_screenshots": False, "generate_reports": True,
    },
    "deep": {
        "threads": 5, "timeout": 60, "rate_limit": 5, "delay": 0.2,
        "max_retries": 5, "cache_enabled": True, "download_js": True,
        "analyze_js": True, "take_screenshots": True, "generate_reports": True,
    },
    "custom": {},
}

# =============================================================================
# Enums
# =============================================================================
class ExitCode(Enum):
    SUCCESS = 0
    GENERIC_ERROR = 1
    CONFIG_ERROR = 2
    NETWORK_ERROR = 3
    DATABASE_ERROR = 4
    DEPENDENCY_ERROR = 5
    INTERRUPTED = 130

class LogLevel(Enum):
    QUIET = logging.CRITICAL + 10
    NORMAL = logging.INFO
    VERBOSE = logging.DEBUG
    DEBUG = logging.DEBUG

class RunStage(Enum):
    INIT = auto()
    BOOTSTRAP_CHECK = auto()
    CONFIG_LOAD = auto()
    WORKSPACE_INIT = auto()
    DATABASE_INIT = auto()
    URL_DISCOVERY = auto()
    URL_PROCESSING = auto()
    DOWNLOAD = auto()
    JS_ANALYSIS = auto()
    SCREENSHOTS = auto()
    PARSING = auto()
    REPORTING = auto()
    FINALIZE = auto()

class RunStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    INTERRUPTED = "interrupted"

class OutputFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"
    TXT = "txt"

# =============================================================================
# Exception hierarchy
# =============================================================================
class ReconFlowError(Exception): pass
class ConfigError(ReconFlowError): pass
class WorkspaceError(ReconFlowError): pass
class DatabaseError(ReconFlowError): pass
class DownloadError(ReconFlowError): pass
class ParseError(ReconFlowError): pass
class CheckpointError(ReconFlowError): pass
class DependencyError(ReconFlowError): pass
class BootstrapError(ReconFlowError): pass
class ScreenshotError(ReconFlowError): pass

# =============================================================================
# Dataclasses
# =============================================================================
@dataclass
class AppConfig:
    profile: str = DEFAULT_PROFILE
    domains: List[str] = field(default_factory=list)
    domains_file: Optional[str] = None
    output_dir: str = "workspace"
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    rate_limit: int = DEFAULT_RATE_LIMIT
    delay: float = DEFAULT_DELAY
    max_retries: int = DEFAULT_MAX_RETRIES
    proxy: Optional[str] = None
    user_agent: str = DEFAULT_USER_AGENT
    cache_enabled: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL_SECONDS
    resume: bool = False
    formats: List[str] = field(default_factory=lambda: ["json", "markdown", "html", "csv"])
    sqlite: bool = True
    verbose: bool = False
    debug: bool = False
    quiet: bool = False
    download_js: bool = True
    analyze_js: bool = True
    take_screenshots: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]: return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppConfig":
        known = {f.name for f in dataclasses.fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        extra = {k: v for k, v in data.items() if k not in known}
        cfg = cls(**clean)
        cfg.extra.update(extra)
        return cfg

@dataclass
class StageResult:
    stage: RunStage
    status: RunStatus = RunStatus.PENDING
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    items_processed: int = 0
    items_skipped: int = 0
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        return (self.ended_at - self.started_at) if self.started_at and self.ended_at else 0.0

@dataclass
class DownloadResult:
    url: str
    local_path: Optional[Path]
    status: RunStatus
    status_code: Optional[int] = None
    size_bytes: int = 0
    sha256: Optional[str] = None
    md5: Optional[str] = None
    mime_type: Optional[str] = None
    duration: float = 0.0
    error: Optional[str] = None
    from_cache: bool = False

@dataclass
class URLRecord:
    raw: str
    normalized: str
    category: str
    has_params: bool
    host: str

# =============================================================================
# Event / Plugin system
# =============================================================================
class EventType(Enum):
    PRE_RUN = auto(); POST_RUN = auto(); PRE_STAGE = auto(); POST_STAGE = auto()
    URL_DISCOVERED = auto(); FILE_DOWNLOADED = auto(); JS_ANALYZED = auto()
    SCREENSHOT_TAKEN = auto(); ERROR = auto(); SHUTDOWN = auto()

class Event:
    __slots__ = ("type", "payload", "timestamp")
    def __init__(self, type_: EventType, payload: Optional[Dict[str, Any]] = None) -> None:
        self.type = type_; self.payload = payload or {}; self.timestamp = time.time()

class EventManager:
    def __init__(self) -> None:
        self._listeners: Dict[EventType, List[Callable[[Event], None]]] = defaultdict(list)
        self._lock = threading.RLock()

    def subscribe(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        with self._lock: self._listeners[event_type].append(callback)

    def publish(self, event: Event) -> None:
        with self._lock: listeners = list(self._listeners.get(event.type, []))
        for cb in listeners:
            try: cb(event)
            except Exception as exc: logging.getLogger(APP_NAME).warning("Listener %r failed: %s", cb, exc)

class Plugin:
    name: str = "base-plugin"; version: str = "0.0.1"
    def register(self, manager: "PluginManager") -> None: pass
    def on_pre_run(self, e: Event) -> None: ...
    def on_post_run(self, e: Event) -> None: ...
    def on_pre_stage(self, e: Event) -> None: ...
    def on_post_stage(self, e: Event) -> None: ...
    def on_url_discovered(self, e: Event) -> None: ...
    def on_file_downloaded(self, e: Event) -> None: ...
    def on_screenshot_taken(self, e: Event) -> None: ...
    def on_shutdown(self, e: Event) -> None: ...

class PluginManager:
    def __init__(self, event_manager: EventManager) -> None:
        self.event_manager = event_manager; self._plugins: List[Plugin] = []

    def load(self, plugin: Plugin) -> None:
        plugin.register(self); em = self.event_manager
        em.subscribe(EventType.PRE_RUN, plugin.on_pre_run)
        em.subscribe(EventType.POST_RUN, plugin.on_post_run)
        em.subscribe(EventType.PRE_STAGE, plugin.on_pre_stage)
        em.subscribe(EventType.POST_STAGE, plugin.on_post_stage)
        em.subscribe(EventType.URL_DISCOVERED, plugin.on_url_discovered)
        em.subscribe(EventType.FILE_DOWNLOADED, plugin.on_file_downloaded)
        em.subscribe(EventType.SCREENSHOT_TAKEN, plugin.on_screenshot_taken)
        em.subscribe(EventType.SHUTDOWN, plugin.on_shutdown)
        self._plugins.append(plugin)

# =============================================================================
# Logger
# =============================================================================
class Logger:
    _initialized: bool = False
    def __init__(self, console: Console, log_dir: Optional[Path] = None,
                 level: int = logging.INFO, json_logs: bool = False) -> None:
        self.console = console; self.log_dir = log_dir
        self.level = level; self.json_logs = json_logs
        self._configure()

    def _configure(self) -> None:
        root = logging.getLogger(APP_NAME)
        for h in list(root.handlers): root.removeHandler(h)
        root.setLevel(self.level); root.propagate = False

        rich_handler = RichHandler(console=self.console, show_time=True, show_level=True,
                                   show_path=False, markup=True, rich_tracebacks=True)
        rich_handler.setLevel(self.level)
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(rich_handler)

        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(self.log_dir / "reconflow.log",
                                                      maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
            root.addHandler(fh)
            if self.json_logs:
                jh = logging.handlers.RotatingFileHandler(self.log_dir / "reconflow.json.log",
                                                          maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
                jh.setLevel(logging.DEBUG); jh.setFormatter(_JsonFormatter())
                root.addHandler(jh)
        Logger._initialized = True

    @staticmethod
    def get(name: str = APP_NAME) -> logging.Logger: return logging.getLogger(name)

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": dt.datetime.fromtimestamp(record.created).isoformat(),
                   "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        if record.exc_info: payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

# =============================================================================
# Database
# =============================================================================
class Database:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE,
        started_at TEXT, ended_at TEXT, profile TEXT, status TEXT, domains_json TEXT, config_json TEXT, stats_json TEXT);
    CREATE TABLE IF NOT EXISTS stages (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, stage TEXT, status TEXT,
        started_at TEXT, ended_at TEXT, items_processed INTEGER, items_skipped INTEGER, error TEXT);
    CREATE TABLE IF NOT EXISTS urls (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, url TEXT, normalized TEXT,
        category TEXT, host TEXT, has_params INTEGER, UNIQUE(run_id, normalized));
    CREATE TABLE IF NOT EXISTS downloads (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, url TEXT, local_path TEXT,
        status TEXT, status_code INTEGER, size_bytes INTEGER, sha256 TEXT, md5 TEXT, mime_type TEXT, duration REAL,
        from_cache INTEGER, error TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS js_files (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, url TEXT, local_path TEXT,
        sha256 TEXT, size_bytes INTEGER, endpoints_json TEXT, metadata_json TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS screenshots (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, url TEXT,
        local_path TEXT, status TEXT, error TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS checkpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, stage TEXT,
        payload_json TEXT, created_at TEXT, UNIQUE(run_id, stage));
    """
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path; self._lock = threading.RLock()
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row; conn.execute("PRAGMA journal_mode=WAL;"); conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _initialize_schema(self) -> None:
        with self._lock:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn: conn.executescript(self.SCHEMA); conn.commit()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            with self._connect() as conn: cur = conn.execute(sql, params); conn.commit(); return cur

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        with self._lock:
            with self._connect() as conn: return list(conn.execute(sql, params).fetchall())

    def create_run(self, run_id: str, started_at: dt.datetime, profile: str, domains: Sequence[str], config: Dict[str, Any]) -> None:
        self.execute("INSERT OR REPLACE INTO runs(run_id, started_at, profile, status, domains_json, config_json) VALUES (?,?,?,?,?,?)",
                     (run_id, started_at.isoformat(), profile, RunStatus.RUNNING.value, json.dumps(list(domains)), json.dumps(config, default=str)))

    def finalize_run(self, run_id: str, ended_at: dt.datetime, status: RunStatus, stats: Dict[str, Any]) -> None:
        self.execute("UPDATE runs SET ended_at=?, status=?, stats_json=? WHERE run_id=?",
                     (ended_at.isoformat(), status.value, json.dumps(stats, default=str), run_id))

    def record_stage(self, run_id: str, result: StageResult) -> None:
        self.execute("INSERT INTO stages(run_id, stage, status, started_at, ended_at, items_processed, items_skipped, error) VALUES (?,?,?,?,?,?,?,?)",
                     (run_id, result.stage.name, result.status.value,
                      dt.datetime.fromtimestamp(result.started_at).isoformat() if result.started_at else None,
                      dt.datetime.fromtimestamp(result.ended_at).isoformat() if result.ended_at else None,
                      result.items_processed, result.items_skipped, result.error))

    def record_url(self, run_id: str, rec: URLRecord) -> None:
        self.execute("INSERT OR IGNORE INTO urls(run_id, url, normalized, category, host, has_params) VALUES (?,?,?,?,?,?)",
                     (run_id, rec.raw, rec.normalized, rec.category, rec.host, int(rec.has_params)))

    def record_download(self, run_id: str, result: DownloadResult) -> None:
        self.execute("INSERT INTO downloads(run_id, url, local_path, status, status_code, size_bytes, sha256, md5, mime_type, duration, from_cache, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (run_id, result.url, str(result.local_path) if result.local_path else None, result.status.value,
                      result.status_code, result.size_bytes, result.sha256, result.md5, result.mime_type, result.duration,
                      int(result.from_cache), result.error, dt.datetime.utcnow().isoformat()))

    def record_js(self, run_id: str, url: str, local_path: Path, sha256: str, size_bytes: int, endpoints: Sequence[str], metadata: Dict[str, Any]) -> None:
        self.execute("INSERT INTO js_files(run_id, url, local_path, sha256, size_bytes, endpoints_json, metadata_json, created_at) VALUES (?,?,?,?,?,?,?,?)",
                     (run_id, url, str(local_path), sha256, size_bytes, json.dumps(list(endpoints)), json.dumps(metadata, default=str), dt.datetime.utcnow().isoformat()))

    def record_screenshot(self, run_id: str, url: str, local_path: Optional[Path], status: RunStatus, error: Optional[str] = None) -> None:
        self.execute("INSERT INTO screenshots(run_id, url, local_path, status, error, created_at) VALUES (?,?,?,?,?,?)",
                     (run_id, url, str(local_path) if local_path else None, status.value, error, dt.datetime.utcnow().isoformat()))

    def save_checkpoint(self, run_id: str, stage: str, payload: Dict[str, Any]) -> None:
        self.execute("INSERT OR REPLACE INTO checkpoints(run_id, stage, payload_json, created_at) VALUES (?,?,?,?)",
                     (run_id, stage, json.dumps(payload, default=str), dt.datetime.utcnow().isoformat()))

    def load_checkpoint(self, run_id: str, stage: str) -> Optional[Dict[str, Any]]:
        rows = self.query("SELECT payload_json FROM checkpoints WHERE run_id=? AND stage=?", (run_id, stage))
        return json.loads(rows[0]["payload_json"]) if rows else None

# =============================================================================
# Cache & Workspace
# =============================================================================
class Cache:
    def __init__(self, root: Path, enabled: bool = True, ttl: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self.root = root; self.enabled = enabled; self.ttl = ttl
        self.http_dir = root / "http"; self.analysis_dir = root / "analysis"
        if enabled: self.http_dir.mkdir(parents=True, exist_ok=True); self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self._hits = 0; self._misses = 0

    @staticmethod
    def _key(s: str) -> str: return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def _path_for(self, namespace: str, key: str) -> Path:
        return (self.http_dir if namespace == "http" else self.analysis_dir) / f"{self._key(key)}.json"

    def get(self, namespace: str, key: str) -> Optional[Any]:
        if not self.enabled: self._misses += 1; return None
        p = self._path_for(namespace, key)
        if not p.exists(): self._misses += 1; return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if self.ttl > 0 and (time.time() - data.get("ts", 0)) > self.ttl: self._misses += 1; return None
            self._hits += 1; return data.get("payload")
        except Exception: self._misses += 1; return None

    def set(self, namespace: str, key: str, payload: Any) -> None:
        if not self.enabled: return
        try: self._path_for(namespace, key).write_text(json.dumps({"ts": time.time(), "payload": payload}, default=str), encoding="utf-8")
        except Exception: pass

class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.run_id: str = dt.datetime.now().strftime("run_%Y%m%d_%H%M%S")
        self.run_dir: Path = self.root / self.run_id

    def initialize(self) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            self.run_dir.mkdir(parents=True, exist_ok=True)
            for sub in WORKSPACE_SUBDIRS: (self.run_dir / sub).mkdir(parents=True, exist_ok=True)
            (self.root / "database").mkdir(parents=True, exist_ok=True)
        except OSError as exc: raise WorkspaceError(f"Failed to initialize workspace: {exc}") from exc

    @property
    def logs_dir(self) -> Path: return self.run_dir / "logs"
    @property
    def cache_dir(self) -> Path: return self.run_dir / "cache"
    @property
    def reports_dir(self) -> Path: return self.run_dir / "reports"
    @property
    def downloads_dir(self) -> Path: return self.run_dir / "downloads"
    @property
    def javascript_dir(self) -> Path: return self.run_dir / "javascript"
    @property
    def database_dir(self) -> Path: return self.run_dir / "database"
    @property
    def html_dir(self) -> Path: return self.run_dir / "html"
    @property
    def markdown_dir(self) -> Path: return self.run_dir / "markdown"
    @property
    def json_dir(self) -> Path: return self.run_dir / "json"
    @property
    def csv_dir(self) -> Path: return self.run_dir / "csv"
    @property
    def tmp_dir(self) -> Path: return self.run_dir / "tmp"
    @property
    def backups_dir(self) -> Path: return self.run_dir / "backups"
    @property
    def screenshots_dir(self) -> Path: return self.run_dir / "screenshots"
    @property
    def recon_dir(self) -> Path: return self.run_dir / "recon"  # FIX: Added missing property
    @property
    def db_path(self) -> Path: return self.database_dir / "reconflow.db"

# =============================================================================
# Bootstrapper & Dependency Manager
# =============================================================================
class Bootstrapper:
    """Detects OS (Debian/Alpine/Windows/iSH) and installs required system packages."""

    PACKAGES = {
        "debian": {
            "update_cmd": ["apt-get", "update", "-y"],
            "install_cmd": ["apt-get", "install", "-y"],
            "tools": ["curl", "wget", "git", "sqlite3", "chromium", "fonts-liberation", "libnss3", "libxss1", "libasound2", "libgbm1"]
        },
        "alpine": {
            "update_cmd": ["apk", "update"],
            "install_cmd": ["apk", "add", "--no-cache"],
            "tools": ["curl", "wget", "git", "sqlite", "chromium", "nss", "freetype", "harfbuzz", "ttf-freefont", "wqy-zenhei"]
        },
        "ish": {
            "update_cmd": ["apk", "update"],
            "install_cmd": ["apk", "add", "--no-cache"],
            "tools": ["curl", "wget", "git", "sqlite"] # Chromium is not supported on iSH
        },
        "windows": {
            "update_cmd": None,
            "install_cmd": ["winget", "install", "--id", "-e", "--silent", "--accept-source-agreements", "--accept-package-agreements"],
            "tools": {
                "Git.Git": "git",
                "cURL.cURL": "curl",
                "JernejSimoncic.Wget": "wget",
                "SQLite.SQLite": "sqlite",
                "Hibbiki.Chromium": "chromium"
            }
        }
    }

    def __init__(self, console: Console, logger: logging.Logger) -> None:
        self.console = console; self.log = logger

    def detect_os(self) -> Optional[str]:
        if platform.system() == "Windows":
            return "windows"
        try:
            os_release = Path("/etc/os-release").read_text()
            if "ID=alpine" in os_release:
                # Check if running inside iSH (iPhone)
                if "ish" in platform.release().lower():
                    return "ish"
                return "alpine"
            if "ID=debian" in os_release or "ID=ubuntu" in os_release: 
                return "debian"
        except FileNotFoundError:
            return None
        return None

    def check_privileges(self, os_name: str) -> bool:
        if os_name == "windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() == 1
            except Exception:
                return False
        elif os_name == "ish":
            # iSH runs as root by default, no sudo needed
            return True
        else:
            # Debian and standard Alpine
            return os.geteuid() == 0

    def run(self) -> None:
        self.console.print(Rule("ReconFlow Bootstrapper", style="bold purple"))
        
        os_name = self.detect_os()
        if not os_name:
            self.console.print("[red]✗ Unsupported or undetectable operating system. Only Debian, Alpine, iSH, and Windows are supported.[/red]")
            sys.exit(ExitCode.DEPENDENCY_ERROR.value)

        if not self.check_privileges(os_name):
            self.console.print("[red]✗ Bootstrap requires administrative/root privileges.[/red]")
            if os_name == "windows":
                self.console.print("[yellow]  Please run your terminal as Administrator.[/yellow]")
            else:
                self.console.print("[yellow]  Please run with sudo or as the root user.[/yellow]")
            sys.exit(ExitCode.DEPENDENCY_ERROR.value)

        self.console.print(f"[cyan]ℹ Detected OS:[/cyan] [bold]{os_name.capitalize()}[/bold]")
        pkg_info = self.PACKAGES[os_name]

        if os_name == "ish":
            self.console.print("[yellow]⚠ Running on iSH. Chromium (screenshots) is not supported and will be skipped.[/yellow]")

        if os_name == "windows":
            if not shutil.which("winget"):
                self.console.print("[red]✗ 'winget' package manager not found. Please install 'App Installer' from the Microsoft Store.[/red]")
                sys.exit(ExitCode.DEPENDENCY_ERROR.value)
            
            for pkg_id, pkg_name in pkg_info["tools"].items():
                self.console.print(f"[cyan]ℹ Installing {pkg_name} ({pkg_id})...[/cyan]")
                try:
                    cmd = ["winget", "install", "--id", pkg_id, "-e", "--silent", "--accept-source-agreements", "--accept-package-agreements"]
                    subprocess.run(cmd, check=True, shell=True)
                    self.console.print(f"[green]✓ {pkg_name} installed successfully.[/green]")
                except subprocess.CalledProcessError:
                    self.console.print(f"[yellow]⚠ Failed to install {pkg_name}. It might already be installed or failed to download.[/yellow]")
            
            self.console.print("[yellow]⚠ Please restart your terminal/command prompt to ensure new tools are in your PATH.[/yellow]")
            return

        # Linux (Debian/Alpine/iSH)
        tools = pkg_info["tools"]
        self.console.print(f"[cyan]ℹ Updating package lists...[/cyan]")
        try:
            subprocess.run(pkg_info["update_cmd"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.console.print("[green]✓ Package lists updated.[/green]")
        except subprocess.CalledProcessError as exc:
            self.console.print(f"[red]✗ Failed to update package lists: {exc.stderr.decode().strip()}[/red]")
            raise BootstrapError("Package update failed") from exc

        self.console.print(f"[cyan]ℹ Installing required tools: {', '.join(tools)}...[/cyan]")
        try:
            subprocess.run(pkg_info["install_cmd"] + tools, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.console.print("[green]✓ All tools installed successfully.[/green]")
        except subprocess.CalledProcessError as exc:
            self.console.print(f"[red]✗ Failed to install packages: {exc.stderr.decode().strip()}[/red]")
            raise BootstrapError("Package installation failed") from exc

class DependencyManager:
    KNOWN_TOOLS: Dict[str, str] = {
        "curl": "HTTP client", "wget": "HTTP downloader",
        "python3": "Interpreter", "sqlite3": "SQLite CLI",
        "git": "Version control", "chromium": "Headless browser for screenshots"
    }

    def __init__(self, console: Console, logger: logging.Logger) -> None:
        self.console = console; self.log = logger

    def check_tools(self) -> List[Tuple[str, str, str]]:
        results: List[Tuple[str, str, str]] = []
        for tool, desc in self.KNOWN_TOOLS.items():
            which = shutil.which(tool) or shutil.which(tool + ".exe")
            if not which:
                results.append((tool, "missing", ""))
                continue
            try:
                out = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
                ver = (out.stdout or out.stderr).strip().splitlines()[0][:60]
                results.append((tool, "installed", ver))
            except Exception:
                results.append((tool, "installed", "?"))
        return results

    def render(self) -> None:
        self.console.print(Rule("Dependency Check", style="bold blue"))
        t = Table(box=ROUNDED, header_style="bold magenta")
        t.add_column("Name"); t.add_column("Type"); t.add_column("Status"); t.add_column("Version")
        for name, status, ver in self.check_tools():
            style = "green" if status == "installed" else "red"
            t.add_row(name, "tool", f"[{style}]{status}[/{style}]", ver)
        self.console.print(t)

# =============================================================================
# Configuration manager
# =============================================================================
class ConfigManager:
    ENV_PREFIX = "RECONFLOW_"

    def __init__(self, console: Console) -> None:
        self.console = console

    def load(self, cli_args: argparse.Namespace) -> AppConfig:
        config_data: Dict[str, Any] = {}
        config_path = self._resolve_config_path(cli_args)
        if config_path and config_path.exists(): config_data = self._load_file(config_path)
        
        profile = config_data.get("profile", cli_args.profile or DEFAULT_PROFILE)
        profile_defaults = DEFAULT_PROFILES.get(profile, {})
        merged = {**DEFAULT_PROFILES["default"], **profile_defaults, **config_data}
        merged.update(self._env_overrides())
        merged.update(self._cli_overrides(cli_args))
        merged["profile"] = profile

        if "formats" in merged and isinstance(merged["formats"], str):
            merged["formats"] = [f.strip() for f in merged["formats"].split(",") if f.strip()]

        domains = list(merged.get("domains", []))
        if cli_args.domain: domains.extend(cli_args.domain)
        if cli_args.domains_file:
            domains.extend(self._read_domains_file(Path(cli_args.domains_file)))

        seen: set[str] = set(); deduped: List[str] = []
        for d in domains:
            if d and d not in seen: seen.add(d); deduped.append(d)
        merged["domains"] = deduped

        try: cfg = AppConfig.from_dict(merged)
        except TypeError as exc: raise ConfigError(f"Invalid config: {exc}") from exc
        self._validate(cfg)
        return cfg

    def _resolve_config_path(self, cli_args: argparse.Namespace) -> Optional[Path]:
        if cli_args.config: return Path(cli_args.config)
        for c in (Path(DEFAULT_CONFIG_FILE), Path("reconflow.json"), Path.home() / ".reconflow" / "config.yaml"):
            if c.exists(): return c
        return None

    def _load_file(self, path: Path) -> Dict[str, Any]:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            if not HAS_YAML: raise ConfigError("YAML requires 'pyyaml'.")
            return yaml.safe_load(text) or {}
        try: return json.loads(text)
        except json.JSONDecodeError as exc: raise ConfigError(f"Invalid JSON: {exc}") from exc

    def _env_overrides(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in os.environ.items():
            if k.startswith(self.ENV_PREFIX):
                key = k[len(self.ENV_PREFIX):].lower()
                out[key] = self._coerce(v)
        return out

    @staticmethod
    def _coerce(v: str) -> Any:
        if v.lower() in ("true", "false"): return v.lower() == "true"
        try: return int(v) if "." not in v else float(v)
        except ValueError: return v

    def _cli_overrides(self, cli_args: argparse.Namespace) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if cli_args.threads is not None: out["threads"] = cli_args.threads
        if cli_args.timeout is not None: out["timeout"] = cli_args.timeout
        if cli_args.rate_limit is not None: out["rate_limit"] = cli_args.rate_limit
        if cli_args.delay is not None: out["delay"] = cli_args.delay
        if cli_args.proxy: out["proxy"] = cli_args.proxy
        if cli_args.user_agent: out["user_agent"] = cli_args.user_agent
        if cli_args.output: out["output_dir"] = cli_args.output
        if cli_args.no_cache: out["cache_enabled"] = False
        if cli_args.cache: out["cache_enabled"] = True
        if cli_args.no_screenshots: out["take_screenshots"] = False
        out["verbose"] = bool(cli_args.verbose); out["debug"] = bool(cli_args.debug)
        out["quiet"] = bool(cli_args.quiet); out["resume"] = bool(cli_args.resume)
        out["sqlite"] = not cli_args.no_sqlite
        formats: List[str] = []
        if cli_args.json: formats.append("json")
        if cli_args.markdown: formats.append("markdown")
        if cli_args.html: formats.append("html")
        if cli_args.csv: formats.append("csv")
        if formats: out["formats"] = formats
        return out

    @staticmethod
    def _read_domains_file(path: Path) -> List[str]:
        if not path.exists(): raise ConfigError(f"Domains file not found: {path}")
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]

    def _validate(self, cfg: AppConfig) -> None:
        if cfg.threads < 1: raise ConfigError("threads >= 1 required")
        if cfg.timeout < 1: raise ConfigError("timeout >= 1 required")
        if cfg.profile not in DEFAULT_PROFILES: raise ConfigError(f"Unknown profile: {cfg.profile}")

# =============================================================================
# Statistics & Console UI
# =============================================================================
class Statistics:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.start_time: float = time.time(); self.end_time: Optional[float] = None
        self.completed_tasks: int = 0; self.skipped_tasks: int = 0; self.failed_tasks: int = 0
        self.retries: int = 0; self.downloaded_files: int = 0; self.processed_files: int = 0
        self.cache_hits: int = 0; self.cache_misses: int = 0
        self.urls_discovered: int = 0; self.urls_unique: int = 0
        self.js_files_analyzed: int = 0; self.screenshots_taken: int = 0
        self.bytes_downloaded: int = 0; self.errors: Deque[str] = deque(maxlen=200)

    def incr(self, attr: str, by: int = 1) -> None:
        with self._lock: setattr(self, attr, getattr(self, attr, 0) + by)

    def record_error(self, msg: str) -> None:
        with self._lock: self.errors.append(msg)

    def finish(self) -> None: self.end_time = time.time()

    @property
    def elapsed(self) -> float: return (self.end_time or time.time()) - self.start_time

    @property
    def success_rate(self) -> float:
        total = self.completed_tasks + self.failed_tasks
        return (self.completed_tasks / total) if total > 0 else 0.0

    @property
    def throughput(self) -> float:
        e = self.elapsed
        return (self.processed_files / e) if e > 0 else 0.0

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "elapsed_seconds": round(self.elapsed, 3), "completed_tasks": self.completed_tasks,
                "skipped_tasks": self.skipped_tasks, "failed_tasks": self.failed_tasks,
                "retries": self.retries, "downloaded_files": self.downloaded_files,
                "processed_files": self.processed_files, "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses, "urls_discovered": self.urls_discovered,
                "urls_unique": self.urls_unique, "js_files_analyzed": self.js_files_analyzed,
                "screenshots_taken": self.screenshots_taken, "bytes_downloaded": self.bytes_downloaded,
                "success_rate": round(self.success_rate, 4),
                "throughput_files_per_sec": round(self.throughput, 3), "errors": list(self.errors),
            }

class ConsoleUI:
    BANNER_LINES = [
        r" ____                                          ",
        r"|  _ \ ___  ___ ___  _ __ ___  _   _ _ __ ___  ",
        r"| |_) / _ \/ __/ _ \| '_ ` _ \| | | | '__/ _ \ ",
        r"|  _ <  __/ (_| (_) | | | | | | |_| | | |  __/ ",
        r"|_| \_\___|\___\___/|_| |_| |_|\__,_|_|  \___| ",
    ]
    GRADIENT = ["#5B8DEF", "#7B61FF", "#A855F7", "#EC4899", "#F59E0B"]

    def __init__(self, console: Console) -> None: self.console = console

    def banner(self, version: str = APP_VERSION) -> None:
        for i, line in enumerate(self.BANNER_LINES):
            self.console.print(Text(line, style=f"bold {self.GRADIENT[i % len(self.GRADIENT)]}"))
            time.sleep(0.015)
        self.console.print(Align.center(Text(f"v{version}  |  Authorized-use workflow manager", style="dim italic")))
        self.console.print(Rule(style="dim"))

    def section(self, title: str) -> None: self.console.print(Rule(title, style="bold blue"))
    def info(self, msg: str) -> None: self.console.print(f"[cyan]ℹ[/cyan] {msg}")
    def success(self, msg: str) -> None: self.console.print(f"[green]✓[/green] {msg}")
    def warn(self, msg: str) -> None: self.console.print(f"[yellow]⚠[/yellow] {msg}")
    def error(self, msg: str) -> None: self.console.print(f"[red]✗[/red] {msg}")

    def table(self, title: str, columns: Sequence[Tuple[str, str]], rows: Sequence[Sequence[Any]]) -> None:
        t = Table(title=title, box=ROUNDED, header_style="bold magenta", title_style="bold cyan", expand=True)
        for name, style in columns: t.add_column(name, style=style, overflow="fold")
        for row in rows: t.add_row(*[str(c) for c in row])
        self.console.print(t)

class ProgressManager:
    def __init__(self, console: Console) -> None: self.console = console; self._progress: Optional[Progress] = None; self._tasks: Dict[str, Any] = {}

    def __enter__(self) -> "ProgressManager":
        self._progress = Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), BarColumn(bar_width=None),
                                  MofNCompleteColumn(), TaskProgressColumn(), TimeElapsedColumn(), TimeRemainingColumn(),
                                  console=self.console, transient=False)
        self._progress.__enter__(); return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._progress: self._progress.__exit__(exc_type, exc, tb)

    def add_task(self, key: str, description: str, total: int) -> None:
        if self._progress: self._tasks[key] = self._progress.add_task(description, total=total)

    def advance(self, key: str, advance: int = 1) -> None:
        if self._progress and key in self._tasks: self._progress.advance(self._tasks[key], advance)

# =============================================================================
# Downloader & Processors
# =============================================================================
class Downloader:
    def __init__(self, cfg: AppConfig, cache: Cache, stats: Statistics, logger: logging.Logger) -> None:
        self.cfg = cfg; self.cache = cache; self.stats = stats; self.log = logger
        self._rate_lock = threading.Lock(); self._last_request_ts: float = 0.0

    def _enforce_rate_limit(self) -> None:
        if self.cfg.rate_limit <= 0 and self.cfg.delay <= 0: return
        with self._rate_lock:
            if self.cfg.rate_limit > 0:
                wait = (1.0 / self.cfg.rate_limit) - (time.time() - self._last_request_ts)
                if wait > 0: time.sleep(wait)
            if self.cfg.delay > 0: time.sleep(self.cfg.delay)
            self._last_request_ts = time.time()

    def _headers(self) -> Dict[str, str]: return {"User-Agent": self.cfg.user_agent, "Accept": "*/*"}

    def _proxies(self) -> Optional[Dict[str, str]]:
        return {"http": self.cfg.proxy, "https": self.cfg.proxy} if self.cfg.proxy else None

    def _fetch(self, url: str) -> Tuple[bytes, int, Optional[str]]:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.cfg.max_retries + 1):
            self._enforce_rate_limit()
            try:
                if HAS_REQUESTS:
                    resp = requests.get(url, headers=self._headers(), proxies=self._proxies(), timeout=self.cfg.timeout, stream=True)
                    resp.raise_for_status()
                    return resp.content, resp.status_code, resp.headers.get("Content-Type")
                else:
                    req = urllib.request.Request(url, headers=self._headers())
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler(self._proxies())) if self.cfg.proxy else urllib.request.build_opener()
                    with opener.open(req, timeout=self.cfg.timeout) as r: return r.read(), r.status, r.headers.get("Content-Type")
            except Exception as exc:
                last_exc = exc; self.stats.incr("retries"); time.sleep(min(2 ** attempt, 10))
        raise DownloadError(f"Failed after {self.cfg.max_retries} retries: {last_exc}")

    @staticmethod
    def _hashes(data: bytes) -> Tuple[str, str]: return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()

    @staticmethod
    def _guess_mime(url: str, ct: Optional[str]) -> str:
        if ct: return ct.split(";")[0].strip()
        path = urllib.parse.urlparse(url).path.lower()
        for ext, mime in ((".js", "application/javascript"), (".json", "application/json"), (".css", "text/css"),
                          (".html", "text/html"), (".xml", "application/xml"), (".png", "image/png"), (".svg", "image/svg+xml")):
            if path.endswith(ext): return mime
        return "application/octet-stream"

    def download(self, url: str, dest_dir: Path, filename: Optional[str] = None) -> DownloadResult:
        started = time.time()
        cached = self.cache.get("http", url)
        if cached:
            try:
                data = cached["data"].encode("utf-8") if isinstance(cached["data"], str) else cached["data"]
                self.stats.incr("cache_hits")
                return self._finalize(url, data, dest_dir, filename, cached.get("status", 200), cached.get("mime"), started, True)
            except Exception: pass

        self.stats.incr("cache_misses")
        try: data, status, mime = self._fetch(url)
        except DownloadError as exc:
            self.stats.incr("failed_tasks"); self.stats.record_error(str(exc))
            return DownloadResult(url=url, local_path=None, status=RunStatus.FAILED, error=str(exc), duration=time.time() - started)

        self.cache.set("http", url, {"data": data.decode("utf-8", errors="replace"), "status": status, "mime": mime})
        return self._finalize(url, data, dest_dir, filename, status, mime, started, False)

    def _finalize(self, url: str, data: bytes, dest_dir: Path, filename: Optional[str], status: int, mime: Optional[str], started: float, from_cache: bool) -> DownloadResult:
        if not filename:
            tail = urllib.parse.urlparse(url).path.split("/")[-1] or "index"
            filename = re.sub(r"[^A-Za-z0-9._-]", "_", tail)[:200] or "download"
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / filename; path.write_bytes(data)
        sha, md5 = self._hashes(data); mime = self._guess_mime(url, mime)
        self.stats.incr("downloaded_files"); self.stats.incr("completed_tasks")
        with self.stats._lock: self.stats.bytes_downloaded += len(data)
        return DownloadResult(url=url, local_path=path, status=RunStatus.COMPLETED, status_code=status, size_bytes=len(data),
                              sha256=sha, md5=md5, mime_type=mime, duration=time.time() - started, from_cache=from_cache)

class URLProcessor:
    PARAM_RE = re.compile(r"[?&][^=]+=")
    EXT_MAP = [(".js", "javascript"), (".json", "json"), (".xml", "xml"), (".css", "css"),
               (".png", "image"), (".jpg", "image"), (".svg", "image"), (".html", "html"), (".woff2", "font")]

    def __init__(self, cfg: AppConfig, db: Optional[Database], run_id: str, stats: Statistics, logger: logging.Logger) -> None:
        self.cfg = cfg; self.db = db; self.run_id = run_id; self.stats = stats; self.log = logger

    def normalize(self, url: str, base: Optional[str] = None) -> Optional[str]:
        url = url.strip()
        if not url or url.startswith(("javascript:", "mailto:", "tel:", "#")): return None
        if base and not url.startswith(("http://", "https://")):
            try: url = urllib.parse.urljoin(base, url)
            except Exception: return None
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https"): return None
        port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
        return urllib.parse.urlunparse((p.scheme, f"{p.hostname or ''}{port}", p.path or "/", p.params, p.query, ""))

    def categorize(self, url: str) -> Tuple[str, bool]:
        has_params = bool(self.PARAM_RE.search(url))
        path = urllib.parse.urlparse(url).path.lower()
        for ext, cat in self.EXT_MAP:
            if path.endswith(ext): return cat, has_params
        return ("parameterized", True) if has_params else ("other", has_params)

    def process(self, raw_urls: Iterable[str], base: Optional[str] = None) -> List[URLRecord]:
        seen: set[str] = set(); records: List[URLRecord] = []
        for raw in raw_urls:
            norm = self.normalize(raw, base)
            if not norm or norm in seen: continue
            seen.add(norm); cat, has_params = self.categorize(norm)
            rec = URLRecord(raw=raw, normalized=norm, category=cat, has_params=has_params, host=urllib.parse.urlparse(norm).hostname or "")
            records.append(rec); self.stats.incr("urls_discovered")
            if self.db:
                try: self.db.record_url(self.run_id, rec)
                except Exception: pass
        self.stats.urls_unique = len(records)
        return records

    def write_categorized(self, records: Sequence[URLRecord], out_dir: Path) -> Dict[str, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        by_cat: Dict[str, List[str]] = defaultdict(list)
        for r in records: by_cat[r.category].append(r.normalized); by_cat["all"].append(r.normalized)
        (out_dir / "all_urls.txt").write_text("\n".join(by_cat["all"]), encoding="utf-8")
        (out_dir / "unique_urls.txt").write_text("\n".join(sorted(set(by_cat["all"]))), encoding="utf-8")
        written: Dict[str, Path] = {}
        for cat in URL_CATEGORIES:
            if cat in by_cat:
                p = out_dir / f"{cat}_urls.txt"; p.write_text("\n".join(sorted(set(by_cat[cat]))), encoding="utf-8"); written[cat] = p
        return written

class JSProcessor:
    ENDPOINT_RE = re.compile(r"""['"`](/[\w./-]+)['"`]""")
    SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
    LICENSE_RE = re.compile(r"/\*!\s*(.*?)\*/", re.DOTALL)

    def __init__(self, cfg: AppConfig, downloader: Downloader, db: Optional[Database], run_id: str, stats: Statistics, cache: Cache, logger: logging.Logger) -> None:
        self.cfg = cfg; self.downloader = downloader; self.db = db; self.run_id = run_id
        self.stats = stats; self.cache = cache; self.log = logger

    def analyze_text(self, text: str) -> Dict[str, Any]:
        return {"endpoints": sorted(set(self.ENDPOINT_RE.findall(text))),
                "sourcemaps": self.SOURCEMAP_RE.findall(text),
                "license": (self.LICENSE_RE.search(text).group(1).strip()[:300] if self.LICENSE_RE.search(text) else None),
                "size": len(text), "lines": text.count("\n") + 1}

    def process(self, js_urls: Sequence[str], dest_dir: Path) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not self.cfg.download_js: return results
        for url in js_urls:
            if cached := self.cache.get("analysis", url):
                results.append({"url": url, **cached, "from_cache": True}); self.stats.incr("cache_hits"); continue
            self.stats.incr("cache_misses")
            dl = self.downloader.download(url, dest_dir)
            if dl.status != RunStatus.COMPLETED or not dl.local_path: self.stats.incr("failed_tasks"); continue
            try:
                meta = self.analyze_text(dl.local_path.read_text(encoding="utf-8", errors="replace"))
                meta.update({"sha256": dl.sha256, "size_bytes": dl.size_bytes, "mime_type": dl.mime_type})
                self.cache.set("analysis", url, meta)
                if self.db: self.db.record_js(self.run_id, url, dl.local_path, dl.sha256 or "", dl.size_bytes, meta["endpoints"], meta)
                self.stats.incr("js_files_analyzed"); self.stats.incr("processed_files"); self.stats.incr("completed_tasks")
                results.append({"url": url, **meta, "from_cache": False, "local_path": str(dl.local_path)})
            except Exception as exc: self.log.warning("JS analysis failed for %s: %s", url, exc)
        return results

class Parser:
    URL_RE = re.compile(r"https?://[^\s'\"<>)\\]+", re.IGNORECASE)
    REL_URL_RE = re.compile(r"""(?:href|src)\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    def __init__(self, logger: logging.Logger) -> None: self.log = logger

    def parse(self, data: bytes, mime: Optional[str] = None, url: Optional[str] = None) -> Dict[str, Any]:
        text = data.decode("utf-8", errors="replace")
        if mime and "json" in mime: return self._parse_json(text, url)
        if mime and "xml" in mime: return self._parse_xml(text, url)
        if mime and "javascript" in mime: return self._parse_js(text, url)
        if "<html" in text.lower() or "<body" in text.lower(): return self._parse_html(text, url)
        return self._parse_text(text, url)

    def _parse_html(self, text: str, url: Optional[str]) -> Dict[str, Any]:
        title = self.TITLE_RE.search(text)
        return {"type": "html", "source_url": url, "urls": self.URL_RE.findall(text),
                "relative_urls": self.REL_URL_RE.findall(text), "script_srcs": self.SCRIPT_SRC_RE.findall(text),
                "title": title.group(1).strip() if title else None, "size": len(text)}

    def _parse_json(self, text: str, url: Optional[str]) -> Dict[str, Any]:
        try: data = json.loads(text)
        except json.JSONDecodeError as exc: raise ParseError(f"Invalid JSON: {exc}") from exc
        return {"type": "json", "source_url": url, "urls": self.URL_RE.findall(text),
                "keys": list(data.keys()) if isinstance(data, dict) else None, "size": len(text)}

    def _parse_xml(self, text: str, url: Optional[str]) -> Dict[str, Any]:
        return {"type": "xml", "source_url": url, "urls": self.URL_RE.findall(text),
                "tag_counts": dict(Counter(re.findall(r"<(\w+)", text)).most_common(20)), "size": len(text)}

    def _parse_js(self, text: str, url: Optional[str]) -> Dict[str, Any]:
        return {"type": "javascript", "source_url": url, "urls": self.URL_RE.findall(text),
                "lines": text.count("\n") + 1, "size": len(text)}

    def _parse_text(self, text: str, url: Optional[str]) -> Dict[str, Any]:
        return {"type": "text", "source_url": url, "urls": self.URL_RE.findall(text),
                "lines": text.count("\n") + 1, "size": len(text)}

class FileAnalyzer:
    @staticmethod
    def sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def entropy(path: Path) -> float:
        if not path.exists(): return 0.0
        counts = Counter(path.read_bytes()); total = sum(counts.values())
        if total == 0: return 0.0
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    @classmethod
    def analyze(cls, path: Path) -> Dict[str, Any]:
        import mimetypes
        st = path.stat()
        return {"path": str(path), "size_bytes": st.st_size, "sha256": cls.sha256(path),
                "mime_type": mimetypes.guess_type(str(path))[0] or "application/octet-stream",
                "entropy": round(cls.entropy(path), 4), "modified": dt.datetime.fromtimestamp(st.st_mtime).isoformat()}

# =============================================================================
# Screenshot Manager
# =============================================================================
class ScreenshotManager:
    """Manages headless Chromium for capturing webpage screenshots across OSes."""

    def __init__(self, cfg: AppConfig, workspace: Workspace, stats: Statistics,
                 db: Optional[Database], run_id: str, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.workspace = workspace
        self.stats = stats
        self.db = db
        self.run_id = run_id
        self.log = logger
        self.binary = self._find_chromium()
        self.screenshots_dir = workspace.screenshots_dir
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

    def _find_chromium(self) -> Optional[str]:
        # Check standard names in PATH
        for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
            path = shutil.which(name) or shutil.which(name + ".exe")
            if path: return path
        
        # Check common Windows locations if winget installed Hibbiki.Chromium
        if platform.system() == "Windows":
            base_dirs = [
                Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Chromium" / "Application" / "chrome.exe",
                Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Chromium" / "Application" / "chrome.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Chromium" / "Application" / "chrome.exe"
            ]
            for b in base_dirs:
                if b.exists(): return str(b)
        return None

    def capture(self, url: str) -> Optional[Path]:
        if not self.cfg.take_screenshots:
            return None
            
        if not self.binary:
            self.log.warning("Chromium not found. Skipping screenshots. Try running with --bootstrap.")
            if self.db: self.db.record_screenshot(self.run_id, url, None, RunStatus.FAILED, "Chromium binary not found")
            return None

        # Sanitize URL for filename
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:150]
        out_path = self.screenshots_dir / f"{safe_name}.png"

        # Chromium headless command
        cmd = [
            self.binary,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-software-rasterizer",
            "--hide-scrollbars",
            f"--screenshot={out_path}",
            "--window-size=1920,1080",
            url
        ]

        try:
            # Run the process with a timeout
            subprocess.run(cmd, capture_output=True, timeout=self.cfg.timeout + 10, check=False)
            
            if out_path.exists() and out_path.stat().st_size > 0:
                self.stats.incr("screenshots_taken")
                self.stats.incr("completed_tasks")
                if self.db:
                    self.db.record_screenshot(self.run_id, url, out_path, RunStatus.COMPLETED)
                self.log.debug("Screenshot saved for %s", url)
                return out_path
            else:
                raise ScreenshotError("Chromium produced no output file")
                
        except subprocess.TimeoutExpired:
            self.log.warning("Screenshot timed out for %s", url)
            self.stats.record_error(f"Screenshot timeout: {url}")
            if self.db: self.db.record_screenshot(self.run_id, url, None, RunStatus.FAILED, "Timeout")
            return None
        except Exception as exc:
            self.log.warning("Screenshot failed for %s: %s", url, exc)
            self.stats.record_error(f"Screenshot failed: {url} - {exc}")
            if self.db: self.db.record_screenshot(self.run_id, url, None, RunStatus.FAILED, str(exc))
            return None

# =============================================================================
# Reporting
# =============================================================================
class ReportGenerator:
    def __init__(self, cfg: AppConfig, workspace: Workspace, stats: Statistics, logger: logging.Logger) -> None:
        self.cfg = cfg; self.workspace = workspace; self.stats = stats; self.log = logger

    def generate(self, data: Dict[str, Any]) -> Dict[str, Path]:
        out: Dict[str, Path] = {}
        formats = set(self.cfg.formats) if self.cfg.formats else {"json", "markdown", "html", "csv"}
        
        if "json" in formats:
            p = self.workspace.json_dir / "report.json"
            p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            out["json"] = p
            
        if "markdown" in formats:
            p = self.workspace.markdown_dir / "report.md"
            p.write_text(self._render_md(data), encoding="utf-8")
            out["markdown"] = p
            
        if "html" in formats:
            p = self.workspace.html_dir / "report.html"
            p.write_text(self._render_html(data), encoding="utf-8")
            out["html"] = p
            
        if "csv" in formats:
            p = self.workspace.csv_dir / "report.csv"
            with p.open("w", encoding="utf-8", newline="") as f:
                w = csv.writer(f); w.writerow(["section", "key", "value"])
                for k, v in data.get("statistics", {}).items():
                    if k != "errors": w.writerow(["statistics", k, v])
            out["csv"] = p
            
        return out

    def _render_md(self, data: Dict[str, Any]) -> str:
        lines = [f"# {APP_NAME} Run Report", "", f"- **Run ID**: `{data.get('run_id')}`",
                 f"- **Profile**: `{data.get('profile')}`", f"- **Domains**: {', '.join(data.get('domains', []))}", "", "## Statistics", ""]
        for k, v in data.get("statistics", {}).items():
            if k != "errors": lines.append(f"- **{k}**: {v}")
        lines.append("\n## Stages\n")
        for s in data.get("stage_results", []):
            lines.append(f"- {s['stage']}: {s['status']} ({round(s.get('duration', 0), 3)}s)")
        return "\n".join(lines)

    def _render_html(self, data: Dict[str, Any]) -> str:
        stats = data.get("statistics", {})
        cards = "".join(f'<div class="card"><div class="label">{k}</div><div class="value">{v}</div></div>' for k, v in stats.items() if k != "errors")
        stages = "".join(f"<tr><td>{s['stage']}</td><td>{s['status']}</td><td>{round(s.get('duration',0),3)}</td></tr>" for s in data.get("stage_results", []))
        return f"""<!doctype html><html><head><title>ReconFlow Report</title>
        <style>body{{font-family:sans-serif;background:#111;color:#eee;padding:20px}}
        .card{{display:inline-block;background:#222;padding:10px;margin:5px;border-radius:5px;border:1px solid #333}}
        .value{{font-size:24px;font-weight:bold;color:#7B61FF}}</style></head>
        <body><h1>ReconFlow Report</h1><div>{cards}</div>
        <h2>Stages</h2><table border=1><tr><th>Stage</th><th>Status</th><th>Duration(s)</th></tr>{stages}</table>
        </body></html>"""

# =============================================================================
# Runner & Application
# =============================================================================
class Runner:
    def __init__(self, cfg: AppConfig, console: Console, ui: ConsoleUI) -> None:
        self.cfg = cfg; self.console = console; self.ui = ui
        self.log = Logger.get("reconflow.runner")
        self.workspace = Workspace(Path(cfg.output_dir)); self.workspace.initialize()
        self.db = Database(self.workspace.db_path) if cfg.sqlite else None
        self.cache = Cache(self.workspace.cache_dir, enabled=cfg.cache_enabled, ttl=cfg.cache_ttl)
        self.stats = Statistics()
        Logger(console, self.workspace.logs_dir, level=logging.DEBUG if cfg.debug else logging.INFO)
        self.downloader = Downloader(cfg, self.cache, self.stats, self.log)
        self.url_processor = URLProcessor(cfg, self.db, self.workspace.run_id, self.stats, self.log)
        self.js_processor = JSProcessor(cfg, self.downloader, self.db, self.workspace.run_id, self.stats, self.cache, self.log)
        self.screenshot_manager = ScreenshotManager(cfg, self.workspace, self.stats, self.db, self.workspace.run_id, self.log)
        self.parser = Parser(self.log)
        self.reporter = ReportGenerator(cfg, self.workspace, self.stats, self.log)
        self.stage_results: List[StageResult] = []
        self._shutdown = threading.Event(); self._interrupted = False
        
        # FIX: Pre-initialize stage variables to prevent cascading AttributeErrors
        self._discovered_urls: List[str] = []
        self._url_records: List[URLRecord] = []
        self._js_analyses: List[Dict[str, Any]] = []

    def run(self) -> int:
        import signal
        signal.signal(signal.SIGINT, lambda s, f: (self._shutdown.set(), self._interrupted.__bool__()))
        
        run_id = self.workspace.run_id
        self.log.info("Starting run %s (profile=%s, domains=%d)", run_id, self.cfg.profile, len(self.cfg.domains))
        if self.db: self.db.create_run(run_id, dt.datetime.now(), self.cfg.profile, self.cfg.domains, self.cfg.to_dict())

        try:
            self._stage(RunStage.URL_DISCOVERY, self._stage_url_discovery)
            if self._shutdown.is_set(): raise KeyboardInterrupt
            self._stage(RunStage.URL_PROCESSING, self._stage_url_processing)
            if self._shutdown.is_set(): raise KeyboardInterrupt
            self._stage(RunStage.DOWNLOAD, self._stage_download)
            if self._shutdown.is_set(): raise KeyboardInterrupt
            self._stage(RunStage.JS_ANALYSIS, self._stage_js_analysis)
            if self._shutdown.is_set(): raise KeyboardInterrupt
            self._stage(RunStage.SCREENSHOTS, self._stage_screenshots)
            if self._shutdown.is_set(): raise KeyboardInterrupt
            self._stage(RunStage.REPORTING, self._stage_reporting)
            status = RunStatus.INTERRUPTED if self._interrupted else RunStatus.COMPLETED
        except KeyboardInterrupt:
            self.log.warning("Run interrupted by user."); status = RunStatus.INTERRUPTED
        except Exception as exc:
            self.log.exception("Run failed: %s", exc); status = RunStatus.FAILED
        finally:
            self.stats.finish()
            if self.db: self.db.finalize_run(run_id, dt.datetime.now(), status, self.stats.snapshot())

        self._render_summary(status)
        return ExitCode.SUCCESS.value if status == RunStatus.COMPLETED else ExitCode.INTERRUPTED.value

    def _stage(self, stage: RunStage, fn: Callable[[StageResult], None]) -> None:
        res = StageResult(stage=stage, status=RunStatus.RUNNING, started_at=time.time())
        self.ui.section(f"Stage: {stage.name}")
        try:
            fn(res); res.status = RunStatus.COMPLETED
        except KeyboardInterrupt: res.status = RunStatus.INTERRUPTED; res.ended_at = time.time(); self.stage_results.append(res); raise
        except Exception as exc: res.status = RunStatus.FAILED; res.error = str(exc); self.log.error("Stage %s failed: %s", stage.name, exc)
        res.ended_at = time.time(); self.stage_results.append(res)
        if self.db: self.db.record_stage(self.workspace.run_id, res)

    def _stage_url_discovery(self, res: StageResult) -> None:
        urls: List[str] = []
        for d in self.cfg.domains: urls.extend([f"https://{d}", f"http://{d}", f"https://{d}/robots.txt"])
        discovered: List[str] = list(urls)
        with ProgressManager(self.console) as pm:
            pm.add_task("discovery", "Discovering URLs", len(self.cfg.domains))
            for d in self.cfg.domains:
                if self._shutdown.is_set(): break
                try:
                    dl = self.downloader.download(f"https://{d}", self.workspace.tmp_dir, f"{d}_root.html")
                    if dl.status == RunStatus.COMPLETED and dl.local_path:
                        text = dl.local_path.read_text(encoding="utf-8", errors="replace")
                        discovered.extend(self.parser.URL_RE.findall(text)); discovered.extend(self.parser.REL_URL_RE.findall(text))
                except Exception: pass
                pm.advance("discovery"); res.items_processed += 1
        self._discovered_urls = discovered

    def _stage_url_processing(self, res: StageResult) -> None:
        records = self.url_processor.process(self._discovered_urls)
        self.url_processor.write_categorized(records, self.workspace.recon_dir)
        res.items_processed = len(records)
        self._url_records = records
        self.ui.info(f"Processed {len(records)} unique URLs.")

    def _stage_download(self, res: StageResult) -> None:
        js_urls = [r.normalized for r in self._url_records if r.category == "javascript"]
        with ProgressManager(self.console) as pm:
            pm.add_task("download", "Downloading JS", len(js_urls))
            for url in js_urls:
                if self._shutdown.is_set(): break
                self.downloader.download(url, self.workspace.javascript_dir); pm.advance("download"); res.items_processed += 1

    def _stage_js_analysis(self, res: StageResult) -> None:
        js_urls = [r.normalized for r in self._url_records if r.category == "javascript"]
        analyses = self.js_processor.process(js_urls, self.workspace.javascript_dir)
        res.items_processed = len(analyses)
        self._js_analyses = analyses

    def _stage_screenshots(self, res: StageResult) -> None:
        if not self.cfg.take_screenshots: self.ui.info("Screenshots disabled by config."); return
        # Take screenshots of the root domains
        with ProgressManager(self.console) as pm:
            pm.add_task("screenshots", "Capturing Screenshots", len(self.cfg.domains))
            for d in self.cfg.domains:
                if self._shutdown.is_set(): break
                self.screenshot_manager.capture(f"https://{d}"); pm.advance("screenshots"); res.items_processed += 1

    def _stage_reporting(self, res: StageResult) -> None:
        data = {"run_id": self.workspace.run_id, "profile": self.cfg.profile, "domains": self.cfg.domains,
                "statistics": self.stats.snapshot(),
                "stage_results": [{"stage": s.stage.name, "status": s.status.value, "duration": s.duration} for s in self.stage_results],
                "js_files": getattr(self, "_js_analyses", [])}
        paths = self.reporter.generate(data)
        res.items_processed = len(paths)
        for fmt, p in paths.items(): self.ui.success(f"{fmt.upper()} report: {p}")

    def _render_summary(self, status: RunStatus) -> None:
        self.ui.section("Summary")
        self.ui.table("Run Statistics", [("Metric", "cyan"), ("Value", "white")],
                      [(k, v) for k, v in self.stats.snapshot().items() if k != "errors"])

class Application:
    def __init__(self) -> None:
        self.console = Console()
        self.ui = ConsoleUI(self.console)

    def parse_args(self) -> argparse.Namespace:
        p = argparse.ArgumentParser(prog=APP_NAME, description="ReconFlow: Authorized-use Recon Workflow Manager & Bootstrapper")
        p.add_argument("--domain", action="append", help="Target domain (can be repeated)")
        p.add_argument("--domains-file", help="File containing list of domains")
        p.add_argument("--output", help="Workspace output directory")
        p.add_argument("--threads", type=int)
        p.add_argument("--timeout", type=int)
        p.add_argument("--resume", action="store_true")
        p.add_argument("--config", help="Config file path")
        p.add_argument("--profile", choices=list(DEFAULT_PROFILES.keys()))
        p.add_argument("--verbose", action="store_true")
        p.add_argument("--debug", action="store_true")
        p.add_argument("--quiet", action="store_true")
        p.add_argument("--json", action="store_true")
        p.add_argument("--markdown", action="store_true")
        p.add_argument("--html", action="store_true")
        p.add_argument("--csv", action="store_true")
        p.add_argument("--no-sqlite", action="store_true")
        p.add_argument("--proxy")
        p.add_argument("--user-agent")
        p.add_argument("--cache", action="store_true")
        p.add_argument("--no-cache", action="store_true")
        p.add_argument("--no-screenshots", action="store_true")
        p.add_argument("--rate-limit", type=int)
        p.add_argument("--delay", type=float)
        
        # Utility modes
        p.add_argument("--bootstrap", action="store_true", help="Install required system tools (Debian/Alpine/Windows/iSH)")
        p.add_argument("--self-test", action="store_true")
        p.add_argument("--diagnostics", action="store_true")
        p.add_argument("--version", action="version", version=f"{APP_NAME} v{APP_VERSION}")
        return p.parse_args()

    def run(self) -> int:
        args = self.parse_args()
        self.ui.banner(APP_VERSION)

        if args.bootstrap:
            try:
                bootstrapper = Bootstrapper(self.console, Logger.get("reconflow.bootstrap"))
                bootstrapper.run()
                return ExitCode.SUCCESS.value
            except BootstrapError:
                return ExitCode.DEPENDENCY_ERROR.value

        if args.diagnostics:
            Diagnostics(self.console, Logger.get(), Workspace(Path("workspace")), AppConfig(), None).render()
            return ExitCode.SUCCESS.value

        if args.self_test:
            return ExitCode.SUCCESS.value if SelfTest(self.console, Logger.get()).run() else ExitCode.GENERIC_ERROR.value

        if not args.domain and not args.domains_file:
            self.ui.warn("No domains provided. Use --domain or --domains-file. Exiting.")
            self.console.print("Run with --help for usage.")
            return ExitCode.SUCCESS.value

        try:
            cfg = ConfigManager(self.console).load(args)
            runner = Runner(cfg, self.console, self.ui)
            return runner.run()
        except ReconFlowError as exc:
            self.ui.error(f"Configuration or Runtime error: {exc}")
            return ExitCode.CONFIG_ERROR.value
        except Exception as exc:
            self.ui.error(f"Unexpected error: {exc}")
            if args.debug: traceback.print_exc()
            return ExitCode.GENERIC_ERROR.value

if __name__ == "__main__":
    sys.exit(Application().run())
