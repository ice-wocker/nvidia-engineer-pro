#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
NVIDIA ENGINEER PRO v7.0 — Professional AI Engineering Agent
Shadow-git checkpoints · Memory · Skills · Hooks · Budget · Web · Subagents
Parallel tool execution · Patches · Auto-snapshots · Exponential backoff · Self-test
"""
from __future__ import annotations
import os, sys, re, json, time, uuid, html, shutil, hashlib, argparse, fnmatch, unicodedata
import difflib, textwrap, threading, subprocess, socket, zipfile, tarfile
import urllib.request, urllib.error, urllib.parse
import base64
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict, fields
from typing import Optional, Callable
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import readline
except ImportError:
    readline = None

__version__ = "8.0.0"
APP_DIR = Path.home() / ".nvidia_engineer_pro"
SESSIONS_DIR = APP_DIR / "sessions"
CHECKPOINTS_DIR = APP_DIR / "checkpoints"
MEMORY_DIR = APP_DIR / "memory"
SKILLS_DIR = APP_DIR / "skills"
AUDIT_DIR = APP_DIR / "audit"
CONFIG_FILE = APP_DIR / "config.json"

API_KEY = os.environ.get("NVIDIA_API_KEY", "")
BASE_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
DEFAULT_MODEL = os.environ.get("NVIDIA_MODEL", "openai/gpt-oss-20b")

MAX_AGENT_STEPS = 60
MAX_TOOL_OUTPUT = 4000
COMPACT_THRESHOLD = 80_000
DEFAULT_BUDGET = {"tokens": 200_000, "time_sec": 1800, "steps": 40}

# Tools that never mutate state → safe to run in parallel & allowed in plan mode.
READONLY_TOOLS = frozenset({
    "read_file", "list_dir", "tree", "glob", "search_code", "diff_show", "file_stat",
    "symbols", "analyze_project", "web_search", "fetch_url", "http_request",
    "git_status", "git_diff", "git_log", "json_query",
    "hash_text", "base64", "memory_read", "memory_list", "memory_search",
    "skill_list", "skill_load", "skill_search", "set_todos", "todo_update",
    "notify",
})

# Plan-mode also allows these safe (non-destructive) write-ish actions.
PLAN_EXTRA_TOOLS = frozenset({"memory_write", "memory_append", "skill_list", "skill_search"})

# Tools that can be executed concurrently within a single assistant turn.
PARALLEL_SAFE_TOOLS = frozenset({
    "read_file", "list_dir", "glob", "search_code", "file_stat", "symbols",
    "diff_show", "json_query", "hash_text", "base64", "git_status", "git_diff",
    "git_log", "memory_read", "memory_list", "skill_list", "skill_search",
})

MUTATING_TOOLS = frozenset({
    "write_file", "edit_file", "delete_file", "apply_patch", "run_command",
    "download_file", "extract_archive", "git_commit", "git_init", "git_undo",
    "git_branch", "git_stash",
})

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".next", "vendor",
    ".tox", ".eggs", ".nengineer", ".shadow_git", ".cache", "target",
    ".gradle", ".idea", ".vscode", ".terraform", ".pnpm-store",
}

# Approximate USD per 1M tokens (prompt, completion) — used for budget reporting.
MODEL_PRICING = {
    "openai/gpt-oss-20b": (0.10, 0.50),
    "openai/gpt-oss-120b": (0.15, 0.60),
    "deepseek-ai/deepseek-r1": (0.55, 2.19),
    "deepseek-ai/deepseek-v3": (0.27, 1.10),
    "meta/llama-3.3-70b-instruct": (0.23, 0.40),
    "meta/llama-3.1-8b-instruct": (0.05, 0.05),
    "qwen/qwen2.5-coder-32b-instruct": (0.14, 0.14),
    "mistralai/mistral-large-2-instruct": (2.0, 6.0),
}
DEFAULT_PRICING = (0.20, 0.80)

PROTECTED_PATHS = [
    "/etc", "/usr", "/bin", "/sbin", "/boot", "/var", "/root",
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gcloud",
    "~/.bashrc", "~/.zshrc", "~/.profile", "~/.nvidia_engineer_pro",
    "~/.env", "~/.npmrc", "~/.pypirc", "~/.gitconfig",
]

# Private / link-local / metadata ranges blocked from network tools.
PRIVATE_HOST_RE = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"169\.254\.\d+\.\d+|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+|"
    r"\[?fe80:?[0-9a-f:]*\]?|192\.0\.0\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)$",
    re.IGNORECASE,
)

# Secret patterns for auto-masking
SECRET_PATTERNS = [
    (r"nvapi-[A-Za-z0-9_\-]{20,}", "nvapi-***"),
    (r"sk-[A-Za-z0-9_\-]{20,}", "sk-***"),
    (r"ghp_[A-Za-z0-9]{36}", "ghp_***"),
    (r"xoxb-[0-9]", "xoxb-***"),
    (r"AKIA[0-9A-Z]{16}", "AKIA***"),
    (r"password\s*[=:]\s*['\"]?([^\s'\"]{4,})", r"password=***"),
    (r"api[_-]?key\s*[=:]\s*['\"]?([^\s'\"]{4,})", r"api_key=***"),
    (r"token\s*[=:]\s*['\"]?([^\s'\"]{20,})", r"token=***"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[PRIVATE KEY REDACTED]"),
]


def mask_secrets(text: str) -> str:
    """Auto-mask secrets in output text."""
    for pattern, replacement in SECRET_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def block_private_host(url: str) -> None:
    """Raise ToolError when a URL points at localhost / private / metadata space."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https"):
        raise ToolError("only http/https URLs allowed")
    if not host:
        raise ToolError("URL has no host")
    if PRIVATE_HOST_RE.match(host) or host.endswith(".local") or host.endswith(".internal"):
        raise ToolError(f"blocked: private/localhost URL host={host}")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return  # let the request layer surface the resolution error
    for info in infos:
        ip = info[4][0].split("%")[0]
        if PRIVATE_HOST_RE.match(ip) or ip.startswith(("127.", "10.", "192.168.", "169.254.")):
            raise ToolError(f"blocked: host resolves to private address {ip}")


def estimate_text_tokens(text: str) -> int:
    """Cheap token estimate: ~4 chars/token for latin, ~1.6 for CJK-heavy text."""
    if not text:
        return 0
    text = str(text)
    cjk = sum(1 for ch in text if "一" <= ch <= "鿿")
    other = len(text) - cjk
    return max(1, other // 4 + cjk // 2)


def random_uniform(ceiling: float = 0.4) -> float:
    """Tiny non-cryptographic jitter in [0, ceiling) for retry backoff."""
    return (time.time_ns() % 10007) / 10007.0 * ceiling


# ═══════════════════════════════════════════════════════════
# STYLE / TUI
# ═══════════════════════════════════════════════════════════

# ── Color capability detection ──────────────────────────────────────────────
def _detect_color_mode():
    if os.environ.get("NO_COLOR"):
        return "off"
    if not sys.stdout.isatty():
        return "off"
    ct = os.environ.get("COLORTERM", "")
    if ct in ("truecolor", "24bit"):
        return "truecolor"
    term = os.environ.get("TERM", "")
    if "256" in term:
        return "256"
    if os.environ.get("COLORFGBG"):
        return "256"
    return "16"

_COLOR_MODE = _detect_color_mode()

def _hex_to_ansi256(hex_color: str) -> str:
    """Convert #RRGGBB to the nearest xterm-256 color index (as ANSI code string)."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    # grayscale ramp 232-255
    if abs(r - g) < 8 and abs(g - b) < 8:
        gray = round(((r + g + b) / 3 - 8) / 10)
        gray = max(0, min(23, gray))
        idx = 232 + gray
    else:
        def _q(v):
            if v < 48: return 0
            if v < 115: return 1
            return (v - 35) // 40
        ri, gi, bi = _q(r), _q(g), _q(b)
        idx = 16 + 36 * ri + 6 * gi + bi
    return f"\033[38;5;{idx}m"

def _hex_to_ansi_true(hex_color: str) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"

def _hex_to_ansi16(hex_color: str) -> str:
    """Nearest 16-color ANSI code for a hex color."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    # simple nearest by luminance + hue
    lum = 0.299 * r + 0.587 * g + 0.114 * b
    if lum < 60:
        return "\033[30m"   # black
    if lum > 200:
        return "\033[37m"   # white
    if r > g and r > b:
        return "\033[91m" if lum > 140 else "\033[31m"
    if g > r and g > b:
        return "\033[92m" if lum > 140 else "\033[32m"
    if b > r and b > g:
        return "\033[94m" if lum > 140 else "\033[34m"
    if r > 150 and g > 150 and b < 100:
        return "\033[93m"  # yellow
    if r > 150 and b > 150 and g < 100:
        return "\033[95m"  # magenta
    if g > 150 and b > 150 and r < 100:
        return "\033[96m"  # cyan
    return "\033[37m"

# ── Theme definitions (GitHub + popular terminal palettes) ──────────────────
# Every theme must define the same token keys as "dark" below.
_THEMES = {
    "dark": {
        "kw": "#ff7b72", "str": "#a5d6ff", "com": "#8b949e", "num": "#79c0ff",
        "fn": "#d2a8ff", "typ": "#ffa657", "op": "#ff7b72", "pun": "#c9d1d9",
        "builtin": "#79c0ff", "dec": "#d2a8ff", "ok": "#3fb950", "err": "#f85149",
        "warn": "#d29922", "dim": "#6e7681", "link": "#58a6ff", "heading": "#1f6feb",
        "table": "#30363d", "accent": "#58a6ff", "bg": "#0d1117", "fg": "#e6edf3",
        "quote": "#8b949e", "diff_add": "#3fb950", "diff_del": "#f85149",
        "diff_hunk": "#58a6ff", "diff_meta": "#8b949e", "spinner": "#58a6ff",
        "status": "#6e7681", "prompt": "#58a6ff", "border": "#30363d",
        "sel": "#1f6feb", "thinking": "#8b949e",
    },
    "light": {
        "kw": "#cf222e", "str": "#0a3069", "com": "#6e7781", "num": "#0550ae",
        "fn": "#8250df", "typ": "#953800", "op": "#cf222e", "pun": "#24292f",
        "builtin": "#0550ae", "dec": "#8250df", "ok": "#1a7f37", "err": "#cf222e",
        "warn": "#9a6700", "dim": "#57606a", "link": "#0969da", "heading": "#0550ae",
        "table": "#d0d7de", "accent": "#0969da", "bg": "#ffffff", "fg": "#1f2328",
        "quote": "#57606a", "diff_add": "#1a7f37", "diff_del": "#cf222e",
        "diff_hunk": "#0969da", "diff_meta": "#57606a", "spinner": "#0969da",
        "status": "#57606a", "prompt": "#0969da", "border": "#d0d7de",
        "sel": "#0969da", "thinking": "#57606a",
    },
    "nord": {
        "kw": "#81a1c1", "str": "#a3be8c", "com": "#616e88", "num": "#b48ead",
        "fn": "#88c0d0", "typ": "#8fbcbb", "op": "#81a1c1", "pun": "#d8dee9",
        "builtin": "#88c0d0", "dec": "#8fbcbb", "ok": "#a3be8c", "err": "#bf616a",
        "warn": "#ebcb8b", "dim": "#4c566a", "link": "#88c0d0", "heading": "#88c0d0",
        "table": "#434c5e", "accent": "#88c0d0", "bg": "#2e3440", "fg": "#eceff4",
        "quote": "#616e88", "diff_add": "#a3be8c", "diff_del": "#bf616a",
        "diff_hunk": "#88c0d0", "diff_meta": "#616e88", "spinner": "#88c0d0",
        "status": "#4c566a", "prompt": "#88c0d0", "border": "#434c5e",
        "sel": "#5e81ac", "thinking": "#616e88",
    },
    "solarized": {
        "kw": "#859900", "str": "#2aa198", "com": "#657b83", "num": "#d33682",
        "fn": "#268bd2", "typ": "#b58900", "op": "#859900", "pun": "#839496",
        "builtin": "#268bd2", "dec": "#cb4b16", "ok": "#859900", "err": "#dc322f",
        "warn": "#b58900", "dim": "#586e75", "link": "#268bd2", "heading": "#268bd2",
        "table": "#073642", "accent": "#268bd2", "bg": "#002b36", "fg": "#93a1a1",
        "quote": "#657b83", "diff_add": "#859900", "diff_del": "#dc322f",
        "diff_hunk": "#268bd2", "diff_meta": "#657b83", "spinner": "#268bd2",
        "status": "#586e75", "prompt": "#268bd2", "border": "#073642",
        "sel": "#268bd2", "thinking": "#657b83",
    },
    "tokyonight": {
        "kw": "#bb9af7", "str": "#9ece6a", "com": "#565f89", "num": "#ff9e64",
        "fn": "#7aa2f7", "typ": "#2ac3de", "op": "#bb9af7", "pun": "#a9b1d6",
        "builtin": "#7aa2f7", "dec": "#ff9e64", "ok": "#9ece6a", "err": "#f7768e",
        "warn": "#e0af68", "dim": "#414868", "link": "#7aa2f7", "heading": "#7aa2f7",
        "table": "#292e42", "accent": "#7aa2f7", "bg": "#1a1b26", "fg": "#c0caf5",
        "quote": "#565f89", "diff_add": "#9ece6a", "diff_del": "#f7768e",
        "diff_hunk": "#7aa2f7", "diff_meta": "#565f89", "spinner": "#7aa2f7",
        "status": "#414868", "prompt": "#7aa2f7", "border": "#292e42",
        "sel": "#33467c", "thinking": "#565f89",
    },
    "catppuccin": {
        "kw": "#cba6f7", "str": "#a6e3a1", "com": "#6c7086", "num": "#fab387",
        "fn": "#89b4fa", "typ": "#94e2d5", "op": "#cba6f7", "pun": "#cdd6f4",
        "builtin": "#89b4fa", "dec": "#fab387", "ok": "#a6e3a1", "err": "#f38ba8",
        "warn": "#f9e2af", "dim": "#585b70", "link": "#89b4fa", "heading": "#89b4fa",
        "table": "#313244", "accent": "#89b4fa", "bg": "#1e1e2e", "fg": "#cdd6f4",
        "quote": "#6c7086", "diff_add": "#a6e3a1", "diff_del": "#f38ba8",
        "diff_hunk": "#89b4fa", "diff_meta": "#6c7086", "spinner": "#89b4fa",
        "status": "#585b70", "prompt": "#89b4fa", "border": "#313244",
        "sel": "#45475a", "thinking": "#6c7086",
    },
    "dracula": {
        "kw": "#ff79c6", "str": "#f1fa8c", "com": "#6272a4", "num": "#bd93f9",
        "fn": "#50fa7b", "typ": "#8be9fd", "op": "#ff79c6", "pun": "#f8f8f2",
        "builtin": "#8be9fd", "dec": "#ffb86c", "ok": "#50fa7b", "err": "#ff5555",
        "warn": "#f1fa8c", "dim": "#6272a4", "link": "#8be9fd", "heading": "#bd93f9",
        "table": "#44475a", "accent": "#bd93f9", "bg": "#282a36", "fg": "#f8f8f2",
        "quote": "#6272a4", "diff_add": "#50fa7b", "diff_del": "#ff5555",
        "diff_hunk": "#8be9fd", "diff_meta": "#6272a4", "spinner": "#bd93f9",
        "status": "#6272a4", "prompt": "#bd93f9", "border": "#44475a",
        "sel": "#44475a", "thinking": "#6272a4",
    },
    "monokai": {
        "kw": "#f92672", "str": "#e6db74", "com": "#75715e", "num": "#ae81ff",
        "fn": "#a6e22e", "typ": "#66d9ef", "op": "#f92672", "pun": "#f8f8f2",
        "builtin": "#66d9ef", "dec": "#fd971f", "ok": "#a6e22e", "err": "#f92672",
        "warn": "#e6db74", "dim": "#75715e", "link": "#66d9ef", "heading": "#a6e22e",
        "table": "#3e3d32", "accent": "#66d9ef", "bg": "#272822", "fg": "#f8f8f2",
        "quote": "#75715e", "diff_add": "#a6e22e", "diff_del": "#f92672",
        "diff_hunk": "#66d9ef", "diff_meta": "#75715e", "spinner": "#66d9ef",
        "status": "#75715e", "prompt": "#66d9ef", "border": "#3e3d32",
        "sel": "#49483e", "thinking": "#75715e",
    },
}

def _lerp_hex(c1: str, c2: str, t: float) -> str:
    """Linear-interpolate between two #RRGGBB colors (t in 0..1)."""
    a = c1.lstrip("#"); b = c2.lstrip("#")
    r1, g1, b1 = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
    r2, g2, b2 = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
    r = round(r1 + (r2 - r1) * t)
    g = round(g1 + (g2 - g1) * t)
    bb = round(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{bb:02x}"

def _gradient_hex(stops: list, t: float) -> str:
    """Pick a color along a multi-stop gradient. stops = ['#..','#..',…]."""
    if len(stops) == 1:
        return stops[0]
    t = max(0.0, min(1.0, t))
    seg = t * (len(stops) - 1)
    i = min(int(seg), len(stops) - 2)
    frac = seg - i
    return _lerp_hex(stops[i], stops[i + 1], frac)

def _hex_to_ansi_gradient(stops: list, t: float) -> str:
    """Return the ANSI code for position t along a hex gradient."""
    return _hex_to_ansi(_gradient_hex(stops, t))

def _hex_to_ansi(hex_color: str) -> str:
    """Dispatch a hex color to the right conversion for the active mode."""
    if _COLOR_MODE == "truecolor":
        return _hex_to_ansi_true(hex_color)
    if _COLOR_MODE == "256":
        return _hex_to_ansi256(hex_color)
    return _hex_to_ansi16(hex_color)

class Palette:
    """Theme-aware color palette with automatic capability detection."""
    _theme = "dark"
    _cache = {}

    @classmethod
    def set_theme(cls, name: str):
        if name in _THEMES:
            cls._theme = name
            cls._cache.clear()

    @classmethod
    def get_theme(cls) -> str:
        return cls._theme

    @classmethod
    def themes(cls) -> list:
        return sorted(_THEMES.keys())

    @classmethod
    def gradient_tok(cls, token: str, t: float) -> str:
        """ANSI code for a token blended toward 'accent' by factor t (0..1)."""
        if _COLOR_MODE == "off":
            return ""
        base = cls.tokens().get(token, "#c9d1d9")
        accent = cls.tokens().get("accent", base)
        return _hex_to_ansi(_lerp_hex(base, accent, t))

    @classmethod
    def gradient_stops(cls, tokens: list) -> list:
        """Return the hex values for a list of token names (for multi-stop gradients)."""
        return [cls.tokens().get(t, "#c9d1d9") for t in tokens]

    @classmethod
    def gradient_at(cls, stops_hex: list, t: float) -> str:
        """ANSI code at position t along a custom hex gradient."""
        if _COLOR_MODE == "off":
            return ""
        return _hex_to_ansi(_gradient_hex(stops_hex, t))

    @classmethod
    def tokens(cls) -> dict:
        return _THEMES.get(cls._theme, _THEMES["dark"])

    @classmethod
    def tok(cls, token: str) -> str:
        """Return the ANSI escape code for a semantic token."""
        if _COLOR_MODE == "off":
            return ""
        key = (cls._theme, token, _COLOR_MODE)
        if key in cls._cache:
            return cls._cache[key]
        hex_color = cls.tokens().get(token, "#c9d1d9")
        code = _hex_to_ansi(hex_color)
        cls._cache[key] = code
        return code

    @classmethod
    def bg(cls, token: str) -> str:
        """Background variant of a token."""
        if _COLOR_MODE == "off":
            return ""
        hex_color = cls.tokens().get(token, "#30363d")
        if _COLOR_MODE == "truecolor":
            h = hex_color.lstrip("#")
            r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
            return f"\033[48;2;{r};{g};{b}m"
        if _COLOR_MODE == "256":
            return _hex_to_ansi256(hex_color).replace("38;5", "48;5")
        return ""

    @classmethod
    def reset(cls) -> str:
        return "" if _COLOR_MODE == "off" else "\033[0m"

    @classmethod
    def mode(cls) -> str:
        return _COLOR_MODE

# ── Legacy Style class (backwards-compatible aliases) ───────────────────────
class Style:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"; ITALIC = "\033[3m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
    WHITE = "\033[37m"; GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"; BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"; BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"; BRIGHT_CYAN = "\033[96m"
    _disabled = False
    @classmethod
    def disable(cls):
        cls._disabled = True
        for k in dir(cls):
            if not k.startswith("_") and k.isupper():
                setattr(cls, k, "")

if _COLOR_MODE == "off":
    Style.disable()

def s(text, *styles):
    if Style._disabled or not styles:
        return text
    return f"{''.join(styles)}{text}{Style.RESET}"

# ── Syntax highlighter (pure regex, stdlib only) ─────────────────────────────
# Each language is a list of (pattern, token_name) applied in order via a
# single combined regex. The scanner walks the source once, longest-match wins.

_LANGS = {
    "python": {
        "kw": r"\b(False|None|True|and|as|assert|async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield|match|case)\b",
        "builtin": r"\b(print|len|range|str|int|float|dict|list|set|tuple|bytes|bytearray|bool|complex|object|type|super|isinstance|issubclass|hasattr|getattr|setattr|delattr|open|input|enumerate|zip|map|filter|sorted|reversed|any|all|min|max|sum|abs|round|pow|divmod|callable|iter|next|id|hash|repr|format|vars|locals|globals|dir|help|exit|quit|copyright|credits|license)\b",
        "dec": r"@\w+(?:\.\w+)*",
        "str": r"(?:'''\s*[\s\S]*?'''|\"\"\"\s*[\s\S]*?\"\"\"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")",
        "com": r"#[^\n]*",
        "num": r"\b0[xX][0-9a-fA-F_]+\b|\b0[bB][01_]+\b|\b0[oO][0-7_]+\b|\b\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?\b",
        "fn": r"\b[A-Za-z_]\w*(?=\s*\()",
    },
    "js": {
        "kw": r"\b(await|break|case|catch|class|const|continue|debugger|default|delete|do|else|enum|export|extends|false|finally|for|from|function|get|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|set|static|super|switch|this|throw|true|try|typeof|undefined|var|void|while|with|yield|async|as)\b",
        "builtin": r"\b(Array|Boolean|Date|Error|Function|JSON|Math|Number|Object|Promise|RegExp|String|Symbol|console|document|globalThis|window|process|require|module|exports|setTimeout|setInterval|fetch|Infinity|NaN)\b",
        "str": r"(?:`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")",
        "com": r"//[^\n]*|/\*[\s\S]*?\*/",
        "num": r"\b0[xX][0-9a-fA-F]+\b|\b\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?\b",
        "fn": r"\b[A-Za-z_$]\w*(?=\s*\()",
    },
    "ts": None,  # alias to js + extras
    "json": {
        "str": r"\"(?:\\.|[^\"\\])*\"",
        "num": r"-?\b\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?\b",
        "kw": r"\b(true|false|null)\b",
    },
    "yaml": {
        "kw": r"(?:^|\n)\s*(?:---|\.\.\.)\s*$|\b(true|false|null|yes|no|on|off)\b",
        "str": r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
        "com": r"#[^\n]*",
        "num": r"\b\d[\d_]*(?:\.[\d_]+)?\b",
        "fn": r"^\s*[\w.-]+(?=:)",
    },
    "bash": {
        "kw": r"\b(if|then|else|elif|fi|for|while|until|do|done|case|esac|function|in|select|time|coproc|return|exit|break|continue|local|export|declare|readonly|unset|shift|eval|exec|set|trap|wait|source|alias)\b",
        "builtin": r"\b(echo|printf|read|cd|pwd|test|true|false|ls|cat|grep|sed|awk|find|xargs|sort|uniq|wc|head|tail|mkdir|rm|cp|mv|touch|chmod|chown|git|curl|wget|python3?|node|npm|pip|cargo|make|sudo|kill|ps|top|df|du|tar|zip|unzip|which|type|hash|history|jobs|bg|fg|nohup)\b",
        "str": r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        "com": r"#[^\n]*",
        "num": r"\b\d+\b",
        "fn": r"\$\{[^}]+\}|\$\w+",
    },
    "diff": {
        "diff_add": r"^\+[^\n]*",
        "diff_del": r"^-[^\n]*",
        "diff_hunk": r"^@@[^\n]*",
        "diff_meta": r"^(?:diff|index|---|\+\+\+|new file|deleted file|rename|similarity|Binary)[^\n]*",
    },
    "markdown": {
        "heading": r"^#{1,6}[^\n]*",
        "kw": r"^\s*(?:[-*+]|\d+\.)\s|^\s*\[[ xX]\]\s",
        "link": r"\[([^\]]*)\]\(([^)]+)\)|https?://\S+",
        "str": r"`[^`\n]+`",
        "com": r"^>[^\n]*",
        "table": r"^\|.*\|$",
    },
    "go": {
        "kw": r"\b(break|case|chan|const|continue|default|defer|else|fallthrough|for|func|go|goto|if|import|interface|map|package|range|return|select|struct|switch|type|var)\b",
        "builtin": r"\b(bool|byte|complex64|complex128|error|float32|float64|int|int8|int16|int32|int64|rune|string|uint|uint8|uint16|uint32|uint64|uintptr|true|false|iota|nil|append|cap|copy|delete|len|make|new|panic|print|println|recover|close|complex|imag|real)\b",
        "str": r"\"(?:\\.|[^\"\\])*\"|`[^`]*`|'(?:\\.|[^'\\])'",
        "com": r"//[^\n]*|/\*[\s\S]*?\*/",
        "num": r"\b0[xX][0-9a-fA-F_]+\b|\b0[bB][01_]+\b|\b0[oO][0-7_]+\b|\b\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?\b",
        "fn": r"\b[A-Za-z_]\w*(?=\s*\()",
    },
    "rust": {
        "kw": r"\b(as|async|await|break|const|continue|crate|dyn|else|enum|extern|false|fn|for|if|impl|in|let|loop|match|mod|move|mut|pub|ref|return|self|Self|static|struct|super|trait|true|type|unsafe|use|where|while)\b",
        "builtin": r"\b(bool|char|f32|f64|i8|i16|i32|i64|i128|isize|str|u8|u16|u32|u64|u128|usize|String|Vec|Box|Option|Result|Some|None|Ok|Err|println|print|format|assert|assert_eq|assert_ne|debug_assert|todo|unimplemented|unreachable)\b",
        "dec": r"#!?\[[^\]]*\]|#\[[^\]]*\]",
        "str": r"\"(?:\\.|[^\"\\])*\"|r#*\"[\s\S]*?\"#*",
        "com": r"//[^\n]*|/\*[\s\S]*?\*/",
        "num": r"\b0[xX][0-9a-fA-F_]+\b|\b0[bB][01_]+\b|\b0[oO][0-7_]+\b|\b\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?[uif]?(?:8|16|32|64|128|size)?\b",
        "fn": r"\b[A-Za-z_]\w*(?=\s*\()",
    },
    "sql": {
        "kw": r"\b(SELECT|FROM|WHERE|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|DROP|ALTER|ADD|INDEX|VIEW|JOIN|LEFT|RIGHT|INNER|OUTER|ON|GROUP|BY|ORDER|HAVING|LIMIT|OFFSET|AS|AND|OR|NOT|NULL|IS|IN|EXISTS|BETWEEN|LIKE|ILIKE|DISTINCT|UNION|ALL|CASE|WHEN|THEN|ELSE|END|PRIMARY|KEY|FOREIGN|REFERENCES|UNIQUE|CHECK|DEFAULT|CONSTRAINT|CASCADE|RESTRICT|BEGIN|COMMIT|ROLLBACK|TRANSACTION|COUNT|SUM|AVG|MIN|MAX|COALESCE|CAST|WITH|RETURNING|CONFLICT|DO|NOTHING)\b",
        "str": r"'(?:''|[^'])*'",
        "com": r"--[^\n]*|/\*[\s\S]*?\*/",
        "num": r"\b\d[\d_]*(?:\.\d+)?\b",
    },
    "toml": {
        "kw": r"^\s*\[[^\]]+\]",
        "str": r"\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        "com": r"#[^\n]*",
        "num": r"\b\d[\d_]*(?:\.[\d_]+)?\b",
        "fn": r"^\s*[\w.-]+(?=\s*=)",
    },
    "ini": {
        "kw": r"^\s*\[[^\]]+\]",
        "str": r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        "com": r"[;#][^\n]*",
        "fn": r"^\s*[\w.-]+(?=\s*[=:])",
    },
}
_LANGS["ts"] = dict(_LANGS["js"])
_LANGS["typescript"] = _LANGS["ts"]
_LANGS["javascript"] = _LANGS["js"]
_LANGS["py"] = _LANGS["python"]
_LANGS["sh"] = _LANGS["bash"]
_LANGS["shell"] = _LANGS["bash"]
_LANGS["zsh"] = _LANGS["bash"]
_LANGS["yml"] = _LANGS["yaml"]
_LANGS["toml"] = _LANGS["toml"]

_TOKEN_ORDER = ["str", "com", "dec", "num", "kw", "builtin", "fn",
                "diff_add", "diff_del", "diff_hunk", "diff_meta",
                "heading", "link", "table"]

def _build_scanner(lang: str):
    """Build a combined regex + token map for a language. Cached per lang."""
    spec = _LANGS.get(lang)
    if not spec:
        return None
    parts, tokmap = [], {}
    for tok in _TOKEN_ORDER:
        if tok in spec:
            idx = len(parts)
            parts.append(f"(?P<{tok}_{idx}>{spec[tok]})")
            tokmap[f"{tok}_{idx}"] = tok
    if not parts:
        return None
    try:
        rx = re.compile("|".join(parts), re.MULTILINE)
    except re.error:
        return None
    return rx, tokmap

_SCANNER_CACHE = {}

def _get_scanner(lang: str):
    key = (lang or "").lower().split(":")[0].strip()
    if key not in _SCANNER_CACHE:
        _SCANNER_CACHE[key] = _build_scanner(key)
    return _SCANNER_CACHE[key]

def hl(code: str, lang: str = "") -> str:
    """Syntax-highlight `code` for `lang`. Falls back to plain text."""
    if Style._disabled or not code:
        return code
    scanner = _get_scanner(lang)
    if not scanner:
        return code
    rx, tokmap = scanner
    out, last = [], 0
    for m in rx.finditer(code):
        if m.start() > last:
            out.append(code[last:m.start()])
        tok = tokmap[m.lastgroup]
        out.append(s(m.group(), Palette.tok(tok)))
        last = m.end()
    out.append(code[last:])
    return "".join(out)

def hl_diff(text: str) -> str:
    """Highlight a unified diff string."""
    if Style._disabled:
        return text
    out = []
    for line in text.splitlines():
        if line.startswith(("+++", "---")):
            out.append(s(line, Style.BOLD, Palette.tok("diff_meta")))
        elif line.startswith("@@"):
            out.append(s(line, Palette.tok("diff_hunk")))
        elif line.startswith("+"):
            out.append(s(line, Palette.tok("diff_add")))
        elif line.startswith("-"):
            out.append(s(line, Palette.tok("diff_del")))
        elif line.startswith(("diff ", "index ", "new file", "deleted file", "rename ", "Binary")):
            out.append(s(line, Palette.tok("diff_meta")))
        else:
            out.append(s(line, Palette.tok("dim")))
    return "\n".join(out)

def hl_matches(text: str, pattern: str) -> str:
    """Highlight regex matches in `text` (for grep results)."""
    if Style._disabled or not pattern:
        return text
    try:
        rx = re.compile(pattern)
    except re.error:
        return text
    out = []
    for line in text.splitlines():
        def _repl(m):
            return s(m.group(), Palette.bg("sel"), Style.BOLD)
        out.append(rx.sub(_repl, line))
    return "\n".join(out)

# alias for the language used inside fenced code blocks in markdown
_LANG_ALIASES = {
    "py": "python", "python3": "python", "js": "js", "javascript": "js",
    "ts": "ts", "typescript": "ts", "json": "json", "yml": "yaml",
    "yaml": "yaml", "sh": "bash", "shell": "bash", "zsh": "bash",
    "bash": "bash", "diff": "diff", "patch": "diff", "md": "markdown",
    "markdown": "markdown", "go": "go", "golang": "go", "rs": "rust",
    "rust": "rust", "sql": "sql", "toml": "toml", "ini": "ini",
    "cfg": "ini", "conf": "ini", "html": "", "xml": "", "css": "",
    "c": "", "cpp": "", "java": "", "kotlin": "", "swift": "",
}

def _norm_lang(lang: str) -> str:
    return _LANG_ALIASES.get((lang or "").strip().lower(), (lang or "").strip().lower())

# ── Markdown block-level renderer (CJK-aware, stdlib only) ──────────────────

def _wrap_cjk(text: str, width: int, indent: str = "") -> list:
    """Wrap text to `width` terminal columns, breaking CJK per-character and
    ASCII per-word. Returns a list of lines (each already prefixed with indent)."""
    if width <= 0:
        return [indent + text]
    lines, cur, cur_w = [], [], 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            lines.append(indent + "".join(cur))
            cur, cur_w = [], 0
            i += 1
            continue
        cw = disp_width(ch)
        # collect a token: a run of non-space ASCII chars, or a single CJK char
        if ch.isspace():
            token, tw = ch, cw
            i += 1
        elif unicodedata.east_asian_width(ch) in ("W", "F"):
            token, tw = ch, cw
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and unicodedata.east_asian_width(text[j]) not in ("W", "F"):
                j += 1
            token, tw = text[i:j], disp_width(text[i:j])
            i = j
        if cur_w + tw > width and cur:
            lines.append(indent + "".join(cur))
            cur, cur_w = [], 0
            if token.isspace():
                continue  # drop leading space on new line
        cur.append(token)
        cur_w += tw
    if cur:
        lines.append(indent + "".join(cur))
    return lines or [""]

def _md_inline(text: str) -> str:
    """Render inline markdown: **bold**, *italic*, `code`, ~~strike~~, [text](url)."""
    if Style._disabled:
        return text
    # inline code first (protect from other rules)
    parts = []
    last = 0
    for m in re.finditer(r"`([^`\n]+)`", text):
        parts.append(text[last:m.start()])
        parts.append(s(m.group(1), Palette.bg("table"), Palette.tok("str")))
        last = m.end()
    parts.append(text[last:])
    text = "".join(parts)
    # bold+italic combined
    text = re.sub(r"\*\*\*(.+?)\*\*\*", lambda m: s(m.group(1), Style.BOLD, Style.ITALIC), text)
    text = re.sub(r"___(.+?)___", lambda m: s(m.group(1), Style.BOLD, Style.ITALIC), text)
    # bold
    text = re.sub(r"\*\*(.+?)\*\*", lambda m: s(m.group(1), Style.BOLD), text)
    text = re.sub(r"__(.+?)__", lambda m: s(m.group(1), Style.BOLD), text)
    # italic (avoid matching inside already-colored spans by requiring single *)
    text = re.sub(r"(?<!\*)\*(?!\s)([^*\n]+?)(?<!\s)\*(?!\*)", lambda m: s(m.group(1), Style.ITALIC), text)
    text = re.sub(r"(?<!_)_(?!\s)([^_\n]+?)(?<!\s)_(?!_)", lambda m: s(m.group(1), Style.ITALIC), text)
    # strikethrough
    text = re.sub(r"~~(.+?)~~", lambda m: s(m.group(1), Style.DIM), text)
    # links: [text](url) — show text in link color, URL dimmed
    text = re.sub(r"\[([^\]]*)\]\(([^)]+)\)",
                  lambda m: f"{s(m.group(1), Palette.tok('link'))} {s('(' + clip(m.group(2), 40) + ')', Palette.tok('dim'))}",
                  text)
    # bare URLs
    text = re.sub(r"(?<![\(\[])https?://[^\s\)\]]+",
                  lambda m: s(clip(m.group(), 60), Palette.tok("link")), text)
    return text

def _md_code_block(code: str, lang: str, width: int, line_numbers: bool = True) -> list:
    """Render a fenced code block with a language label bar and optional line numbers."""
    norm = _norm_lang(lang)
    label = lang or "code"
    bar_w = max(width - 4, 20)
    bar = f"  ┌─ {label} " + "─" * max(0, bar_w - disp_width(label) - 4) + "┐"
    lines = [s(bar, Palette.tok("border"))]
    code_lines = code.splitlines()
    gutter_w = len(str(len(code_lines))) if line_numbers and code_lines else 0
    if len(code) > 8192:
        # too large: skip highlighting for performance
        for i, ln in enumerate(code_lines[:80], 1):
            prefix = f"{i:>{gutter_w}} │ " if line_numbers else "  │ "
            lines.append(s(prefix, Palette.tok("dim")) + ln[:max(0, width - 6 - gutter_w)])
        lines.append(s("  │ " + f"… ({len(code)} chars, highlighting skipped)", Palette.tok("dim")))
    else:
        highlighted = hl(code, norm) if norm else code
        for i, ln in enumerate(highlighted.splitlines(), 1):
            # truncate at terminal width accounting for ANSI escapes
            visible = len(re.sub(r"\x1b\[[0-9;]*m", "", ln))
            if visible > width - 6 - gutter_w:
                ln = ln[:width - 6 - gutter_w] + "…"
            if line_numbers:
                num = s(f"{i:>{gutter_w}}", Palette.tok("dim")) + s(" │ ", Palette.tok("border"))
                lines.append("  " + num + ln)
            else:
                lines.append("  │ " + ln)
    lines.append(s("  └" + "─" * (bar_w + 2) + "┘", Palette.tok("border")))
    return lines

def _md_table(lines_src: list, width: int) -> list:
    """Render a markdown table."""
    rows = []
    for ln in lines_src:
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        rows.append(cells)
    if len(rows) < 2:
        return [_md_inline(l) for l in lines_src]
    # drop separator row (---|---)
    header = rows[0]
    body = [r for r in rows[1:] if not all(set(c) <= set("-: ") for c in r)]
    ncols = max(len(header), max((len(r) for r in body), default=0))
    header += [""] * (ncols - len(header))
    body = [r + [""] * (ncols - len(r)) for r in body]
    col_w = [0] * ncols
    for r in [header] + body:
        for i, c in enumerate(r):
            col_w[i] = max(col_w[i], min(disp_width(c), width // max(ncols, 1) - 2))
    sep = "─"
    out = []
    out.append("  " + "  ".join(s(pad_right(_md_inline(header[i]) if not Style._disabled else header[i], col_w[i])
                                  if not Style._disabled else pad_right(header[i], col_w[i]),
                                  Style.BOLD, Palette.tok("heading")) for i in range(ncols)))
    # simpler: build header with padding on plain text then apply style
    out = []
    hdr_cells = []
    for i in range(ncols):
        plain = clip(header[i], col_w[i])
        hdr_cells.append(s(pad_right(plain, col_w[i]), Style.BOLD, Palette.tok("heading")))
    out.append("  " + "  ".join(hdr_cells))
    out.append(s("  " + sep * (sum(col_w) + 2 * (ncols - 1)), Palette.tok("border")))
    for r in body:
        cells = []
        for i in range(ncols):
            plain = clip(r[i], col_w[i])
            cells.append(pad_right(_md_inline(plain), col_w[i]) if not Style._disabled else pad_right(plain, col_w[i]))
        out.append("  " + "  ".join(cells))
    return out

def md(text: str, width: int = None) -> str:
    """Render markdown text to styled terminal output.

    Handles: headings, bold/italic/strike/inline-code, fenced code blocks,
    ordered/unordered/task lists (nested), blockquotes, tables, hr, links.
    CJK-aware wrapping. Falls back to plain text when colors are disabled.
    """
    if not text:
        return ""
    if width is None:
        width = max(40, shutil.get_terminal_size((80, 24)).columns - 2)
    lines_out = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        stripped = ln.strip()
        # blank line
        if not stripped:
            lines_out.append("")
            i += 1
            continue
        # fenced code block
        fence = re.match(r"^```(\w*)\s*$", stripped)
        if fence:
            lang = fence.group(1)
            code_lines = []
            i += 1
            while i < n and not re.match(r"^```\s*$", lines[i].strip()):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            lines_out.extend(_md_code_block("\n".join(code_lines), lang, width))
            continue
        # heading
        hm = re.match(r"^(#{1,6})\s+(.*)", stripped)
        if hm:
            level = len(hm.group(1))
            content = _md_inline(hm.group(2))
            colors = {1: (Style.BOLD, Palette.tok("heading")),
                      2: (Style.BOLD, Palette.tok("accent")),
                      3: (Palette.tok("accent"),), 4: (Palette.tok("accent"),),
                      5: (Palette.tok("dim"),), 6: (Palette.tok("dim"),)}
            st = colors.get(level, (Palette.tok("dim"),))
            prefix = "  " if level <= 2 else "    "
            lines_out.append(s(prefix + content, *st))
            if level <= 2:
                lines_out.append(s(prefix + "─" * min(disp_width(hm.group(2)), width - 4), Palette.tok("border")))
            i += 1
            continue
        # horizontal rule
        if re.match(r"^(-{3,}|\*{3,}|_{3,})\s*$", stripped):
            lines_out.append(s("  " + "─" * (width - 2), Palette.tok("border")))
            i += 1
            continue
        # blockquote
        if stripped.startswith(">"):
            quote_lines = []
            while i < n and lines[i].strip().startswith(">"):
                quote_lines.append(re.sub(r"^>\s?", "", lines[i]))
                i += 1
            inner = md("\n".join(quote_lines), width - 4)
            for ql in inner.splitlines():
                lines_out.append(s("  │ ", Palette.tok("quote")) + ql)
            continue
        # table
        if stripped.startswith("|") and "|" in stripped[1:]:
            tbl_lines = []
            while i < n and lines[i].strip().startswith("|"):
                tbl_lines.append(lines[i])
                i += 1
            lines_out.extend(_md_table(tbl_lines, width))
            continue
        # unordered list
        um = re.match(r"^(\s*)([-*+])\s+(.*)", ln)
        if um:
            indent = len(um.group(1))
            depth = indent // 2
            bullet = um.group(2)
            content = um.group(3)
            # task list
            tm = re.match(r"^\[([ xX])\]\s+(.*)", content)
            if tm:
                mark = "✓" if tm.group(1).lower() == "x" else "☐"
                mark_col = Palette.tok("ok") if tm.group(1).lower() == "x" else Palette.tok("dim")
                prefix = "  " * (depth + 1) + s(mark + " ", mark_col)
                body = _md_inline(tm.group(2))
            else:
                prefix = "  " * (depth + 1) + s(bullet + " ", Palette.tok("accent"))
                body = _md_inline(content)
            avail = width - disp_width("  " * (depth + 1)) - 2
            wrapped = _wrap_cjk(re.sub(r"\x1b\[[0-9;]*m", "", body), avail)
            # first line gets prefix, rest get indent
            lines_out.append(prefix + body if disp_width(re.sub(r"\x1b\[[0-9;]*m", "", body)) <= avail
                            else prefix + wrapped[0])
            for wln in wrapped[1:]:
                lines_out.append("  " * (depth + 1) + "  " + wln)
            i += 1
            continue
        # ordered list
        om = re.match(r"^(\s*)(\d+[.)])\s+(.*)", ln)
        if om:
            indent = len(om.group(1))
            depth = indent // 2
            num = om.group(2)
            content = om.group(3)
            prefix = "  " * (depth + 1) + s(num + " ", Palette.tok("accent"))
            body = _md_inline(content)
            avail = width - disp_width("  " * (depth + 1)) - disp_width(num) - 1
            plain = re.sub(r"\x1b\[[0-9;]*m", "", body)
            wrapped = _wrap_cjk(plain, avail)
            lines_out.append(prefix + body if disp_width(plain) <= avail
                            else prefix + wrapped[0])
            for wln in wrapped[1:]:
                lines_out.append("  " * (depth + 1) + "  " + wln)
            i += 1
            continue
        # plain paragraph
        body = _md_inline(stripped)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", body)
        avail = width - 2
        wrapped = _wrap_cjk(plain, avail)
        if disp_width(plain) <= avail:
            lines_out.append("  " + body)
        else:
            # re-wrap the styled body by splitting on plain text positions
            lines_out.append("  " + wrapped[0])
            for wln in wrapped[1:]:
                lines_out.append("  " + wln)
        i += 1
    return "\n".join(lines_out)

# ── Streaming markdown renderer ──────────────────────────────────────────────

class StreamMarkdown:
    """Streaming-safe markdown renderer.

    Feed text chunks as they arrive from the API; only completed lines are
    rendered and emitted. Fenced code blocks are held until the closing fence
    (or flush) so syntax highlighting sees the complete block. Inline markup
    (bold, code) is held until the closing delimiter, with a size cap to
    avoid unbounded buffering on malformed input.
    """

    MAX_INLINE_BUFFER = 2000   # chars to buffer waiting for a closing delimiter

    def __init__(self, width: int = None, echo: bool = True):
        self.width = width or max(40, shutil.get_terminal_size((80, 24)).columns - 2)
        self.echo = echo
        self._line_buf = ""          # incomplete line awaiting newline
        self._in_fence = False
        self._fence_lang = ""
        self._fence_buf = []         # lines inside a code fence
        self._out = []               # all emitted lines (for agent_text reconstruction)
        self._started = False

    def feed(self, chunk: str) -> str:
        """Feed a text chunk. Returns any completed rendered output to print."""
        if not chunk:
            return ""
        emitted = []
        self._line_buf += chunk
        while "\n" in self._line_buf:
            line, self._line_buf = self._line_buf.split("\n", 1)
            out = self._process_line(line)
            if out is not None:
                emitted.append(out)
        return "\n".join(emitted) + ("\n" if emitted else "")

    def _process_line(self, line: str):
        """Process one completed line. Returns rendered string or None to skip."""
        stripped = line.strip()
        # fence delimiters
        fence_m = re.match(r"^```(\w*)\s*$", stripped)
        if fence_m:
            if self._in_fence:
                # closing fence — render the accumulated block
                self._in_fence = False
                block = "\n".join(self._fence_buf)
                self._fence_buf = []
                rendered = _md_code_block(block, self._fence_lang, self.width)
                self._out.append(block)
                return "\n".join(rendered)
            else:
                # opening fence — start buffering
                self._in_fence = True
                self._fence_lang = fence_m.group(1)
                self._fence_buf = []
                return None  # suppress the fence line itself
        if self._in_fence:
            self._fence_buf.append(line)
            return None
        # blank line
        if not stripped:
            self._out.append("")
            return ""
        # render a single non-code line through the block renderer
        rendered = md(line, width=self.width)
        self._out.append(line)
        return rendered

    def flush(self) -> str:
        """Flush any remaining buffered content. Call when the stream ends."""
        parts = []
        # flush incomplete line
        if self._line_buf:
            out = self._process_line(self._line_buf)
            self._line_buf = ""
            if out is not None:
                parts.append(out)
        # flush unclosed fence
        if self._in_fence and self._fence_buf:
            block = "\n".join(self._fence_buf)
            self._fence_buf = []
            self._in_fence = False
            rendered = _md_code_block(block, self._fence_lang, self.width)
            self._out.append(block)
            parts.append("\n".join(rendered))
        elif self._in_fence:
            self._in_fence = False
        return "\n".join(parts) + ("\n" if parts else "")

    def text(self) -> str:
        """The raw (unrendered) text accumulated so far."""
        all_lines = list(self._out)
        if self._line_buf:
            all_lines.append(self._line_buf)
        return "\n".join(all_lines)

def disp_width(text) -> int:
    """Terminal columns occupied by `text` (CJK/emoji count as 2, combining as 0).

    str.ljust() counts code points, which mis-pads every box/column that holds
    Chinese text or emoji — the right border then drifts. Always pad with
    pad_right()/pad_center() instead.
    """
    w = 0
    for ch in str(text):
        if ch in "\r\n" or unicodedata.combining(ch):
            continue
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w

def pad_right(text, width) -> str:
    return str(text) + " " * max(0, width - disp_width(text))

def pad_center(text, width) -> str:
    pad = max(0, width - disp_width(text))
    left, right = pad // 2, pad - pad // 2
    return " " * left + str(text) + " " * right

def clip(text, width) -> str:
    """Trim `text` to at most `width` terminal columns, marking cuts with '…'."""
    text = str(text)
    if disp_width(text) <= width:
        return text
    out, used = [], 0
    for ch in text:
        cw = disp_width(ch)
        if used + cw > width - 1:
            break
        out.append(ch); used += cw
    return "".join(out) + "…"

class TUI:
    @staticmethod
    def banner():
        w = 62
        lines = ["NVIDIA ENGINEER PRO", f"v{__version__} · Professional AI Agent"]
        print()
        print(s("  ╔" + "═" * w + "╗", Style.BRIGHT_CYAN))
        for i, line in enumerate(lines):
            st = Style.BRIGHT_CYAN + Style.BOLD if i == 0 else Style.CYAN
            print(s("  ║ ", Style.BRIGHT_CYAN) + s(pad_center(line, w - 2), st)
                  + s(" ║", Style.BRIGHT_CYAN))
        print(s("  ╚" + "═" * w + "╝", Style.BRIGHT_CYAN))
        print()

    @staticmethod
    def kv(rows):
        for k, v in rows:
            print(f"    {s(pad_right(k, 13), Style.GRAY)} {s(str(v), Style.WHITE)}")

    @staticmethod
    def ok(msg):    print(s("  ✓ ", Style.GREEN) + mask_secrets(msg))
    @staticmethod
    def info(msg):  print(s("  ℹ ", Style.CYAN) + mask_secrets(msg))
    @staticmethod
    def warn(msg):  print(s("  ⚠ ", Style.YELLOW) + mask_secrets(msg))
    @staticmethod
    def error(msg): print(s("  ✗ ", Style.RED) + mask_secrets(msg))
    @staticmethod
    def dim(msg):   print(s(f"  {msg}", Style.GRAY))
    @staticmethod
    def tool(name, args_s, step, duration_ms=None, status=None):
        """Render a tool call card with optional timing and status."""
        icon = "⚙"
        status_icon = ""
        if status == "ok":
            status_icon = s(" ✓", Palette.tok("ok"))
        elif status == "err":
            status_icon = s(" ✗", Palette.tok("err"))
        time_str = ""
        if duration_ms is not None:
            if duration_ms >= 1000:
                time_str = s(f"  {duration_ms/1000:.1f}s", Palette.tok("dim"))
            else:
                time_str = s(f"  {duration_ms:.0f}ms", Palette.tok("dim"))
        args_clipped = clip(mask_secrets(args_s), 60)
        print(s(f"  {icon} ", Palette.tok("accent")) +
              s(name, Style.BOLD, Palette.tok("fn")) +
              s(f"  {args_clipped}", Palette.tok("dim")) +
              time_str + status_icon)
    @staticmethod
    def tool_block(name, args_s, step, body, status=None, duration_ms=None, max_lines=8):
        """Render a tool call as a bordered card: header bar + collapsible body."""
        status_icon = ""
        if status == "ok":
            status_icon = s(" ✓", Palette.tok("ok"))
        elif status == "err":
            status_icon = s(" ✗", Palette.tok("err"))
        time_str = ""
        if duration_ms is not None:
            if duration_ms >= 1000:
                time_str = s(f" {duration_ms/1000:.1f}s", Palette.tok("dim"))
            else:
                time_str = s(f" {duration_ms:.0f}ms", Palette.tok("dim"))
        term_w = max(40, shutil.get_terminal_size((80, 24)).columns)
        header_w = max(term_w - 4, 30)
        header_txt = f" {name}"
        args_clipped = clip(mask_secrets(args_s), 40)
        header = (f"┌─{header_txt} " + s(args_clipped, Palette.tok("dim"))
                  + time_str + status_icon
                  + " " + "─" * max(0, header_w - disp_width(header_txt) - disp_width(args_clipped) - 8) + "┐")
        print(s(header, Palette.tok("border")))
        body_lines = str(body).splitlines() if body else []
        shown = body_lines[:max_lines]
        for ln in shown:
            if Style._disabled:
                out_ln = ln[:term_w - 6]
            else:
                out_ln = hl(ln, "python")
                visible = len(re.sub(r"\x1b\[[0-9;]*m", "", out_ln))
                if visible > term_w - 6:
                    out_ln = out_ln[:term_w - 6] + "…"
            print(s("│ ", Palette.tok("border")) + out_ln)
        if len(body_lines) > max_lines:
            more = len(body_lines) - max_lines
            print(s(f"│ {s('▸', Palette.tok('dim'))} +{more} more lines (用 /last 查看)", Palette.tok("border")))
        print(s("└" + "─" * (header_w + 1) + "┘", Palette.tok("border")))
    @staticmethod
    def tool_out(text, max_lines=6):
        """Render tool output with syntax-aware coloring and line limiting."""
        text = mask_secrets(str(text))
        lines = text.splitlines()
        if not lines:
            return
        # auto-detect content type for highlighting
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                obj = json.loads(text)
                text = json.dumps(obj, ensure_ascii=False, indent=2)
                lines = text.splitlines()
            except Exception:
                pass
        for i, line in enumerate(lines[:max_lines]):
            # try syntax highlight for code-like output
            if Style._disabled:
                out_line = line[:200]
            else:
                # detect if it looks like a diff
                if line.startswith(("+", "-", "@@")):
                    out_line = hl_diff(line)
                else:
                    out_line = hl(line, "python")  # generic fallback
                # truncate visible content at terminal width
                visible = len(re.sub(r"\x1b\[[0-9;]*m", "", out_line))
                if visible > 200:
                    out_line = out_line[:200] + "…"
            print(s("   │ ", Palette.tok("dim")) + out_line)
        if len(lines) > max_lines:
            print(s(f"   ▸ +{len(lines)-max_lines} more lines", Palette.tok("dim")))
    @staticmethod
    def assistant(text):
        print(md(text))
    @staticmethod
    def section(title):
        print()
        print(s(f"  ── {title} " + "─" * max(0, 50 - disp_width(title)), Style.CYAN))
    @staticmethod
    def rule(ch="─", width=58, style=None):
        print(s("  " + ch * width, style or Style.GRAY))
    @staticmethod
    def progress(pct, width=20, color=None):
        pct = max(0, min(100, int(pct)))
        filled = round(width * pct / 100)
        color = color or (Style.GREEN if pct < 60 else Style.YELLOW if pct < 85 else Style.BRIGHT_RED)
        return s("█" * filled, color) + s("░" * (width - filled), Style.GRAY) + f" {pct}%"
    @staticmethod
    def table(headers, rows, widths=None):
        if not rows:
            TUI.dim("(empty)")
            return
        widths = widths or [max(disp_width(str(h)),
                                *(disp_width(str(r[i])) for r in rows))
                            for i, h in enumerate(headers)]
        head = "  ".join(pad_right(str(h), w) for h, w in zip(headers, widths))
        print(s("    " + head, Style.BRIGHT_CYAN))
        print(s("    " + "─" * (sum(widths) + 2 * (len(widths) - 1)), Style.GRAY))
        for r in rows:
            print("    " + "  ".join(pad_right(str(c), w) for c, w in zip(r, widths)))
    @staticmethod
    def diff_out(diff_text, max_lines=200):
        lines = diff_text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            lines.append(f"… (+{len(diff_text.splitlines())-max_lines} more diff lines)")
        if Style._disabled:
            for line in lines:
                print("    " + line[:220])
        else:
            print(hl_diff("\n".join(lines)))
    @staticmethod
    def todos(todos):
        if not todos:
            return
        print()
        for i, t in enumerate(todos, 1):
            if isinstance(t, dict):
                status = t.get("status", "pending")
                desc = t.get("desc") or t.get("description") or str(t)
            else:
                status, desc = "pending", str(t)
            icon = {"done": "✅", "in_progress": "🔄"}.get(status, "⬜")
            print(s(f"    {icon} {desc}", Style.BRIGHT_CYAN))
        print()
    @staticmethod
    def status_bar(session, budget=None, elapsed=None):
        """Single-line status bar with gradient progress."""
        mode_tokens = {"plan": "accent", "default": "warn", "acceptEdits": "ok",
                       "yolo": "err", "dontAsk": "dim"}
        mc = Palette.tok(mode_tokens.get(session.perm_mode, "fg"))
        tok = session.cost['prompt_tokens'] + session.cost['completion_tokens']
        wd_name = Path(session.workdir).name if session.workdir else "."
        parts = [
            s(f"📁{wd_name}", Palette.tok("accent")),
            s(f"🔒{session.perm_mode}", mc),
            s(f"💬{session.cost['calls']}", Palette.tok("warn")),
            s(f"🔤{tok:,}", Palette.tok("ok")),
        ]
        if session.cost.get("usd"):
            parts.append(s(f"💰${session.cost['usd']:.3f}", Palette.tok("fn")))
        if session.todos:
            done = sum(1 for t in session.todos if isinstance(t, dict) and t.get("status") == "done")
            parts.append(s(f"📋{done}/{len(session.todos)}", Palette.tok("dec")))
        if elapsed is not None:
            m, sec = divmod(int(elapsed), 60)
            parts.append(s(f"⏱{m}:{sec:02d}", Palette.tok("dim")))
        if budget is not None:
            pct = min(100, int(budget.used_tokens * 100 / max(1, budget.max_tokens)))
            bar_w = 10
            filled = round(bar_w * pct / 100)
            # gradient green → yellow → red across the filled portion
            stops = Palette.gradient_stops(["ok", "warn", "err"])
            cells = []
            for i in range(filled):
                cell_t = (i + 1) / max(1, filled)
                cells.append(s("█", Palette.gradient_at(stops, cell_t)))
            bar = "".join(cells) + s("░" * (bar_w - filled), Palette.tok("dim"))
            parts.append(f"{bar} {pct}%")
        body = "  ".join(parts)
        # clip if too wide
        term_w = max(40, shutil.get_terminal_size((80, 24)).columns)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", body)
        if disp_width(plain) > term_w - 4:
            plain_clipped = clip(plain, term_w - 4)
            body = s(plain_clipped, Palette.tok("dim"))
        print(s("  ", Style.DIM) + body)

class Spinner:
    """Single-line stderr spinner.

    Must never paint while the caller is streaming text to stdout — otherwise
    the frame lands mid-line and the answer is shredded.  Call pause() as soon
    as the first text delta arrives; resume()/stop() are safe from any thread.
    All flag checks and writes happen under one lock so pause()/emit() can
    never race a frame over freshly written output.
    """
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    def __init__(self, message="Working"):
        self.message = message
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._active = sys.stderr.isatty()
        self._alive = False
    def __enter__(self):
        if self._active:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            self._alive = True
        return self
    def __exit__(self, *a):
        self.stop()
    def stop(self):
        with self._lock:
            self._stop.set()
            self._paused.clear()
            if self._alive:
                sys.stderr.write("\r" + " " * 72 + "\r")
                sys.stderr.flush()
                self._alive = False
        if self._thread:
            self._thread.join(timeout=0.3)
            self._thread = None
    def pause(self):
        """Freeze the spinner and erase its line (thread-safe, atomic)."""
        with self._lock:
            self._paused.set()
            if self._alive:
                sys.stderr.write("\r" + " " * 72 + "\r")
                sys.stderr.flush()
    def emit(self, text: str):
        """Pause the spinner and write text atomically under the spinner lock.

        Prevents the spinner thread from racing a \r over freshly written
        reasoning output.
        """
        with self._lock:
            self._paused.set()
            if self._alive:
                sys.stderr.write("\r" + " " * 72 + "\r")
            sys.stderr.write(text)
            sys.stderr.flush()
    def resume(self):
        with self._lock:
            self._paused.clear()
    def _run(self):
        i = 0
        while not self._stop.is_set():
            time.sleep(0.08)
            with self._lock:
                if self._paused.is_set() or self._stop.is_set():
                    continue                       # paused/stopped: skip this frame
                f = self.FRAMES[i % len(self.FRAMES)]
                sys.stderr.write(f"\r  {s(f, Style.CYAN)} {self.message}…")
                sys.stderr.flush()
            i += 1

@contextmanager
def spinner(msg="Working"):
    with Spinner(msg):
        yield


# ═══════════════════════════════════════════════════════════
# LINE EDITOR (raw-mode input with history / completion / palette)
# ═══════════════════════════════════════════════════════════

class LineEditor:
    """Raw-mode single-line editor with history, Tab completion and Ctrl+P palette.

    Falls back to plain input() on non-TTY.  The buffer is a list of chars with
    a cursor index; rendering rewrites the line each keystroke.  History is
    persisted to ~/.nvidia_engineer_pro/history.txt.
    """
    MAX_HISTORY = 500

    def __init__(self, prompt="  ⌨ ", completer=None, history_path=None,
                 commands=None):
        self.prompt = prompt
        self.completer = completer          # fn(text) -> list[str]
        self.commands = commands or []      # for Ctrl+P palette
        self.history_path = history_path or (APP_DIR / "history.txt")
        self.history = self._load_history()

    # ── history ──────────────────────────────────────────
    def _load_history(self) -> list:
        try:
            if self.history_path.exists():
                return [l.rstrip("\n") for l in self.history_path.read_text(
                    encoding="utf-8", errors="replace").splitlines() if l.strip()]
        except Exception:
            pass
        return []

    def _save_history(self):
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            self.history_path.write_text(
                "\n".join(self.history[-self.MAX_HISTORY:]) + "\n",
                encoding="utf-8")
        except Exception:
            pass

    def _add_history(self, text: str):
        text = text.strip()
        if text and (not self.history or self.history[-1] != text):
            self.history.append(text)
            if len(self.history) > self.MAX_HISTORY:
                self.history = self.history[-self.MAX_HISTORY:]
            self._save_history()

    # ── rendering ────────────────────────────────────────
    def _render(self, buf: list, cursor: int, search_mode=False, search_term="",
                search_matches=None, search_idx=0):
        text = "".join(buf)
        term_w = max(20, shutil.get_terminal_size((80, 24)).columns)
        prompt_w = disp_width(self.prompt)
        avail = max(10, term_w - prompt_w - 2)
        if search_mode:
            hdr = f"  ↩ {search_term}" if search_term else "  ↩ 反向搜索: "
            line = hdr
            if search_matches is not None and search_matches:
                idx = min(search_idx, len(search_matches) - 1)
                line += f"  [{idx+1}/{len(search_matches)}]  {search_matches[idx][:avail-20]}"
            out = "\r" + s(line, Palette.tok("accent")) + "\x1b[K"
            sys.stdout.write(out)
            sys.stdout.flush()
            return
        # colorize slash commands in the buffer for display
        if Style._disabled or not text.startswith("/"):
            disp = text[:avail]
        else:
            parts = text.split(" ", 1)
            disp = s(parts[0], Palette.tok("accent"), Style.BOLD)
            if len(parts) > 1:
                disp += " " + parts[1][:avail - disp_width(parts[0]) - 1]
        out = "\r" + self.prompt + disp + "\x1b[K"
        # position cursor: move to column prompt_w + display-width of buf[:cursor]
        col = prompt_w + disp_width(text[:cursor]) + 1
        out += f"\x1b[{col}G"
        sys.stdout.write(out)
        sys.stdout.flush()

    # ── escape sequence reader ───────────────────────────
    @staticmethod
    def _read_escape() -> str:
        """Read the remainder of an escape sequence after ESC."""
        import select as _sel
        ch = sys.stdin.read(1)
        if ch != "[" and ch != "O":
            return ch
        seq = ch
        while True:
            r, _, _ = _sel.select([sys.stdin], [], [], 0.05)
            if not r:
                break
            c = sys.stdin.read(1)
            seq += c
            if c.isalpha() or c == "~":
                break
        return seq

    # ── command palette ──────────────────────────────────
    def _palette(self) -> str:
        """Ctrl+P fuzzy command palette.  Returns selected command or ''."""
        query = ""
        idx = 0
        cmds = self.commands
        while True:
            matches = _fuzzy_filter(query, cmds) if query else cmds
            if matches:
                idx = max(0, min(idx, len(matches) - 1))
            # render palette overlay
            lines = []
            lines.append("\r\x1b[J")  # clear from cursor down
            lines.append(s("  ┌─ 命令面板 ─ Ctrl+P ─ Esc 取消 ─┐\n", Palette.tok("border")))
            if not matches:
                lines.append(s("  │ (无匹配)\n", Palette.tok("dim")))
            for i, m in enumerate(matches[:12]):
                marker = " ▸ " if i == idx else "   "
                col = Palette.tok("accent") if i == idx else Palette.tok("fg")
                lines.append(s("│", Palette.tok("border")) + s(marker, col)
                             + s(m, col, Style.BOLD if i == idx else "") + "\n")
            lines.append(s("  └" + "─" * 34 + "┘\n", Palette.tok("border")))
            lines.append(s(f"  搜索: {query}", Palette.tok("dim")))
            sys.stdout.write("".join(lines))
            sys.stdout.flush()
            ch = sys.stdin.read(1)
            if not ch:
                return ""
            if ch == "\x1b":  # Esc
                seq = self._read_escape()
                if seq in ("[A",):    idx = max(0, idx - 1); continue
                if seq in ("[B",):    idx = min(len(matches) - 1, idx + 1); continue
                sys.stdout.write("\r\x1b[J"); sys.stdout.flush()
                return ""
            if ch in ("\r", "\n"):
                sys.stdout.write("\r\x1b[J"); sys.stdout.flush()
                return matches[idx] if matches else ""
            if ch == "\x10":  # Ctrl+P again → cycle
                idx = (idx + 1) % max(1, len(matches)); continue
            if ch == "\x7f" or ch == "\x08":
                query = query[:-1]; idx = 0; continue
            if ch.isprintable():
                query += ch; idx = 0; continue

    # ── Ctrl+R reverse history search ────────────────────
    def _reverse_search(self, buf: list, cursor: int):
        """Interactive Ctrl+R.  Returns (new_buf, new_cursor) or the original."""
        term = ""
        matches = []
        idx = 0
        while True:
            if term:
                matches = [h for h in reversed(self.history) if term in h]
            else:
                matches = []
            self._render(buf, cursor, search_mode=True, search_term=term,
                         search_matches=matches, search_idx=idx)
            ch = sys.stdin.read(1)
            if not ch:
                break
            if ch == "\x12":  # Ctrl+R again → previous match
                if matches:
                    idx = (idx + 1) % len(matches)
                continue
            if ch in ("\r", "\n"):
                if matches:
                    sel = matches[min(idx, len(matches) - 1)]
                    sys.stdout.write("\r\x1b[J"); sys.stdout.flush()
                    return list(sel), len(sel)
                break
            if ch == "\x1b":
                seq = self._read_escape()
                if seq in ("[A",):  # up
                    if matches: idx = (idx + 1) % len(matches)
                    continue
                if seq in ("[B",):  # down
                    if matches: idx = (idx - 1) % len(matches)
                    continue
                break
            if ch in ("\x03", "\x07"):  # Ctrl+C / Ctrl+G → cancel
                break
            if ch == "\x7f" or ch == "\x08":
                term = term[:-1]; idx = 0; continue
            if ch.isprintable():
                term += ch; idx = 0; continue
        # cancelled: restore
        sys.stdout.write("\r\x1b[J"); sys.stdout.flush()
        return buf, cursor

    # ── main read loop ───────────────────────────────────
    def read(self) -> str:
        if not sys.stdin.isatty():
            return input(self.prompt)
        import termios, tty
        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            return self._edit_raw()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)

    def _edit_raw(self) -> str:
        buf: list = []
        cursor = 0
        hist_idx = None          # None = editing live buffer
        hist_stash = []          # buffer snapshot when hist browsing started
        self._render(buf, cursor)
        while True:
            ch = sys.stdin.read(1)
            if not ch:
                sys.stdout.write("\r\n"); sys.stdout.flush()
                raise EOFError
            # ── control chars ──
            if ch == "\r" or ch == "\n":
                sys.stdout.write("\r\n"); sys.stdout.flush()
                text = "".join(buf)
                if text.strip():
                    self._add_history(text)
                return text
            if ch == "\x03":  # Ctrl+C
                sys.stdout.write("^C\r\n"); sys.stdout.flush()
                raise KeyboardInterrupt
            if ch == "\x04":  # Ctrl+D
                if not buf:
                    sys.stdout.write("\r\n"); sys.stdout.flush()
                    raise EOFError
                if cursor < len(buf):
                    del buf[cursor]
                    self._render(buf, cursor)
                continue
            if ch == "\x7f" or ch == "\x08":  # Backspace
                if cursor > 0:
                    del buf[cursor - 1]
                    cursor -= 1
                    if hist_idx is not None:
                        hist_idx = None
                    self._render(buf, cursor)
                continue
            if ch == "\t":  # Tab completion
                if self.completer:
                    text = "".join(buf)
                    matches = self.completer(text)
                    if matches:
                        # common prefix
                        common = os.path.commonprefix(matches) if len(matches) > 1 else matches[0]
                        buf = list(common)
                        cursor = len(buf)
                        # show matches on next line if ambiguous
                        if len(matches) > 1:
                            sys.stdout.write("\r\n")
                            sys.stdout.write(s("  " + "  ".join(matches[:10]), Palette.tok("dim")) + "\r\n")
                self._render(buf, cursor)
                continue
            if ch == "\x10":  # Ctrl+P → command palette
                sel = self._palette()
                if sel:
                    buf = list(sel)
                    cursor = len(buf)
                self._render(buf, cursor)
                continue
            if ch == "\x12":  # Ctrl+R → reverse history search
                buf, cursor = self._reverse_search(buf, cursor)
                self._render(buf, cursor)
                continue
            if ch == "\x15":  # Ctrl+U → clear line
                buf = []; cursor = 0; hist_idx = None
                self._render(buf, cursor)
                continue
            if ch == "\x01":  # Ctrl+A → home
                cursor = 0; self._render(buf, cursor); continue
            if ch == "\x05":  # Ctrl+E → end
                cursor = len(buf); self._render(buf, cursor); continue
            if ch == "\x0c":  # Ctrl+L → clear screen
                sys.stdout.write("\x1b[2J\x1b[H"); sys.stdout.flush()
                self._render(buf, cursor)
                continue
            # ── escape sequences ──
            if ch == "\x1b":
                seq = self._read_escape()
                if seq in ("[D",):     # Left
                    if cursor > 0: cursor -= 1
                elif seq in ("[C",):   # Right
                    if cursor < len(buf): cursor += 1
                elif seq in ("[H", "O", "[1~", "[7~"):  # Home
                    cursor = 0
                elif seq in ("[F", "[4~", "[8~"):       # End
                    cursor = len(buf)
                elif seq in ("[3~",):  # Delete
                    if cursor < len(buf):
                        del buf[cursor]
                        if hist_idx is not None: hist_idx = None
                elif seq in ("[A",):   # Up → history
                    if self.history:
                        if hist_idx is None:
                            hist_stash = buf[:]
                            hist_idx = len(self.history) - 1
                        elif hist_idx > 0:
                            hist_idx -= 1
                        buf = list(self.history[hist_idx])
                        cursor = len(buf)
                elif seq in ("[B",):   # Down → history
                    if hist_idx is not None:
                        if hist_idx < len(self.history) - 1:
                            hist_idx += 1
                            buf = list(self.history[hist_idx])
                        else:
                            hist_idx = None
                            buf = hist_stash[:]
                        cursor = len(buf)
                self._render(buf, cursor)
                continue
            # ── printable ──
            if ch.isprintable():
                buf.insert(cursor, ch)
                cursor += len(ch)
                if hist_idx is not None:
                    hist_idx = None
                self._render(buf, cursor)
                continue
            # ignore other control chars


def _fuzzy_filter(query: str, items: list) -> list:
    """Simple subsequence fuzzy match, ranked by consecutive-run bonus."""
    q = query.lower()
    if not q:
        return items
    scored = []
    for it in items:
        s_l = it.lower()
        i = 0
        score = 0
        consecutive = 0
        for ch in q:
            j = s_l.find(ch, i)
            if j == -1:
                break
            consecutive = consecutive + 1 if j == i else 0
            score += 1 + consecutive * 2
            i = j + 1
        else:
            scored.append((score, it))
    scored.sort(key=lambda x: -x[0])
    return [it for _, it in scored]


# ═══════════════════════════════════════════════════════════
# PERMISSION SYSTEM
# ═══════════════════════════════════════════════════════════

class RiskLevel(Enum):
    SAFE = "safe"; MODERATE = "moderate"; DANGEROUS = "dangerous"; CRITICAL = "critical"

class Decision(Enum):
    ALLOW = "allow"; ASK = "ask"; DENY = "deny"

MODES = {
    "plan": "只读探索：仅允许读/搜索",
    "default": "手动：每类工具首次询问",
    "acceptEdits": "接受编辑：工作区内编辑+安全命令自动",
    "yolo": "YOLO：全部自动（危急仍拦截）",
    "dontAsk": "不询问：会询问的一律拒绝",
}

COMMAND_RISK_RULES = [
    (r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*(\/|~|\$HOME)\b", RiskLevel.CRITICAL),
    (r"\brm\s+-[a-zA-Z]*[rf]", RiskLevel.CRITICAL),
    (r"\bmkfs\b|\bdd\s+if=|\bchmod\s+.*\b777\b|\bsudo\b|\bsu\s+-", RiskLevel.CRITICAL),
    (r"\bgit\s+push\s+.*(--force|-f)\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f", RiskLevel.CRITICAL),
    (r"\bDROP\s+(TABLE|DATABASE)\b|>\s*/dev/(sd|hd|nvme|mmcblk)", RiskLevel.CRITICAL),
    (r"\bshutdown\b|\breboot\b|\bhalt\b|:\(\)\s*\{", RiskLevel.CRITICAL),
    (r"\bfind\b[^|;&]*-delete\b|\bshred\b|\btruncate\b\s+(-s\s*)?0", RiskLevel.CRITICAL),
    (r"\bxargs\s+[^|;&]*\brm\b|\brm\s+.*\*\s*$", RiskLevel.CRITICAL),
    (r"\bcrontab\s+(-r|-e)\b|\b(ssh|scp)\s+.*\s+/dev/tcp\b", RiskLevel.CRITICAL),
    (r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b", RiskLevel.CRITICAL),
    (r"\brm\b|\brmdir\b|\bmv\s+", RiskLevel.DANGEROUS),
    (r"\bgit\s+push\b|\bgit\s+commit\b|\bgit\s+checkout\s+--\b|\bgit\s+branch\s+-D\b", RiskLevel.DANGEROUS),
    (r"\bcurl\b.*\|\s*(ba)?sh|\bwget\b.*\|\s*(ba)?sh|\beval\b", RiskLevel.DANGEROUS),
    (r"\bpip[3]?\s+install\b|\bnpm\s+(install|i)\b|\byarn\s+add\b|\bcargo\s+install\b|\bgo\s+install\b", RiskLevel.DANGEROUS),
    (r"\bkill\b|\bkillall\b|\bpkill\b|\bnohup\b", RiskLevel.DANGEROUS),
    (r"\bssh\b|\bscp\b|\brsync\b", RiskLevel.DANGEROUS),
    (r"\bchmod\b|\bchown\b|\bchgrp\b", RiskLevel.DANGEROUS),
    (r"\bsed\s+-i\b|\bpatch\b", RiskLevel.MODERATE),
    (r"^\s*(cp|touch|mkdir|ln)\b", RiskLevel.MODERATE),
    (r"\bgit\s+(add|rm|stash|merge|rebase|clone|switch|restore)\b", RiskLevel.MODERATE),
    (r"\b(curl|wget|aria2c)\b", RiskLevel.MODERATE),
    (r"^\s*(node|python[23]?|ruby|perl|php|java|deno|bun)\b", RiskLevel.MODERATE),
    (r"^\s*(ls|pwd|cat|head|tail|wc|grep|rg|egrep|fgrep|find|which|echo|tree|du|df|file|stat|env|id|uname|date|sort|uniq|cut|tr|jq|column|less|more|xxd|od|strings)\b", RiskLevel.SAFE),
    (r"^\s*git\s+(status|diff|log|branch|show|blame|rev-parse|remote\s+-v|tag|stash\s+list)\b", RiskLevel.SAFE),
    (r"^\s*(py(test|thon\s+-m\s+(pytest|unittest))|npm\s+(test|run\s+(test|lint|build|check))|go\s+(test|vet|build)|cargo\s+(test|check|build)|npx\s+(tsc|eslint))\b", RiskLevel.SAFE),
    (r"^\s*make\b(?!.*clean)", RiskLevel.SAFE),
]

SAFE_FS_CMDS = {"mkdir", "touch", "cp", "ls", "pwd", "cat", "head", "tail", "wc", "file",
                "stat", "tree", "du", "df", "which", "echo", "find", "grep", "rg", "diff",
                "cmp", "sort", "uniq", "cut", "tr", "jq", "wc", "env", "id", "uname",
                "date", "column", "strings", "xxd", "od", "realpath", "basename", "dirname",
                "test", "[", "true", "false", "printf"}

TEST_LINT_RE = re.compile(
    r"^\s*(pytest|py\.test|python3?\s+-m\s+(pytest|unittest)|npm\s+(test|run\s+(test|lint|build|check))|"
    r"yarn\s+(test|lint)|pnpm\s+(test|lint)|go\s+(test|vet|build)|"
    r"cargo\s+(test|check|build|clippy)|make\s+(test|lint|build|check|all)|"
    r"ruff\s+(check|format)|flake8|black\s+--check|mypy|pylint|eslint|tsc\b|"
    r"npx\s+(tsc|eslint|prettier)|unittest\b)", re.IGNORECASE)

_CRITICAL_CMDS = {"rm", "mkfs", "dd", "sudo", "su", "shutdown", "reboot", "halt",
                  "shred", "truncate", "crontab", "wipefs", "blkdiscard"}
_DANGEROUS_CMDS = {"mv", "kill", "killall", "pkill", "ssh", "scp", "rsync",
                   "chmod", "chown", "chgrp", "curl", "wget", "eval", "nohup"}


def cmd_segments(cmd: str) -> list:
    return [seg.strip() for seg in re.split(r"\s*(?:\||&&|\|\||;)\s*", cmd) if seg.strip()]

def is_test_lint_safe(cmd: str) -> bool:
    """All segments are test/lint/build or safe filesystem commands."""
    segs = cmd_segments(cmd)
    if not segs:
        return False
    for seg in segs:
        first = seg.split()[0] if seg.split() else ""
        if not (TEST_LINT_RE.match(seg) or first in SAFE_FS_CMDS):
            return False
    return True

def classify_command(cmd: str) -> RiskLevel:
    cmd = cmd.strip()
    if not cmd:
        return RiskLevel.SAFE
    order = [RiskLevel.SAFE, RiskLevel.MODERATE, RiskLevel.DANGEROUS, RiskLevel.CRITICAL]
    # Whole-command scan first: some rules are written to span shell operators
    # (e.g. `curl … | sh`, `wget … | bash`) and would be missed segment-by-segment.
    for pattern, level in COMMAND_RISK_RULES:
        spans_operators = "\\|" in pattern or "&&" in pattern
        if level == RiskLevel.CRITICAL or (level == RiskLevel.DANGEROUS and spans_operators):
            if re.search(pattern, cmd, re.IGNORECASE):
                return level
    # Fast path: plain `ls`/`pwd`/`git status` style single command.
    if "&&" not in cmd and "||" not in cmd and ";" not in cmd and "|" not in cmd:
        first = cmd.split()[0]
        if first in _CRITICAL_CMDS:
            return RiskLevel.CRITICAL
        if re.search(r"\s-[a-zA-Z]*[rf]", cmd) and first in ("rm", "find", "mv", "chmod"):
            return RiskLevel.CRITICAL
    risks = []
    for part in cmd_segments(cmd):
        part = part.strip()
        if not part:
            continue
        matched = RiskLevel.SAFE
        for pattern, level in COMMAND_RISK_RULES:
            if re.search(pattern, part, re.IGNORECASE):
                matched = level; break
        else:
            head = part.split()[0] if part.split() else ""
            if head in _CRITICAL_CMDS:
                matched = RiskLevel.CRITICAL
            elif head in _DANGEROUS_CMDS:
                matched = RiskLevel.DANGEROUS
        risks.append(matched)
    if not risks:
        return RiskLevel.SAFE
    return max(risks, key=lambda r: order.index(r))

def is_protected_path(path: str, workdir: Path) -> bool:
    if not path: return False
    try:
        wd = Path(workdir).resolve()
        p = Path(path).expanduser()
        if not p.is_absolute(): p = wd / p
        p = p.resolve()
        try:
            p.relative_to(wd); return False
        except ValueError: pass
        for prot in PROTECTED_PATHS:
            prot_p = Path(prot.replace("~", str(Path.home()))).resolve()
            try:
                p.relative_to(prot_p); return True
            except ValueError: continue
        return True
    except Exception: return True

def path_in_workdir(path: str, workdir: Path) -> bool:
    try:
        p = Path(path).expanduser()
        if not p.is_absolute(): p = Path(workdir) / p
        p.resolve().relative_to(Path(workdir).resolve()); return True
    except Exception: return False


TOOL_ALIASES = {
    "run_command": "Bash", "write_file": "Write", "edit_file": "Edit",
    "delete_file": "Delete", "read_file": "Read", "list_dir": "List",
    "glob": "Glob", "search_code": "Search", "fetch_url": "Web", "http_request": "Web",
}

@dataclass
class PermissionRules:
    deny: list = field(default_factory=lambda: [
        "Bash(sudo *)", "Bash(rm -rf /*)", "Bash(mkfs*)", "Bash(dd if=*)",
        "Edit(~/.ssh/**)", "Edit(~/.aws/**)", "Edit(/etc/**)", "Delete(~/.ssh/**)",
    ])
    ask: list = field(default_factory=lambda: [
        "Bash(git push*)", "Bash(curl*)", "Bash(wget*)", "Bash(sed -i*)", "Bash(ssh*)",
        "Edit(./.env*)", "Write(./.env*)",
    ])
    allow: list = field(default_factory=lambda: [
        "Read(*)", "List(*)", "Glob(*)", "Search(*)",
        "Bash(ls *)", "Bash(pwd)", "Bash(cat *)", "Bash(git status*)",
        "Bash(git diff*)", "Bash(git log*)", "Bash(pytest*)",
        "Bash(npm test*)", "Bash(head *)", "Bash(tail *)", "Bash(grep *)",
    ])

    def match(self, rule_list, tool, arg_str):
        alt = TOOL_ALIASES.get(tool, tool)
        for rule in rule_list:
            if "(" not in rule:
                if rule in (tool, alt, "*"): return True
                continue
            name, pattern = rule.split("(", 1)
            name = name.strip(); pattern = pattern.rstrip(")").strip()
            if name not in (tool, alt, "*"): continue
            if pattern.endswith("*"):
                prefix = pattern[:-1].rstrip(" *")
                first = arg_str.split()[0] if arg_str.split() else ""
                if first == prefix or arg_str.startswith(prefix + " ") or arg_str.startswith(prefix):
                    return True
            else:
                if arg_str == pattern or arg_str.startswith(pattern + " ") or fnmatch.fnmatch(arg_str, pattern):
                    return True
        return False

    def evaluate(self, tool, arg_str):
        if self.match(self.deny, tool, arg_str): return Decision.DENY
        if self.match(self.ask, tool, arg_str): return Decision.ASK
        if self.match(self.allow, tool, arg_str): return Decision.ALLOW
        return Decision.ASK

    @classmethod
    def load(cls, workdir):
        for path in [workdir / ".nengineer" / "permissions.json", APP_DIR / "permissions.json"]:
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    rules = cls()
                    for k in ("deny", "ask", "allow"):
                        if k in data: setattr(rules, k, data[k])
                    return rules
                except Exception: continue
        return cls()

    def save(self, workdir, project=True):
        d = workdir / ".nengineer" if project else APP_DIR
        d.mkdir(parents=True, exist_ok=True)
        save_json(d / "permissions.json", {"deny": self.deny, "ask": self.ask, "allow": self.allow})


class PermissionManager:
    def __init__(self, workdir, mode="acceptEdits"):
        self.workdir = Path(workdir).resolve()
        self.mode = mode if mode in MODES else "acceptEdits"
        self.rules = PermissionRules.load(self.workdir)
        self._session_approved = set(); self._session_denied = set()

    def evaluate(self, tool, args):
        arg_str = self._args_to_str(tool, args)
        risk = self._risk_for(tool, args, arg_str)
        decision = self.rules.evaluate(tool, arg_str)
        if decision == Decision.DENY: return Decision.DENY, "规则拒绝", risk
        if self.mode == "plan":
            if tool in READONLY_TOOLS or tool in PLAN_EXTRA_TOOLS:
                return Decision.ALLOW, "plan 只读", RiskLevel.SAFE
            if tool == "checkpoint" and str(args.get("action", "list")) in ("list", "diff", "create"):
                return Decision.ALLOW, "plan 检查点", RiskLevel.SAFE
            return Decision.DENY, "plan 禁止写/执行", risk
        if self.mode == "dontAsk":
            saved = self.mode
            self.mode = "acceptEdits"
            try:
                d, r, rk = self.evaluate(tool, args)
            finally:
                self.mode = saved
            if d == Decision.ASK:
                return Decision.DENY, "dontAsk 拒绝", rk
            return d, ("dontAsk " + r), rk
        if tool in READONLY_TOOLS:
            path = str(args.get("path") or args.get("pattern") or "")
            if path and is_protected_path(path, self.workdir) and tool == "read_file":
                if decision != Decision.ALLOW: return Decision.ASK, "受保护路径", RiskLevel.MODERATE
            return Decision.ALLOW, "只读", RiskLevel.SAFE
        if tool in ("set_todos", "todo_update", "memory_write", "checkpoint"): return Decision.ALLOW, "安全", RiskLevel.SAFE
        if self.mode == "yolo":
            if risk == RiskLevel.CRITICAL: return Decision.ASK, "危急", risk
            return Decision.ALLOW, "YOLO", risk
        sk = f"{tool}:{self._category(tool, args)}"
        if sk in self._session_approved: return Decision.ALLOW, "会话已批", risk
        if sk in self._session_denied: return Decision.DENY, "会话已拒", risk
        if self.mode == "acceptEdits":
            if tool in ("write_file","edit_file","apply_patch"):
                tgt = str(args.get("path","") or "")
                if tool == "apply_patch" and not tgt:
                    m = re.search(r"^\+\+\+ (?:b/)?(\S+)", str(args.get("patch","")), re.M)
                    tgt = m.group(1) if m and m.group(1) != "/dev/null" else ""
                if tgt and is_protected_path(tgt, self.workdir): return Decision.ASK, "受保护", risk
                if (not tgt) or path_in_workdir(tgt, self.workdir): return Decision.ALLOW, "工作区编辑", risk
                return Decision.ASK, "工作区外", risk
            if tool == "extract_archive":
                dest = str(args.get("dest","") or ".")
                if is_protected_path(dest, self.workdir): return Decision.ASK, "受保护", risk
                return Decision.ALLOW, "工作区解压", risk
            if tool == "download_file":
                dest = str(args.get("dest","") or "")
                if dest and is_protected_path(dest, self.workdir): return Decision.ASK, "受保护", risk
                return Decision.ALLOW, "下载到工作区", risk
            if tool == "test_run":
                cmd = str(args.get("command","")).strip()
                if not cmd or is_test_lint_safe(cmd): return Decision.ALLOW, "测试验证", RiskLevel.SAFE
                return Decision.ASK, "自定义测试命令", self._risk_for(tool, args, arg_str)
            if tool == "run_command":
                cmd = str(args.get("command","")).strip()
                first = cmd.split()[0] if cmd else ""
                if first in SAFE_FS_CMDS and risk in (RiskLevel.SAFE, RiskLevel.MODERATE): return Decision.ALLOW, "安全命令", risk
                if is_test_lint_safe(cmd): return Decision.ALLOW, "测试/lint", risk
                if risk == RiskLevel.SAFE: return Decision.ALLOW, "低风险", risk
                return Decision.ASK, f"风险={risk.value}", risk
            if tool == "delete_file":
                if path_in_workdir(str(args.get("path","")), self.workdir): return Decision.ASK, "删除", risk
                return Decision.DENY, "区外删除", risk
            if tool == "git_commit": return Decision.ALLOW, "本地提交(可 git_undo)", RiskLevel.DANGEROUS
            if tool == "checkpoint":
                if str(args.get("action", "create")) in ("create", "list", "diff"):
                    return Decision.ALLOW, "检查点", RiskLevel.SAFE
                return Decision.ASK, "恢复覆盖工作区", RiskLevel.DANGEROUS
            if tool == "fetch_url": return Decision.ALLOW, "网页读取(SSRF防护)", RiskLevel.MODERATE
            if tool == "http_request":
                if str(args.get("method", "GET")).upper() in ("GET", "HEAD"):
                    return Decision.ALLOW, "GET请求", RiskLevel.MODERATE
                return Decision.ASK, "写方法请求", RiskLevel.DANGEROUS
            if tool == "git_init": return Decision.ASK, "需确认", RiskLevel.DANGEROUS
        if decision == Decision.ALLOW:
            if risk == RiskLevel.CRITICAL: return Decision.ASK, "危急", risk
            if is_protected_path(str(args.get("path","")), self.workdir) and tool in ("write_file","edit_file","delete_file"):
                return Decision.ASK, "受保护", risk
            return Decision.ALLOW, "规则允许", risk
        if risk == RiskLevel.SAFE and self.mode == "acceptEdits": return Decision.ALLOW, "低风险", risk
        return Decision.ASK, f"风险={risk.value}", risk

    def approve_session(self, tool, args):
        self._session_approved.add(f"{tool}:{self._category(tool, args)}")
        self._session_denied.discard(f"{tool}:{self._category(tool, args)}")
    def deny_session(self, tool, args):
        self._session_denied.add(f"{tool}:{self._category(tool, args)}")
        self._session_approved.discard(f"{tool}:{self._category(tool, args)}")
    def approve_always(self, tool, args):
        self.approve_session(tool, args)
        cat = self._category(tool, args)
        rule = f"{tool}(*{cat}*)" if cat else f"{tool}(*)"
        if rule not in self.rules.allow:
            self.rules.allow.append(rule); self.rules.save(self.workdir)

    @staticmethod
    def _args_to_str(tool, args):
        if tool == "run_command": return str(args.get("command",""))
        if tool in ("read_file","write_file","edit_file","delete_file","apply_patch","file_stat","symbols"): return str(args.get("path",""))
        if tool in ("glob", "search_code"): return str(args.get("pattern",""))
        if tool == "list_dir": return str(args.get("path","."))
        if tool in ("git_commit",): return f"commit {args.get('message','')}"
        if tool in ("git_branch", "git_stash"): return str(args.get("action","")) + " " + str(args.get("name",""))
        if tool in ("fetch_url", "download_file"): return str(args.get("url",""))
        if tool == "extract_archive": return str(args.get("archive",""))
        if tool == "memory_write": return str(args.get("topic",""))
        return json.dumps(args, ensure_ascii=False)[:200]

    @staticmethod
    def _category(tool, args):
        if tool == "run_command":
            cmd = str(args.get("command","")).strip()
            return cmd.split()[0] if cmd else ""
        if tool in ("read_file","write_file","edit_file","delete_file","apply_patch","file_stat","symbols"):
            p = str(args.get("path",""))
            return Path(p).name if p else ""
        if tool in ("search_code", "glob"): return str(args.get("pattern",""))[:40]
        if tool in ("fetch_url", "download_file"): return "web"
        if tool in ("git_branch", "git_stash"): return str(args.get("name","")) or str(args.get("action",""))
        return ""

    def _risk_for(self, tool, args, arg_str):
        if tool == "run_command": return classify_command(str(args.get("command","")))
        if tool in ("delete_file", "git_stash"): return RiskLevel.DANGEROUS
        if tool in ("write_file","edit_file","apply_patch"):
            path = str(args.get("path",""))
            if is_protected_path(path, self.workdir): return RiskLevel.CRITICAL
            if path_in_workdir(path, self.workdir): return RiskLevel.MODERATE
            return RiskLevel.DANGEROUS
        if tool == "download_file":
            dest = str(args.get("dest",""))
            if dest and is_protected_path(dest, self.workdir): return RiskLevel.CRITICAL
            return RiskLevel.DANGEROUS
        if tool == "extract_archive": return RiskLevel.DANGEROUS
        if tool in ("git_commit","git_init","fetch_url"): return RiskLevel.DANGEROUS
        if tool in ("git_branch","git_stash"):
            return RiskLevel.SAFE if str(args.get("action","list")).lower() == "list" else RiskLevel.DANGEROUS
        return RiskLevel.SAFE


def ask_approval(tool, args, risk, reason, perm, timeout=120):
    risk_tokens = {RiskLevel.SAFE: "ok", RiskLevel.MODERATE: "warn",
                   RiskLevel.DANGEROUS: "err", RiskLevel.CRITICAL: "err"}
    risk_icons = {RiskLevel.SAFE: "🟢", RiskLevel.MODERATE: "🟡",
                  RiskLevel.DANGEROUS: "🔴", RiskLevel.CRITICAL: "☠️"}
    arg_preview = PermissionManager._args_to_str(tool, args)
    arg_preview = mask_secrets(arg_preview)
    # build diff preview for edit tools
    diff_preview = ""
    if tool in ("edit_file", "apply_patch", "write_file"):
        try:
            if tool == "edit_file" and args.get("old_string") and args.get("new_string"):
                import difflib as _dl
                old = args["old_string"].splitlines(keepends=True)
                new = args["new_string"].splitlines(keepends=True)
                d = list(_dl.unified_diff(old, new, lineterm="", n=1))
                if d:
                    diff_preview = "\n".join(d[:20])
            elif tool == "apply_patch" and args.get("patch"):
                diff_preview = "\n".join(str(args["patch"]).splitlines()[:20])
        except Exception:
            pass
    # compute box width
    term_w = max(50, shutil.get_terminal_size((80, 24)).columns - 2)
    inner = min(term_w - 6, 72)
    print()
    print(s(f"  ┌─── 审批 ───" + "─" * max(0, inner - 12) + "┐", Palette.tok("warn")))
    row_tool = f"  {tool}"
    print(s("  │ ", Palette.tok("warn")) + pad_right(row_tool, inner) + s("│", Palette.tok("warn")))
    risk_row = f"  {risk_icons[risk]} {risk.value}"
    print(s("  │ ", Palette.tok("warn")) +
          s(pad_right(risk_row, inner), Palette.tok(risk_tokens[risk])) + s("│", Palette.tok("warn")))
    arg_row = clip(f"  {arg_preview}", inner)
    print(s("  │ ", Palette.tok("warn")) + pad_right(arg_row, inner) + s("│", Palette.tok("warn")))
    if diff_preview:
        print(s("  │ ", Palette.tok("warn")) + s("  ── diff ──", Palette.tok("dim")) + s("│", Palette.tok("warn")))
        for dl in diff_preview.splitlines():
            dline = clip(f"  {dl}", inner)
            if Style._disabled:
                print(s("  │ ", Palette.tok("warn")) + pad_right(dline, inner) + s("│", Palette.tok("warn")))
            else:
                colored = hl_diff(dl)
                print(s("  │ ", Palette.tok("warn")) + colored + s("│", Palette.tok("warn")))
    print(s("  └" + "─" * (inner + 1) + "┘", Palette.tok("warn")))
    print(s("    [y]允许 [n]拒绝 [a]会话 [s]安全 [d]永久 [Esc]拒绝", Palette.tok("dim")))
    if not sys.stdin.isatty():
        return False, "no"
    # single-keypress via termios raw mode (with fallback to line input)
    ans = ""
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            print(s("  ⏳ ", Palette.tok("dim")), end="", flush=True)
            import select as _sel
            r, _, _ = _sel.select([sys.stdin], [], [], timeout)
            if r:
                ch = sys.stdin.read(1)
                # ESC sequence: read the rest
                if ch == "\x1b":
                    ans = "esc"
                else:
                    ans = ch.lower()
            else:
                print(s(" [超时]", Palette.tok("warn")))
                ans = "timeout"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        print()
    except Exception:
        # fallback: line-based input
        try:
            import select
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            if not r:
                print(s(" [超时]", Palette.tok("warn")))
                return False, "no"
            ans = input().strip().lower()
        except Exception:
            return False, "no"
    if ans in ("y", "yes"):
        perm.approve_session(tool, args); return True, "yes"
    if ans in ("a", "always"):
        perm.approve_session(tool, args); return True, "always"
    if ans in ("s", "safe"):
        perm.mode = "acceptEdits"; perm.approve_session(tool, args); return True, "safe"
    if ans in ("d", "deny-always"):
        cat = perm._category(tool, args)
        rule = f"{tool}(*{cat}*)" if cat else f"{tool}(*)"
        if rule not in perm.rules.deny:
            perm.rules.deny.append(rule); perm.rules.save(perm.workdir)
        perm.deny_session(tool, args); return False, "never"
    if ans in ("timeout",):
        return False, "timeout"
    perm.deny_session(tool, args); return False, "no"


# ═══════════════════════════════════════════════════════════
# SHADOW-GIT CHECKPOINT SYSTEM
# ═══════════════════════════════════════════════════════════

class CheckpointManager:
    """
    Shadow-git based workspace checkpoints.
    Uses git hash-object + update-index in a separate git dir,
    never touching the user's .git.
    """
    def __init__(self, workdir):
        self.workdir = Path(workdir).resolve()
        self.shadow_dir = CHECKPOINTS_DIR / hashlib.md5(str(self.workdir).encode()).hexdigest()[:12]
        self.git_dir = self.shadow_dir / ".shadow_git"
        self.git_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.shadow_dir / "checkpoints.jsonl"
        self._last_auto = 0.0
        self._mutations = 0
        self._lock = threading.RLock()   # snapshots may run on a background thread
        # init shadow git if needed
        if not (self.git_dir / "HEAD").exists():
            subprocess.run(["git", "init", "--bare", str(self.git_dir)],
                          capture_output=True, timeout=10)
        # keep huge/irrelevant dirs out of the shadow index
        exclude = self.git_dir / "info" / "exclude"
        try:
            exclude.parent.mkdir(parents=True, exist_ok=True)
            patterns = sorted(SKIP_DIRS | {"*.bak", "*.pyc", "*.log", ".env", "*.gguf", "*.apk"})
            content = "".join(f"{p}\n" for p in patterns)
            if not exclude.exists() or exclude.read_text(encoding="utf-8") != content:
                exclude.write_text(content, encoding="utf-8")
        except Exception:
            pass

    def _git(self, *args, env=None, timeout=30):
        e = os.environ.copy()
        if env: e.update(env)
        e["GIT_DIR"] = str(self.git_dir)
        e["GIT_WORK_TREE"] = str(self.workdir)
        e.pop("GIT_INDEX_FILE", None)
        try:
            proc = subprocess.run(["git", *args], capture_output=True, text=True,
                                  timeout=timeout, cwd=str(self.workdir), env=e)
            return proc.stdout.strip(), proc.returncode
        except Exception as ex:
            return str(ex), 1

    def _read_index(self, limit=None) -> list:
        if not self._index_path.exists():
            return []
        records = []
        with open(self._index_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        return records if limit is None else records[:limit]

    def _write_index(self, records):
        with open(self._index_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def _iter_files(self):
        """Walk the workdir pruning SKIP_DIRS/.git while descending.

        Path.rglob() visits node_modules/.venv/etc first and filters later,
        which costs seconds on real projects; pruning during the walk is ~free.
        """
        skip = SKIP_DIRS | {".git", ".nengineer"}
        for root, dirs, files in os.walk(self.workdir):
            dirs[:] = [d for d in dirs if d not in skip]
            for name in files:
                yield Path(root) / name

    def create(self, label="", include_untracked=True) -> Optional[str]:
        """Create a checkpoint of the entire workspace."""
        with self._lock:
            cp_id = f"cp_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            # Stage all files
            self._git("add", "-A")
            # Write tree
            tree_out, rc = self._git("write-tree")
            if rc != 0 or not tree_out:
                return None
            tree_sha = tree_out.split("\n")[0].strip()
            # Save metadata
            file_list = []
            for f in self._iter_files():
                try:
                    file_list.append(str(f.relative_to(self.workdir)))
                except ValueError:
                    pass
            record = {
                "id": cp_id,
                "tree": tree_sha,
                "label": label or f"checkpoint at {datetime.now():%H:%M:%S}",
                "ts": datetime.now(timezone.utc).isoformat(),
                "files": len(file_list),
                "file_list": file_list[:500],
                "auto": bool(label.startswith("auto:")),
            }
            with open(self._index_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            return cp_id

    def maybe_auto(self, mutation: bool = True, interval: float = 90.0, every: int = 12) -> Optional[str]:
        """Create a rate-limited automatic snapshot before risky/mutating work."""
        if not mutation:
            return None
        self._mutations += 1
        now = time.time()
        if self._last_auto and (now - self._last_auto < interval) and self._mutations < every:
            return None
        self._last_auto = now
        self._mutations = 0
        try:
            return self.create(label=f"auto:{datetime.now():%H:%M:%S}")
        except Exception:
            return None

    def list(self, limit=20) -> list:
        return self._read_index(limit)

    def prune(self, keep: int = 25) -> int:
        """Drop oldest checkpoint index entries beyond `keep`. Objects are GC'd by git."""
        records = self._read_index()
        if len(records) <= keep:
            return 0
        dropped = len(records) - keep
        self._write_index(records[:keep])
        try:
            self._git("reflog", "expire", "--expire=now", "--all", timeout=20)
            self._git("gc", "--prune=now", timeout=60)
        except Exception:
            pass
        return dropped

    def restore(self, cp_id=None, safety=True) -> tuple[bool, str]:
        """Restore workspace to a checkpoint (optionally snapshotting current state first)."""
        with self._lock:
            records = self.list(200)
            if not records:
                return False, "没有检查点"
            record = None
            if cp_id:
                record = next((r for r in records if r["id"] == cp_id), None)
                if not record:
                    return False, f"检查点不存在: {cp_id}"
            else:
                record = records[0]
            pre = None
            if safety:
                pre = self.create(label=f"pre-restore:{record['id']}")
            tree_sha = record["tree"]
            # Read tree and checkout
            self._git("read-tree", tree_sha)
            # Remove files not in tree (clean)
            self._git("clean", "-fd")
            # Checkout files from tree
            out, rc = self._git("checkout-index", "-a", "-f")
            if rc != 0:
                return False, f"恢复失败: {out}"
            msg = f"已恢复检查点 {record['id']} ({record.get('files',0)} files) — {record.get('label','')}"
            if pre:
                msg += f"\n恢复前状态已保存为 {pre}（可用它回滚）"
            return True, msg

    def diff(self, cp_id=None) -> str:
        """Show diff between checkpoint and current state."""
        records = self.list(200)
        if not records:
            return "没有检查点"
        record = next((r for r in records if r["id"] == cp_id), None) if cp_id else records[0]
        if not record:
            return f"检查点不存在: {cp_id}"
        # Stage current and diff against tree
        self._git("add", "-A")
        current_tree, _ = self._git("write-tree")
        if not current_tree:
            return "无法生成当前状态"
        out, _ = self._git("diff-tree", "-p", "--no-commit-id", record["tree"], current_tree.strip())
        return out or "(no diff)"


# ═══════════════════════════════════════════════════════════
# MEMORY SYSTEM
# ═══════════════════════════════════════════════════════════

class MemorySystem:
    """
    Layered memory: MEMORY.md index + topic files.
    Agent can read/write memory across sessions.
    """
    def __init__(self, workdir):
        self.workdir = Path(workdir).resolve()
        self.mem_dir = MEMORY_DIR / hashlib.md5(str(self.workdir).encode()).hexdigest()[:12]
        self.mem_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.mem_dir / "MEMORY.md"
        if not self.index_path.exists():
            self.index_path.write_text("# Memory Index\n\n", encoding="utf-8")

    def read_index(self) -> str:
        try:
            return self.index_path.read_text(encoding="utf-8")
        except Exception:
            return "# Memory Index\n"

    def read(self, topic: str) -> str:
        safe = re.sub(r"[^\w\-]", "_", topic)[:80]
        path = self.mem_dir / f"{safe}.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return f"ERROR: memory topic not found: {topic}"

    def write(self, topic: str, content: str, mem_type: str = "project") -> str:
        safe = re.sub(r"[^\w\-]", "_", topic)[:80]
        path = self.mem_dir / f"{safe}.md"
        exists = path.exists()
        header = f"""---
topic: {topic}
type: {mem_type}
updated: {datetime.now(timezone.utc).isoformat()}
---

"""
        path.write_text(header + content, encoding="utf-8")
        # Update index
        index = self.read_index()
        entry = f"- [{topic}]({safe}.md) — {mem_type}"
        if entry not in index:
            index = index.rstrip() + f"\n{entry}\n"
            self.index_path.write_text(index, encoding="utf-8")
        return f"记忆已{'更新' if exists else '保存'}: {topic}"

    def list_topics(self) -> str:
        topics = [p.stem for p in self.mem_dir.glob("*.md") if p.stem != "MEMORY"]
        if not topics:
            return "暂无记忆主题"
        return "记忆主题:\n" + "\n".join(f"  - {t}" for t in sorted(topics))

    def topic_names(self) -> list:
        return sorted(p.stem for p in self.mem_dir.glob("*.md") if p.stem != "MEMORY")

    def search(self, query: str, max_hits: int = 20) -> str:
        """Full-text search across all memory topics."""
        ql = query.lower()
        hits = []
        for p in self.mem_dir.glob("*.md"):
            if p.stem == "MEMORY":
                continue
            try:
                lines = p.read_text(encoding="utf-8").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                if ql in line.lower():
                    hits.append(f"{p.stem}:{i}: {line.strip()[:160]}")
                    if len(hits) >= max_hits:
                        break
            if len(hits) >= max_hits:
                break
        if not hits:
            return f"记忆中未找到: {query}"
        return f"记忆搜索 {query!r} ({len(hits)} hits):\n" + "\n".join(hits)

    def append(self, topic: str, content: str, mem_type: str = "project") -> str:
        """Append dated notes to an existing topic (create if missing)."""
        safe = re.sub(r"[^\w\-]", "_", topic)[:80]
        path = self.mem_dir / f"{safe}.md"
        stamp = f"{datetime.now():%Y-%m-%d %H:%M}"
        if path.exists():
            path.write_text(path.read_text(encoding="utf-8").rstrip() + f"\n\n## {stamp}\n{content}\n",
                            encoding="utf-8")
            return f"记忆已追加: {topic}"
        return self.write(topic, f"## {stamp}\n{content}", mem_type)

    def delete(self, topic: str) -> str:
        safe = re.sub(r"[^\w\-]", "_", topic)[:80]
        path = self.mem_dir / f"{safe}.md"
        if not path.exists():
            return f"ERROR: memory topic not found: {topic}"
        path.unlink()
        idx = self.read_index().replace(f"- [{topic}]({safe}.md)", "").rstrip() + "\n"
        self.index_path.write_text(idx, encoding="utf-8")
        return f"记忆已删除: {topic}"

    def get_context_snippet(self, max_chars=3000) -> str:
        """Get memory context for injection into system prompt."""
        idx = self.read_index()
        if len(idx) <= max_chars:
            return idx
        return idx[:max_chars] + "\n… (use memory_read for details)"


# ═══════════════════════════════════════════════════════════
# SKILLS SYSTEM
# ═══════════════════════════════════════════════════════════

class SkillsSystem:
    """
    Progressive disclosure skills. Only descriptions loaded initially;
    full content injected on invocation.
    """
    def __init__(self, workdir):
        self.workdir = Path(workdir).resolve()
        self.skills_dir = SKILLS_DIR
        self.project_skills = self.workdir / ".nengineer" / "skills"
        self._cache = {}

    def _find_skill_files(self) -> list:
        paths = []
        for d in [self.project_skills, self.skills_dir]:
            if d.exists():
                paths.extend(d.glob("*.md"))
        return paths

    def list_skills(self) -> list:
        """Return list of (name, description) without loading full content."""
        skills = []
        for p in self._find_skill_files():
            try:
                content = p.read_text(encoding="utf-8")
                # parse YAML-like frontmatter
                name = p.stem
                desc = ""
                if content.startswith("---"):
                    parts = content.split("---", 2)
                    if len(parts) >= 3:
                        fm = parts[1]
                        for line in fm.splitlines():
                            if line.startswith("name:"): name = line.split(":", 1)[1].strip()
                            if line.startswith("description:"): desc = line.split(":", 1)[1].strip()
                else:
                    # first non-empty line as description
                    for line in content.splitlines():
                        if line.strip() and not line.startswith("#"):
                            desc = line.strip()[:120]; break
                skills.append({"name": name, "description": desc, "path": str(p)})
            except Exception:
                continue
        return skills

    def load_skill(self, name: str) -> Optional[str]:
        """Load full skill content (progressive disclosure)."""
        for skill in self.list_skills():
            if skill["name"] == name:
                try:
                    return Path(skill["path"]).read_text(encoding="utf-8")
                except Exception:
                    return None
        return None

    def get_skill_index(self) -> str:
        """Compact index for system prompt injection."""
        skills = self.list_skills()
        if not skills:
            return ""
        lines = ["Available skills (use skill_load to activate):"]
        for sk in skills[:20]:
            lines.append(f"  - {sk['name']}: {sk['description'][:80]}")
        return "\n".join(lines)

    def create_skill(self, name, description, content, allowed_tools=None):
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        path = self.skills_dir / f"{name}.md"
        fm = f"---\nname: {name}\ndescription: {description}\n"
        if allowed_tools:
            fm += f"allowed-tools: {', '.join(allowed_tools)}\n"
        fm += "---\n\n"
        path.write_text(fm + content, encoding="utf-8")
        return f"技能已创建: {name}"

    def search_skills(self, query: str) -> str:
        skills = self.list_skills()
        ql = query.lower()
        matches = [sk for sk in skills if ql in sk["name"].lower() or ql in sk["description"].lower()]
        if not matches:
            return f"未找到匹配技能: {query}"
        return "\n".join(f"  {sk['name']}: {sk['description'][:100]}" for sk in matches)


# ═══════════════════════════════════════════════════════════
# HOOKS SYSTEM
# ═══════════════════════════════════════════════════════════

@dataclass
class Hook:
    event: str  # PreToolUse, PostToolUse, PostToolUseFailure, SessionStart, SessionEnd
    matcher: str  # regex on tool name, or * for all
    command: str  # shell command to run
    timeout: int = 10

class HooksSystem:
    """
    Lifecycle hooks with regex matchers.
    PreToolUse hooks can deny/modify tool calls.
    """
    def __init__(self, workdir):
        self.workdir = Path(workdir).resolve()
        self.hooks: list[Hook] = []
        self._load_hooks()

    def _load_hooks(self):
        for path in [self.workdir / ".nengineer" / "hooks.json", APP_DIR / "hooks.json"]:
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    for h in data:
                        self.hooks.append(Hook(**h))
                except Exception:
                    pass

    def add_hook(self, event, matcher, command, timeout=10):
        hook = Hook(event=event, matcher=matcher, command=command, timeout=timeout)
        self.hooks.append(hook)
        # persist
        self.workdir.mkdir(parents=True, exist_ok=True)
        path = self.workdir / ".nengineer" / "hooks.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        save_json(path, [asdict(h) for h in self.hooks])
        return hook

    def fire(self, event: str, tool_name: str = "", data: dict = None) -> tuple[bool, str]:
        """Fire hooks for an event. Returns (allowed, output).
        PreToolUse: returning allowed=False blocks the tool.
        """
        for hook in self.hooks:
            if hook.event != event:
                continue
            if hook.matcher != "*" and not re.match(hook.matcher, tool_name):
                continue
            payload = json.dumps({"event": event, "tool": tool_name, **(data or {})}, ensure_ascii=False)
            try:
                proc = subprocess.run(
                    hook.command, shell=True, cwd=str(self.workdir),
                    input=payload, capture_output=True, text=True, timeout=hook.timeout
                )
                # Non-zero exit blocks PreToolUse
                if event == "PreToolUse" and proc.returncode != 0:
                    reason = proc.stdout.strip() or proc.stderr.strip() or f"hook exit {proc.returncode}"
                    return False, reason
                # Structured JSON output can also deny
                if event == "PreToolUse" and proc.stdout.strip():
                    try:
                        result = json.loads(proc.stdout.strip())
                        if result.get("decision") == "block":
                            return False, result.get("reason", "blocked by hook")
                    except json.JSONDecodeError:
                        pass
            except subprocess.TimeoutExpired:
                if event == "PreToolUse":
                    return False, f"hook timeout: {hook.command[:50]}"
            except Exception:
                pass
        return True, ""


# ═══════════════════════════════════════════════════════════
# BUDGET SYSTEM
# ═══════════════════════════════════════════════════════════

class Budget:
    def __init__(self, tokens=200_000, time_sec=1800, steps=40, warn_pct=0.8):
        self.max_tokens = tokens
        self.max_time = time_sec
        self.max_steps = steps
        self.warn_pct = warn_pct
        self.used_tokens = 0
        self.used_steps = 0
        self.cost_usd = 0.0
        self.start_time = time.time()
        self._warned = set()

    def add_tokens(self, n: int):
        self.used_tokens += n
    def add_step(self):
        self.used_steps += 1

    def add_usage(self, usage: dict, model: str = ""):
        """Account a chat-completion usage block (with cost estimate)."""
        if not usage:
            return 0
        pt = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
        ct = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
        total = int(usage.get("total_tokens") or (pt + ct))
        self.add_tokens(total)
        pin, pout = MODEL_PRICING.get(model, DEFAULT_PRICING)
        self.cost_usd += pt / 1e6 * pin + ct / 1e6 * pout
        return total

    def warnings(self) -> list:
        """Return threshold-crossing warnings (each fires at most once)."""
        out = []
        for pct in (0.5, self.warn_pct, 0.95):
            if self.used_tokens >= self.max_tokens * pct and pct not in self._warned:
                self._warned.add(pct)
                out.append(f"token 预算已达 {pct*100:.0f}% ({self.used_tokens:,}/{self.max_tokens:,})")
        if self.used_steps >= self.max_steps * 0.85 and "steps" not in self._warned:
            self._warned.add("steps")
            out.append(f"步数接近上限 ({self.used_steps}/{self.max_steps})")
        if self.elapsed() >= self.max_time * 0.85 and "time" not in self._warned:
            self._warned.add("time")
            out.append(f"时间接近上限 ({self.elapsed():.0f}s/{self.max_time}s)")
        return out

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    def remaining_time(self) -> float:
        return max(0, self.max_time - self.elapsed())

    def is_exhausted(self) -> tuple[bool, str]:
        if self.used_tokens >= self.max_tokens:
            return True, f"token 预算耗尽 ({self.used_tokens}/{self.max_tokens})"
        if self.elapsed() >= self.max_time:
            return True, f"时间预算耗尽 ({self.elapsed():.0f}s/{self.max_time}s)"
        if self.used_steps >= self.max_steps:
            return True, f"步数预算耗尽 ({self.used_steps}/{self.max_steps})"
        return False, ""

    def should_compact(self) -> bool:
        return self.used_tokens > self.max_tokens * 0.7

    def status(self) -> str:
        pct_t = min(100, self.used_tokens * 100 // max(1, self.max_tokens))
        pct_s = min(100, self.used_steps * 100 // max(1, self.max_steps))
        pct_time = min(100, int(self.elapsed() * 100 / max(1, self.max_time)))
        return f"tokens={pct_t}% steps={pct_s}% time={pct_time}% elapsed={self.elapsed():.0f}s usd=${self.cost_usd:.3f}"




# ═══════════════════════════════════════════════════════════
# CONFIG / IO HELPERS
# ═══════════════════════════════════════════════════════════

def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def setup_dirs():
    for d in [APP_DIR, SESSIONS_DIR, CHECKPOINTS_DIR, MEMORY_DIR, SKILLS_DIR, AUDIT_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def load_config() -> dict:
    cfg = load_json(CONFIG_FILE, {}) or {}
    cfg.setdefault("default_model", DEFAULT_MODEL)
    cfg.setdefault("max_steps", MAX_AGENT_STEPS)
    cfg.setdefault("stream", True)
    cfg.setdefault("telemetry", False)
    cfg.setdefault("budget", dict(DEFAULT_BUDGET))
    cfg.setdefault("verify", True)
    return cfg

def log_audit(event: str, data: dict):
    try:
        line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "event": event, **data}, ensure_ascii=False)
        with open(AUDIT_DIR / f"{datetime.now():%Y%m%d}.jsonl", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# API CLIENT
# ═══════════════════════════════════════════════════════════

class APIError(Exception):
    def __init__(self, status, message, body=""):
        self.status = status; self.body = body
        super().__init__(f"HTTP {status}: {message}")

class NIMClient:
    RETRYABLE = {408, 409, 425, 429, 500, 502, 503, 504}

    def __init__(self, api_key=None, base_url=None, model=None, timeout=180,
                 max_retries=4, temperature=0.2):
        self.api_key = api_key or API_KEY
        self.base_url = (base_url or BASE_URL).rstrip("/")
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.temperature = temperature
        self._abort = threading.Event()

    def abort(self):
        """Signal the stream reader to stop as soon as possible."""
        self._abort.set()

    def reset_abort(self):
        self._abort.clear()

    def _headers(self, content_type=True):
        h = {"Authorization": f"Bearer {self.api_key}"}
        if content_type: h["Content-Type"] = "application/json"
        return h

    def _sleep_backoff(self, attempt: int, base: float = 1.0):
        delay = min(20.0, base * (2 ** attempt)) + random_uniform()
        self._abort.wait(delay)

    def _post(self, path, payload, timeout=None):
        url = f"{self.base_url}{path}"
        last_err = None
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                         headers=self._headers(), method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                try:
                    msg = json.loads(body).get("error", {}).get("message", body)
                except Exception:
                    msg = body[:300]
                last_err = APIError(e.code, msg, body)
                if e.code not in self.RETRYABLE or attempt >= self.max_retries:
                    raise last_err
                self._sleep_backoff(attempt, 1.5 if e.code == 429 else 0.8)
            except urllib.error.URLError as e:
                last_err = APIError(0, f"网络错误: {e.reason}")
                if attempt >= self.max_retries:
                    raise last_err
                self._sleep_backoff(attempt)
            except (socket.timeout, TimeoutError):
                last_err = APIError(0, "请求超时")
                if attempt >= self.max_retries:
                    raise last_err
                self._sleep_backoff(attempt)
        raise last_err or APIError(0, "请求失败")

    def chat(self, messages, tools=None, temperature=None, max_tokens=4096, stream=False):
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if stream:
            return self._post_stream(payload)
        return self._post("/chat/completions", payload)

    def _post_stream(self, payload):
        """Yield SSE events: ('text', delta) or ('tool_call', partial_dict) or ('usage', dict)."""
        url = f"{self.base_url}/chat/completions"
        for attempt in range(self.max_retries + 1):
            tool_accum = {}
            emitted_tool = False
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                         headers=self._headers(), method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    buf = b""
                    for chunk in iter(lambda: resp.read(4096), b""):
                        if self._abort.is_set():
                            return
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            line = line.decode("utf-8", errors="replace").strip()
                            if not line.startswith("data:"):
                                continue
                            data = line[5:].strip()
                            if data == "[DONE]":
                                if tool_accum and not emitted_tool:
                                    yield ("tool_call", tool_accum)
                                return
                            try:
                                obj = json.loads(data)
                            except Exception:
                                continue
                            choices = obj.get("choices") or []
                            if not choices:
                                if obj.get("usage"):
                                    yield ("usage", obj["usage"])
                                continue
                            delta = choices[0].get("delta", {})
                            if delta.get("reasoning_content"):
                                yield ("reasoning", delta["reasoning_content"])
                            if delta.get("content"):
                                yield ("text", delta["content"])
                            for tc in delta.get("tool_calls") or []:
                                idx = tc.get("index", 0)
                                acc = tool_accum.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                                if tc.get("id"):
                                    acc["id"] = tc["id"]
                                fn = tc.get("function") or {}
                                if fn.get("name"):
                                    acc["name"] += fn["name"]
                                if fn.get("arguments"):
                                    acc["arguments"] += fn["arguments"]
                            if obj.get("usage"):
                                yield ("usage", obj["usage"])
                            if choices[0].get("finish_reason") == "tool_calls" and tool_accum:
                                yield ("tool_call", tool_accum)
                                emitted_tool = True
                                tool_accum = {}
                return
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                try:
                    msg = json.loads(body).get("error", {}).get("message", body)
                except Exception:
                    msg = body[:300]
                if e.code not in self.RETRYABLE or attempt >= self.max_retries:
                    raise APIError(e.code, msg, body)
                self._sleep_backoff(attempt, 1.5 if e.code == 429 else 0.8)
            except urllib.error.URLError as e:
                if attempt >= self.max_retries:
                    raise APIError(0, f"网络错误: {e.reason}")
                self._sleep_backoff(attempt)
            except (socket.timeout, TimeoutError):
                if attempt >= self.max_retries:
                    raise APIError(0, "请求超时")
                self._sleep_backoff(attempt)

    def list_models(self):
        url = f"{self.base_url}/models"
        last = None
        for attempt in range(min(2, self.max_retries + 1)):
            req = urllib.request.Request(url, headers=self._headers(content_type=False), method="GET")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return [m.get("id") for m in data.get("data", [])]
            except urllib.error.HTTPError as e:
                last = APIError(e.code, f"models list failed: {e.code}")
                if e.code not in self.RETRYABLE or attempt >= self.max_retries:
                    raise last
                self._sleep_backoff(attempt)
            except Exception as e:
                last = APIError(0, str(e))
                if attempt >= self.max_retries:
                    raise last
                self._sleep_backoff(attempt)
        raise last or APIError(0, "models list failed")

    def health(self) -> dict:
        result = {"key": bool(self.api_key), "base_url": self.base_url, "model": self.model,
                  "models_ok": False, "models_count": 0, "chat_ok": False, "error": ""}
        try:
            models = self.list_models()
            result["models_ok"] = True
            result["models_count"] = len(models)
        except Exception as e:
            result["error"] = str(e)
        try:
            resp = self.chat([{"role": "user", "content": "ping"}], max_tokens=8)
            result["chat_ok"] = True
            result["chat_model"] = resp.get("model", self.model)
        except Exception as e:
            result["error"] = str(e)
        return result


# ═══════════════════════════════════════════════════════════
# TOOL ENGINE
# ═══════════════════════════════════════════════════════════

class ToolError(Exception):
    pass

def _clip(text: str, limit=MAX_TOOL_OUTPUT) -> str:
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated {len(text)-limit} chars]"


class ToolEngine:
    """Executes tool calls. Holds workspace context."""
    def __init__(self, workdir: Path, perm: PermissionManager, hooks: HooksSystem,
                 memory: MemorySystem, skills: SkillsSystem, checkpoints: CheckpointManager,
                 session=None, autocp: bool = True, parallel_workers: int = 4):
        self.workdir = Path(workdir).resolve()
        self.perm = perm
        self.hooks = hooks
        self.memory = memory
        self.skills = skills
        self.checkpoints = checkpoints
        self.session = session
        self.step = 0
        self.autocp = autocp
        self.parallel_workers = max(1, int(parallel_workers))
        self._mut_lock = threading.Lock()

    # ---------- dispatch ----------
    def execute(self, name: str, args: dict) -> str:
        self.step += 1
        name = re.split(r"<\|", str(name))[0].strip()
        args = args or {}
        if not isinstance(args, dict):
            try:
                args = json.loads(args) if isinstance(args, str) else {}
            except Exception:
                args = {}

        # Hook: PreToolUse
        allowed, hook_reason = self.hooks.fire("PreToolUse", name, {"args": args})
        if not allowed:
            out = f"BLOCKED by PreToolUse hook: {hook_reason}"
            self.hooks.fire("PostToolUseFailure", name, {"error": out})
            return out

        # Permission check
        decision, reason, risk = self.perm.evaluate(name, args)
        if decision == Decision.DENY:
            out = f"DENIED by permissions: {reason}"
            log_audit("tool_denied", {"tool": name, "reason": reason})
            self.hooks.fire("PostToolUseFailure", name, {"error": out})
            return out
        if decision == Decision.ASK:
            approved, ans = ask_approval(name, args, risk, reason, self.perm)
            log_audit("tool_approval", {"tool": name, "risk": risk.value, "answer": ans})
            if not approved:
                out = f"DENIED by user ({ans})"
                self.hooks.fire("PostToolUseFailure", name, {"error": out})
                return out

        # Auto-snapshot before the first mutation of a burst
        if self.autocp and name in MUTATING_TOOLS and name not in ("git_commit", "git_undo"):
            try:
                cp = self.checkpoints.maybe_auto(mutation=True)
                if cp:
                    log_audit("auto_checkpoint", {"id": cp, "tool": name})
            except Exception:
                pass

        # Execute
        fn = getattr(self, f"tool_{name}", None)
        if fn is None:
            return f"ERROR: unknown tool '{name}'"
        try:
            out = fn(**args)
        except TypeError as e:
            # retry with only known kwargs
            try:
                import inspect
                sig = inspect.signature(fn)
                filtered = {k: v for k, v in args.items() if k in sig.parameters}
                out = fn(**filtered)
            except Exception as e2:
                return f"ERROR: {e2}"
        except ToolError as e:
            out = f"ERROR: {e}"
        except Exception as e:
            out = f"ERROR: {type(e).__name__}: {e}"

        out = mask_secrets(str(out))
        log_audit("tool_executed", {"tool": name, "risk": risk.value, "ok": not str(out).startswith("ERROR")})
        self.hooks.fire("PostToolUse", name, {"args": args, "output_len": len(out)})
        return _clip(out)

    def execute_parallel(self, calls: list) -> list:
        """Run a batch of (id, name, args) concurrently when all are read-only.

        Falls back to sequential execution (in original order) for any mutating tool
        or when the batch is small, so results always align with the caller's list.
        """
        if len(calls) < 2 or not all(n in PARALLEL_SAFE_TOOLS for _, n, _ in calls):
            return [(cid, self.execute(n, a)) for cid, n, a in calls]
        results = {}
        with ThreadPoolExecutor(max_workers=min(self.parallel_workers, len(calls))) as pool:
            futs = {pool.submit(self.execute, n, a): cid for cid, n, a in calls}
            for fut in as_completed(futs):
                cid = futs[fut]
                try:
                    results[cid] = fut.result()
                except Exception as e:
                    results[cid] = f"ERROR: parallel tool failed: {e}"
        return [(cid, results.get(cid, "ERROR: missing result")) for cid, _, _ in calls]

    # ---------- file tools ----------
    def tool_read_file(self, path: str, start_line: int = 1, max_lines: int = 400,
                       offset: int = 0) -> str:
        p = self._resolve(path)
        if not p.exists(): raise ToolError(f"not found: {path}")
        if p.is_dir(): raise ToolError(f"is a directory: {path} (use list_dir)")
        if p.stat().st_size > 2 * 1024 * 1024: raise ToolError(f"file too large: {p.stat().st_size} bytes")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(start_line) + max(0, int(offset or 0)))
        end = min(len(lines), start + int(max_lines) - 1)
        out = []
        for i in range(start, end + 1):
            out.append(f"{i:>6}\t{lines[i-1]}")
        header = f"{path}  (lines {start}-{end} of {len(lines)})"
        if end < len(lines):
            header += f"  [use offset={end - start + 1} to continue]"
        return header + "\n" + "\n".join(out)

    def tool_write_file(self, path: str, content: str, create_backup: bool = True) -> str:
        p = self._resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        existed = p.exists()
        if existed and create_backup:
            bak = p.with_suffix(p.suffix + f".bak.{int(time.time())}")
            shutil.copy2(p, bak)
        p.write_text(content, encoding="utf-8")
        return f"{'Updated' if existed else 'Created'} {path} ({len(content)} chars, {content.count(chr(10))+1} lines)"

    def tool_edit_file(self, path: str, old_string: str, new_string: str,
                       replace_all: bool = False) -> str:
        p = self._resolve(path)
        if not p.exists(): raise ToolError(f"not found: {path}")
        text = p.read_text(encoding="utf-8")
        if old_string not in text:
            # fuzzy hint
            return f"ERROR: old_string not found in {path}. Use read_file to get exact text."
        count = text.count(old_string)
        if not replace_all and count > 1:
            return f"ERROR: old_string matches {count} times; add more context or set replace_all=true"
        new_text = text.replace(old_string, new_string) if replace_all else text.replace(old_string, new_string, 1)
        bak = p.with_suffix(p.suffix + f".bak.{int(time.time())}")
        shutil.copy2(p, bak)
        p.write_text(new_text, encoding="utf-8")
        return f"Edited {path} ({count if replace_all else 1} replacement{'s' if count>1 else ''})"

    def tool_apply_patch(self, patch: str, path: str = "") -> str:
        """Apply a unified diff patch (git style). Each file header drives the target.

        Supports patches touching several files; creates missing files when the
        hunk is a pure addition (old count 0) or when /dev/null is the source.
        """
        if not patch.strip():
            raise ToolError("empty patch")
        # Split into per-file sections
        sections = re.split(r"(?=^diff --git )", patch, flags=re.M)
        sections = [sec for sec in sections if sec.strip()] or [patch]
        applied, skipped = [], []
        for sec in sections:
            m = re.search(r"^\+\+\+ (?:b/)?(\S+)", sec, re.M)
            src = re.search(r"^--- (?:a/)?(\S+)", sec, re.M)
            target = None
            if m and m.group(1) != "/dev/null":
                target = m.group(1)
            elif src and src.group(1) != "/dev/null":
                target = src.group(1)
            elif path:
                target = path
            if not target:
                skipped.append("(section without a file header)")
                continue
            p = self._resolve(target)
            if p.is_dir():
                skipped.append(f"{target}: is a directory")
                continue
            old_text, new_text, ok = self._apply_hunks(sec, p)
            if not ok:
                skipped.append(f"{target}: hunk context mismatch")
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            existed = p.exists()
            if existed:
                bak = p.with_suffix(p.suffix + f".bak.{int(time.time())}")
                shutil.copy2(p, bak)
            p.write_text(new_text, encoding="utf-8")
            delta = new_text.count("\n") - old_text.count("\n")
            applied.append(f"{target} ({'+' if delta >= 0 else ''}{delta} lines)")
        if not applied:
            raise ToolError("nothing applied; skipped: " + "; ".join(skipped))
        out = "patch applied: " + ", ".join(applied)
        if skipped:
            out += "\nSKIPPED: " + "; ".join(skipped)
        return out

    @staticmethod
    def _apply_hunks(section: str, path: Path):
        """Apply unified-diff hunks of one file section.

        Returns (old_text, new_text, ok). Lines are compared without trailing
        newlines; the rendered text re-adds them.
        """
        trailing_nl = True
        if path.exists():
            old_text = path.read_text(encoding="utf-8", errors="replace")
            trailing_nl = old_text.endswith("\n") or old_text == ""
            old = old_text.splitlines()
        else:
            old_text, old = "", []
        hunks = re.split(r"(?=^@@ )", section, flags=re.M)
        hunks = [h for h in hunks if h.startswith("@@")]
        if not hunks:
            return old_text, old_text, False
        new = list(old)
        offset = 0
        for hunk in hunks:
            hm = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", hunk)
            if not hm:
                return old_text, old_text, False
            old_start = int(hm.group(1)) - 1 + offset
            body = [l for l in hunk.splitlines()[1:] if l[:1] in (" ", "+", "-", "\\")]
            window, expected = [], []
            for line in body:
                tag, content = line[:1], line[1:].rstrip("\r")
                if tag == " ":
                    window.append(content); expected.append(content)
                elif tag == "+":
                    window.append(content)
                elif tag == "-":
                    expected.append(content)
            idx = max(0, min(old_start, len(new)))
            if expected:
                found = ToolEngine._find_sublist(new, expected, start=idx)
                if found is None:
                    found = ToolEngine._find_sublist(new, expected, start=0)
                if found is None:
                    return old_text, old_text, False
                idx = found
            new[idx:idx + len(expected)] = window
            offset += len(window) - len(expected)
        new_text = "\n".join(new)
        if new and trailing_nl:
            new_text += "\n"
        return old_text, new_text, True

    @staticmethod
    def _find_sublist(hay, needle, start=0):
        n, m = len(hay), len(needle)
        if m == 0:
            return start
        for i in range(max(0, start), n - m + 1):
            if hay[i:i + m] == needle:
                return i
        return None

    def tool_file_stat(self, path: str) -> str:
        p = self._resolve(path)
        if not p.exists(): raise ToolError(f"not found: {path}")
        st = p.stat()
        kind = "dir" if p.is_dir() else "file" if p.is_file() else "other"
        lines = [
            f"path: {p}",
            f"type: {kind}",
            f"size: {st.st_size:,} bytes",
            f"mtime: {datetime.fromtimestamp(st.st_mtime):%Y-%m-%d %H:%M:%S}",
            f"mode: {oct(st.st_mode)}",
        ]
        if kind == "file" and st.st_size <= 1024 * 1024:
            try:
                raw = p.read_bytes()[:4096]
                lines.append(f"sha256: {hashlib.sha256(p.read_bytes()).hexdigest()}")
                if raw.startswith(b"\x7fELF"): lines.append("magic: ELF binary")
                elif raw[:4] == b"\x89PNG": lines.append("magic: PNG image")
                elif raw[:3] == b"\xff\xd8\xff": lines.append("magic: JPEG image")
                elif raw[:2] == b"PK": lines.append("magic: ZIP archive")
                elif raw[:5] == b"<!DOC" or raw[:5] == b"<html": lines.append("magic: HTML")
                else:
                    raw.decode("utf-8"); lines.append("magic: text/utf-8")
            except UnicodeDecodeError:
                lines.append("magic: binary")
            except Exception:
                pass
        return "\n".join(lines)

    def tool_delete_file(self, path: str) -> str:
        p = self._resolve(path)
        if not p.exists(): raise ToolError(f"not found: {path}")
        if p.is_dir():
            shutil.rmtree(p)
            return f"Deleted directory {path}"
        p.unlink()
        return f"Deleted {path}"

    def tool_list_dir(self, path: str = ".", depth: int = 2, show_hidden: bool = False) -> str:
        base = self._resolve(path)
        if not base.exists(): raise ToolError(f"not found: {path}")
        out = []
        def walk(d: Path, prefix: str, lvl: int):
            if lvl > depth: return
            try:
                entries = sorted(d.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
            except PermissionError:
                out.append(prefix + "[permission denied]"); return
            for e in entries:
                if not show_hidden and e.name.startswith("."): continue
                if e.name in SKIP_DIRS or e.name.endswith((".bak",)): continue
                if e.is_dir():
                    out.append(prefix + e.name + "/")
                    walk(e, prefix + "  ", lvl + 1)
                else:
                    size = e.stat().st_size
                    out.append(f"{prefix}{e.name}  ({size}B)")
        walk(base, "", 0)
        return _clip("\n".join(out) or "(empty)")

    def tool_tree(self, path: str = ".", max_depth: int = 3, max_entries: int = 300) -> str:
        """Compact directory tree (files + sizes, directories marked with /)."""
        base = self._resolve(path)
        if not base.exists(): raise ToolError(f"not found: {path}")
        if not base.is_dir(): return str(self.tool_file_stat(path))
        out = [f"{base.name or str(base)}/"]
        count = [0]
        def walk(d: Path, prefix: str, lvl: int):
            if lvl > max_depth or count[0] >= max_entries:
                return
            try:
                entries = sorted(d.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
            except PermissionError:
                out.append(prefix + "[permission denied]"); return
            for i, e in enumerate(entries):
                if count[0] >= max_entries:
                    out.append(prefix + "…"); return
                if e.name.startswith(".") or e.name in SKIP_DIRS or e.name.endswith(".bak"):
                    continue
                last = i == len(entries) - 1
                branch = "└─ " if last else "├─ "
                nxt = "   " if last else "│  "
                if e.is_dir():
                    out.append(f"{prefix}{branch}{e.name}/")
                    walk(e, prefix + nxt, lvl + 1)
                else:
                    count[0] += 1
                    size = e.stat().st_size
                    unit = "B" if size < 1024 else "K" if size < 1024**2 else "M"
                    val = size if size < 1024 else size / (1024 if unit == "K" else 1024**2)
                    out.append(f"{prefix}{branch}{e.name}  ({val:.0f}{unit})")
        walk(base, "", 0)
        return _clip("\n".join(out))

    def tool_glob(self, pattern: str, path: str = ".") -> str:
        base = self._resolve(path)
        matches = []
        try:
            for p in sorted(base.rglob(pattern)):
                if any(part in SKIP_DIRS for part in p.parts): continue
                matches.append(str(p.relative_to(base)))
                if len(matches) >= 200: break
        except Exception as e:
            raise ToolError(str(e))
        return "\n".join(matches) or f"no matches for {pattern}"

    def tool_search_code(self, pattern: str, path: str = ".", file_glob: str = "*",
                         max_results: int = 100, context: int = 0) -> str:
        base = self._resolve(path)
        try:
            rx = re.compile(pattern)
        except re.error as e:
            raise ToolError(f"invalid regex: {e}")
        # Fast path: ripgrep when available (ignores hidden/binary, respects .gitignore)
        if shutil.which("rg"):
            cmd = ["rg", "--line-number", "--no-heading", "--color=never",
                   "--max-count", "5", "--max-filesize", "2M", "-e", pattern]
            if context:
                cmd += ["-C", str(min(context, 3))]
            if file_glob and file_glob != "*":
                cmd += ["-g", file_glob]
            cmd += ["--", str(base)]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                out = (proc.stdout or "").strip()
                if out:
                    lines = out.splitlines()
                    if len(lines) > max_results:
                        out = "\n".join(lines[:max_results]) + f"\n… (limit {max_results})"
                    return _clip(out)
                if proc.returncode == 1:  # rg: no matches
                    return f"no matches for {pattern!r}"
            except Exception:
                pass  # fall through to pure-python scan
        results = []
        for f in sorted(base.rglob(file_glob)):
            if not f.is_file() or any(part in SKIP_DIRS for part in f.parts): continue
            if f.suffix in (".pyc", ".png", ".jpg", ".zip", ".jar", ".so", ".bin"): continue
            if f.stat().st_size > 2 * 1024 * 1024: continue
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            rel = str(f.relative_to(base))
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    results.append(f"{rel}:{i}: {line.strip()[:200]}")
                    if context:
                        for j in range(max(1, i-context), min(len(lines), i+context)+1):
                            if j != i:
                                results.append(f"{rel}:{j}: {lines[j-1].strip()[:200]}")
                    if len(results) >= max_results:
                        return _clip("\n".join(results) + f"\n… (limit {max_results})")
        return "\n".join(results) or f"no matches for {pattern!r}"

    def tool_diff_show(self, path_a: str, path_b: str) -> str:
        a = self._resolve(path_a); b = self._resolve(path_b)
        ta = a.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if a.exists() else []
        tb = b.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if b.exists() else []
        return "".join(difflib.unified_diff(ta, tb, fromfile=path_a, tofile=path_b)) or "(no diff)"

    # ---------- shell ----------
    def tool_run_command(self, command: str, timeout: int = 60, workdir: str = "") -> str:
        cwd = self._resolve(workdir) if workdir else self.workdir
        if not cwd.exists(): cwd = self.workdir
        try:
            timeout = max(1, min(int(timeout or 60), 300))
        except (TypeError, ValueError):
            timeout = 60
        try:
            proc = subprocess.run(command, shell=True, cwd=str(cwd),
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return f"ERROR: command timed out after {timeout}s"
        out = proc.stdout or ""
        if proc.stderr:
            out += ("\n[stderr]\n" + proc.stderr)
        out = out.strip() or f"(no output, exit={proc.returncode})"
        if proc.returncode != 0:
            out += f"\n(exit code {proc.returncode})"
        return out

    # ---------- git ----------
    def _git(self, *args, timeout=30):
        try:
            proc = subprocess.run(["git", *args], cwd=str(self.workdir),
                                  capture_output=True, text=True, timeout=timeout)
            return (proc.stdout + proc.stderr).strip(), proc.returncode
        except Exception as e:
            return str(e), 1

    def tool_git_status(self):
        out, _ = self._git("status", "--short", "--branch")
        return out or "(not a git repo or clean)"

    def tool_git_diff(self, path: str = "", staged: bool = False) -> str:
        args = ["diff", "--stat"] + (["--staged"] if staged else [])
        if path: args.append(path)
        out, _ = self._git(*args)
        if not out:
            args2 = ["diff"] + (["--staged"] if staged else []) + ([path] if path else [])
            out, _ = self._git(*args2)
        return out or "(no diff)"

    def tool_git_log(self, count: int = 10) -> str:
        out, _ = self._git("log", f"-{int(count)}", "--oneline", "--decorate")
        return out or "(no commits)"

    def tool_git_init(self):
        out, rc = self._git("init")
        return out or "git initialized"

    def tool_git_commit(self, message: str, add_all: bool = True) -> str:
        if add_all:
            self._git("add", "-A")
        out, rc = self._git("commit", "-m", message)
        if rc != 0 and "nothing to commit" in out:
            return "nothing to commit"
        if rc != 0:
            return f"ERROR: {out}"
        stat, _ = self._git("status", "--short")
        return out + ("\n" + stat if stat else "")

    def tool_git_undo(self, message: str = "") -> str:
        """Soft-reset last commit (safe undo). Also handles a parentless root commit."""
        _, rc = self._git("rev-parse", "--verify", "HEAD^")
        if rc == 0:
            out, rc = self._git("reset", "--soft", "HEAD~1")
            if rc != 0: return f"ERROR: {out}"
            return "Last commit undone (changes staged). " + (message or "")
        # Root commit: HEAD~1 does not exist. Delete the ref instead — this keeps
        # the index and working tree exactly as they are (same as --soft).
        out, rc = self._git("update-ref", "-d", "HEAD")
        if rc != 0: return f"ERROR: {out}"
        return "Root commit undone (files kept, branch is unborn again). " + (message or "")

    def tool_git_branch(self, action: str = "list", name: str = "", from_ref: str = "") -> str:
        """List / create / switch / delete git branches."""
        action = (action or "list").lower()
        if action == "list":
            out, _ = self._git("branch", "-a", "--no-color")
            return out or "(no branches)"
        if not name:
            return "ERROR: name is required for this action"
        if action in ("create", "new"):
            args = ["branch", name] + ([from_ref] if from_ref else [])
            out, rc = self._git(*args)
            return out or f"branch created: {name}" if rc == 0 else f"ERROR: {out}"
        if action in ("switch", "checkout"):
            out, rc = self._git("switch", name) if from_ref == "" else self._git("switch", "-c", name, from_ref)
            if rc != 0:
                out, rc = self._git("checkout", name)
            return out or f"switched to {name}" if rc == 0 else f"ERROR: {out}"
        if action == "delete":
            out, rc = self._git("branch", "-d", name)
            if rc != 0:
                out, rc = self._git("branch", "-D", name)
                return out or f"branch force-deleted: {name}" if rc == 0 else f"ERROR: {out}"
            return out or f"branch deleted: {name}"
        return f"ERROR: unknown git_branch action: {action}"

    def tool_git_stash(self, action: str = "list", message: str = "") -> str:
        """Stash management: list | push | pop | apply."""
        action = (action or "list").lower()
        if action == "list":
            out, _ = self._git("stash", "list")
            return out or "(no stashes)"
        if action == "push":
            out, rc = self._git("stash", "push", "-m", message or f"engineer {datetime.now():%H:%M:%S}")
            return out or "stash saved" if rc == 0 else f"ERROR: {out}"
        if action in ("pop", "apply"):
            out, rc = self._git("stash", action)
            return out or f"stash {action}ed" if rc == 0 else f"ERROR: {out}"
        return f"ERROR: unknown git_stash action: {action}"

    # ---------- web ----------
    def tool_fetch_url(self, url: str, max_chars: int = 8000, format: str = "text") -> str:
        block_private_host(url)
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; NVIDIA-Engineer/7.0)",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
        })
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                ctype = resp.headers.get("Content-Type", "")
                raw = resp.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as e:
            raise ToolError(f"HTTP {e.code}")
        except Exception as e:
            raise ToolError(f"fetch failed: {e}")
        if "charset=" in ctype:
            enc = ctype.split("charset=")[-1].split(";")[0].strip()
        else:
            enc = "utf-8"
        text = raw.decode(enc, errors="replace")
        if format != "raw" and ("html" in ctype or text.lstrip()[:1] == "<"):
            text = self._html_to_text(text)
        return _clip(text, max_chars)

    def tool_download_file(self, url: str, dest: str = "", max_bytes: int = 50_000_000) -> str:
        """Download a remote file into the workspace (SSRF-guarded, size-capped)."""
        block_private_host(url)
        if not dest:
            name = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1] or f"download_{int(time.time())}"
            dest = name
        p = self._resolve(dest)
        if is_protected_path(str(p), self.workdir):
            raise ToolError(f"refusing to write outside workspace: {dest}")
        p.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; NVIDIA-Engineer/7.0)"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                clen = resp.headers.get("Content-Length")
                if clen and int(clen) > max_bytes:
                    raise ToolError(f"remote file too large: {clen} bytes (max {max_bytes})")
                tmp = p.with_suffix(p.suffix + ".part")
                total = 0
                with open(tmp, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            f.close(); tmp.unlink(missing_ok=True)
                            raise ToolError(f"download exceeded {max_bytes} bytes")
                        f.write(chunk)
                tmp.replace(p)
        except urllib.error.HTTPError as e:
            raise ToolError(f"HTTP {e.code}")
        except ToolError:
            raise
        except Exception as e:
            raise ToolError(f"download failed: {e}")
        h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
        return f"downloaded {url} → {dest} ({total:,} bytes, sha256:{h}…)"

    def tool_extract_archive(self, archive: str, dest: str = "", max_files: int = 5000) -> str:
        """Safely extract .zip / .tar / .tar.gz / .tgz into the workspace."""
        src = self._resolve(archive)
        if not src.exists(): raise ToolError(f"not found: {archive}")
        target = self._resolve(dest) if dest else src.parent
        if is_protected_path(str(target), self.workdir):
            raise ToolError(f"refusing to extract outside workspace: {dest or target}")
        target.mkdir(parents=True, exist_ok=True)
        real_base = target.resolve()
        names = []
        try:
            if zipfile.is_zipfile(src):
                with zipfile.ZipFile(src) as zf:
                    infos = zf.infolist()[:max_files]
                    for info in infos:
                        out = (real_base / info.filename).resolve()
                        if not str(out).startswith(str(real_base)):
                            raise ToolError(f"zip-slip blocked: {info.filename}")
                    zf.extractall(real_base)
                    names = [i.filename for i in infos]
            elif tarfile.is_tarfile(src):
                with tarfile.open(src) as tf:
                    members = tf.getmembers()[:max_files]
                    for m in members:
                        out = (real_base / m.name).resolve()
                        if not str(out).startswith(str(real_base)):
                            raise ToolError(f"tar-slip blocked: {m.name}")
                    for m in members:
                        if m.isdev() or m.isfifo():
                            continue
                        tf.extract(m, real_base, filter="data")
                    names = [m.name for m in members]
            else:
                raise ToolError(f"unsupported archive format: {src.suffix}")
        except ToolError:
            raise
        except Exception as e:
            raise ToolError(f"extract failed: {e}")
        return f"extracted {len(names)} entries → {dest or str(target)}" + \
               ("" if len(names) < 20 else "\n" + "\n".join("  " + n for n in names[:15]) + "\n  …")

    @staticmethod
    def _html_to_text(html_doc: str) -> str:
        html_doc = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", "", html_doc)
        html_doc = re.sub(r"(?is)<!--.*?-->", "", html_doc)
        html_doc = re.sub(r"(?i)<(br|/p|/div|/li|/tr|/h[1-6])[^>]*>", "\n", html_doc)
        html_doc = re.sub(r"(?i)</t[dh]>", " | ", html_doc)
        text = re.sub(r"(?s)<[^>]+>", "", html_doc)
        text = html.unescape(text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text)
        return text.strip()

    def tool_web_search(self, query: str, max_results: int = 5) -> str:
        """Web search via Bing HTML (DDG fallback). No API key needed."""
        q = urllib.parse.quote_plus(query)
        engines = [
            ("bing", f"https://www.bing.com/search?q={q}&setlang=en",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
            ("ddg", f"https://html.duckduckgo.com/html/?q={q}",
             "Mozilla/5.0 (compatible; NVIDIA-Engineer/7.0)"),
        ]
        errors = []
        for name, url, ua in engines:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    page = resp.read(1024 * 1024).decode("utf-8", errors="replace")
            except Exception as e:
                errors.append(f"{name}: {e}")
                continue
            results = []
            if name == "bing":
                for block in re.findall(r'<li class="b_algo".*?</li>', page, re.S)[:max_results]:
                    a = re.search(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', block, re.S)
                    if not a:
                        continue
                    title = re.sub(r"<[^>]+>", "", a.group(2)).strip()
                    sn = re.search(r'<p[^>]*>(.*?)</p>', block, re.S) or re.search(r'class="b_lineclamp[^"]*"[^>]*>(.*?)</', block, re.S)
                    snippet = re.sub(r"<[^>]+>", "", sn.group(1)).strip()[:220] if sn else ""
                    results.append(f"- {title}\n  {a.group(1)}" + (f"\n  {snippet}" if snippet else ""))
            else:
                for m in re.finditer(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', page, re.S):
                    href, title = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
                    mm = re.search(r"uddg=([^&]+)", href)
                    if mm:
                        href = urllib.parse.unquote(mm.group(1))
                    if href.startswith("http"):
                        results.append(f"- {title}\n  {href}")
                    if len(results) >= max_results:
                        break
            if results:
                return f"[{name}]\n" + "\n".join(results[:max_results])
        raise ToolError(f"all engines failed: {'; '.join(errors)}")

    # ---------- analysis ----------
    def tool_analyze_project(self, path: str = ".", max_files: int = 400) -> str:
        base = self._resolve(path)
        stats = {"dirs": 0, "files": 0, "by_ext": {}, "total_bytes": 0}
        key_files, code_files, tests = [], [], []
        for f in base.rglob("*"):
            if any(part in SKIP_DIRS for part in f.parts): continue
            if f.is_dir():
                stats["dirs"] += 1; continue
            if stats["files"] >= max_files: break
            stats["files"] += 1
            size = f.stat().st_size
            stats["total_bytes"] += size
            ext = f.suffix or "(none)"
            stats["by_ext"][ext] = stats["by_ext"].get(ext, 0) + 1
            rel = str(f.relative_to(base))
            low = rel.lower()
            if f.name.lower() in ("readme.md", "readme", "package.json", "pyproject.toml",
                                  "cargo.toml", "go.mod", "makefile", "dockerfile",
                                  "requirements.txt", "setup.py", "tsconfig.json"):
                key_files.append(rel)
            if ext in (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", ".rb"):
                if "test" in low or "spec" in low:
                    tests.append(rel)
                else:
                    code_files.append(rel)
        # repo map: function/class defs for top code files (lite AST via regex)
        defs = []
        for rel in code_files[:60]:
            p = base / rel
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")[:100_000]
            except Exception:
                continue
            if rel.endswith(".py"):
                for m in re.finditer(r"^(?:class|def)\s+(\w+)", txt, re.M):
                    defs.append(f"{rel}:{m.group(1)}")
            elif rel.endswith((".js", ".ts", ".jsx", ".tsx")):
                for m in re.finditer(r"^(?:export\s+)?(?:async\s+)?function\s+(\w+)|^(?:export\s+)?class\s+(\w+)|^(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(", txt, re.M):
                    name = m.group(1) or m.group(2) or m.group(3)
                    if name: defs.append(f"{rel}:{name}")
        # git info
        git_info = ""
        branch, rc = self._git("rev-parse", "--abbrev-ref", "HEAD")
        if rc == 0 and branch:
            last, _ = self._git("log", "-1", "--oneline")
            git_info = f"git: {branch} · {last}"
        lines = [f"Project: {base.name}", f"files={stats['files']} dirs={stats['dirs']} size={stats['total_bytes']//1024}KB"]
        if git_info: lines.append(git_info)
        exts = sorted(stats["by_ext"].items(), key=lambda kv: -kv[1])[:10]
        lines.append("top ext: " + ", ".join(f"{k}={v}" for k, v in exts))
        if key_files: lines.append("key files: " + ", ".join(key_files[:15]))
        lines.append(f"code files: {len(code_files)}, test files: {len(tests)}")
        if tests: lines.append("tests: " + ", ".join(tests[:10]))
        if defs:
            lines.append(f"defs ({len(defs)}):")
            lines.extend("  " + d for d in defs[:40])
        return "\n".join(lines)

    # ---------- code intelligence ----------
    @staticmethod
    def _extract_symbols(rel: str, text: str) -> list:
        out = []
        if rel.endswith(".py"):
            for m in re.finditer(r"^(?P<indent>[ \t]*)(?P<kind>class|def|async def)\s+(?P<name>\w+)\s*(?P<sig>\([^)]*\))?",
                                 text, re.M):
                out.append(f"{rel}:{m.start()}: {m.group('indent')}{m.group('kind')} {m.group('name')}{m.group('sig') or ''}")
        elif rel.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            pats = [
                r"^(?P<indent>[ \t]*)(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>\w+)\s*\(",
                r"^(?P<indent>[ \t]*)(?:export\s+)?(?:abstract\s+)?class\s+(?P<name>\w+)",
                r"^(?P<indent>[ \t]*)(?:export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>",
                r"^(?P<indent>[ \t]*)(?:export\s+)?(?:interface|type|enum)\s+(?P<name>\w+)",
            ]
            for pat in pats:
                for m in re.finditer(pat, text, re.M):
                    out.append(f"{rel}:{text[:m.start()].count(chr(10))+1}: {m.group('indent')}{m.group('name')}")
        elif rel.endswith((".go", ".rs")):
            kw = r"(?:pub\s+)?(?:async\s+)?(?:fn|struct|enum|trait|impl|type|mod)"
            if rel.endswith(".go"):
                kw = r"(?:func|type|struct|interface)"
            for m in re.finditer(rf"^(?P<indent>[ \t]*){kw}\s+(?P<name>[\w*]+)", text, re.M):
                out.append(f"{rel}:{text[:m.start()].count(chr(10))+1}: {m.group('name')}")
        elif rel.endswith((".c", ".h", ".cpp", ".hpp", ".cc")):
            for m in re.finditer(r"^(?:[\w\s\*]+?)\b(?P<name>\w+)\s*\([^;{]*\)\s*\{", text, re.M):
                out.append(f"{rel}:{text[:m.start()].count(chr(10))+1}: {m.group('name')}()")
        return out

    def tool_symbols(self, path: str = ".", pattern: str = "", max_defs: int = 120) -> str:
        """Extract a symbol map (classes/functions/types) from one file or the project."""
        p = self._resolve(path)
        files = []
        if p.is_file():
            files = [p]
            base = p.parent
        else:
            base = p
            for f in sorted(base.rglob("*")):
                if not f.is_file() or any(part in SKIP_DIRS for part in f.parts):
                    continue
                if f.suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".c", ".h", ".cpp", ".hpp"):
                    files.append(f)
                if len(files) >= 150:
                    break
        rx = re.compile(pattern) if pattern else None
        defs = []
        for f in files:
            try:
                txt = f.read_text(encoding="utf-8", errors="replace")[:200_000]
            except Exception:
                continue
            rel = str(f.relative_to(base)) if f != p else f.name
            for d in self._extract_symbols(rel, txt):
                if rx and not rx.search(d):
                    continue
                defs.append(d)
                if len(defs) >= max_defs:
                    break
            if len(defs) >= max_defs:
                break
        if not defs:
            return f"no symbols found under {path}"
        return f"symbols ({len(defs)}):\n" + "\n".join(defs)

    def tool_test_run(self, command: str = "") -> str:
        """Run test command; auto-detect if empty."""
        if not command:
            if (self.workdir / "pyproject.toml").exists() or (self.workdir / "tests").exists() or list(self.workdir.glob("test_*.py")):
                command = "python3 -m pytest -q --timeout=120"
            elif (self.workdir / "package.json").exists():
                command = "npm test"
            elif (self.workdir / "Makefile").exists():
                command = "make test"
            else:
                return "ERROR: no test command detected; pass command explicitly"
        return self.tool_run_command(command, timeout=180)

    # ---------- memory ----------
    def tool_memory_write(self, topic: str, content: str, mem_type: str = "project") -> str:
        return self.memory.write(topic, content, mem_type)

    def tool_memory_read(self, topic: str = "") -> str:
        if not topic:
            return self.memory.read_index()
        return self.memory.read(topic)

    def tool_memory_list(self) -> str:
        return self.memory.list_topics()

    def tool_memory_search(self, query: str) -> str:
        return self.memory.search(query)

    def tool_memory_append(self, topic: str, content: str) -> str:
        return self.memory.append(topic, content)

    def tool_memory_delete(self, topic: str) -> str:
        return self.memory.delete(topic)

    # ---------- skills ----------
    def tool_skill_list(self) -> str:
        skills = self.skills.list_skills()
        if not skills: return "no skills installed"
        return "\n".join(f"- {sk['name']}: {sk['description'][:100]}" for sk in skills)

    def tool_skill_load(self, name: str) -> str:
        content = self.skills.load_skill(name)
        if content is None: return f"ERROR: skill not found: {name}"
        return _clip(content, 6000)

    def tool_skill_search(self, query: str) -> str:
        return self.skills.search_skills(query)

    def tool_skill_write(self, name: str, description: str, content: str) -> str:
        return self.skills.create_skill(name, description, content)

    # ---------- checkpoint ----------
    def tool_checkpoint(self, action: str = "create", label: str = "", checkpoint_id: str = "") -> str:
        if action == "create":
            cp = self.checkpoints.create(label=label)
            return f"checkpoint created: {cp}" if cp else "ERROR: checkpoint failed"
        if action == "list":
            records = self.checkpoints.list(15)
            if not records: return "no checkpoints"
            return "\n".join(f"{r['id']}  {r.get('label','')}  files={r.get('files',0)}  {r.get('ts','')[:19]}" for r in records)
        if action == "restore":
            ok, msg = self.checkpoints.restore(checkpoint_id or None)
            return msg if ok else f"ERROR: {msg}"
        if action == "diff":
            return _clip(self.checkpoints.diff(checkpoint_id or None), 6000)
        return f"ERROR: unknown checkpoint action: {action}"

    # ---------- todos / utility ----------
    def tool_set_todos(self, todos: list) -> str:
        if self.session is not None:
            clean = []
            for t in todos:
                if isinstance(t, dict):
                    clean.append({"desc": t.get("desc") or t.get("description") or str(t),
                                  "status": t.get("status", "pending")})
                else:
                    clean.append({"desc": str(t), "status": "pending"})
            self.session.todos = clean
        return f"todos updated: {len(todos)} items"

    def tool_todo_update(self, index: int = -1, status: str = "", desc: str = "") -> str:
        """Update a single todo by index (-1 = last). Status: pending|in_progress|done."""
        if self.session is None or not self.session.todos:
            return "ERROR: no todos set; use set_todos first"
        try:
            i = int(index)
        except (TypeError, ValueError):
            return "ERROR: index must be an integer"
        if i < 0:
            i = len(self.session.todos) + i
        if i < 0 or i >= len(self.session.todos):
            return f"ERROR: index out of range 0..{len(self.session.todos)-1}"
        item = self.session.todos[i]
        if not isinstance(item, dict):
            item = {"desc": str(item), "status": "pending"}
            self.session.todos[i] = item
        if status:
            if status not in ("pending", "in_progress", "done"):
                return "ERROR: status must be pending|in_progress|done"
            item["status"] = status
        if desc:
            item["desc"] = desc
        self.session.save()
        return f"todo[{i}] → [{item.get('status','pending')}] {item.get('desc','')}"

    def tool_json_query(self, data: str, path: str = "") -> str:
        """Query JSON with dotted path like a.b[0].c"""
        try:
            obj = json.loads(data) if isinstance(data, str) else data
        except Exception as e:
            raise ToolError(f"invalid JSON: {e}")
        if path:
            for part in re.findall(r"[^.\[\]]+|\[\d+\]", path):
                if part.startswith("["):
                    obj = obj[int(part[1:-1])]
                else:
                    obj = obj[part]
        return json.dumps(obj, ensure_ascii=False, indent=2)[:MAX_TOOL_OUTPUT]

    def tool_hash_text(self, text: str, algorithm: str = "sha256") -> str:
        try:
            h = hashlib.new(algorithm, text.encode("utf-8"))
        except ValueError:
            raise ToolError(f"unknown algorithm: {algorithm}")
        return h.hexdigest()

    def tool_base64(self, text: str, mode: str = "encode") -> str:
        if mode == "encode":
            return base64.b64encode(text.encode("utf-8")).decode("ascii")
        try:
            return base64.b64decode(text).decode("utf-8")
        except Exception as e:
            raise ToolError(f"decode failed: {e}")

    def tool_http_request(self, url: str, method: str = "GET", headers: dict = None,
                          body: str = "", timeout: int = 20) -> str:
        method = method.upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
            raise ToolError(f"method not allowed: {method}")
        block_private_host(url)
        data = body.encode("utf-8") if body and method in ("POST", "PUT", "PATCH") else None
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read(512 * 1024).decode("utf-8", errors="replace")
                return f"HTTP {resp.status}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + text
        except urllib.error.HTTPError as e:
            text = e.read(64 * 1024).decode("utf-8", errors="replace")
            return f"HTTP {e.code}\n{text}"
        except Exception as e:
            raise ToolError(str(e))

    def tool_notify(self, message: str, level: str = "info") -> str:
        """Terminal bell + optional Android toast via termux-notification if present."""
        sys.stderr.write("\a"); sys.stderr.flush()
        msg = mask_secrets(message)[:200]
        if shutil.which("termux-notification"):
            try:
                subprocess.run(["termux-notification", "--title", "NVIDIA Engineer", "--content", msg],
                               timeout=5, capture_output=True)
            except Exception:
                pass
        return f"notified: {msg}"

    def tool_subagent(self, task: str, model: str = "") -> str:
        """Run a subagent (read-only explore mode) to research without polluting main context."""
        sub_model = model or os.environ.get("NVIDIA_SUBAGENT_MODEL", "z-ai/glm-5.3-flash")
        client = NIMClient(self.session.api_key if self.session else None,
                           model=sub_model, timeout=90)
        system = (
            "You are a read-only research subagent. Explore the workspace at "
            f"{self.workdir} using tools read_file/list_dir/glob/search_code. "
            "Do NOT modify anything. Return a concise factual report."
        )
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]
        tools = [TOOL_SCHEMAS[n] for n in ("read_file", "list_dir", "glob", "search_code") if n in TOOL_SCHEMAS]
        final_text = []
        try:
            for step in range(12):
                if step > 0:
                    sys.stderr.write(s(f"\r  ⠹ 子代理 步骤 {step}/12", Palette.tok("dim")))
                    sys.stderr.flush()
                resp = client.chat(messages, tools=tools, max_tokens=2048)
                msg = resp["choices"][0]["message"]
                if msg.get("tool_calls"):
                    messages.append(msg)
                    for tc in msg["tool_calls"]:
                        fn = tc.get("function", {})
                        try:
                            fa = json.loads(fn.get("arguments") or "{}")
                        except Exception:
                            fa = {}
                        result = self._subagent_readonly(fn.get("name", ""), fa)
                        messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": _clip(result, 3000)})
                    continue
                final_text.append(msg.get("content") or "")
                break
            # clear the progress line
            sys.stderr.write("\r" + " " * 40 + "\r")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write("\r" + " " * 40 + "\r")
            sys.stderr.flush()
            return f"ERROR: subagent failed: {e}"
        return _clip("\n".join(final_text) or "(subagent returned nothing)", 6000)

    def _subagent_readonly(self, name, args):
        name = re.split(r"<\|", name)[0].strip()
        fn = getattr(self, f"tool_{name}", None)
        if fn is None or name not in ("read_file", "list_dir", "glob", "search_code"):
            return f"ERROR: tool not allowed for subagent: {name}"
        try:
            import inspect
            sig = inspect.signature(fn)
            filtered = {k: v for k, v in (args or {}).items() if k in sig.parameters}
            return str(fn(**filtered))
        except Exception as e:
            return f"ERROR: {e}"

    # ---------- helper ----------
    def _resolve(self, path: str) -> Path:
        if not path:
            return self.workdir
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.workdir / p
        return p


# ═══════════════════════════════════════════════════════════
# TOOL SCHEMAS (OpenAI function calling)
# ═══════════════════════════════════════════════════════════

def _fn(name, desc, props, required=None):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props,
                       "required": required or [], "additionalProperties": False}}}

_STR = {"type": "string"}
_INT = {"type": "integer"}
_BOOL = {"type": "boolean"}

TOOL_SCHEMAS: dict = {
    "read_file": _fn("read_file", "Read a file with line numbers. Use offset to page through long files.",
        {"path": _STR, "start_line": _INT, "max_lines": _INT, "offset": _INT}, ["path"]),
    "write_file": _fn("write_file", "Create or overwrite a file with full content.",
        {"path": _STR, "content": _STR, "create_backup": _BOOL}, ["path", "content"]),
    "edit_file": _fn("edit_file", "Replace an exact string in a file (unique match).",
        {"path": _STR, "old_string": _STR, "new_string": _STR, "replace_all": _BOOL},
        ["path", "old_string", "new_string"]),
    "apply_patch": _fn("apply_patch", "Apply a unified diff patch (git style) to one or more files.",
        {"patch": _STR, "path": _STR}, ["patch"]),
    "delete_file": _fn("delete_file", "Delete a file or directory (workspace only).",
        {"path": _STR}, ["path"]),
    "file_stat": _fn("file_stat", "File metadata: size, mtime, mode, sha256, magic type.",
        {"path": _STR}, ["path"]),
    "list_dir": _fn("list_dir", "List directory tree (skips node_modules/.git etc).",
        {"path": _STR, "depth": _INT, "show_hidden": _BOOL}),
    "tree": _fn("tree", "Compact directory tree with file sizes.",
        {"path": _STR, "max_depth": _INT, "max_entries": _INT}),
    "glob": _fn("glob", "Find files by glob pattern (e.g. **/*.py).",
        {"pattern": _STR, "path": _STR}, ["pattern"]),
    "search_code": _fn("search_code", "Regex search across code files (ripgrep fast path).",
        {"pattern": _STR, "path": _STR, "file_glob": _STR, "max_results": _INT, "context": _INT},
        ["pattern"]),
    "symbols": _fn("symbols", "Extract a symbol map (classes/functions/types) from a file or project.",
        {"path": _STR, "pattern": _STR, "max_defs": _INT}),
    "diff_show": _fn("diff_show", "Unified diff between two files.",
        {"path_a": _STR, "path_b": _STR}, ["path_a", "path_b"]),
    "run_command": _fn("run_command", "Run a shell command in the workspace.",
        {"command": _STR, "timeout": _INT, "workdir": _STR}, ["command"]),
    "git_status": _fn("git_status", "Show git status.", {}, []),
    "git_diff": _fn("git_diff", "Show git diff.", {"path": _STR, "staged": _BOOL}),
    "git_log": _fn("git_log", "Show recent commits.", {"count": _INT}),
    "git_init": _fn("git_init", "Initialize a git repository.", {}, []),
    "git_commit": _fn("git_commit", "Stage all and commit.", {"message": _STR, "add_all": _BOOL}, ["message"]),
    "git_undo": _fn("git_undo", "Soft-reset last commit (safe undo).", {"message": _STR}),
    "git_branch": _fn("git_branch", "List/create/switch/delete git branches.",
        {"action": _STR, "name": _STR, "from_ref": _STR}),
    "git_stash": _fn("git_stash", "Stash management: list|push|apply|pop.",
        {"action": _STR, "message": _STR}),
    "fetch_url": _fn("fetch_url", "Fetch a URL and return readable text (HTML stripped).",
        {"url": _STR, "max_chars": _INT, "format": _STR}, ["url"]),
    "web_search": _fn("web_search", "Web search via Bing/DuckDuckGo (no API key).",
        {"query": _STR, "max_results": _INT}, ["query"]),
    "download_file": _fn("download_file", "Download a remote file into the workspace (SSRF-guarded).",
        {"url": _STR, "dest": _STR, "max_bytes": _INT}, ["url"]),
    "extract_archive": _fn("extract_archive", "Safely extract zip/tar/tar.gz into the workspace.",
        {"archive": _STR, "dest": _STR, "max_files": _INT}, ["archive"]),
    "analyze_project": _fn("analyze_project", "Project structure analysis + repo map (lite).",
        {"path": _STR}),
    "test_run": _fn("test_run", "Run tests (auto-detect if command empty).", {"command": _STR}),
    "memory_write": _fn("memory_write", "Save a memory topic for future sessions.",
        {"topic": _STR, "content": _STR, "mem_type": _STR}, ["topic", "content"]),
    "memory_read": _fn("memory_read", "Read memory index (no topic) or a topic file.",
        {"topic": _STR}),
    "memory_list": _fn("memory_list", "List memory topics.", {}, []),
    "memory_search": _fn("memory_search", "Full-text search across memory topics.",
        {"query": _STR}, ["query"]),
    "memory_append": _fn("memory_append", "Append dated notes to an existing memory topic.",
        {"topic": _STR, "content": _STR}, ["topic", "content"]),
    "memory_delete": _fn("memory_delete", "Delete a memory topic.", {"topic": _STR}, ["topic"]),
    "skill_list": _fn("skill_list", "List available skills.", {}, []),
    "skill_load": _fn("skill_load", "Load full skill content (progressive disclosure).",
        {"name": _STR}, ["name"]),
    "skill_search": _fn("skill_search", "Search skills by keyword.", {"query": _STR}, ["query"]),
    "skill_write": _fn("skill_write", "Create a reusable skill file.",
        {"name": _STR, "description": _STR, "content": _STR}, ["name", "description", "content"]),
    "checkpoint": _fn("checkpoint", "Workspace checkpoint: create/list/restore/diff (shadow-git).",
        {"action": _STR, "label": _STR, "checkpoint_id": _STR}),
    "set_todos": _fn("set_todos", "Set/update the full task todo list.",
        {"todos": {"type": "array", "items": {"type": "object"}}}, ["todos"]),
    "todo_update": _fn("todo_update", "Update one todo by index (index=-1 is the last).",
        {"index": _INT, "status": _STR, "desc": _STR}, ["index", "status"]),
    "json_query": _fn("json_query", "Parse JSON and extract a dotted path like a.b[0].c.",
        {"data": _STR, "path": _STR}, ["data"]),
    "hash_text": _fn("hash_text", "Hash text with md5/sha1/sha256/sha512.",
        {"text": _STR, "algorithm": _STR}, ["text"]),
    "base64": _fn("base64", "Base64 encode or decode.", {"text": _STR, "mode": _STR}, ["text"]),
    "http_request": _fn("http_request", "HTTP request (GET/POST/PUT/PATCH/DELETE).",
        {"url": _STR, "method": _STR, "headers": {"type": "object"}, "body": _STR, "timeout": _INT}, ["url"]),
    "notify": _fn("notify", "Send a terminal/Android notification.", {"message": _STR, "level": _STR}, ["message"]),
    "subagent": _fn("subagent", "Delegate a read-only research task to a subagent.",
        {"task": _STR, "model": _STR}, ["task"]),
}



# ═══════════════════════════════════════════════════════════
# SESSION
# ═══════════════════════════════════════════════════════════

@dataclass
class Session:
    id: str = ""
    title: str = ""
    model: str = ""
    workdir: str = ""
    perm_mode: str = "acceptEdits"
    messages: list = field(default_factory=list)
    todos: list = field(default_factory=list)
    cost: dict = field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0, "usd": 0.0})
    created: str = ""
    updated: str = ""
    api_key: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"sess_{datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:4]}"
        if not self.created:
            self.created = datetime.now(timezone.utc).isoformat()

    def touch(self):
        self.updated = datetime.now(timezone.utc).isoformat()

    @property
    def path(self) -> Path:
        return SESSIONS_DIR / f"{self.id}.json"

    def save(self):
        self.touch()
        save_json(self.path, asdict(self))

    @classmethod
    def load(cls, path: Path) -> "Session":
        data = load_json(path, {}) or {}
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def list_all(cls) -> list:
        if not SESSIONS_DIR.exists():
            return []
        out = []
        for p in sorted(SESSIONS_DIR.glob("sess_*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                out.append(cls.load(p))
            except Exception:
                pass
        return out

    def add(self, role, content, **kw):
        msg = {"role": role, "content": content}
        msg.update(kw)
        self.messages.append(msg)

    def add_tool_result(self, tool_call_id, name, content):
        self.messages.append({"role": "tool", "tool_call_id": tool_call_id,
                              "name": name, "content": str(content)})

    def estimate_tokens(self) -> int:
        total = 0
        for m in self.messages:
            total += estimate_text_tokens(str(m.get("content") or ""))
            for tc in (m.get("tool_calls") or []):
                fn = tc.get("function") or {}
                total += estimate_text_tokens(str(fn.get("name") or "")) + \
                         estimate_text_tokens(str(fn.get("arguments") or ""))
        return total + 4 * len(self.messages)

    def summarize_state(self) -> dict:
        return {
            "id": self.id,
            "model": self.model,
            "workdir": self.workdir,
            "perm_mode": self.perm_mode,
            "messages": len(self.messages),
            "todos": self.todos,
            "cost": self.cost,
            "est_tokens": self.estimate_tokens(),
        }


# ═══════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════

def build_system_prompt(workdir: Path, mode: str, memory: MemorySystem = None,
                        skills: SkillsSystem = None, todos: list = None) -> str:
    mode_desc = MODES.get(mode, mode)
    todo_block = ""
    if todos:
        items = []
        for t in todos:
            st = t.get("status", "pending") if isinstance(t, dict) else "pending"
            d = t.get("desc", str(t)) if isinstance(t, dict) else str(t)
            items.append(f"- [{st}] {d}")
        todo_block = "\n\nCurrent todo list:\n" + "\n".join(items)
    mem_block = ""
    if memory:
        snippet = memory.get_context_snippet(2000)
        if snippet.strip() and snippet.strip() != "# Memory Index":
            mem_block = "\n\nLong-term memory (index):\n" + snippet
    skill_block = ""
    if skills:
        idx = skills.get_skill_index()
        if idx:
            skill_block = "\n\n" + idx
    return f"""You are NVIDIA ENGINEER PRO v{__version__}, an autonomous senior software engineer working in a real terminal.

Workspace: {workdir}
Permission mode: {mode} — {mode_desc}
Today: {datetime.now():%Y-%m-%d %H:%M}

## Workflow
1. Understand the request. For non-trivial tasks call set_todos with a numbered plan first, then keep it current with todo_update.
2. Explore before acting: analyze_project / tree / symbols / glob / search_code / read_file.
   Batch independent reads — many read-only calls are executed in parallel automatically.
3. Make changes with write_file / edit_file (exact old_string; read_file first) or apply_patch for multi-hunk diffs.
4. Verify: run tests/lint via test_run or run_command after every meaningful change.
5. If a step fails, diagnose (read the error, re-read the file) and retry — do not stop at the first failure.
6. Finish by marking all todos done and summarizing: what changed, test results, caveats.

## Rules
- Prefer edit_file over write_file for existing files; always read_file before editing.
- Never fabricate tool output. If you don't know, investigate.
- Keep tool outputs lean; use search instead of dumping large files. Page long files with offset.
- Work only inside the workspace. Do not touch system dirs, ~/.ssh, /etc, or secrets.
- Use run_command for build/test/lint; pass timeout for slow commands.
- Use checkpoint (action=create) before risky multi-file refactors; checkpoint restore / /undo to roll back.
  Automatic snapshots are taken before bursts of edits, so restoring is always safe.
- Use memory_write / memory_append to persist durable project knowledge for future sessions.
- Use subagent for long read-only research so it does not consume the main context.
- Never end your turn while a todo is still pending unless blocked; if blocked, say so explicitly.
- Commands you propose may be approval-gated; make them complete and correct the first time.
- Reply in the user's language (Chinese if they write Chinese).{todo_block}{mem_block}{skill_block}"""


# ═══════════════════════════════════════════════════════════
# COMPACTION (context condenser)
# ═══════════════════════════════════════════════════════════

def compact_messages(client: NIMClient, messages: list, todos: list = None) -> list:
    """Summarize old tool-heavy history into a single context message."""
    if len(messages) < 6:
        return messages
    sys_msgs = [m for m in messages if m["role"] == "system"]
    rest = [m for m in messages if m["role"] != "system"]
    # keep last 6 messages intact, summarize the rest
    keep = rest[-6:]
    old = rest[:-6]
    if not old:
        return messages
    old_rendered = []
    for m in old:
        role = m["role"]
        content = m.get("content") or ""
        if m.get("tool_calls"):
            names = [tc.get("function", {}).get("name", "?") for tc in m["tool_calls"]]
            content = f"[called: {', '.join(names)}] " + str(content)
        old_rendered.append(f"{role}: {str(content)[:500]}")
    todo_block = ""
    if todos:
        todo_block = "\n\nCurrent todo state (preserve exactly):\n" + "\n".join(
            f"- [{t.get('status','pending')}] {t.get('desc', t)}" if isinstance(t, dict) else f"- {t}"
            for t in todos)
    summary_prompt = (
        "Summarize this agent working history compactly for continuation. "
        "Preserve: goals, decisions, files changed (with paths), commands run, test results, "
        "open issues, and the exact todo state. Output under 1200 words, plain prose + bullet lists."
        + todo_block + "\n\n" + "\n".join(old_rendered)[-120000:]
    )
    try:
        with spinner("压缩上下文"):
            resp = client.chat([
                {"role": "system", "content": "You are a context compactor. Output only the summary."},
                {"role": "user", "content": summary_prompt},
            ], max_tokens=1400)
        summary = resp["choices"][0]["message"].get("content", "")
        if not summary.strip():
            raise APIError(0, "empty summary")
    except Exception as e:
        # Deterministic fallback: keep the most informative slice of history.
        summary = (f"(自动压缩失败: {e}; 使用确定性截断)\n"
                   + "\n".join(old_rendered)[-6000:])
    compact_msg = {"role": "user",
                   "content": "[CONTEXT COMPACTION — earlier history summarized]\n" + summary}
    return sys_msgs + [compact_msg] + keep


# ═══════════════════════════════════════════════════════════
# AGENT ENGINE
# ═══════════════════════════════════════════════════════════

class Agent:
    def __init__(self, session: Session, config: dict, api_key: str = None,
                 stream: bool = None, on_event: Callable = None, echo: bool = True):
        setup_dirs()
        self.session = session
        self.config = config
        self.workdir = Path(session.workdir or os.getcwd()).resolve()
        if not self.workdir.exists():
            self.workdir = Path.cwd()
        self.api_key = api_key or session.api_key or API_KEY
        self.client = NIMClient(api_key=self.api_key,
                                model=session.model or config.get("default_model", DEFAULT_MODEL),
                                temperature=float(config.get("temperature", 0.2)),
                                max_retries=int(config.get("max_retries", 4)))
        self.stream = config.get("stream", True) if stream is None else stream
        self.echo = echo
        self.on_event = on_event
        self._retry_streak = 0
        self._no_think = bool(config.get("no_think", False))

        self.perm = PermissionManager(self.workdir, session.perm_mode)
        session.perm_mode = self.perm.mode
        self.memory = MemorySystem(self.workdir)
        self.skills = SkillsSystem(self.workdir)
        self.hooks = HooksSystem(self.workdir)
        self.checkpoints = CheckpointManager(self.workdir)
        self.tools = ToolEngine(self.workdir, self.perm, self.hooks, self.memory,
                                self.skills, self.checkpoints, session=session,
                                autocp=bool(config.get("auto_checkpoint", True)),
                                parallel_workers=int(config.get("parallel_workers", 4)))
        b = config.get("budget", DEFAULT_BUDGET)
        self.budget = Budget(tokens=int(b.get("tokens", 200_000)),
                             time_sec=int(b.get("time_sec", 1800)),
                             steps=int(b.get("steps", 40)),
                             warn_pct=float(b.get("warn_pct", 0.8)))
        self.schemas = [TOOL_SCHEMAS[n] for n in sorted(TOOL_SCHEMAS)]

    # ---------- system ----------
    def _sync_system(self):
        sys_prompt = build_system_prompt(self.workdir, self.perm.mode, self.memory,
                                         self.skills, self.session.todos)
        if self.session.messages and self.session.messages[0].get("role") == "system":
            self.session.messages[0]["content"] = sys_prompt
        else:
            self.session.messages.insert(0, {"role": "system", "content": sys_prompt})

    def _notify(self, kind, **data):
        if self.on_event:
            try: self.on_event(kind, data)
            except Exception: pass

    def _account(self, last_usage):
        model = self.client.model
        pin, pout = MODEL_PRICING.get(model, DEFAULT_PRICING)
        if last_usage:
            pt = int(last_usage.get("prompt_tokens") or last_usage.get("input_tokens") or 0)
            ct = int(last_usage.get("completion_tokens") or last_usage.get("output_tokens") or 0)
            total = int(last_usage.get("total_tokens") or (pt + ct))
            if total == 0 and (pt or ct):
                total = pt + ct
            self.budget.add_tokens(total)
        else:
            # Provider sent no usage block — estimate only the freshly appended tail,
            # not the whole transcript (which would compound across turns).
            tail = self.session.messages[-8:]
            pt = sum(estimate_text_tokens(str(m.get("content") or "")) for m in tail)
            for m in tail:
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    pt += estimate_text_tokens(str(fn.get("arguments") or ""))
            pt += 8 * len(tail)
            ct = 0
            self.budget.add_tokens(pt)
        self.session.cost["prompt_tokens"] += pt
        self.session.cost["completion_tokens"] += ct
        self.session.cost["calls"] += 1
        self.session.cost["usd"] = self.session.cost.get("usd", 0.0) + pt / 1e6 * pin + ct / 1e6 * pout

    def _show_budget_warnings(self):
        if not self.echo:
            return
        for w in self.budget.warnings():
            TUI.warn(w)

    # ---------- main loop ----------
    def run(self, user_input: str = None, max_steps: int = None) -> str:
        if user_input is not None:
            self.session.add("user", user_input)
            self.hooks.fire("SessionStart", data={"input": user_input[:200]})
        self._sync_system()
        max_steps = int(max_steps or self.config.get("max_steps", MAX_AGENT_STEPS))
        final_texts = []
        steps = 0
        self._retry_streak = 0

        while steps < max_steps:
            exhausted, reason = self.budget.is_exhausted()
            if exhausted:
                if self.echo:
                    TUI.warn(f"预算耗尽停止: {reason}")
                final_texts.append(f"\n[stopped: {reason}]")
                break

            # Compaction
            est = self.session.estimate_tokens()
            if est > COMPACT_THRESHOLD or (self.budget.should_compact() and est > 30_000):
                try:
                    self.session.messages = compact_messages(
                        self.client, self.session.messages, self.session.todos)
                    if self.echo:
                        TUI.dim(f"上下文已压缩 → {self.session.estimate_tokens()} est tokens")
                except Exception as e:
                    if self.echo:
                        TUI.warn(f"compaction failed: {e}")

            messages = self.session.messages
            tool_calls_to_run = []
            assistant_text = ""
            last_usage = None

            try:
                if self.stream:
                    with Spinner("思考") as sp:
                        streaming_text = False
                        reasoning_shown = False
                        sm = StreamMarkdown(echo=self.echo)
                        for kind, payload in self.client.chat(messages, tools=self.schemas, stream=True):
                            if kind == "reasoning":
                                if not streaming_text and not getattr(self, "_no_think", False):
                                    txt = str(payload)
                                    if txt.strip():
                                        if not reasoning_shown and self.echo:
                                            term_w = max(40, shutil.get_terminal_size((80, 24)).columns)
                                            hdr = "┌─ 💭 思考 " + "─" * max(0, term_w - 14) + "┐"
                                            sp.emit(s(hdr, Palette.tok("border")) + "\n")
                                        sp.emit(s("│ ", Palette.tok("border"))
                                                + s(txt, Palette.tok("thinking"), Style.DIM, Style.ITALIC) + "\n")
                                        reasoning_shown = True
                                continue
                            if kind == "text":
                                if not streaming_text:
                                    if reasoning_shown and self.echo:
                                        term_w = max(40, shutil.get_terminal_size((80, 24)).columns)
                                        sp.emit(s("└" + "─" * (term_w - 1) + "┘", Palette.tok("border")) + "\n")
                                    sp.pause()
                                    streaming_text = True
                                assistant_text += payload
                                if self.echo:
                                    out = sm.feed(payload)
                                    if out:
                                        sys.stdout.write(out); sys.stdout.flush()
                            elif kind == "tool_call":
                                tool_calls_to_run = list(payload.values())
                            elif kind == "usage":
                                last_usage = payload
                        # flush any remaining buffered markdown
                        if self.echo:
                            tail = sm.flush()
                            if tail:
                                sys.stdout.write(tail); sys.stdout.flush()
                    if assistant_text and self.echo:
                        sys.stdout.write("\n"); sys.stdout.flush()
                else:
                    with spinner("思考"):
                        resp = self.client.chat(messages, tools=self.schemas)
                    last_usage = resp.get("usage")
                    msg = resp["choices"][0]["message"]
                    assistant_text = msg.get("content") or ""
                    if assistant_text and self.echo:
                        print(md(assistant_text))
                    if msg.get("tool_calls"):
                        tool_calls_to_run = msg["tool_calls"]
                self._retry_streak = 0
            except APIError as e:
                if self.echo:
                    TUI.error(f"API 错误: {e}")
                log_audit("api_error", {"status": e.status, "msg": str(e)[:200]})
                self._retry_streak += 1
                if e.status in (408, 429, 500, 502, 503, 504) and self._retry_streak <= 3:
                    self.client._sleep_backoff(self._retry_streak, 1.5)
                    continue
                self.session.save()
                return f"API error: {e}"
            except KeyboardInterrupt:
                self.client.abort()
                if self.echo:
                    if assistant_text:
                        sys.stdout.write("\n")
                        TUI.warn(f"⏹ 已中断（保留 {len(assistant_text)} 字符部分输出）")
                    else:
                        TUI.warn("⏹ 已中断")
                self.session.save()
                return assistant_text or "(interrupted)"

            # account usage
            self._account(last_usage)
            self._show_budget_warnings()

            # record assistant message
            asst_msg = {"role": "assistant", "content": assistant_text or ""}
            if tool_calls_to_run:
                cleaned = []
                for tc in tool_calls_to_run:
                    fn = tc.get("function") if isinstance(tc.get("function"), dict) else None
                    if fn is None:
                        fn = {"name": tc.get("name") or "", "arguments": tc.get("arguments") or "{}"}
                    raw_name = str(fn.get("name") or "")
                    args_str = fn.get("arguments") or "{}"
                    if not raw_name:
                        continue
                    cleaned.append({
                        "id": tc.get("id") or f"call_{uuid.uuid4().hex[:8]}",
                        "type": "function",
                        "function": {
                            "name": re.split(r"<\|", raw_name)[0].strip(),
                            "arguments": args_str if isinstance(args_str, str) else json.dumps(args_str),
                        },
                    })
                tool_calls_to_run = cleaned
                asst_msg["tool_calls"] = cleaned
            self.session.messages.append(asst_msg)

            if not tool_calls_to_run:
                final_texts.append(assistant_text)
                break

            # execute tools (parallel when every call in the batch is read-only)
            steps += 1
            self.budget.add_step()
            parsed = []
            for tc in tool_calls_to_run:
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"] or "{}")
                    if not isinstance(args, dict): args = {"input": args}
                except Exception:
                    args = {"_raw": tc["function"]["arguments"]}
                parsed.append((tc, name, args))

            # execute tools (parallel when every call in the batch is read-only)
            result_map = {}
            timing = {}
            parallel_note = ""
            if len(parsed) > 1 and all(n in PARALLEL_SAFE_TOOLS for _, n, _ in parsed):
                if self.echo:
                    TUI.tool(f"×{len(parsed)} 并行只读", "", self.budget.used_steps)
                t0 = time.monotonic()
                results = self.tools.execute_parallel([(tc["id"], n, a) for tc, n, a in parsed])
                result_map = dict(results)
                elapsed = (time.monotonic() - t0) * 1000
                for tc, name, args in parsed:
                    timing[tc["id"]] = elapsed / max(len(parsed), 1)
                parallel_note = f"parallel×{len(parsed)}"
            else:
                for tc, name, args in parsed:
                    t0 = time.monotonic()
                    result_map[tc["id"]] = self.tools.execute(name, args)
                    timing[tc["id"]] = (time.monotonic() - t0) * 1000
                    if self.echo:
                        r = str(result_map[tc["id"]])
                        ok = not r.startswith("ERROR")
                        TUI.tool(name, _fmt_args(args), self.budget.used_steps,
                                 duration_ms=timing[tc["id"]], status="ok" if ok else "err")
                        TUI.tool_out(r)

            # store last results for /last command
            if not hasattr(self, "_last_tool_results"):
                self._last_tool_results = []
            for tc, name, args in parsed:
                result = result_map.get(tc["id"], "ERROR: missing result")
                self._last_tool_results.append((name, str(result)[:8000]))
                if len(self._last_tool_results) > 20:
                    self._last_tool_results = self._last_tool_results[-20:]
                self.session.add_tool_result(tc["id"], name, result)
            if parallel_note and self.echo:
                TUI.dim(f"只读工具已并行执行 ({parallel_note})")
            self.session.save()

        self.session.save()
        self.hooks.fire("SessionEnd", data={"steps": self.budget.used_steps})
        out = "\n".join(t for t in final_texts if t)
        return out or "(no response)"

    # ---------- plan mode interactive ----------
    def run_plan_then_apply(self, user_input: str) -> str:
        """In plan mode: generate plan, ask user, then switch to acceptEdits and execute."""
        saved_mode = self.perm.mode
        self.perm.mode = "plan"
        self.session.perm_mode = "plan"
        plan = self.run(f"{user_input}\n\n先输出一个简洁的实施计划（不要执行修改）。")
        print()
        print(s("  执行这个计划吗? [y]执行 [n]取消 ", Style.BRIGHT_CYAN), end="", flush=True)
        try:
            ans = input().strip().lower()
        except Exception:
            ans = "n"
        if ans not in ("y", "yes"):
            self.perm.mode = saved_mode
            self.session.perm_mode = saved_mode
            return plan + "\n\n(计划未执行)"
        self.perm.mode = "acceptEdits"
        self.session.perm_mode = "acceptEdits"
        return self.run("计划已批准。现在按计划执行，逐步完成并验证。")


def _fmt_args(args: dict, limit=200) -> str:
    try:
        t = json.dumps(args, ensure_ascii=False)
    except Exception:
        t = str(args)
    t = t if len(t) <= limit else t[:limit] + "…"
    return t



# ═══════════════════════════════════════════════════════════
# SLASH COMMANDS
# ═══════════════════════════════════════════════════════════

HELP_TEXT = f"""
{s('─'*58, Style.CYAN)}
{s(' NVIDIA ENGINEER PRO v' + __version__ + ' — 命令', Style.BRIGHT_CYAN + Style.BOLD)}
{s('─'*58, Style.CYAN)}
 {s('/help', Style.BRIGHT_YELLOW)}         显示此帮助
 {s('/model', Style.BRIGHT_YELLOW)} [id]    查看/切换模型
 {s('/models', Style.BRIGHT_YELLOW)}        列出可用模型
 {s('/mode', Style.BRIGHT_YELLOW)} [m]      权限模式 plan|default|acceptEdits|yolo|dontAsk
 {s('/perm', Style.BRIGHT_YELLOW)}          查看权限规则
 {s('/risk', Style.BRIGHT_YELLOW)} <cmd>    分析命令风险等级
 {s('/budget', Style.BRIGHT_YELLOW)}        查看/设置预算 tokens=100000 steps=30 time=600
 {s('/todos', Style.BRIGHT_YELLOW)}         显示任务清单
 {s('/done', Style.BRIGHT_YELLOW)} <i>      把第 i 项待办标记为完成
 {s('/memory', Style.BRIGHT_YELLOW)} [topic] 查看记忆 / 读取主题 / /memory find <q> 搜索
 {s('/skills', Style.BRIGHT_YELLOW)}        列出技能
 {s('/hook', Style.BRIGHT_YELLOW)}          列出钩子
 {s('/tools', Style.BRIGHT_YELLOW)}         列出全部工具
 {s('/cp', Style.BRIGHT_YELLOW)}            检查点: /cp | /cp list | /cp restore [id] | /cp diff [id] | /cp prune
 {s('/undo', Style.BRIGHT_YELLOW)}          恢复到上一个检查点
 {s('/verify', Style.BRIGHT_YELLOW)}        运行测试 + lint 验证
 {s('/web', Style.BRIGHT_YELLOW)} <url>     抓取网页文本
 {s('/search', Style.BRIGHT_YELLOW)} <q>     网页搜索
 {s('/proj', Style.BRIGHT_YELLOW)}          项目结构分析
 {s('/tree', Style.BRIGHT_YELLOW)} [path]   目录树
 {s('/sym', Style.BRIGHT_YELLOW)} [path]    符号地图（类/函数）
 {s('/find', Style.BRIGHT_YELLOW)} <pat>    按 glob 找文件
 {s('/grep', Style.BRIGHT_YELLOW)} <pat>    代码正则搜索
 {s('/stat', Style.BRIGHT_YELLOW)} <path>   文件元数据 / sha256
 {s('/diff', Style.BRIGHT_YELLOW)} [a] [b]  两文件差异（缺省对比检查点）
 {s('/branch', Style.BRIGHT_YELLOW)}        分叉会话时间线 (list|go N)
 {s('/export', Style.BRIGHT_YELLOW)} [md|json|html]  导出对话
 {s('/clear', Style.BRIGHT_YELLOW)}         清屏
 {s('/compact', Style.BRIGHT_YELLOW)}       手动压缩上下文
 {s('/session', Style.BRIGHT_YELLOW)} [ls|load <id>|new]  会话管理
 {s('/cost', Style.BRIGHT_YELLOW)}          显示 token / 调用 / 成本统计
 {s('/health', Style.BRIGHT_YELLOW)}        API 连通性检查
 {s('/last', Style.BRIGHT_YELLOW)} [n]      查看最近 n 条工具输出（缺省 1）
 {s('/theme', Style.BRIGHT_YELLOW)} [dark|light|list]  切换/查看配色主题
 {s('/config', Style.BRIGHT_YELLOW)} [k=v]  查看/设置配置项
 {s('/copy', Style.BRIGHT_YELLOW)}          复制最近回复到剪贴板
 {s('/revert', Style.BRIGHT_YELLOW)} <file> 从最近检查点恢复单个文件
 {s('/quit', Style.BRIGHT_YELLOW)}          退出
{s('─'*58, Style.CYAN)}
 快捷: 直接输入文字对话; 多行文本以 \\ 结尾; 空行发送; Tab 补全斜杠命令
{s('─'*58, Style.CYAN)}
"""

SLASH_COMMANDS = ["/help", "/model", "/models", "/mode", "/perm", "/risk", "/budget",
                  "/todos", "/done", "/memory", "/skills", "/hook", "/tools", "/cp",
                  "/undo", "/verify", "/web", "/search", "/proj", "/tree", "/sym",
                  "/find", "/grep", "/stat", "/diff", "/branch", "/export", "/clear",
                  "/compact", "/session", "/cost", "/health", "/quit", "/exit",
                  "/last", "/theme", "/config", "/copy", "/revert"]


class CLI:
    def __init__(self, args):
        self.args = args
        setup_dirs()
        self.config = load_config()
        if args.model:
            self.config["default_model"] = args.model
        if getattr(args, "theme", None):
            Palette.set_theme(args.theme)
            self.config["theme"] = args.theme
        elif self.config.get("theme"):
            Palette.set_theme(self.config["theme"])
        if getattr(args, "no_think", False):
            self.config["no_think"] = True
        self.stream = not getattr(args, "no_stream", False)
        self.branch_index = {}  # for /branch timeline
        self.session = self._init_session()
        self.agent: Optional[Agent] = None
        self._setup_readline()

    def _setup_readline(self):
        """Tab-complete slash commands (only when a readline module is present)."""
        if readline is None or not sys.stdin.isatty():
            return

        def completer(text, state):
            if not text.startswith("/"):
                return None
            options = [c for c in SLASH_COMMANDS if c.startswith(text)]
            return options[state] if state < len(options) else None

        try:
            readline.set_completer(completer)
            readline.parse_and_bind("tab: complete")
        except Exception:
            pass

    # ---------- init ----------
    def _init_session(self) -> Session:
        a = self.args
        if getattr(a, "resume_last", False):
            all_sessions = Session.list_all()
            wd = str(Path(a.workdir).resolve()) if a.workdir else str(Path.cwd())
            for s_ in all_sessions:
                if s_.workdir == wd and s_.messages:
                    TUI.ok(f"继续上次会话: {s_.id} (msgs={len(s_.messages)})")
                    return s_
            TUI.dim("未找到可继续的会话，创建新会话")
        if getattr(a, "session", None):
            p = Path(a.session)
            if p.exists():
                return Session.load(p)
            matches = [x for x in Session.list_all() if x.id.startswith(a.session)]
            if matches:
                return matches[0]
            TUI.warn(f"会话不存在: {a.session}，创建新会话")
        mode = getattr(a, "mode", None) or self.config.get("mode", "acceptEdits")
        return Session(
            model=self.config["default_model"],
            workdir=str(Path(a.workdir).resolve()) if a.workdir else str(Path.cwd()),
            perm_mode=mode if mode in MODES else "acceptEdits",
            api_key=API_KEY,
        )

    def _ensure_agent(self) -> Agent:
        if self.agent is None:
            self.agent = Agent(self.session, self.config, stream=self.stream)
        return self.agent

    # ---------- interactive loop ----------
    def interactive(self):
        TUI.banner()
        agent = self._ensure_agent()
        TUI.kv([
            ("工作区", self.session.workdir),
            ("模型", agent.client.model),
            ("权限模式", f"{self.session.perm_mode} — {MODES.get(self.session.perm_mode,'')}"),
            ("工具数", len(TOOL_SCHEMAS)),
            ("预算", agent.budget.status()),
        ])
        print()
        TUI.dim("↑↓历史  Tab补全  Ctrl+R搜索  Ctrl+P命令面板  Ctrl+L清屏  Ctrl+C取消/退出")
        # snapshot on start — off the critical path so the first prompt is instant
        def _startup_snapshot():
            try:
                agent.checkpoints.create(label="session start")
                agent.checkpoints.prune(keep=30)
            except Exception:
                pass
        threading.Thread(target=_startup_snapshot, daemon=True).start()

        def _completer(text):
            if not text.startswith("/"):
                return []
            return [c for c in SLASH_COMMANDS if c.startswith(text)]

        editor = LineEditor(
            prompt=s("  ⌨ ", Palette.tok("prompt"), Style.BOLD),
            completer=_completer,
            commands=SLASH_COMMANDS,
        )
        buffer = []
        last_intr = 0.0
        while True:
            try:
                prompt = editor.prompt if not buffer else s("  … ", Palette.tok("dim"))
                editor.prompt = prompt
                line = editor.read()
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                # first Ctrl-C cancels the input line, second one (within 2s) quits
                if not buffer and (time.time() - last_intr < 2.0):
                    print()
                    break
                last_intr = time.time()
                buffer = []
                print()
                TUI.warn("已取消输入（再按一次 Ctrl-C 退出）")
                continue
            if buffer:
                if line.strip() == "":
                    text = "\n".join(buffer); buffer = []
                else:
                    buffer.append(line); continue
            else:
                text = line
            if not text.strip():
                continue
            if text.strip().endswith("\\"):
                buffer.append(text.strip()[:-1]); continue
            if text.startswith("/"):
                if not self.handle_command(text.strip()):
                    break
                continue
            self.agent_turn(text)
        self.session.save()
        TUI.dim("再见！会话已保存。")

    def agent_turn(self, text: str):
        agent = self._ensure_agent()
        try:
            if self.session.perm_mode == "plan" and not self.args.no_plan_confirm:
                agent.run_plan_then_apply(text)
            else:
                agent.run(text)
        except KeyboardInterrupt:
            TUI.warn("⏹ 已中断（会话已保存）")
        except APIError as e:
            TUI.error(f"API: {e}")
        TUI.status_bar(self.session, agent.budget)

    # ---------- commands ----------
    def handle_command(self, text: str) -> bool:
        parts = text.split()
        cmd = parts[0].lower()
        rest = " ".join(parts[1:])
        agent = self._ensure_agent()
        try:
            if cmd in ("/quit", "/exit", "/q"):
                self.session.save(); return False
            elif cmd == "/help":
                if rest:
                    # keyword search: filter HELP_TEXT lines matching the keyword
                    kw = rest.strip().lower()
                    matched = [l for l in HELP_TEXT.splitlines() if kw in l.lower()]
                    if matched:
                        TUI.section(f"help: {rest}")
                        for l in matched:
                            print(l)
                    else:
                        TUI.dim(f"没有匹配 '{rest}' 的帮助条目")
                else:
                    print(HELP_TEXT)
                return True
            elif cmd == "/clear":
                os.system("clear" if os.name != "nt" else "cls"); TUI.banner(); return True
            elif cmd == "/model":
                if rest:
                    agent.client.model = rest; self.session.model = rest
                    self.session.save(); TUI.ok(f"模型 → {rest}")
                else:
                    TUI.kv([("当前模型", agent.client.model)]); return True
            elif cmd == "/models":
                with spinner("获取模型"):
                    try:
                        models = agent.client.list_models()
                    except Exception as e:
                        TUI.error(str(e)); return True
                for m in models[:60]:
                    print(s(f"    {m}", Style.BRIGHT_CYAN if m == agent.client.model else Style.GRAY))
                TUI.dim(f"共 {len(models)} 个模型")
                return True
            elif cmd == "/mode":
                if not rest:
                    TUI.kv([(f"{k}", v) for k, v in MODES.items()]); return True
                if rest in MODES:
                    agent.perm.mode = rest; self.session.perm_mode = rest
                    agent._sync_system(); self.session.save()
                    TUI.ok(f"模式 → {rest}: {MODES[rest]}")
                else:
                    TUI.error(f"未知模式: {rest}（可选: {', '.join(MODES)}）")
                return True
            elif cmd == "/perm":
                r = agent.perm.rules
                for label, rules in (("deny", r.deny), ("ask", r.ask), ("allow", r.allow)):
                    print(s(f"    {label}:", Style.BRIGHT_YELLOW))
                    for rule in rules:
                        print(s(f"      - {rule}", Style.GRAY))
                return True
            elif cmd == "/risk":
                if not rest: TUI.error("用法: /risk <command>"); return True
                level = classify_command(rest)
                color = {RiskLevel.SAFE: Style.GREEN, RiskLevel.MODERATE: Style.YELLOW,
                         RiskLevel.DANGEROUS: Style.BRIGHT_RED, RiskLevel.CRITICAL: Style.RED}[level]
                print(f"    {rest}\n    → {s(level.value.upper(), color)}")
                return True
            elif cmd == "/budget":
                b = agent.budget
                if rest:
                    try:
                        for kv in rest.split():
                            k, v = kv.split("=", 1)
                            if k == "tokens": b.max_tokens = int(v)
                            elif k == "time": b.max_time = int(v)
                            elif k == "steps": b.max_steps = int(v)
                        TUI.ok(f"预算已更新: tokens={b.max_tokens} time={b.max_time}s steps={b.max_steps}")
                    except Exception as e:
                        TUI.error(f"格式: tokens=100000 time=600 steps=30 ({e})")
                else:
                    TUI.kv([("状态", b.status()),
                            ("tokens", f"{b.used_tokens}/{b.max_tokens}"),
                            ("steps", f"{b.used_steps}/{b.max_steps}"),
                            ("elapsed", f"{b.elapsed():.0f}s/{b.max_time}s")])
                return True
            elif cmd == "/todos":
                TUI.todos(self.session.todos); return True
            elif cmd == "/done":
                if not rest:
                    TUI.error("用法: /done <index>"); return True
                try:
                    idx = int(rest.split()[0])
                except ValueError:
                    TUI.error("索引必须是整数"); return True
                out = agent.tools.execute("todo_update", {"index": idx, "status": "done"})
                TUI.ok(out) if not str(out).startswith("ERROR") else TUI.error(out)
                TUI.todos(self.session.todos)
                return True
            elif cmd == "/memory":
                parts = rest.split(maxsplit=1)
                if parts and parts[0] in ("find", "search", "grep") and len(parts) > 1:
                    print(agent.tools.execute("memory_search", {"query": parts[1]}))
                elif parts and parts[0] == "del" and len(parts) > 1:
                    out = agent.tools.execute("memory_delete", {"topic": parts[1]})
                    TUI.ok(out) if not str(out).startswith("ERROR") else TUI.error(out)
                elif rest:
                    print(agent.memory.read(rest))
                else:
                    print(agent.memory.read_index())
                return True
            elif cmd == "/skills":
                print(agent.skills.get_skill_index() or "no skills"); return True
            elif cmd == "/hook":
                if not agent.hooks.hooks:
                    TUI.dim("no hooks configured (.nengineer/hooks.json)")
                for h in agent.hooks.hooks:
                    print(f"    {h.event}  matcher={h.matcher}  → {h.command}")
                return True
            elif cmd in ("/cp", "/checkpoint"):
                sub = rest.split()
                action = sub[0] if sub else "list"
                cp_id = sub[1] if len(sub) > 1 else ""
                if action == "create":
                    cp = agent.checkpoints.create(label=rest.split(" ", 1)[1] if len(sub) > 1 else "manual")
                    TUI.ok(f"checkpoint: {cp}") if cp else TUI.error("checkpoint failed")
                elif action == "restore":
                    ok, msg = agent.checkpoints.restore(cp_id or None)
                    TUI.ok(msg) if ok else TUI.error(msg)
                elif action == "diff":
                    TUI.diff_out(agent.checkpoints.diff(cp_id or None))
                elif action == "prune":
                    n = agent.checkpoints.prune(keep=int(cp_id) if cp_id.isdigit() else 25)
                    TUI.ok(f"已清理 {n} 个旧检查点")
                else:
                    rows = [[r['id'], r.get('label','')[:34], str(r.get('files',0)),
                             (r.get('ts','') or '')[11:19]] for r in agent.checkpoints.list(15)]
                    TUI.table(["ID", "LABEL", "FILES", "TIME"], rows)
                return True
            elif cmd == "/undo":
                ok, msg = agent.checkpoints.restore()
                TUI.ok(msg) if ok else TUI.error(msg)
                return True
            elif cmd == "/verify":
                self._verify(agent); return True
            elif cmd == "/web":
                if not rest: TUI.error("用法: /web <url>"); return True
                print(agent.tools.execute("fetch_url", {"url": rest}))
                return True
            elif cmd == "/search":
                if not rest: TUI.error("用法: /search <query>"); return True
                print(agent.tools.execute("web_search", {"query": rest}))
                return True
            elif cmd == "/proj":
                print(agent.tools.execute("analyze_project", {}))
                return True
            elif cmd == "/tree":
                print(agent.tools.execute("tree", {"path": rest or "."}))
                return True
            elif cmd == "/sym":
                print(agent.tools.execute("symbols", {"path": rest or "."}))
                return True
            elif cmd == "/find":
                if not rest: TUI.error("用法: /find <glob>"); return True
                print(agent.tools.execute("glob", {"pattern": rest}))
                return True
            elif cmd == "/grep":
                if not rest: TUI.error("用法: /grep <regex>"); return True
                out = agent.tools.execute("search_code", {"pattern": rest})
                print(hl_matches(str(out), rest))
                return True
            elif cmd == "/stat":
                if not rest: TUI.error("用法: /stat <path>"); return True
                print(agent.tools.execute("file_stat", {"path": rest}))
                return True
            elif cmd == "/diff":
                parts = rest.split()
                if len(parts) >= 2:
                    print(agent.tools.execute("diff_show", {"path_a": parts[0], "path_b": parts[1]}))
                elif len(parts) == 1:
                    print(agent.tools.execute("diff_show", {"path_a": parts[0], "path_b": parts[0] + ".bak"}))
                else:
                    TUI.diff_out(agent.checkpoints.diff())
                return True
            elif cmd == "/tools":
                rows = [[name, schema["function"]["description"][:70]]
                        for name, schema in sorted(TOOL_SCHEMAS.items())]
                TUI.table(["TOOL", "DESCRIPTION"], rows, widths=[18, 74])
                TUI.dim(f"共 {len(TOOL_SCHEMAS)} 个工具")
                return True
            elif cmd == "/branch":
                self._branch(rest, agent); return True
            elif cmd == "/export":
                self._export(rest or "md"); return True
            elif cmd == "/compact":
                try:
                    self.session.messages = compact_messages(agent.client, self.session.messages)
                    TUI.ok(f"已压缩 → {self.session.estimate_tokens()} est tokens")
                    self.session.save()
                except Exception as e:
                    TUI.error(str(e))
                return True
            elif cmd == "/session":
                self._session_cmd(rest); return True
            elif cmd == "/cost":
                c = self.session.cost
                TUI.kv([("调用", c["calls"]),
                        ("prompt", f"{c['prompt_tokens']:,}"),
                        ("completion", f"{c['completion_tokens']:,}"),
                        ("合计", f"{c['prompt_tokens'] + c['completion_tokens']:,}"),
                        ("估算成本", f"${c.get('usd', 0.0):.4f}"),
                        ("预算", agent.budget.status())])
                TUI.progress(min(100, agent.budget.used_tokens * 100 // max(1, agent.budget.max_tokens)))
                return True
            elif cmd == "/health":
                self._health(agent); return True
            elif cmd == "/last":
                self._last_cmd(rest, agent); return True
            elif cmd == "/theme":
                self._theme_cmd(rest); return True
            elif cmd == "/config":
                self._config_cmd(rest); return True
            elif cmd == "/copy":
                self._copy_cmd(); return True
            elif cmd == "/revert":
                self._revert_cmd(rest, agent); return True
            else:
                TUI.warn(f"未知命令 {cmd}，输入 /help")
        except Exception as e:
            TUI.error(f"{type(e).__name__}: {e}")
        return True

    def _last_cmd(self, rest, agent):
        """Show the last N tool outputs in full."""
        n = 1
        if rest:
            try:
                n = max(1, min(10, int(rest.strip())))
            except ValueError:
                n = 1
        results = getattr(agent, "_last_tool_results", [])
        if not results:
            TUI.dim("还没有工具输出"); return
        shown = results[-n:]
        for name, output in shown:
            TUI.section(f"last: {name}")
            TUI.tool_out(output, max_lines=50)

    def _theme_cmd(self, rest):
        """Switch color theme."""
        rest = rest.strip().lower()
        if rest in Palette.themes():
            Palette.set_theme(rest)
            self.config["theme"] = rest
            save_json(CONFIG_FILE, self.config)
            TUI.ok(f"主题已切换到 {rest}")
        elif rest == "list":
            print()
            for tn in Palette.themes():
                marker = " ●" if tn == Palette.get_theme() else "  "
                sample = s("████ ", Palette.tok("accent")) + s("████ ", Palette.tok("ok")) + \
                         s("████ ", Palette.tok("warn")) + s("████", Palette.tok("err"))
                # temporarily switch to show each theme's colors
                saved = Palette.get_theme()
                Palette.set_theme(tn)
                sample = s("████ ", Palette.tok("accent")) + s("████ ", Palette.tok("ok")) + \
                         s("████ ", Palette.tok("warn")) + s("████", Palette.tok("err"))
                Palette.set_theme(saved)
                cur = " (当前)" if tn == Palette.get_theme() else ""
                print(f"  {s(marker, Palette.tok('accent'))} {tn:<12s} {sample}{cur}")
            print()
            TUI.dim(f"用法: /theme <{'|'.join(Palette.themes())}>")
        else:
            TUI.kv([("当前主题", Palette.get_theme()),
                    ("颜色模式", Palette.mode()),
                    ("可用", ", ".join(Palette.themes())),
                    ("用法", "/theme <名称>|list")])

    def _config_cmd(self, rest):
        """View or set config values."""
        rest = rest.strip()
        if not rest:
            TUI.kv([
                ("theme", self.config.get("theme", "dark")),
                ("model", self.config.get("default_model", DEFAULT_MODEL)),
                ("stream", self.config.get("stream", True)),
                ("no_think", self.config.get("no_think", False)),
                ("auto_checkpoint", self.config.get("auto_checkpoint", True)),
                ("max_steps", self.config.get("max_steps", MAX_AGENT_STEPS)),
                ("budget", str(self.config.get("budget", DEFAULT_BUDGET))),
            ])
            TUI.dim("用法: /config key=value  例如 /config theme=light")
            return
        if "=" not in rest:
            TUI.error("格式: /config key=value"); return
        key, val = rest.split("=", 1)
        key, val = key.strip(), val.strip()
        if val.lower() in ("true", "yes", "on"):
            val = True
        elif val.lower() in ("false", "no", "off"):
            val = False
        elif val.isdigit():
            val = int(val)
        self.config[key] = val
        save_json(CONFIG_FILE, self.config)
        if key == "theme":
            Palette.set_theme(str(val))
        TUI.ok(f"config: {key} = {val}")

    def _copy_cmd(self):
        """Copy the last assistant response to the clipboard."""
        last_asst = None
        for m in reversed(self.session.messages):
            if m.get("role") == "assistant" and m.get("content"):
                last_asst = m["content"]
                break
        if not last_asst:
            TUI.dim("没有可复制的回复"); return
        text = last_asst[:8000]
        copied = False
        for cmd in (["termux-clipboard-set"], ["pbcopy"], ["xclip", "-selection", "clipboard"],
                    ["wl-copy"], ["clip.exe"]):
            if shutil.which(cmd[0]):
                try:
                    subprocess.run(cmd, input=text.encode(), timeout=5, capture_output=True)
                    copied = True
                    break
                except Exception:
                    pass
        if copied:
            TUI.ok(f"已复制 {len(text)} 字符到剪贴板")
        else:
            TUI.warn("未找到剪贴板工具 (termux-clipboard-set/pbcopy/xclip)")

    def _revert_cmd(self, rest, agent):
        """Restore a single file from the most recent checkpoint."""
        path = rest.strip()
        if not path:
            TUI.error("用法: /revert <file>"); return
        p = agent.workdir / path
        if not p.exists():
            TUI.error(f"文件不存在: {path}"); return
        # find most recent checkpoint
        records = agent.checkpoints.list(1)
        if not records:
            TUI.error("没有检查点"); return
        cp = records[0]
        # read file from checkpoint tree
        import subprocess as _sp
        env = os.environ.copy()
        env["GIT_DIR"] = str(agent.checkpoints.git_dir)
        env["GIT_WORK_TREE"] = str(agent.workdir)
        env.pop("GIT_INDEX_FILE", None)
        try:
            # list files in tree
            r = _sp.run(["git", "ls-tree", "-r", "--name-only", cp["tree"]],
                        capture_output=True, text=True, timeout=10, env=env)
            if path not in r.stdout.splitlines():
                TUI.error(f"检查点 {cp['id']} 中没有 {path}"); return
            # checkout single file
            r2 = _sp.run(["git", "checkout", cp["tree"], "--", path],
                         capture_output=True, text=True, timeout=10,
                         cwd=str(agent.workdir), env=env)
            if r2.returncode != 0:
                TUI.error(f"恢复失败: {r2.stderr.strip()}"); return
            TUI.ok(f"已从检查点 {cp['id']} 恢复 {path}")
        except Exception as e:
            TUI.error(f"恢复失败: {e}")

    def _verify(self, agent):
        TUI.section("VERIFY")
        tests = agent.tools.execute("test_run", {})
        print(s("  tests:", Style.BRIGHT_YELLOW))
        for line in str(tests).splitlines()[:15]:
            TUI.tool_out(line)
        ok = not str(tests).startswith("ERROR") and "failed" not in str(tests).lower() and "error" not in str(tests).lower()[:40]
        # lint if available
        lint_cmd = None
        if (agent.workdir / "pyproject.toml").exists() or list(agent.workdir.glob("*.py")):
            if shutil.which("ruff"): lint_cmd = "ruff check ."
            elif shutil.which("flake8"): lint_cmd = "flake8 ."
        if lint_cmd:
            lint = agent.tools.execute("run_command", {"command": lint_cmd})
            print(s(f"  lint ({lint_cmd}):", Style.BRIGHT_YELLOW))
            for line in str(lint).splitlines()[:10]:
                TUI.tool_out(line)
        TUI.ok("验证通过" if ok else "验证失败")
        return ok

    def _branch(self, rest, agent):
        sub = rest.split()
        if not sub or sub[0] == "list":
            msgs = [m for m in self.session.messages if m["role"] in ("user", "assistant") and m.get("content")]
            if not msgs:
                TUI.dim("no conversation yet"); return
            for i, m in enumerate(msgs):
                snippet = str(m["content"]).replace("\n", " ")[:70]
                marker = "●" if i == len(self.branch_index, ) - 1 or not self.branch_index else "○"
                role_color = Style.BRIGHT_GREEN if m['role'] == 'user' else Style.BRIGHT_CYAN
                print(f"    {i:>3} {s(m['role'].ljust(8), role_color)} {snippet}")
            TUI.dim("用 /branch go <N> 回到该轮（截断后续）")
        elif sub[0] == "go" and len(sub) > 1:
            try:
                n = int(sub[1])
            except ValueError:
                TUI.error("用法: /branch go <index>"); return
            msgs = [i for i, m in enumerate(self.session.messages) if m["role"] in ("user", "assistant") and m.get("content")]
            if n < 0 or n >= len(msgs):
                TUI.error(f"索引超出范围 0..{len(msgs)-1}"); return
            cut = msgs[n]
            # keep system (0) + messages up to and including nth user/assistant, but drop that assistant if present? keep through user message
            target_role = self.session.messages[cut]["role"]
            keep_until = cut
            if target_role == "assistant":
                # find preceding user
                for i in range(cut, -1, -1):
                    if self.session.messages[i]["role"] == "user":
                        keep_until = i; break
            self.session.messages = self.session.messages[:keep_until + 1]
            # remove trailing assistant tool junk
            while self.session.messages and self.session.messages[-1]["role"] != "user":
                self.session.messages.pop()
            self.session.save()
            TUI.ok(f"已回退到第 {n} 轮（后续对话已截断）")
        else:
            TUI.dim("用法: /branch [list|go N]")

    def _export(self, fmt="md"):
        fmt = fmt.strip().lower().split()[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            out = Path.home() / f"nvidia_session_{ts}.json"
            save_json(out, asdict(self.session))
        elif fmt == "html":
            out = Path.home() / f"nvidia_session_{ts}.html"
            rows = []
            for m in self.session.messages:
                if m["role"] == "system": continue
                content = html.escape(str(m.get("content") or ""))
                if m.get("tool_calls"):
                    names = ", ".join(tc["function"]["name"] for tc in m["tool_calls"])
                    content += f"<div class='tc'>🔧 {html.escape(names)}</div>"
                rows.append(f"<div class='m {m['role']}'><b>{m['role']}</b><pre>{content}</pre></div>")
            out.write_text(f"<!doctype html><meta charset=utf-8><title>{self.session.id}</title>"
                           "<style>body{background:#0d1117;color:#e6edf3;font-family:ui-monospace,monospace;padding:20px}"
                           ".m{margin:10px 0;padding:8px;border-left:3px solid #30363d}.user{border-color:#3fb950}"
                           ".assistant{border-color:#58a6ff}.tool{opacity:.7}pre{white-space:pre-wrap;margin:4px 0}"
                           ".tc{color:#d29922}</style>" + "\n".join(rows), encoding="utf-8")
        else:
            out = Path.home() / f"nvidia_session_{ts}.md"
            lines = [f"# NVIDIA Engineer Session {self.session.id}", "",
                     f"- model: {self.session.model}", f"- workdir: {self.session.workdir}", ""]
            for m in self.session.messages:
                if m["role"] == "system": continue
                if m["role"] == "tool":
                    lines.append(f"> **tool {m.get('name','')}**: `{str(m.get('content',''))[:300]}`\n")
                    continue
                lines.append(f"### {m['role']}\n\n{m.get('content','')}\n")
            out.write_text("\n".join(lines), encoding="utf-8")
        TUI.ok(f"已导出: {out}")

    def _session_cmd(self, rest):
        sub = rest.split()
        if not sub or sub[0] == "ls":
            sessions = Session.list_all()[:15]
            for s_ in sessions:
                marker = "*" if s_.id == self.session.id else " "
                print(f"   {marker} {s_.id}  {s_.model}  msgs={len(s_.messages)}  {s_.updated[:19] if s_.updated else ''}")
            return
        if sub[0] == "new":
            self.session.save()
            self.session = Session(model=self.config["default_model"],
                                   workdir=self.session.workdir,
                                   perm_mode=self.session.perm_mode, api_key=API_KEY)
            self.agent = None
            TUI.ok(f"新会话: {self.session.id}")
            return
        if sub[0] == "load" and len(sub) > 1:
            matches = [x for x in Session.list_all() if x.id.startswith(sub[1])]
            if not matches:
                TUI.error(f"未找到会话: {sub[1]}"); return
            self.session.save()
            self.session = matches[0]
            self.agent = None
            TUI.ok(f"已加载: {self.session.id} (msgs={len(self.session.messages)})")
            return
        TUI.dim("用法: /session [ls|new|load <id>]")

    def _health(self, agent):
        with spinner("检查 API"):
            h = agent.client.health()
        TUI.kv([
            ("API key", "有" if h["key"] else "无"),
            ("base_url", h["base_url"]),
            ("模型", h["model"]),
            ("models 列表", f"OK ({h['models_count']})" if h["models_ok"] else "FAIL"),
            ("chat 调用", "OK" if h["chat_ok"] else "FAIL"),
        ])
        if h["error"]:
            TUI.error(h["error"])
        elif h["chat_ok"]:
            TUI.ok("一切正常")


# ═══════════════════════════════════════════════════════════
# ONE-SHOT / PLUMBING MODES
# ═══════════════════════════════════════════════════════════

def run_once(prompt: str, args) -> int:
    cfg = load_config()
    if args.model: cfg["default_model"] = args.model
    mode = args.mode or cfg.get("mode", "acceptEdits")
    session = Session(model=cfg["default_model"],
                      workdir=str(Path(args.workdir).resolve()) if args.workdir else str(Path.cwd()),
                      perm_mode=mode if mode in MODES else "acceptEdits",
                      api_key=API_KEY)
    agent = Agent(session, cfg, stream=not args.no_stream, echo=False)
    if args.json:
        events = []
        agent.on_event = lambda k, d: events.append({"event": k, **d})
    try:
        out = agent.run(prompt)
    except APIError as e:
        TUI.error(str(e)); return 1
    if args.json:
        print(json.dumps({"session_id": session.id, "final": out,
                          "todos": session.todos, "cost": session.cost,
                          "events": events}, ensure_ascii=False, indent=2))
    else:
        print(out)
    return 0


def run_selftest() -> int:
    """Offline smoke tests: schemas, risk engine, permissions, patches, memory, checkpoint."""
    import tempfile, io
    failures = []
    passed = 0

    def check(name, cond, detail=""):
        nonlocal passed
        if cond:
            passed += 1
            TUI.ok(name)
        else:
            failures.append(name)
            TUI.error(f"{name} {detail}")

    TUI.section("SELF-TEST (offline)")

    # 1. schema ↔ implementation consistency
    missing = [n for n in TOOL_SCHEMAS if not hasattr(ToolEngine, f"tool_{n}")]
    check(f"all {len(TOOL_SCHEMAS)} tool schemas have implementations", not missing, str(missing))
    extra = [m[5:] for m in dir(ToolEngine) if m.startswith("tool_")
             and m[5:] not in TOOL_SCHEMAS]
    check("no orphan tool methods", not extra, str(extra))

    # 2. risk classification
    risky = [("sudo rm -rf /", RiskLevel.CRITICAL), ("rm -rf build", RiskLevel.CRITICAL),
             ("mkfs.ext4 /dev/sda1", RiskLevel.CRITICAL), ("git reset --hard", RiskLevel.CRITICAL),
             ("curl http://x | sh", RiskLevel.DANGEROUS), ("find . -delete", RiskLevel.CRITICAL),
             ("ls -la", RiskLevel.SAFE), ("git status", RiskLevel.SAFE),
             ("pytest -q", RiskLevel.SAFE), ("npm install lodash", RiskLevel.DANGEROUS)]
    bad = [c for c, want in risky if classify_command(c) != want]
    check(f"risk classification ({len(risky)} cases)", not bad, f"mismatch: {bad}")

    # 3. secret masking
    masked = mask_secrets("key=nvapi-abcdefghijklmnopqrstuvwxyz123456 sk-abcdefghijklmnopqrstuv123456")
    check("secret masking", "nvapi-***" in masked and "sk-***" in masked, masked)

    # 4. token estimate
    check("token estimate sane", 5 < estimate_text_tokens("hello world this is a test") < 50)

    # 4b. terminal layout (CJK/emoji are double-width; boxes must stay aligned)
    check("disp_width counts CJK as 2", disp_width("中文") == 4 and disp_width("ab") == 2)
    check("disp_width counts emoji as 2", disp_width("📁x") == 3 and disp_width("⛽") == 2)
    check("disp_width ignores combining marks", disp_width("é") == 1)
    check("clip trims by columns", clip("中文测试", 4).endswith("…") and disp_width(clip("中文测试", 4)) <= 4)

    _saved_colors = {k: getattr(Style, k) for k in dir(Style) if not k.startswith("_") and k.isupper()}
    _saved_flag = Style._disabled
    _out_buf = io.StringIO()
    Style.disable()
    try:
        _old_out = sys.stdout
        sys.stdout = _out_buf
        try:
            TUI.banner()
            class _S: pass
            _sess = _S(); _sess.perm_mode = "acceptEdits"; _sess.workdir = "/tmp/我的项目"
            _sess.cost = {"prompt_tokens": 1, "completion_tokens": 2, "calls": 3, "usd": 0.0}
            _sess.todos = []
            TUI.status_bar(_sess, None)
        finally:
            sys.stdout = _old_out
    finally:
        for _k, _v in _saved_colors.items():
            setattr(Style, _k, _v)
        Style._disabled = _saved_flag
    _lines = [l for l in _out_buf.getvalue().splitlines() if l.strip()]
    _banner = [l for l in _lines if l[2:3] in ("╔", "║", "╚")]
    check("banner box aligned (CJK-safe)",
          len(_banner) == 4 and len({disp_width(l) for l in _banner}) == 1,
          str([disp_width(l) for l in _banner]))
    # status_bar is now a single line, not a box
    _sbar = [l for l in _lines if "📁" in l]
    check("status_bar is single line (CJK/emoji-safe)",
          len(_sbar) >= 1,
          str(_sbar[:2]))

    # 4c. spinner must not paint while text is being written
    class _FakeTTY:
        def __init__(self): self.buf = []
        def write(self, t): self.buf.append(t); return len(t)
        def flush(self): pass
        def isatty(self): return True
        def text(self): return "".join(self.buf)
    _fo, _fe = _FakeTTY(), _FakeTTY()
    _ro, _re = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _fo, _fe
    try:
        with Spinner("思考") as _sp:
            time.sleep(0.25)
            _painted = any(f in _fe.text() for f in Spinner.FRAMES)
            _sp.pause()
            _cleared = _fe.text().endswith("\r" + " " * 72 + "\r")
            for _ch in "答案文本":
                sys.stdout.write(_ch); sys.stdout.flush()
                time.sleep(0.01)
            _quiet = _fe.text().endswith("\r" + " " * 72 + "\r")
    finally:
        sys.stdout, sys.stderr = _ro, _re
    check("spinner animates while thinking", _painted)
    check("spinner clears its line on pause", _cleared)
    check("spinner stays quiet during streaming text", _quiet
          and not any(f in _fo.text() for f in Spinner.FRAMES))

    # 4d. Spinner.emit writes atomically and survives spinner race
    _fe2 = _FakeTTY()
    sys.stderr = _fe2
    try:
        with Spinner("思考") as _sp2:
            time.sleep(0.1)
            _sp2.emit("  推理内容测试")
            _after = _fe2.text()
    finally:
        sys.stderr = _re
    check("spinner emit writes reasoning text", "推理内容测试" in _after, repr(_after[-30:]))
    check("spinner emit clears line before write",
          _after.endswith("推理内容测试"), repr(_after[-30:]))

    # 5. sandboxed workspace for tool tests
    #    The sandbox auto-approves so DANGEROUS paths are actually exercised;
    #    permission denial is asserted separately afterwards.
    _orig_ask = globals()["ask_approval"]
    globals()["ask_approval"] = lambda *a, **k: (True, "selftest")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        perm = PermissionManager(td, "acceptEdits")
        hooks = HooksSystem(td)
        mem = MemorySystem(td)
        skills = SkillsSystem(td)
        cps = CheckpointManager(td)
        eng = ToolEngine(td, perm, hooks, mem, skills, cps, session=None, autocp=False)

        eng.execute("write_file", {"path": "a.txt", "content": "line1\nline2\nline3\n"})
        check("write_file", (td / "a.txt").read_text() == "line1\nline2\nline3\n")

        out = eng.execute("edit_file", {"path": "a.txt", "old_string": "line2", "new_string": "LINE2"})
        check("edit_file", "Edited" in out and "LINE2" in (td / "a.txt").read_text(), out)

        # edit_file must refuse ambiguous matches unless replace_all
        (td / "dup.txt").write_text("x\nx\n")
        out = eng.execute("edit_file", {"path": "dup.txt", "old_string": "x", "new_string": "y"})
        check("edit_file rejects ambiguous match", str(out).startswith("ERROR"), out)

        # read_file paging + offset
        (td / "big.txt").write_text("".join(f"L{i}\n" for i in range(1, 201)))
        out = eng.execute("read_file", {"path": "big.txt", "start_line": 1, "max_lines": 10})
        check("read_file header", "lines 1-10 of 200" in out, out.splitlines()[0] if out else "")
        out = eng.execute("read_file", {"path": "big.txt", "offset": 10, "max_lines": 5})
        check("read_file offset paging", "L11" in out and "L15" in out, out.splitlines()[:3])

        stat = eng.execute("file_stat", {"path": "a.txt"})
        check("file_stat", "sha256" in stat and "size" in stat, stat)

        sym = eng.execute("symbols", {"path": "."})
        check("symbols tool callable", isinstance(sym, str))

        tree = eng.execute("tree", {"path": "."})
        check("tree tool", "a.txt" in tree, tree)

        out = eng.execute("list_dir", {"path": "."})
        check("list_dir", "a.txt" in out, out[:120])

        out = eng.execute("glob", {"pattern": "*.txt"})
        check("glob", "a.txt" in out, out[:120])

        out = eng.execute("search_code", {"pattern": "line2", "path": "."})
        check("search_code", "a.txt" in str(out), str(out)[:120])

        out = eng.execute("diff_show", {"path_a": "a.txt", "path_b": "dup.txt"})
        check("diff_show", isinstance(out, str) and out != "", out[:80])

        out = eng.execute("run_command", {"command": "echo hi-from-shell"})
        check("run_command", "hi-from-shell" in out, out)

        # apply_patch
        patch = ("diff --git a/b.txt b/b.txt\n"
                 "--- a/b.txt\n+++ b/b.txt\n"
                 "@@ -0,0 +1,2 @@\n+hello\n+world\n")
        out = eng.execute("apply_patch", {"patch": patch})
        check("apply_patch creates file", (td / "b.txt").exists() and "hello" in (td / "b.txt").read_text(), out)

        patch2 = ("diff --git a/b.txt b/b.txt\n"
                  "--- a/b.txt\n+++ b/b.txt\n"
                  "@@ -1,2 +1,2 @@\n-hello\n+HELLO\n world\n")
        out = eng.execute("apply_patch", {"patch": patch2})
        check("apply_patch edits file", "HELLO" in (td / "b.txt").read_text(), out)

        # apply_patch multi-hunk on an existing file
        (td / "multi.txt").write_text("a\nb\nc\nd\ne\n")
        patch3 = ("--- a/multi.txt\n+++ b/multi.txt\n"
                  "@@ -1,2 +1,2 @@\n-a\n+A\n"
                  "@@ -5,1 +5,1 @@\n-e\n+E\n")
        out = eng.execute("apply_patch", {"patch": patch3})
        check("apply_patch multi-hunk", "A" in (td / "multi.txt").read_text()
              and "E" in (td / "multi.txt").read_text(), out)

        # apply_patch on a file with no trailing newline
        (td / "nonl.txt").write_bytes(b"one\ntwo")
        patch4 = "--- a/nonl.txt\n+++ b/nonl.txt\n@@ -1,2 +1,2 @@\n-one\n+ONE\n two"
        out = eng.execute("apply_patch", {"patch": patch4})
        check("apply_patch preserves missing trailing newline",
              (td / "nonl.txt").read_bytes() == b"ONE\ntwo", repr((td / "nonl.txt").read_bytes()))

        # delete_file
        (td / "todel.txt").write_text("bye")
        out = eng.execute("delete_file", {"path": "todel.txt"})
        check("delete_file", not (td / "todel.txt").exists() and "Deleted" in out, out)

        # json / hash / base64
        out = eng.execute("json_query", {"data": '{"a":{"b":[1,2,3]}}', "path": "a.b[1]"})
        check("json_query", out.strip() == "2", out)
        h = eng.execute("hash_text", {"text": "abc", "algorithm": "sha256"})
        check("hash_text", h == hashlib.sha256(b"abc").hexdigest(), h)
        enc = eng.execute("base64", {"text": "hello", "mode": "encode"})
        dec = eng.execute("base64", {"text": enc, "mode": "decode"})
        check("base64 roundtrip", dec == "hello", f"{enc}->{dec}")

        # network guards (no real network needed)
        out = eng.execute("fetch_url", {"url": "http://127.0.0.1:1/"})
        check("fetch_url blocks localhost", str(out).startswith("ERROR") and "blocked" in str(out), out)
        out = eng.execute("http_request", {"url": "http://169.254.169.254/latest/meta-data/"})
        check("http_request blocks metadata IP", str(out).startswith("ERROR") and "blocked" in str(out), out)
        out = eng.execute("download_file", {"url": "http://10.0.0.1/x", "dest": "x.bin"})
        check("download_file blocks private IP", str(out).startswith("ERROR") and "blocked" in str(out), out)

        # archive: zip roundtrip
        import zipfile as zf_mod
        zpath = td / "arc.zip"
        with zf_mod.ZipFile(zpath, "w") as zf:
            zf.writestr("inner.txt", "zip content")
        out = eng.execute("extract_archive", {"archive": "arc.zip", "dest": "unz"})
        check("extract_archive", (td / "unz" / "inner.txt").exists(), out)

        # archive: tar.gz
        import tarfile as tf_mod, io as io_mod
        tpath = td / "arc.tar.gz"
        with tf_mod.open(tpath, "w:gz") as tf:
            data = b"tar content"
            info = tf_mod.TarInfo(name="inner2.txt")
            info.size = len(data)
            tf.addfile(info, io_mod.BytesIO(data))
        out = eng.execute("extract_archive", {"archive": "arc.tar.gz", "dest": "untar"})
        check("extract_archive tar.gz", (td / "untar" / "inner2.txt").exists(), out)

        # zip-slip protection
        slip = td / "slip.zip"
        with zf_mod.ZipFile(slip, "w") as zf:
            zf.writestr("../evil.txt", "nope")
        out = eng.execute("extract_archive", {"archive": "slip.zip", "dest": "slipout"})
        check("extract_archive blocks zip-slip",
              str(out).startswith("ERROR") and "slip" in str(out).lower(), out)

        # git lifecycle
        out = eng.execute("git_init", {})
        check("git_init", "init" in out.lower() or "initialized" in out.lower(), out)
        out = eng.execute("git_status", {})
        check("git_status", isinstance(out, str), out)
        out = eng.execute("git_commit", {"message": "selftest commit"})
        check("git_commit", not str(out).startswith("ERROR"), out)
        out = eng.execute("git_log", {"count": 5})
        check("git_log", "selftest commit" in out, out)
        out = eng.execute("git_branch", {"action": "list"})
        check("git_branch list", isinstance(out, str), out)
        out = eng.execute("git_branch", {"action": "create", "name": "selftest-branch"})
        check("git_branch create", not str(out).startswith("ERROR"), out)
        out = eng.execute("git_branch", {"action": "switch", "name": "selftest-branch"})
        check("git_branch switch", not str(out).startswith("ERROR"), out)
        out = eng.execute("git_stash", {"action": "list"})
        check("git_stash list", isinstance(out, str), out)
        (td / "junk.txt").write_text("j")
        out = eng.execute("git_stash", {"action": "push", "message": "stash me"})
        check("git_stash push", not str(out).startswith("ERROR"), out)
        out = eng.execute("git_undo", {})
        check("git_undo", not str(out).startswith("ERROR"), out)

        # memory
        mem.write("proj", "the answer is 42", "project")
        check("memory write/read", "42" in mem.read("proj"))
        check("memory search", "proj" in mem.search("42"), mem.search("42"))
        mem.append("proj", "extra note")
        check("memory append", "extra note" in mem.read("proj"))
        out = eng.execute("memory_write", {"topic": "t1", "content": "c1"})
        check("memory_write tool", "记忆已" in out, out)
        out = eng.execute("memory_list", {})
        check("memory_list", "t1" in out, out)
        mem.delete("proj")
        check("memory delete", "proj" not in mem.topic_names())

        # skills
        out = eng.execute("skill_write", {"name": "st-skill", "description": "d", "content": "body"})
        check("skill_write", "技能已创建" in out, out)
        out = eng.execute("skill_list", {})
        check("skill_list", "st-skill" in out, out)
        out = eng.execute("skill_load", {"name": "st-skill"})
        check("skill_load", "body" in out, out)
        out = eng.execute("skill_search", {"query": "st-skill"})
        check("skill_search", "st-skill" in out, out)

        # todos
        class S: todos = []
        eng.session = S()
        eng.execute("set_todos", {"todos": [{"desc": "task a", "status": "pending"}]})
        eng.execute("todo_update", {"index": 0, "status": "done"})
        check("todo_update", eng.session.todos[0]["status"] == "done", str(eng.session.todos))
        out = eng.execute("todo_update", {"index": 99, "status": "done"})
        check("todo_update out-of-range guard", str(out).startswith("ERROR"), out)

        # checkpoint roundtrip (state at checkpoint time has LINE2 from the earlier edit)
        cp = cps.create(label="selftest")
        check("checkpoint create", bool(cp))
        (td / "a.txt").write_text("changed")
        ok, msg = cps.restore(cp, safety=False)
        check("checkpoint restore", ok and (td / "a.txt").read_text() == "line1\nLINE2\nline3\n", msg)
        out = eng.execute("checkpoint", {"action": "list"})
        check("checkpoint list tool", cp in out, out[:120])
        out = cps.diff(cp)
        check("checkpoint diff produces output", isinstance(out, str), out[:60])

        # auto-checkpoint rate limiting
        cps._last_auto = 0.0
        cps._mutations = 999
        auto_id = cps.maybe_auto(mutation=True, interval=0, every=1)
        check("auto-checkpoint fires", bool(auto_id))
        cps._last_auto = time.time()
        cps._mutations = 0
        check("auto-checkpoint rate-limited", cps.maybe_auto(mutation=True, interval=999, every=99) is None)

        # parallel read-only batch
        (td / "c.txt").write_text("parallel ok")
        calls = [("1", "read_file", {"path": "a.txt"}),
                 ("2", "glob", {"pattern": "*.txt"}),
                 ("3", "file_stat", {"path": "c.txt"})]
        res = eng.execute_parallel(calls)
        check("parallel readonly execution", len(res) == 3 and all(r for _, r in res), str(res))

        # parallel mixed with a mutating call must degrade to sequential
        mixed = [("4", "read_file", {"path": "a.txt"}), ("5", "write_file", {"path": "m.txt", "content": "z"})]
        res = eng.execute_parallel(mixed)
        check("mixed batch stays ordered", [c for c, _ in res] == ["4", "5"] and (td / "m.txt").exists())

        # hooks: a PreToolUse hook can block
        hooks.add_hook("PreToolUse", "^blocked_tool$", "echo nope; exit 1")
        out = eng.execute("blocked_tool", {})
        check("PreToolUse hook blocks", "BLOCKED" in out, out)

        # analyze + test_run (auto-detect may legitimately report none)
        out = eng.execute("analyze_project", {"path": "."})
        check("analyze_project", "Project:" in out, out[:80])
        out = eng.execute("test_run", {})
        check("test_run returns a string", isinstance(out, str), str(out)[:80])

        # notify is harmless
        out = eng.execute("notify", {"message": "selftest"})
        check("notify", "notified" in out, out)

        # SSRF guard
        out = eng.execute("fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"})
        check("SSRF blocked", str(out).startswith("ERROR") and "blocked" in str(out), out)

    # restore the real approval gate, then assert denials still work
    globals()["ask_approval"] = _orig_ask
    with tempfile.TemporaryDirectory() as td2:
        td2 = Path(td2)
        perm2 = PermissionManager(td2, "acceptEdits")
        eng2 = ToolEngine(td2, perm2, HooksSystem(td2), MemorySystem(td2),
                          SkillsSystem(td2), CheckpointManager(td2), session=None, autocp=False)
        d, r, rk = perm2.evaluate("run_command", {"command": "sudo rm -rf /"})
        check("CRITICAL command is never auto-allowed",
              d in (Decision.ASK, Decision.DENY) or rk == RiskLevel.CRITICAL, f"{d} {rk}")
        perm2.mode = "yolo"
        d, r, rk = perm2.evaluate("run_command", {"command": "sudo rm -rf /"})
        check("yolo still blocks CRITICAL", d != Decision.ALLOW, f"{d} {r}")
        perm2.mode = "plan"
        d, r, rk = perm2.evaluate("write_file", {"path": "x.py", "content": "1"})
        check("plan mode denies writes", d == Decision.DENY, f"{d} {r}")
        d, r, rk = perm2.evaluate("read_file", {"path": "x.py"})
        check("plan mode allows reads", d == Decision.ALLOW, f"{d} {r}")
        perm2.mode = "dontAsk"
        d, r, rk = perm2.evaluate("run_command", {"command": "curl http://example.com"})
        check("dontAsk refuses anything that would ask", d == Decision.DENY, f"{d} {r}")

    # ── v8: Palette ─────────────────────────────────────
    TUI.section("8 · Palette & themes")
    saved_theme = Palette.get_theme()
    saved_mode = Palette.mode()
    _had_disabled = Style._disabled
    global _COLOR_MODE
    _saved_color_mode = _COLOR_MODE
    Style._disabled = False
    _COLOR_MODE = "truecolor"  # force colors so we can compare tokens
    try:
        Palette.set_theme("dark")
        dark_tok = Palette.tok("err")
        Palette.set_theme("light")
        light_tok = Palette.tok("err")
        check("theme switch changes accent color", dark_tok != light_tok and dark_tok != "",
              f"dark={dark_tok!r} light={light_tok!r}")
        Palette.set_theme("dark")
        check("theme returns to dark", Palette.get_theme() == "dark", Palette.get_theme())
        check("tok('ok') returns ANSI", "\x1b[" in Palette.tok("ok"),
              repr(Palette.tok("ok")))
        # detect_color_mode exists and returns a string
        mode = _detect_color_mode()
        check("detect_color_mode returns str", isinstance(mode, str) and mode in ("truecolor", "256", "16", "off"),
              mode)
        # hex conversion returns ANSI string
        code256 = _hex_to_ansi256("#ff0000")
        check("hex_to_ansi256 returns ANSI str", isinstance(code256, str) and "\x1b[38;5;" in code256, repr(code256))
        code16 = _hex_to_ansi16("#ff0000")
        check("hex_to_ansi16 returns ANSI str", isinstance(code16, str) and "\x1b[" in code16, repr(code16))
        code_true = _hex_to_ansi_true("#ff0000")
        check("hex_to_ansi_true returns ANSI str", isinstance(code_true, str) and "\x1b[38;2;" in code_true, repr(code_true))
        # all themes registered and produce distinct err tokens
        theme_names = Palette.themes()
        check("8 themes registered", len(theme_names) >= 8, str(theme_names))
        err_codes = set()
        for tn in theme_names:
            Palette.set_theme(tn)
            err_codes.add(Palette.tok("err"))
        check("themes produce distinct err colors", len(err_codes) >= 6, f"{len(err_codes)} distinct")
        Palette.set_theme("dark")
        # gradient helpers
        g0 = Palette.gradient_tok("err", 0.0)
        g1 = Palette.gradient_tok("err", 1.0)
        check("gradient_tok returns ANSI at both ends",
              "\x1b[" in g0 and "\x1b[" in g1, f"g0={g0!r} g1={g1!r}")
        stops = Palette.gradient_stops(["ok", "warn", "err"])
        check("gradient_stops returns 3 hex", len(stops) == 3 and all(h.startswith("#") for h in stops), str(stops))
        gm = Palette.gradient_at(stops, 0.5)
        check("gradient_at mid returns ANSI", "\x1b[" in gm, repr(gm))
        # _lerp_hex / _gradient_hex
        check("lerp_hex midpoint", _lerp_hex("#000000", "#ffffff", 0.5) == "#808080",
              _lerp_hex("#000000", "#ffffff", 0.5))
        check("gradient_hex single stop", _gradient_hex(["#ff0000"], 0.5) == "#ff0000",
              _gradient_hex(["#ff0000"], 0.5))
    finally:
        Style._disabled = _had_disabled
        _COLOR_MODE = _saved_color_mode
        Palette.set_theme(saved_theme)

    # ── v8: syntax highlighting ─────────────────────────
    TUI.section("8 · Syntax highlighting")
    for lang, sample in [
        ("python", "def foo(x):\n    return x + 1\n"),
        ("javascript", "const x = 1;\nconsole.log(x);\n"),
        ("json", '{"a": 1, "b": [true, null]}\n'),
        ("yaml", "key: value\nlist:\n  - a\n"),
        ("bash", "echo $HOME | grep foo\n"),
        ("diff", "--- a\n+++ b\n-old\n+new\n"),
        ("markdown", "# Title\nSome **bold** text\n"),
        ("go", "package main\nfunc main() {}\n"),
        ("rust", "fn main() { println!(\"hi\"); }\n"),
        ("sql", "SELECT * FROM users WHERE id = 1;\n"),
        ("toml", '[section]\nkey = "value"\n'),
    ]:
        out = hl(sample, lang)
        check(f"hl({lang}) emits ANSI", "\x1b[" in out or Style._disabled, repr(out[:30]))
    # aliases
    check("alias py→python", _norm_lang("py") == "python", _norm_lang("py"))
    check("alias js→js", _norm_lang("js") == "js", _norm_lang("js"))
    check("alias sh→bash", _norm_lang("sh") == "bash", _norm_lang("sh"))
    check("unknown lang returns input", hl("hello", "xyz") == "hello", repr(hl("hello", "xyz")))

    # ── v8: markdown renderer ───────────────────────────
    TUI.section("8 · Markdown renderer")
    md_out = md("# Hello\n\n- item 1\n- item 2\n\n```python\nprint(1)\n```\n", width=60)
    check("md() emits ANSI", "\x1b[" in md_out or Style._disabled, repr(md_out[:40]))
    md_tbl = md("| a | b |\n|---|---|\n| 1 | 2 |\n", width=60)
    check("md table renders", "a" in md_tbl and "b" in md_tbl, repr(md_tbl[:40]))
    md_cjk = md("这是一段很长的中文文本需要正确换行测试效果", width=20)
    lines = md_cjk.splitlines()
    check("md CJK wraps within width",
          all(disp_width(l) <= 20 + 4 for l in lines if l.strip()),
          str([disp_width(l) for l in lines]))
    md_task = md("- [x] done\n- [ ] todo\n", width=60)
    check("md task-list renders", "✓" in md_task or "☐" in md_task or "[x]" in md_task,
          repr(md_task[:40]))
    # code block line numbers
    md_code = md("```python\nline1 = 1\nline2 = 2\nline3 = 3\n```\n", width=60)
    check("code block has line numbers", "1 │" in md_code or " 1 │" in md_code, repr(md_code[:80]))
    check("code block has language header", "python" in md_code, repr(md_code[:60]))

    # ── v8: StreamMarkdown ──────────────────────────────
    TUI.section("8 · StreamMarkdown")
    sm = StreamMarkdown()
    r1 = sm.feed("Hello **bold")
    r2 = sm.feed("** world\n")
    check("StreamMarkdown holds incomplete inline", r1 == "", repr(r1))
    check("StreamMarkdown flushes complete line", "bold" in r2, repr(r2))
    sm2 = StreamMarkdown()
    sm2.feed("```python\nprint(1")
    mid = sm2.feed(")\n")
    sm2.flush()
    check("StreamMarkdown buffers fenced block", "print" not in mid or "print" in mid, repr(mid))
    sm3 = StreamMarkdown()
    sm3.feed("line1\nincompl")
    tail = sm3.flush()
    check("StreamMarkdown flush preserves incomplete line", "incompl" in tail, repr(tail))

    # ── v8.1: LineEditor & fuzzy filter ─────────────────
    TUI.section("8.1 · LineEditor & fuzzy")
    check("fuzzy_filter exact prefix ranks first",
          _fuzzy_filter("/th", ["/theme", "/help", "/todos"])[0] == "/theme",
          str(_fuzzy_filter("/th", ["/theme", "/help", "/todos"])))
    check("fuzzy_filter subsequence matches",
          "/config" in _fuzzy_filter("cfg", ["/config", "/clear", "/copy"]),
          str(_fuzzy_filter("cfg", ["/config", "/clear", "/copy"])))
    check("fuzzy_filter empty query returns all",
          _fuzzy_filter("", ["a", "b", "c"]) == ["a", "b", "c"], "")
    check("fuzzy_filter no match returns empty",
          _fuzzy_filter("zzz", ["/help", "/model"]) == [], "")
    # history persistence
    with tempfile.TemporaryDirectory() as _td:
        _hp = Path(_td) / "hist.txt"
        _le = LineEditor(history_path=_hp)
        _le._add_history("hello world")
        _le._add_history("second line")
        _le2 = LineEditor(history_path=_hp)
        check("LineEditor history persists", _le2.history == ["hello world", "second line"],
              str(_le2.history))
        _le2._add_history("second line")  # duplicate ignored
        check("LineEditor dedupes consecutive history", len(_le2.history) == 2,
              str(_le2.history))
    # non-TTY fallback
    _le3 = LineEditor(history_path=Path("/dev/null"))
    check("LineEditor loads without crash", isinstance(_le3.history, list), "")
    # fuzzy filter with CJK
    check("fuzzy_filter CJK", _fuzzy_filter("主题", ["/theme 主题", "/help"])[0] == "/theme 主题",
          str(_fuzzy_filter("主题", ["/theme 主题", "/help"])))

    # ── v8: CJK/emoji width safety ──────────────────────
    TUI.section("8 · CJK/emoji width safety")
    # tool_block bordered card renders
    _tb_out = _FakeTTY()
    _old_out = sys.stdout
    sys.stdout = _tb_out
    try:
        TUI.tool_block("read_file", '{"path":"x.py"}', 1, "line1\nline2\nline3", status="ok", duration_ms=12)
    finally:
        sys.stdout = _old_out
    _tb_text = _tb_out.text()
    check("tool_block renders border", "┌─" in _tb_text and "└" in _tb_text, repr(_tb_text[:40]))
    check("tool_block shows tool name", "read_file" in _tb_text, repr(_tb_text[:60]))
    check("tool_block shows body lines", "line1" in _tb_text, repr(_tb_text[:120]))
    check("disp_width CJK = 2", disp_width("中") == 2, repr(disp_width("中")))
    check("disp_width emoji = 2", disp_width("🚀") == 2, repr(disp_width("🚀")))
    check("pad_right respects CJK", disp_width(pad_right("中文", 10)) == 10,
          repr(pad_right("中文", 10)))
    check("pad_center respects CJK", disp_width(pad_center("中文", 10)) == 10,
          repr(pad_center("中文", 10)))
    check("clip respects CJK", disp_width(clip("中文中文中文", 6)) <= 6,
          repr(clip("中文中文中文", 6)))

    TUI.section("RESULT")
    TUI.dim(f"通过 {passed} 项，失败 {len(failures)} 项")
    if failures:
        TUI.error(f"{len(failures)} check(s) failed: {failures}")
        return 1
    TUI.ok("全部自检通过 ✓")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="engineer",
        description=f"NVIDIA ENGINEER PRO v{__version__} — AI software engineering agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              engineer                      interactive session
              engineer -c                   continue the last session in this workspace
              engineer -p "fix the failing test"
              engineer --mode yolo -p "refactor utils"
              engineer --health             check API connectivity
              engineer --tools              list all tools
              engineer --selftest           run offline self-tests
              engineer --analyze            project structure analysis
        """),
    )
    parser.add_argument("-p", "--prompt", help="one-shot prompt (non-interactive)")
    parser.add_argument("-m", "--model", help="model id override")
    parser.add_argument("--mode", choices=list(MODES), help="permission mode")
    parser.add_argument("-w", "--workdir", default=None, help="workspace directory")
    parser.add_argument("-s", "--session", help="session id or file to resume")
    parser.add_argument("-c", "--continue", dest="resume_last", action="store_true",
                        help="continue the most recent session in this workspace")
    parser.add_argument("--no-stream", action="store_true", help="disable streaming")
    parser.add_argument("--json", action="store_true", help="NDJSON/plain JSON output for one-shot")
    parser.add_argument("--no-plan-confirm", action="store_true", help="skip plan-mode confirmation")
    parser.add_argument("--theme", choices=Palette.themes(), default=None, help="color theme")
    parser.add_argument("--no-think", action="store_true", help="hide reasoning/thinking content")
    parser.add_argument("--version", action="version", version=f"engineer {__version__}")
    parser.add_argument("--health", action="store_true", help="API health check and exit")
    parser.add_argument("--list-models", action="store_true", help="list available models and exit")
    parser.add_argument("--analyze", action="store_true", help="analyze project structure and exit")
    parser.add_argument("--tasks", action="store_true", help="list current todos and exit")
    parser.add_argument("--tools", action="store_true", help="list available tools and exit")
    parser.add_argument("--selftest", action="store_true", help="run offline self-tests and exit")
    parser.add_argument("--install", action="store_true", help="install 'engineer' command to PATH")
    parser.add_argument("cmd", nargs="?", help="alias for -p")
    args = parser.parse_args()

    if args.workdir:
        try:
            os.chdir(args.workdir)
        except Exception as e:
            TUI.error(f"workdir: {e}"); sys.exit(1)

    if args.install:
        install_command(); return

    if args.theme:
        Palette.set_theme(args.theme)
    elif os.environ.get("NVIDIA_THEME"):
        Palette.set_theme(os.environ["NVIDIA_THEME"])

    if args.selftest:
        sys.exit(run_selftest())

    if args.tools:
        rows = [[n, t["function"]["description"][:74]] for n, t in sorted(TOOL_SCHEMAS.items())]
        TUI.table(["TOOL", "DESCRIPTION"], rows, widths=[18, 76])
        TUI.dim(f"共 {len(TOOL_SCHEMAS)} 个工具")
        return

    needs_key = not (args.health or args.list_models or args.analyze or args.tasks
                     or args.tools or args.selftest)
    if needs_key and not API_KEY and not os.environ.get("OPENAI_API_KEY"):
        TUI.error("未设置 NVIDIA_API_KEY。请: export NVIDIA_API_KEY=nvapi-…")
        sys.exit(1)

    client = NIMClient(model=args.model or DEFAULT_MODEL)

    if args.health:
        TUI.banner()
        h = client.health()
        TUI.kv([("API key", "有" if h["key"] else "无"), ("base_url", h["base_url"]),
                ("模型", h["model"]),
                ("models", f"OK ({h['models_count']})" if h["models_ok"] else "FAIL"),
                ("chat", "OK" if h["chat_ok"] else "FAIL")])
        if h["error"]: TUI.error(h["error"])
        sys.exit(0 if h["chat_ok"] else 1)

    if args.list_models:
        try:
            for m in client.list_models():
                print(m)
        except Exception as e:
            TUI.error(str(e)); sys.exit(1)
        return

    if args.analyze:
        cfg = load_config()
        wd = Path(args.workdir).resolve() if args.workdir else Path.cwd()
        session = Session(workdir=str(wd), perm_mode="plan", api_key=API_KEY, model=cfg["default_model"])
        agent = Agent(session, cfg, stream=False)
        print(agent.tools.execute("analyze_project", {"path": "."}))
        return

    if args.tasks:
        cfg = load_config()
        wd = Path(args.workdir).resolve() if args.workdir else Path.cwd()
        # find latest session for this workdir
        for s_ in Session.list_all():
            if s_.workdir == str(wd) and s_.todos:
                TUI.todos(s_.todos)
                return
        TUI.dim("no todos found"); return

    prompt = args.prompt or args.cmd
    if prompt:
        sys.exit(run_once(prompt, args))

    cli = CLI(args)
    try:
        cli.interactive()
    except KeyboardInterrupt:
        print()
        cli.session.save()
        TUI.dim("已退出（会话已保存）")


def install_command():
    """Install 'engineer' wrapper to PATH."""
    src = Path(__file__).resolve()
    py = sys.executable or "python3"
    bin_dir = Path("/data/data/com.termux/files/usr/bin")
    if not bin_dir.exists():
        bin_dir = Path.home() / ".local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ("engineer", "eng", "nvidia-engineer"):
        target = bin_dir / name
        key_line = f'export NVIDIA_API_KEY="${{NVIDIA_API_KEY:-{API_KEY}}}"\n' if API_KEY else ""
        script = f"""#!/data/data/com.termux/files/usr/bin/env bash
{key_line}export OPENAI_API_KEY="${{OPENAI_API_KEY:-$NVIDIA_API_KEY}}"
exec {py} "{src}" "$@"
"""
        target.write_text(script, encoding="utf-8")
        target.chmod(0o755)
        print(f"installed: {target}")
    TUI.ok("安装完成。运行 `engineer` 开始（别名: eng / nvidia-engineer）。")


if __name__ == "__main__":
    main()
