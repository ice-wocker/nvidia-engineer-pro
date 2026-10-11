# NVIDIA ENGINEER PRO v8.0.0

Terminal AI coding agent · **one stdlib-only Python file**, works with any
NVIDIA NIM / OpenAI-compatible endpoint · 46 tools, streaming, parallel reads,
shadow-git checkpoints, budgets, hooks, skills, memory, themes.

终端 AI 编程助手 · **单文件 · 纯标准库（零依赖）** · 46 个工具、流式输出、只读工具并行、
shadow-git 检查点、预算与成本统计、钩子 / 技能 / 长期记忆、主题切换。

---

## Install 安装

```bash
git clone https://github.com/ice-wocker/nvidia-engineer-pro.git
cd nvidia-engineer-pro
export NVIDIA_API_KEY=nvapi-…        # https://build.nvidia.com
python3 nvidia_pro.py --install      # installs: engineer / eng / nvidia-engineer
```

Requires Python 3.9+ and `git` on PATH. Nothing else — no pip packages.

## Quick start 快速开始

```bash
engineer                       # interactive session 交互会话
engineer -c                    # continue last session 继续上次会话
engineer -p "fix the failing test"
engineer --mode yolo -p "refactor utils"
engineer --selftest            # offline self-tests (116 checks) 离线自检
engineer --health              # API connectivity check
engineer --tools               # list all 46 tools
engineer --analyze             # project structure analysis
engineer --theme light         # switch color theme 切换配色主题
engineer --no-think            # hide reasoning stream 隐藏推理流
```

## Why v8 架构

| Area | What you get |
|---|---|
| **Streaming** | SSE deltas printed live; the spinner pauses the moment text arrives so the answer is never shredded |
| **Syntax highlighting** | built-in ANSI highlighter for 12 languages (Python/JS/TS/JSON/YAML/Bash/Diff/Markdown/Go/Rust/SQL/TOML/INI) — no Pygments, no dependencies |
| **Markdown renderer** | CJK/emoji-aware block renderer: headings, lists, task-lists, fenced code blocks, tables, quotes — streams correctly |
| **Theme system** | GitHub-inspired dark/light themes; auto-detect truecolor / 256-color / 16-color / off; switch at runtime (`/theme` or `--theme`) |
| **Parallel tools** | read-only batches (`read_file`/`list_dir`/`glob`/`search_code`/…) run concurrently, results merged in order |
| **Safety** | 5 permission modes, whole-command risk classification (`curl … \| sh` is judged as one command), CRITICAL rules always block, SSRF guard blocks private/metadata IPs; approval dialog shows inline diff preview |
| **Checkpoints** | shadow-git snapshots in `~/.nvidia_engineer_pro` — never touches your `.git`; auto-snapshot before every mutating tool, `pre-restore` snapshot by default; `/revert` restores single files |
| **Patch tool** | `apply_patch` takes real unified diffs (multi-hunk, missing trailing newline OK) |
| **Budget** | token / step / wall-clock / USD caps with 50/80/95 % warnings, context auto-compaction that preserves your todo list |
| **Resilience** | retry with exponential backoff on 408/425/429/5xx, `Ctrl-C` aborts the in-flight stream but keeps the session (partial output preserved) |
| **Memory & skills** | persistent topics with search/append, reusable skill prompts |
| **Hooks** | PreToolUse / PostToolUse / SessionEnd hooks from `.nengineer/hooks.json` — return code 1 blocks the tool |
| **TUI** | CJK/emoji-aware layout, progress bars, colored diffs, Tab completion for slash commands, `/last` review, `/copy` to clipboard |

## Modes 权限模式

| Mode | Behaviour |
|---|---|
| `plan` | read-only exploration, then ask to apply the plan |
| `default` | ask once per risky category |
| `acceptEdits` | auto-allow in-workspace edits + safe commands (default) |
| `yolo` | auto-allow everything except CRITICAL |
| `dontAsk` | refuse anything that would ask |

```bash
engineer --mode plan          # explore first
engineer /mode yolo           # switch at runtime
```

## Slash commands 斜杠命令

`/help [keyword]` `/model` `/models` `/mode` `/perm` `/risk` `/budget` `/todos` `/done`
`/memory` `/skills` `/hook` `/tools` `/cp` `/undo` `/verify` `/web` `/search`
`/proj` `/tree` `/sym` `/find` `/grep` `/stat` `/diff` `/branch` `/export`
`/clear` `/compact` `/session` `/cost` `/health`
`/last [n]` `/theme [dark|light]` `/config [k=v]` `/copy` `/revert <file>` `/quit`

## Tools 工具（46）

file ops (`read_file` offset paging, `write_file`, `edit_file` ambiguity guard,
`apply_patch`, `delete_file`, `file_stat`, `tree`, `symbols`, `list_dir`, `glob`,
`search_code` with ripgrep fast path), `run_command`, `test_run`, `fetch_url` /
`http_request` / `download_file` / `extract_archive` (zip-slip & tar-slip
protected), `git_status` / `git_diff` / `git_log` / `git_commit` / `git_init` /
`git_branch` / `git_stash` / `git_undo`, checkpoint tools, memory tools, skill
tools, `todo_update`, `json_query`, `hash_text`, `base64`, `notify`,
`analyze_project`, `web_search`, `subagent`.

## Config 配置

State lives in `~/.nvidia_engineer_pro/` (`config.json`, `sessions/`,
`checkpoints/`, `memory/`, `skills/`, `audit.jsonl`). Environment:

```bash
export NVIDIA_API_KEY=nvapi-…
export NVIDIA_MODEL=openai/gpt-oss-20b   # optional override
export NO_COLOR=1                        # disable ANSI
```

## Self-test 自检

```bash
engineer --selftest
```

116 offline checks: schema↔implementation consistency, risk engine, permission
matrix, patch application, zip-slip, git lifecycle, memory/skill/todo tools,
checkpoint auto-rate-limiting, parallel batching, hook blocking, spinner/TUI
layout, Palette theme switching, syntax highlighting across 12 languages,
markdown renderer (CJK wrap, tables, task-lists), StreamMarkdown buffering,
CJK/emoji width safety. No network required.

## License

MIT — see `nvidia_pro.py` header.
