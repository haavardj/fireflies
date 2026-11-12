#!/bin/bash
# Stop hook: when Python files or pyproject.toml have uncommitted changes,
# run ruff, pyright and the Trial tests. On failure, exit 2 so Claude Code
# keeps the turn going and shows Claude the output.

input=$(cat)

cd "$(dirname "$0")/../.." || exit 0

# Nothing to check if no Python or config file has changed.
if [ -z "$(git status --porcelain -- '*.py' '*.pyi' pyproject.toml 2>/dev/null)" ]; then
    exit 0
fi

if [ -x .venv/Scripts/python.exe ]; then
    py=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then
    py=.venv/bin/python
else
    exit 0
fi

failed=""
ruff_out=$("$py" -m ruff check fireflies 2>&1) || failed="ruff"
pyright_out=$("$py" -m pyright --pythonpath "$py" 2>&1) || failed="pyright"
trial_out=$("$py" -m twisted.trial fireflies.test 2>&1) || failed="$failed trial"

[ -z "$failed" ] && exit 0

# Claude was already sent back once this turn: report, do not loop.
if printf '%s' "$input" | grep -q '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then
    echo "{\"systemMessage\": \"Checks still failing:$failed\"}"
    exit 0
fi

{
    echo "Checks failed:$failed. Fix them before finishing."
    case "$failed" in *ruff*)
        echo; echo "== ruff (python -m ruff check --fix fireflies fixes most) =="; printf '%s\n' "$ruff_out" | head -40;;
    esac
    case "$failed" in *pyright*)
        echo; echo "== pyright =="; printf '%s\n' "$pyright_out" | grep -E "error|warning" | head -40;;
    esac
    case "$failed" in *trial*)
        echo; echo "== trial =="; printf '%s\n' "$trial_out" | tail -60;;
    esac
} >&2
exit 2
