#!/usr/bin/env bash
# Example: run OpenAI's `codex exec` inside the airlock so the agent cannot
# read anything on this machine except its own auth and an empty workdir.
#
# Field-tested pattern: this exact shape ran a 9-case benchmark where the
# host repo (including the answer keys) had to be unreachable by the model.
set -euo pipefail

JAIL_HOME=$(mktemp -d)   # only the CLI's auth + model config live here
WORKDIR=$(mktemp -d)     # empty cwd for the agent
RESULTS=$(mktemp -d)

mkdir -p "$JAIL_HOME/.codex"
cp ~/.codex/auth.json "$JAIL_HOME/.codex/"
printf 'model = "gpt-5.2"\nmodel_reasoning_effort = "high"\n' > "$JAIL_HOME/.codex/config.toml"

PROMPT="Reply with exactly: airlock ok"

bwrap --die-with-parent \
  --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
  --ro-bind /etc/ssl /etc/ssl --ro-bind /etc/resolv.conf /etc/resolv.conf --ro-bind /etc/hosts /etc/hosts \
  --ro-bind /usr/local/bin/codex /usr/local/bin/codex \
  --bind "$JAIL_HOME" /jailhome --bind "$RESULTS" /results --ro-bind "$WORKDIR" /work \
  --proc /proc --dev /dev --tmpfs /tmp \
  --unshare-pid --unshare-ipc --unshare-uts \
  --setenv HOME /jailhome --setenv PATH /usr/local/bin:/usr/bin:/bin --chdir /work \
  codex exec --sandbox read-only --skip-git-repo-check \
  -o /results/response.txt -- "$PROMPT"

echo "--- agent response ---"
cat "$RESULTS/response.txt"
