#!/usr/bin/env bash
# Release distrib handoff via VERDICTAN_DISTRIB_CACHE_ROOT.
set -euo pipefail

# BatchMode=yes makes a missing or passphrase-protected key fail fast instead of
# waiting on a password prompt.
readonly remote_ssh_options='-o BatchMode=yes -o ConnectTimeout=15'

cache_root() {
  if [[ -n "${VERDICTAN_DISTRIB_CACHE_ROOT:-}" ]]; then
    printf '%s\n' "$VERDICTAN_DISTRIB_CACHE_ROOT"
    return
  fi
  if [[ -n "${VERDICTAN_DISTRIB_RUN_ID:-}" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      printf '%s/Work/verdictan/target/distrib-runs/%s\n' "${HOME}" "$VERDICTAN_DISTRIB_RUN_ID"
      return
    fi
    printf '/mnt/Work/verdictan/target/distrib-runs/%s\n' "$VERDICTAN_DISTRIB_RUN_ID"
    return
  fi
  echo "release_distrib_cache.sh: set VERDICTAN_DISTRIB_CACHE_ROOT or VERDICTAN_DISTRIB_RUN_ID" >&2
  exit 1
}

target_base() {
  printf '%s\n' "${CARGO_TARGET_DIR:-target}"
}

distrib_dir() {
  printf '%s/distrib\n' "$(target_base)"
}

wire_distrib_link() {
  local root target_dir distrib root_real distrib_real
  root="$(cache_root)"
  root_real="$(readlink -f "$root" 2>/dev/null || printf '%s' "$root")"
  target_dir="$(target_base)"
  distrib="$(distrib_dir)"
  distrib_real="$(readlink -f "$distrib" 2>/dev/null || true)"

  mkdir -p "$root" "$target_dir"
  if [[ "$distrib_real" != "$root_real" ]]; then
    rm -rf "$distrib"
    ln -sfn "$root" "$distrib"
  fi

  # cargo-dist workflow paths use workspace-relative target/distrib even when
  # CARGO_TARGET_DIR points outside the workspace.
  if [[ "$target_dir" != "$(pwd)/target" && "$target_dir" != "target" ]]; then
    local target_real workspace_target_real
    workspace_target_real="$(readlink -f target 2>/dev/null || true)"
    target_real="$(readlink -f "$target_dir" 2>/dev/null || printf '%s' "$target_dir")"
    if [[ "$workspace_target_real" != "$target_real" ]]; then
      mkdir -p "$(dirname target)"
      rm -rf target
      ln -sfn "$target_dir" target
    fi
  fi
}

remote_ssh() {
  # -n keeps ssh from reading the stdin of the calling shell.
  # SC2086: remote_ssh_options must split into separate ssh arguments.
  # SC2029: the caller quotes remote paths, so client-side expansion is intended.
  # shellcheck disable=SC2086,SC2029
  ssh -n $remote_ssh_options "$@"
}

require_env() {
  local name="$1" hint="$2" value
  value="${!name:-}"
  if [[ -z "$value" ]]; then
    echo "release_distrib_cache.sh: set $name ($hint)" >&2
    return 1
  fi
  printf '%s\n' "$value"
}

# Preserve outputs that earlier jobs delivered for the same run.
push_remote() {
  local host root run_id source dest remote_count
  host="$(require_env VERDICTAN_DISTRIB_REMOTE_HOST \
    'user@host of the Linux release host')"
  root="$(require_env VERDICTAN_DISTRIB_REMOTE_ROOT \
    'run-scoped distrib parent dir on the Linux release host')"
  run_id="$(require_env VERDICTAN_DISTRIB_RUN_ID \
    'run-scoped distrib dir name shared with the Linux jobs')"

  source="$(cache_root)"
  if [[ ! -d "$source" ]]; then
    echo "release_distrib_cache.sh: local distrib dir is missing: $source" >&2
    exit 1
  fi

  dest="${root%/}/${run_id}"
  remote_ssh "$host" "mkdir -p '$dest'"
  rsync -av -e "ssh $remote_ssh_options" "$source"/ "$host:$dest/"

  remote_count="$(remote_ssh "$host" "ls -1 '$dest' | wc -l" | tr -d '[:space:]')"
  if [[ "$remote_count" == "0" ]]; then
    echo "release_distrib_cache.sh: remote distrib dir is empty after push: $host:$dest" >&2
    exit 1
  fi
  echo "release_distrib_cache.sh: pushed $source to $host:$dest ($remote_count entries)"
}

cmd="${1:-}"
shift || true

case "$cmd" in
  prepare)
    wire_distrib_link
    ;;

  fetch-linux)
    wire_distrib_link
    ;;

  publish-linux)
    wire_distrib_link
    if [[ ! -d "$(distrib_dir)" ]]; then
      echo "release_distrib_cache.sh: distrib dir is missing after build: $(distrib_dir)" >&2
      exit 1
    fi
    ;;

  push-remote)
    push_remote
    ;;

  prepare-release)
    wire_distrib_link
    mkdir -p artifacts
    shopt -s nullglob
    for file in "$(distrib_dir)"/*; do
      [[ -f "$file" ]] || continue
      case "$(basename "$file")" in
        *-dist-manifest.json|dist-manifest.json) continue ;;
      esac
      cp -f "$file" artifacts/
    done
    ;;

  cleanup-run)
    root="$(cache_root)"
    rm -rf "$root"
    ;;

  *)
    echo "usage: $0 {prepare|fetch-linux|publish-linux|push-remote|prepare-release|cleanup-run}" >&2
    exit 1
    ;;
esac
