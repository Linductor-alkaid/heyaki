#!/usr/bin/env bash

set -euo pipefail

heyaki_script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
heyaki_repo_root=$(CDPATH= cd -- "${heyaki_script_dir}/.." && pwd)
heyaki_lock_file=${HEYAKI_DEPENDENCIES_LOCK:-"${heyaki_repo_root}/third_party/dependencies.lock"}
heyaki_third_party_dir=${HEYAKI_THIRD_PARTY_DIR:-"${heyaki_repo_root}/third_party"}

heyaki_include_tests=false
heyaki_include_optional=false
heyaki_check_only=false
heyaki_list_only=false
heyaki_selected_names=()
heyaki_dependency_records=()
heyaki_temp_dirs=()

usage() {
  cat <<'EOF'
Usage: scripts/fetch_third_party.sh [options] [dependency ...]

Fetch the pinned Heyaki dependencies into third_party/. With no dependency
names, runtime dependencies are selected.

Options:
  --with-tests       Include dependencies in the test group.
  --with-optional    Include optional dependencies such as zstd.
  --all              Include runtime, test, and optional dependencies.
  --check            Verify local repositories without network access.
  --list             Print the lock file entries and exit.
  -h, --help         Show this help.

Environment:
  HEYAKI_DEPENDENCIES_LOCK  Override the dependency lock file.
  HEYAKI_THIRD_PARTY_DIR    Override the destination directory.

Examples:
  scripts/fetch_third_party.sh
  scripts/fetch_third_party.sh --with-tests
  scripts/fetch_third_party.sh libdatachannel protobuf
  scripts/fetch_third_party.sh --check --all
EOF
}

log() {
  printf '[heyaki-deps] %s\n' "$*"
}

fail() {
  printf '[heyaki-deps] error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local heyaki_temp_dir
  for heyaki_temp_dir in "${heyaki_temp_dirs[@]}"; do
    if [[ -n "${heyaki_temp_dir}" && -d "${heyaki_temp_dir}" ]]; then
      rm -rf -- "${heyaki_temp_dir}"
    fi
  done
}

trap cleanup EXIT

while (($# > 0)); do
  case "$1" in
    --with-tests)
      heyaki_include_tests=true
      ;;
    --with-optional)
      heyaki_include_optional=true
      ;;
    --all)
      heyaki_include_tests=true
      heyaki_include_optional=true
      ;;
    --check)
      heyaki_check_only=true
      ;;
    --list)
      heyaki_list_only=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while (($# > 0)); do
        heyaki_selected_names+=("$1")
        shift
      done
      break
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      heyaki_selected_names+=("$1")
      ;;
  esac
  shift
done

command -v git >/dev/null 2>&1 || fail "git is required"
[[ -f "${heyaki_lock_file}" ]] || fail "lock file not found: ${heyaki_lock_file}"

while IFS= read -r heyaki_lock_line || [[ -n "${heyaki_lock_line}" ]]; do
  heyaki_lock_line=${heyaki_lock_line%$'\r'}
  [[ -z "${heyaki_lock_line}" || "${heyaki_lock_line}" == \#* ]] && continue
  IFS='|' read -r heyaki_name heyaki_url heyaki_ref heyaki_commit heyaki_recursive heyaki_group <<< \
    "${heyaki_lock_line}"
  [[ "${heyaki_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
    fail "invalid dependency name in ${heyaki_lock_file}: ${heyaki_name}"
  [[ -n "${heyaki_url}" && -n "${heyaki_ref}" && -n "${heyaki_commit}" ]] || \
    fail "invalid entry in ${heyaki_lock_file}: ${heyaki_name}"
  [[ "${heyaki_commit}" =~ ^[0-9a-f]{40}$ ]] || \
    fail "invalid commit for ${heyaki_name}: ${heyaki_commit}"
  [[ "${heyaki_recursive}" == "true" || "${heyaki_recursive}" == "false" ]] || \
    fail "invalid recursive value for ${heyaki_name}: ${heyaki_recursive}"
  [[ "${heyaki_group}" == "runtime" || "${heyaki_group}" == "test" || "${heyaki_group}" == "optional" ]] || \
    fail "invalid group for ${heyaki_name}: ${heyaki_group}"
  heyaki_dependency_records+=("${heyaki_name}|${heyaki_url}|${heyaki_ref}|${heyaki_commit}|${heyaki_recursive}|${heyaki_group}")
done < "${heyaki_lock_file}"

((${#heyaki_dependency_records[@]} > 0)) || fail "no dependencies found in ${heyaki_lock_file}"

if [[ "${heyaki_list_only}" == "true" ]]; then
  printf '%-16s %-9s %-12s %s\n' NAME GROUP REF COMMIT
  for heyaki_record in "${heyaki_dependency_records[@]}"; do
    IFS='|' read -r heyaki_name _ heyaki_ref heyaki_commit _ heyaki_group <<< "${heyaki_record}"
    printf '%-16s %-9s %-12s %s\n' "${heyaki_name}" "${heyaki_group}" "${heyaki_ref}" "${heyaki_commit}"
  done
  exit 0
fi

is_explicitly_selected() {
  local heyaki_candidate=$1
  local heyaki_selected
  for heyaki_selected in "${heyaki_selected_names[@]}"; do
    [[ "${heyaki_selected}" == "${heyaki_candidate}" ]] && return 0
  done
  return 1
}

record_exists() {
  local heyaki_candidate=$1
  local heyaki_record
  local heyaki_name
  for heyaki_record in "${heyaki_dependency_records[@]}"; do
    IFS='|' read -r heyaki_name _ <<< "${heyaki_record}"
    [[ "${heyaki_name}" == "${heyaki_candidate}" ]] && return 0
  done
  return 1
}

for heyaki_selected in "${heyaki_selected_names[@]}"; do
  record_exists "${heyaki_selected}" || fail "unknown dependency: ${heyaki_selected}"
done

is_selected() {
  local heyaki_name=$1
  local heyaki_group=$2

  if ((${#heyaki_selected_names[@]} > 0)); then
    is_explicitly_selected "${heyaki_name}"
    return
  fi

  case "${heyaki_group}" in
    runtime)
      return 0
      ;;
    test)
      [[ "${heyaki_include_tests}" == "true" ]]
      ;;
    optional)
      [[ "${heyaki_include_optional}" == "true" ]]
      ;;
  esac
}

ensure_clean_repository() {
  local heyaki_name=$1
  local heyaki_destination=$2
  local heyaki_status

  heyaki_status=$(git -C "${heyaki_destination}" status --porcelain --untracked-files=all)
  [[ -z "${heyaki_status}" ]] || \
    fail "${heyaki_name} has local changes; preserve or remove them before syncing"
}

verify_submodules() {
  local heyaki_name=$1
  local heyaki_destination=$2
  local heyaki_line
  local heyaki_prefix

  while IFS= read -r heyaki_line; do
    [[ -z "${heyaki_line}" ]] && continue
    heyaki_prefix=${heyaki_line:0:1}
    case "${heyaki_prefix}" in
      -|+|U)
        fail "${heyaki_name} has an uninitialized or mismatched submodule: ${heyaki_line}"
        ;;
    esac
  done < <(git -C "${heyaki_destination}" submodule status --recursive)
}

verify_dependency() {
  local heyaki_name=$1
  local heyaki_url=$2
  local heyaki_commit=$3
  local heyaki_recursive=$4
  local heyaki_destination="${heyaki_third_party_dir}/${heyaki_name}"
  local heyaki_actual_url
  local heyaki_actual_commit

  [[ -d "${heyaki_destination}/.git" ]] || fail "${heyaki_name} is not fetched: ${heyaki_destination}"
  heyaki_actual_url=$(git -C "${heyaki_destination}" remote get-url origin)
  [[ "${heyaki_actual_url}" == "${heyaki_url}" ]] || \
    fail "${heyaki_name} origin mismatch: expected ${heyaki_url}, got ${heyaki_actual_url}"
  ensure_clean_repository "${heyaki_name}" "${heyaki_destination}"
  heyaki_actual_commit=$(git -C "${heyaki_destination}" rev-parse HEAD)
  [[ "${heyaki_actual_commit}" == "${heyaki_commit}" ]] || \
    fail "${heyaki_name} commit mismatch: expected ${heyaki_commit}, got ${heyaki_actual_commit}"
  if [[ "${heyaki_recursive}" == "true" ]]; then
    verify_submodules "${heyaki_name}" "${heyaki_destination}"
  fi
  log "verified ${heyaki_name} @ ${heyaki_commit:0:12}"
}

initialize_repository() {
  local heyaki_name=$1
  local heyaki_url=$2
  local heyaki_ref=$3
  local heyaki_commit=$4
  local heyaki_recursive=$5
  local heyaki_destination="${heyaki_third_party_dir}/${heyaki_name}"
  local heyaki_temp_dir
  local heyaki_fetched_commit

  heyaki_temp_dir=$(mktemp -d "${heyaki_third_party_dir}/.fetch-${heyaki_name}.XXXXXX")
  heyaki_temp_dirs+=("${heyaki_temp_dir}")

  log "fetching ${heyaki_name} (${heyaki_ref})"
  git -C "${heyaki_temp_dir}" init --quiet
  git -C "${heyaki_temp_dir}" remote add origin "${heyaki_url}"
  git -C "${heyaki_temp_dir}" fetch --quiet --depth 1 origin "${heyaki_ref}"
  heyaki_fetched_commit=$(git -C "${heyaki_temp_dir}" rev-parse 'FETCH_HEAD^{commit}')
  [[ "${heyaki_fetched_commit}" == "${heyaki_commit}" ]] || \
    fail "${heyaki_name} ref ${heyaki_ref} moved: expected ${heyaki_commit}, got ${heyaki_fetched_commit}"
  git -C "${heyaki_temp_dir}" checkout --quiet --detach "${heyaki_commit}"

  if [[ "${heyaki_recursive}" == "true" ]]; then
    git -C "${heyaki_temp_dir}" submodule update --init --recursive --depth 1
  fi

  [[ "$(git -C "${heyaki_temp_dir}" rev-parse HEAD)" == "${heyaki_commit}" ]] || \
    fail "${heyaki_name} ref ${heyaki_ref} did not resolve to locked commit ${heyaki_commit}"

  mv -- "${heyaki_temp_dir}" "${heyaki_destination}"
  heyaki_temp_dirs=()
}

sync_existing_repository() {
  local heyaki_name=$1
  local heyaki_url=$2
  local heyaki_ref=$3
  local heyaki_commit=$4
  local heyaki_recursive=$5
  local heyaki_destination="${heyaki_third_party_dir}/${heyaki_name}"
  local heyaki_actual_url
  local heyaki_actual_commit
  local heyaki_fetched_commit

  [[ -d "${heyaki_destination}/.git" ]] || \
    fail "${heyaki_destination} exists but is not a Git repository"
  heyaki_actual_url=$(git -C "${heyaki_destination}" remote get-url origin)
  [[ "${heyaki_actual_url}" == "${heyaki_url}" ]] || \
    fail "${heyaki_name} origin mismatch: expected ${heyaki_url}, got ${heyaki_actual_url}"
  ensure_clean_repository "${heyaki_name}" "${heyaki_destination}"

  heyaki_actual_commit=$(git -C "${heyaki_destination}" rev-parse HEAD)
  if [[ "${heyaki_actual_commit}" != "${heyaki_commit}" ]]; then
    log "updating ${heyaki_name} to ${heyaki_ref}"
    git -C "${heyaki_destination}" fetch --quiet --depth 1 origin "${heyaki_ref}"
    heyaki_fetched_commit=$(git -C "${heyaki_destination}" rev-parse 'FETCH_HEAD^{commit}')
    [[ "${heyaki_fetched_commit}" == "${heyaki_commit}" ]] || \
      fail "${heyaki_name} ref ${heyaki_ref} moved: expected ${heyaki_commit}, got ${heyaki_fetched_commit}"
    git -C "${heyaki_destination}" checkout --quiet --detach "${heyaki_commit}"
  else
    log "${heyaki_name} already pinned @ ${heyaki_commit:0:12}"
  fi

  if [[ "${heyaki_recursive}" == "true" ]]; then
    git -C "${heyaki_destination}" submodule sync --recursive
    git -C "${heyaki_destination}" submodule update --init --recursive --depth 1
  fi
}

mkdir -p -- "${heyaki_third_party_dir}"

heyaki_selected_count=0
for heyaki_record in "${heyaki_dependency_records[@]}"; do
  IFS='|' read -r heyaki_name heyaki_url heyaki_ref heyaki_commit heyaki_recursive heyaki_group <<< "${heyaki_record}"
  is_selected "${heyaki_name}" "${heyaki_group}" || continue
  ((heyaki_selected_count += 1))

  if [[ "${heyaki_check_only}" == "true" ]]; then
    verify_dependency "${heyaki_name}" "${heyaki_url}" "${heyaki_commit}" "${heyaki_recursive}"
    continue
  fi

  heyaki_destination="${heyaki_third_party_dir}/${heyaki_name}"
  if [[ -e "${heyaki_destination}" ]]; then
    sync_existing_repository "${heyaki_name}" "${heyaki_url}" "${heyaki_ref}" "${heyaki_commit}" "${heyaki_recursive}"
  else
    initialize_repository "${heyaki_name}" "${heyaki_url}" "${heyaki_ref}" "${heyaki_commit}" "${heyaki_recursive}"
  fi

  verify_dependency "${heyaki_name}" "${heyaki_url}" "${heyaki_commit}" "${heyaki_recursive}"
done

((heyaki_selected_count > 0)) || fail "no dependencies selected"

if [[ "${heyaki_check_only}" == "true" ]]; then
  log "all selected dependencies are valid"
else
  log "all selected dependencies are ready"
fi
