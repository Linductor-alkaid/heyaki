#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# M9-14 secret scan over the repository's full git history.
#
#   1. Fetch (or reuse a cached) gitleaks build pinned by digest in
#      deploy/security/secret-scan.lock; the tarball checksum is verified
#      before the binary runs.
#   2. Positive control: a planted AWS-style key in a scratch directory must
#      be detected (proves the rule set can fire before reporting an
#      all-clear).
#   3. Real scan: gitleaks over the whole git history with the reviewed
#      allowlist in deploy/security/gitleaks.toml; any finding fails.
#
# Gated by HEYAKI_REQUIRE_SECRET_SCAN=1 because step 1 may need the network;
# SKIP 77 otherwise. Pass --gitleaks PATH to use a preinstalled binary
# (still version-checked against the pin).

repo_dir=
gitleaks_bin=${HEYAKI_GITLEAKS_BIN:-}
cache_dir=${HEYAKI_SECRET_SCAN_CACHE:-${TMPDIR:-/tmp}/heyaki-secret-scan}

usage() {
  cat <<USAGE_EOF
Usage: $0 --repo PATH [--gitleaks PATH] [--cache-dir PATH]
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --repo) repo_dir=${2:?missing repo value}; shift 2;;
    --gitleaks) gitleaks_bin=${2:?missing gitleaks value}; shift 2;;
    --cache-dir) cache_dir=${2:?missing cache-dir value}; shift 2;;
    *) usage >&2; exit 2;;
  esac
done
[[ -n ${repo_dir} ]] || { usage >&2; exit 2; }
repo_dir=$(CDPATH= cd -- "${repo_dir}" && pwd)
lock_file="${repo_dir}/deploy/security/secret-scan.lock"
config_file="${repo_dir}/deploy/security/gitleaks.toml"
for required in "${lock_file}" "${config_file}"; do
  [[ -f ${required} ]] || { printf 'FAIL: missing %s\n' "${required}" >&2; exit 2; }
done

if [[ -z ${gitleaks_bin} ]]; then
  [[ "${HEYAKI_REQUIRE_SECRET_SCAN:-0}" == "1" ]] || {
    printf 'SKIP: set HEYAKI_REQUIRE_SECRET_SCAN=1 to run the secret scan\n'
    exit 77
  }
  pin_line=$(grep -v '^#' "${lock_file}" | grep -v '^$' | head -1)
  [[ $(grep -v '^#' "${lock_file}" | grep -vc '^$') -eq 1 ]] || {
    printf 'FAIL: secret-scan.lock must pin exactly one tool\n' >&2
    exit 2
  }
  IFS='|' read -r tool_name tool_version tool_url tool_sha256 <<<"${pin_line}"
  [[ ${tool_name} == "gitleaks" ]] || { printf 'FAIL: unexpected tool %s\n' "${tool_name}" >&2; exit 2; }
  mkdir -p "${cache_dir}"
  tarball="${cache_dir}/gitleaks-${tool_version}.tar.gz"
  if [[ ! -f ${tarball} ]]; then
    curl -fsSL --retry 3 --retry-delay 3 --max-time 300 -o "${tarball}.part" "${tool_url}"
    mv "${tarball}.part" "${tarball}"
  fi
  actual_sha256=$(sha256sum "${tarball}" | awk '{print $1}')
  [[ ${actual_sha256} == "${tool_sha256}" ]] || {
    printf 'FAIL: gitleaks tarball digest mismatch: got %s, pinned %s\n' \
      "${actual_sha256}" "${tool_sha256}" >&2
    exit 2
  }
  extract_dir="${cache_dir}/gitleaks-${tool_version}"
  if [[ ! -x ${extract_dir}/gitleaks ]]; then
    rm -rf "${extract_dir}"
    mkdir -p "${extract_dir}"
    tar -xzf "${tarball}" -C "${extract_dir}" gitleaks
  fi
  gitleaks_bin="${extract_dir}/gitleaks"
else
  # A preinstalled binary must still match the pinned version.
  pin_line=$(grep -v '^#' "${lock_file}" | grep -v '^$' | head -1)
  IFS='|' read -r tool_name tool_version _url _sha256 <<<"${pin_line}"
fi
[[ -x ${gitleaks_bin} ]] || { printf 'FAIL: gitleaks binary unavailable\n' >&2; exit 2; }
version_output=$("${gitleaks_bin}" version)
[[ ${version_output} == "${tool_version}" ]] || {
  printf 'FAIL: gitleaks version %s does not match pin %s\n' \
    "${version_output}" "${tool_version}" >&2
  exit 2
}

# Positive control: the default rule set must detect a planted credential
# before this scan is allowed to report an all-clear.
control_dir=$(mktemp -d "${TMPDIR:-/tmp}/heyaki-secret-control.XXXXXX")
trap 'rm -rf "${control_dir}"' EXIT
printf 'aws_access_key_id = AKIAIMNOJVGFDXXXE4OA\n' >"${control_dir}/creds.txt"
if "${gitleaks_bin}" dir "${control_dir}" --no-banner --exit-code 1 \
    --log-level error >/dev/null 2>&1; then
  printf 'FAIL: planted credential was not detected; scanner cannot be trusted\n' >&2
  exit 2
fi
printf 'SECRET_SCAN_STEP_OK: control credential detected\n'

# Real scan over the full history with the reviewed allowlist.
report="${cache_dir}/gitleaks-report.json"
"${gitleaks_bin}" git "${repo_dir}" \
  --config "${config_file}" \
  --no-banner --exit-code 1 --log-level error \
  --report-path "${report}"
findings=$(jq 'length' "${report}" 2>/dev/null || echo "parse-error")
printf 'SECRET_SCAN_OK: %s findings over full git history (report: %s)\n' \
  "${findings}" "${report}"
