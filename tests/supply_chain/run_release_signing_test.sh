#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# M9-14 release signing roundtrip. Assembles a miniature release bundle from
# real build artifacts (relay binary + SPDX SBOM + license manifest), then
# exercises the full signing procedure and every tamper direction:
#
#   keygen -> manifest -> sign -> verify + check
#   tampered artifact    -> check fails
#   tampered manifest    -> verify fails
#   wrong public key     -> verify fails
#   extra unlisted file  -> check fails
#   missing file         -> check fails
#   restored bundle      -> verify + check pass again
#
# The key material here is ephemeral test material generated per run; the
# production procedure (offline key, published key id) lives in
# docs/operations/release-signing.md.

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

sign_bin=${HEYAKI_RELEASE_SIGN_BIN:-}
artifact_bin=${HEYAKI_RELEASE_ARTIFACT_BIN:-}
sbom_file=${HEYAKI_RELEASE_SBOM_FILE:-}
licenses_file=${HEYAKI_RELEASE_LICENSES_FILE:-}
work_dir=${HEYAKI_RELEASE_WORK_DIR:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --sign-bin PATH --artifact-bin PATH --sbom PATH --licenses PATH
       [--work-dir PATH]
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --sign-bin) sign_bin=${2:?missing sign-bin value}; shift 2;;
    --artifact-bin) artifact_bin=${2:?missing artifact-bin value}; shift 2;;
    --sbom) sbom_file=${2:?missing sbom value}; shift 2;;
    --licenses) licenses_file=${2:?missing licenses value}; shift 2;;
    --work-dir) work_dir=${2:?missing work-dir value}; shift 2;;
    *) usage >&2; exit 2;;
  esac
done
[[ -n ${sign_bin} && -n ${artifact_bin} && -n ${sbom_file} && -n ${licenses_file} ]] || {
  usage >&2
  exit 2
}
[[ -x ${sign_bin} ]] || { printf 'sign tool missing: %s\n' "${sign_bin}" >&2; exit 2; }
[[ -f ${artifact_bin} && -f ${sbom_file} && -f ${licenses_file} ]] || {
  printf 'artifact/sbom/licenses inputs must exist\n' >&2
  exit 2
}
if [[ -z ${work_dir} ]]; then
  work_dir=$(mktemp -d "${TMPDIR:-/tmp}/heyaki-release-signing.XXXXXX")
else
  mkdir -p "${work_dir}"
fi
work_dir=$(CDPATH= cd -- "${work_dir}" && pwd)
bundle_dir="${work_dir}/bundle"

expect_ok() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'SIGNING_STEP_OK: %s\n' "${label}"
  else
    printf 'SIGNING_FAIL: expected success: %s\n' "${label}" >&2
    exit 1
  fi
}

expect_reject() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'SIGNING_FAIL: expected rejection: %s\n' "${label}" >&2
    exit 1
  else
    printf 'SIGNING_STEP_OK: rejected %s\n' "${label}"
  fi
}

rm -rf "${bundle_dir}"
mkdir -p "${bundle_dir}/bin"
cp "${artifact_bin}" "${bundle_dir}/bin/heyaki-relay"
cp "${sbom_file}" "${bundle_dir}/heyaki.spdx"
cp "${licenses_file}" "${bundle_dir}/THIRD_PARTY_LICENSES.md"

# 1. keygen: fresh keypair; secret must be owner-only on POSIX.
"${sign_bin}" keygen "${work_dir}/secret.key" "${work_dir}/public.key" \
  >"${work_dir}/keygen.out"
grep -q '^RELEASE_KEY_ID [0-9a-f]\{16\}$' "${work_dir}/keygen.out" || {
  printf 'SIGNING_FAIL: keygen did not print a key id\n' >&2
  exit 1
}
if [[ $(uname -s) == "Linux" ]]; then
  secret_mode=$(stat -c '%a' "${work_dir}/secret.key")
  [[ ${secret_mode} == "600" ]] || {
    printf 'SIGNING_FAIL: secret key mode is %s, expected 600\n' "${secret_mode}" >&2
    exit 1
  }
fi
printf 'SIGNING_STEP_OK: keygen\n'

# 2. manifest: deterministic shape — header, exact file count, sorted paths.
expect_ok "manifest" "${sign_bin}" manifest "${bundle_dir}" "${work_dir}/release.manifest"
head -n 1 "${work_dir}/release.manifest" | grep -qx 'heyaki-release-manifest/1' || {
  printf 'SIGNING_FAIL: manifest header wrong\n' >&2
  exit 1
}
manifest_lines=$(wc -l <"${work_dir}/release.manifest")
[[ ${manifest_lines} -eq 5 ]] || {
  printf 'SIGNING_FAIL: manifest has %s lines, expected 5 (header+count+3 files)\n' \
    "${manifest_lines}" >&2
  exit 1
}
awk 'NR > 2 { print $3 }' "${work_dir}/release.manifest" >"${work_dir}/listed.paths"
sort -u "${work_dir}/listed.paths" -o "${work_dir}/listed.sorted"
diff -u "${work_dir}/listed.paths" "${work_dir}/listed.sorted" || {
  printf 'SIGNING_FAIL: manifest paths not sorted\n' >&2
  exit 1
}
grep -q '^bin/heyaki-relay$' "${work_dir}/listed.paths" || {
  printf 'SIGNING_FAIL: manifest missing bin/heyaki-relay\n' >&2
  exit 1
}
printf 'SIGNING_STEP_OK: manifest shape\n'

# 3. sign + verify + check happy path.
expect_ok "sign" "${sign_bin}" sign "${work_dir}/release.manifest" "${work_dir}/secret.key"
[[ -f ${work_dir}/release.manifest.sig ]] || {
  printf 'SIGNING_FAIL: signature file missing\n' >&2
  exit 1
}
sig_size=$(wc -c <"${work_dir}/release.manifest.sig")
[[ ${sig_size} -eq 64 ]] || {
  printf 'SIGNING_FAIL: signature is %s bytes, expected 64 (Ed25519)\n' "${sig_size}" >&2
  exit 1
}
expect_ok "verify" "${sign_bin}" verify "${work_dir}/release.manifest" \
  "${work_dir}/public.key" "${work_dir}/release.manifest.sig"
expect_ok "check" "${sign_bin}" check "${work_dir}/release.manifest" "${bundle_dir}"

# 4. tampered artifact -> signature still valid, content check must fail.
cp "${bundle_dir}/heyaki.spdx" "${work_dir}/heyaki.spdx.orig"
printf 'x' >>"${bundle_dir}/heyaki.spdx"
expect_ok "verify-after-tamper" "${sign_bin}" verify "${work_dir}/release.manifest" \
  "${work_dir}/public.key" "${work_dir}/release.manifest.sig"
expect_reject "tampered artifact" "${sign_bin}" check "${work_dir}/release.manifest" \
  "${bundle_dir}"
cp "${work_dir}/heyaki.spdx.orig" "${bundle_dir}/heyaki.spdx"

# 5. tampered manifest -> signature must fail (flip the first digest digit).
cp "${work_dir}/release.manifest" "${work_dir}/release.manifest.orig"
awk '!flipped && /^SHA256 / {
  first = substr($3, 1, 1)
  replacement = (first == "0") ? "1" : "0"
  sub(/^SHA256 ./, "SHA256 " replacement)
  flipped = 1
} { print }' "${work_dir}/release.manifest.orig" >"${work_dir}/release.manifest"
cmp -s "${work_dir}/release.manifest" "${work_dir}/release.manifest.orig" && {
  printf 'SIGNING_FAIL: manifest tamper did not change any byte\n' >&2
  exit 1
}
expect_reject "tampered manifest" "${sign_bin}" verify "${work_dir}/release.manifest" \
  "${work_dir}/public.key" "${work_dir}/release.manifest.sig"
cp "${work_dir}/release.manifest.orig" "${work_dir}/release.manifest"

# 6. wrong public key -> signature must fail.
"${sign_bin}" keygen "${work_dir}/other-secret.key" "${work_dir}/other-public.key" \
  >/dev/null
expect_reject "wrong key" "${sign_bin}" verify "${work_dir}/release.manifest" \
  "${work_dir}/other-public.key" "${work_dir}/release.manifest.sig"

# 7. extra unlisted file and missing file -> content check must fail.
printf 'unlisted\n' >"${bundle_dir}/extra.txt"
expect_reject "extra unlisted file" "${sign_bin}" check "${work_dir}/release.manifest" \
  "${bundle_dir}"
rm "${bundle_dir}/extra.txt"
mv "${bundle_dir}/bin/heyaki-relay" "${work_dir}/heyaki-relay.moved"
expect_reject "missing file" "${sign_bin}" check "${work_dir}/release.manifest" \
  "${bundle_dir}"
mv "${work_dir}/heyaki-relay.moved" "${bundle_dir}/bin/heyaki-relay"

# 8. restored bundle passes end to end.
expect_ok "final verify" "${sign_bin}" verify "${work_dir}/release.manifest" \
  "${work_dir}/public.key" "${work_dir}/release.manifest.sig"
expect_ok "final check" "${sign_bin}" check "${work_dir}/release.manifest" "${bundle_dir}"

printf 'M9_RELEASE_SIGNING_OK\n'
