#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
model_name="Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf"
model_dir="${PERSONAL_AGENT_QWEN_MODEL_DIR:-$project_dir/models}"
model_path="$model_dir/$model_name"
partial_path="$model_path.part"
expected_sha256="707a55a8a4397ecde44de0c499d3e68c1ad1d240d1da65826b4949d1043f4450" # pragma: allowlist secret
download_url="https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF/resolve/main/$model_name?download=true"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to download the model." >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required to verify the model." >&2
  exit 1
fi

mkdir -p "$model_dir"
if [[ -f "$model_path" ]]; then
  actual_sha256="$(sha256sum "$model_path" | awk '{print $1}')"
  if [[ "$actual_sha256" == "$expected_sha256" ]]; then
    echo "Model is already present and verified: $model_path"
    exit 0
  fi
  echo "Existing model failed SHA-256 verification: $model_path" >&2
  echo "Move it aside before retrying; it will not be overwritten." >&2
  exit 1
fi

echo "Downloading the 22.4 GB Unsloth UD-Q4_K_XL artifact."
echo "An interrupted download resumes from: $partial_path"
curl --fail --location --retry 5 --retry-all-errors --continue-at - \
  --output "$partial_path" "$download_url"

actual_sha256="$(sha256sum "$partial_path" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "Downloaded model SHA-256 mismatch; partial file was kept for inspection." >&2
  echo "Expected: $expected_sha256" >&2
  echo "Actual:   $actual_sha256" >&2
  exit 1
fi

mv -- "$partial_path" "$model_path"
echo "Model downloaded and verified: $model_path"
