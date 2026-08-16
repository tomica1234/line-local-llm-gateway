#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
server_bin="${PERSONAL_AGENT_LLAMA_SERVER_BIN:-llama-server}"
model_path="${PERSONAL_AGENT_QWEN_MODEL_PATH:-$project_dir/models/Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf}"
expected_sha256="${PERSONAL_AGENT_QWEN_MODEL_SHA256:-707a55a8a4397ecde44de0c499d3e68c1ad1d240d1da65826b4949d1043f4450}"
context_size="${PERSONAL_AGENT_QWEN_CONTEXT_SIZE:-32768}"
verify_sha256="${PERSONAL_AGENT_QWEN_VERIFY_SHA256:-true}"
model_api_key="${PERSONAL_AGENT_MODEL_API_KEY:-}"

if [[ "$model_path" != /* ]]; then
  model_path="$project_dir/$model_path"
fi

if ! command -v "$server_bin" >/dev/null 2>&1 && [[ ! -x "$server_bin" ]]; then
  echo "llama.cpp server not found: $server_bin" >&2
  echo "Set PERSONAL_AGENT_LLAMA_SERVER_BIN to the CUDA-enabled llama-server path." >&2
  exit 1
fi

if [[ ! -f "$model_path" ]]; then
  echo "Qwen model not found: $model_path" >&2
  echo "Download unsloth/Qwen3.6-35B-A3B-GGUF UD-Q4_K_XL before starting." >&2
  exit 1
fi

if [[ ! "$context_size" =~ ^[1-9][0-9]*$ ]]; then
  echo "PERSONAL_AGENT_QWEN_CONTEXT_SIZE must be a positive integer." >&2
  exit 1
fi

if (( ${#model_api_key} < 32 )); then
  echo "PERSONAL_AGENT_MODEL_API_KEY must contain at least 32 characters." >&2
  exit 1
fi

if [[ "$verify_sha256" == "true" || "$verify_sha256" == "1" ]]; then
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum is required while PERSONAL_AGENT_QWEN_VERIFY_SHA256 is enabled." >&2
    exit 1
  fi
  actual_sha256="$(sha256sum "$model_path" | awk '{print $1}')"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "Qwen model SHA-256 mismatch." >&2
    echo "Expected: $expected_sha256" >&2
    echo "Actual:   $actual_sha256" >&2
    exit 1
  fi
fi

# llama-server reads this without exposing the shared token in the process command line.
export LLAMA_API_KEY="$model_api_key"

exec "$server_bin" \
  --model "$model_path" \
  --alias Qwen3.6-35B-A3B \
  --host 127.0.0.1 \
  --port 8000 \
  --ctx-size "$context_size" \
  --parallel 1 \
  --n-gpu-layers all \
  --n-cpu-moe 40 \
  --flash-attn auto \
  --jinja \
  --metrics \
  --no-webui \
  --no-slots \
  --cors-origins localhost \
  --no-cors-credentials
