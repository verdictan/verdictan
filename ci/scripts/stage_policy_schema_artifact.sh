#!/usr/bin/env bash
# Stage the policy schema as a release artifact.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "${root}/dist-artifacts"
cp "${root}/schema/policy-configuration.schema.json" \
  "${root}/dist-artifacts/policy-configuration.schema.json"
