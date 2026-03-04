#!/usr/bin/env bash
# Build a weekly refreshed container image, validate it for vulnerabilities,
# and emit an SBOM that can be published on GitHub.
set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_NAME="${IMAGE_NAME:-${GITHUB_REPOSITORY:-parsedmarc/parsedmarc}}"
TAG="${TAG:-weekly-$(date +%G-%V)}"
PLATFORM="${PLATFORM:-linux/amd64}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"
SBOM_PATH="${SBOM_PATH:-sbom-${TAG}.spdx.json}"
PUSH_IMAGE="${PUSH_IMAGE:-false}"

FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"

echo "==> Building image ${FULL_IMAGE} for ${PLATFORM}"
build_flags=(--pull --platform "${PLATFORM}" --tag "${FULL_IMAGE}" "${BUILD_CONTEXT}")
if [[ "${PUSH_IMAGE}" == "true" ]]; then
  echo "==> Build will push image to the registry"
  build_flags=(--push "${build_flags[@]}")
else
  echo "==> Build will load image locally (set PUSH_IMAGE=true to push)"
  build_flags=(--load "${build_flags[@]}")
fi

docker buildx build "${build_flags[@]}"

echo "==> Generating SBOM to ${SBOM_PATH}"
docker sbom --output "${SBOM_PATH}" --format spdx-json "${FULL_IMAGE}"

if command -v trivy >/dev/null 2>&1; then
  echo "==> Scanning image for HIGH/CRITICAL vulnerabilities"
  trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "${FULL_IMAGE}"
else
  echo "==> Trivy not found; skipping vulnerability scan. Install Trivy to enable this check." >&2
fi

echo "==> Done. Image: ${FULL_IMAGE}, SBOM: ${SBOM_PATH}"
