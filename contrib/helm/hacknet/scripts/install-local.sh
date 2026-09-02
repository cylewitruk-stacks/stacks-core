#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = --help ]; then
  cat <<'EOF'
usage: install-local.sh

Build images first with scripts/build-local.sh. Environment overrides:
  HACKNET_NAMESPACE, HACKNET_RELEASE, HACKNET_OPERATOR_IMAGE,
  HACKNET_RUN_OPERATOR_IMAGE, HACKNET_BURNCHAIN_CLOCK_IMAGE,
  HACKNET_IO_PRESSURE_IMAGE,
  HACKNET_KIND_IMAGE_LOAD (auto, require, or disabled),
  HACKNET_CHAOS_NAMESPACE_INJECTION (enabled or disabled),
  HACKNET_FORCE_CRD_CONFLICTS,
  HACKNET_FORCE_CONFLICTS, HACKNET_RECOVER_FAILED_RELEASE.
EOF
  exit 0
fi
[ "$#" -eq 0 ] || { echo "unknown install-local argument: $1" >&2; exit 2; }

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
namespace="${HACKNET_NAMESPACE:-hacknet-system}"
release="${HACKNET_RELEASE:-hacknet}"
operator_image="${HACKNET_OPERATOR_IMAGE:-stacks-hacknet-operator:dev}"
run_operator_image="${HACKNET_RUN_OPERATOR_IMAGE:-stacks-hacknet-run-operator:dev}"
burnchain_clock_image="${HACKNET_BURNCHAIN_CLOCK_IMAGE:-stacks-hacknet-burnchain-clock:dev}"
io_pressure_image="${HACKNET_IO_PRESSURE_IMAGE:-stacks-hacknet-io-pressure:dev}"
kind_image_load="${HACKNET_KIND_IMAGE_LOAD:-auto}"
chaos_namespace_injection="${HACKNET_CHAOS_NAMESPACE_INJECTION:-enabled}"
case "${kind_image_load}" in
  auto|require|disabled) ;;
  *) echo 'HACKNET_KIND_IMAGE_LOAD must be auto, require, or disabled' >&2; exit 2 ;;
esac
case "${chaos_namespace_injection}" in
  enabled|disabled) ;;
  *) echo 'HACKNET_CHAOS_NAMESPACE_INJECTION must be enabled or disabled' >&2; exit 2 ;;
esac

helm_version="$(helm version --template '{{.Version}}')" || {
  echo 'could not determine Helm version' >&2
  exit 1
}
if [[ ! "${helm_version}" =~ ^v?([0-9]+)\. ]]; then
  echo "could not parse Helm version: ${helm_version}" >&2
  exit 1
fi
helm_major="${BASH_REMATCH[1]}"
case "${helm_major}" in
  3) helm_failure_args=(--atomic) ;;
  4) helm_failure_args=(--rollback-on-failure) ;;
  *) echo "unsupported Helm major version: ${helm_major}; expected 3 or 4" >&2; exit 1 ;;
esac

operator_id="$(docker image inspect --format '{{.Id}}' "${operator_image}")"
run_operator_id="$(docker image inspect --format '{{.Id}}' "${run_operator_image}")"
burnchain_clock_id="$(docker image inspect --format '{{.Id}}' "${burnchain_clock_image}")"
io_pressure_id="$(docker image inspect --format '{{.Id}}' "${io_pressure_image}")"
[[ "${operator_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "could not resolve immutable local image ID for ${operator_image}" >&2
  exit 1
}
[[ "${run_operator_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "could not resolve immutable local image ID for ${run_operator_image}" >&2
  exit 1
}
[[ "${burnchain_clock_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "could not resolve immutable local image ID for ${burnchain_clock_image}" >&2
  exit 1
}
[[ "${io_pressure_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "could not resolve immutable local image ID for ${io_pressure_image}" >&2
  exit 1
}

# A rollout annotation changes the Pod template but does not defeat
# imagePullPolicy=IfNotPresent: kind can reuse an older cached `:dev` image.
# Give each immutable local build its own tag and deploy that exact tag.
[[ "${operator_image}" != *@* && "${operator_image}" == *:* ]] \
  || { echo "operator image must be a locally tagged reference" >&2; exit 2; }
[[ "${run_operator_image}" != *@* && "${run_operator_image}" == *:* ]] \
  || { echo "run operator image must be a locally tagged reference" >&2; exit 2; }
[[ "${burnchain_clock_image}" != *@* && "${burnchain_clock_image}" == *:* ]] \
  || { echo "burnchain clock image must be a locally tagged reference" >&2; exit 2; }
[[ "${io_pressure_image}" != *@* && "${io_pressure_image}" == *:* ]] \
  || { echo "I/O-pressure image must be a locally tagged reference" >&2; exit 2; }
operator_repository="${operator_image%:*}"
run_operator_repository="${run_operator_image%:*}"
burnchain_clock_repository="${burnchain_clock_image%:*}"
io_pressure_repository="${io_pressure_image%:*}"
operator_tag="local-${operator_id#sha256:}"
run_operator_tag="local-${run_operator_id#sha256:}"
burnchain_clock_tag="local-${burnchain_clock_id#sha256:}"
io_pressure_tag="local-${io_pressure_id#sha256:}"
operator_tag="${operator_tag:0:22}"
run_operator_tag="${run_operator_tag:0:22}"
burnchain_clock_tag="${burnchain_clock_tag:0:22}"
io_pressure_tag="${io_pressure_tag:0:22}"
docker image tag "${operator_image}" "${operator_repository}:${operator_tag}"
docker image tag "${run_operator_image}" "${run_operator_repository}:${run_operator_tag}"
docker image tag "${burnchain_clock_image}" "${burnchain_clock_repository}:${burnchain_clock_tag}"
docker image tag "${io_pressure_image}" "${io_pressure_repository}:${io_pressure_tag}"

release_status="$(helm status "${release}" -n "${namespace}" -o json 2>/dev/null \
  | jq -r '.info.status // empty' || true)"
if [ "${release_status}" = failed ] && [ "${HACKNET_RECOVER_FAILED_RELEASE:-0}" != 1 ]; then
  cat >&2 <<EOF
Helm release ${namespace}/${release} is failed. Inspect it before retrying:
  helm status ${release} -n ${namespace}
Set HACKNET_RECOVER_FAILED_RELEASE=1 only after the cause and live resources are understood.
EOF
  exit 1
fi

case "${kind_image_load}" in
  auto|require)
    "${chart_dir}/scripts/load-kind-images.sh" "--mode=${kind_image_load}" \
      "${operator_repository}:${operator_tag}" \
      "${run_operator_repository}:${run_operator_tag}" \
      "${burnchain_clock_repository}:${burnchain_clock_tag}" \
      "${io_pressure_repository}:${io_pressure_tag}"
    ;;
  disabled) ;;
esac

# Chaos Mesh namespace filtering is enabled in the supported local profile.
# Without this annotation mutations are admitted but cannot select actor Pods.
if ! kubectl get namespace "${namespace}" >/dev/null 2>&1; then
  kubectl create namespace "${namespace}"
fi
if [ "${chaos_namespace_injection}" = enabled ]; then
  kubectl annotate namespace "${namespace}" chaos-mesh.org/inject=enabled --overwrite
fi

# Helm deliberately does not add or upgrade CRDs from chart crds/ on an
# existing release. Keep API lifecycle explicit and wait for discovery before
# starting a controller that depends on the resources.
crd_apply=(apply --server-side --field-manager=hacknet-local-installer)
if [ "${HACKNET_FORCE_CRD_CONFLICTS:-0}" = 1 ]; then
  echo "WARNING: installer will explicitly reclaim conflicting CRD schema fields" >&2
  crd_apply+=(--force-conflicts)
fi
for crd in \
  testing.stacks.org_stacksnetworks.yaml \
  testing.stacks.org_burnchainpolicies.yaml \
  testing.stacks.org_faultcampaigns.yaml \
  testing.stacks.org_attacknetruns.yaml; do
  kubectl "${crd_apply[@]}" -f "${chart_dir}/crds/${crd}"
done
kubectl wait --for=condition=Established --timeout=60s \
  crd/stacksnetworks.testing.stacks.org \
  crd/burnchainpolicies.testing.stacks.org \
  crd/faultcampaigns.testing.stacks.org \
  crd/attacknetruns.testing.stacks.org

helm_args=(
  upgrade --install "${release}" "${chart_dir}"
  --namespace "${namespace}"
  --create-namespace
  --wait
  "${helm_failure_args[@]}"
  --set-string "operator.podAnnotations.attacknet-build=${operator_id}"
  --set-string "runOperator.podAnnotations.attacknet-build=${run_operator_id}"
  --set-string "operator.image.repository=${operator_repository}"
  --set-string "operator.image.tag=${operator_tag}"
  --set-string "runOperator.image.repository=${run_operator_repository}"
  --set-string "runOperator.image.tag=${run_operator_tag}"
  --set-string "burnchainClock.image.repository=${burnchain_clock_repository}"
  --set-string "burnchainClock.image.tag=${burnchain_clock_tag}"
  --set-string "runOperator.ioPressureImage.repository=${io_pressure_repository}"
  --set-string "runOperator.ioPressureImage.tag=${io_pressure_tag}"
)
if [ "${HACKNET_FORCE_CONFLICTS:-0}" = 1 ]; then
  echo "WARNING: Helm will explicitly reclaim conflicting managed fields" >&2
  helm_args+=(--force-conflicts)
fi
helm "${helm_args[@]}"
