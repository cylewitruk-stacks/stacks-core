#!/usr/bin/env bash
set -euo pipefail

namespace="${KUBE_NAMESPACE:-hacknet-system}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
environment_lock="${ATTACKNET_ENVIRONMENT_LOCK_NAME:-attacknet-environment-lease}"
mutation_lock="${ATTACKNET_MUTATION_LOCK_NAME:-attacknet-mutation-lease}"
default_owner="${ATTACKNET_LOCK_OWNER:-${ATTACKNET_AGENT_ID:-${USER:-unknown}}:$$}"

usage() {
  cat >&2 <<'EOF'
usage:
  environment-lock.sh claim NETWORK [OWNER] [PURPOSE]
  environment-lock.sh release NETWORK
  environment-lock.sh status
  environment-lock.sh environment-assert NETWORK
  environment-lock.sh mutation-acquire NETWORK [OWNER] [PURPOSE]
  environment-lock.sh mutation-release NETWORK TOKEN
  environment-lock.sh assert NETWORK TOKEN
  environment-lock.sh run NETWORK [OWNER] [PURPOSE] -- COMMAND [ARG...]

The environment lease persists for the lifetime of one active network. The
mutation lease serializes applies, cadence changes, fault injection and
teardown. Read-only inspection does not require the mutation lease.
EOF
}

field() {
  local name="$1" key="$2"
  "${kubectl_bin}" -n "${namespace}" get configmap "${name}" \
    -o "jsonpath={.data.${key}}" 2>/dev/null
}

describe_holder() {
  local name="$1" network owner purpose acquired
  network="$(field "${name}" network || true)"
  owner="$(field "${name}" owner || true)"
  purpose="$(field "${name}" purpose || true)"
  acquired="$(field "${name}" acquiredAt || true)"
  printf 'network=%s owner=%s purpose=%s acquiredAt=%s' \
    "${network:-unknown}" "${owner:-unknown}" "${purpose:-unknown}" "${acquired:-unknown}"
}

claim_environment() {
  local network="$1" owner="${2:-${default_owner}}" purpose="${3:-environment-run}"
  local held existing
  existing="$(field "${environment_lock}" network || true)"
  if [ -n "${existing}" ]; then
    if [ "${existing}" = "${network}" ]; then
      echo "Environment lease already belongs to ${network}: $(describe_holder "${environment_lock}")" >&2
      return 0
    fi
    echo "Refusing a second active attacknet; lease held by $(describe_holder "${environment_lock}")" >&2
    return 1
  fi
  if ! "${kubectl_bin}" -n "${namespace}" create configmap "${environment_lock}" \
    "--from-literal=network=${network}" "--from-literal=owner=${owner}" \
    "--from-literal=purpose=${purpose}" "--from-literal=acquiredAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >/dev/null 2>&1; then
    held="$(field "${environment_lock}" network || true)"
    [ "${held}" = "${network}" ] || {
      echo "Lost environment-lease race: $(describe_holder "${environment_lock}")" >&2
      return 1
    }
  fi
  echo "Environment lease: ${network} (${owner}; ${purpose})" >&2
}

release_environment() {
  local network="$1" held
  held="$(field "${environment_lock}" network || true)"
  [ -z "${held}" ] && return 0
  [ "${held}" = "${network}" ] || {
    echo "Will not release environment ${held} for requester ${network}" >&2
    return 1
  }
  "${kubectl_bin}" -n "${namespace}" delete configmap "${environment_lock}" \
    --ignore-not-found >/dev/null
}

assert_environment() {
  local network="$1" held
  held="$(field "${environment_lock}" network || true)"
  [ "${held}" = "${network}" ] || {
    echo "Active environment lease is not ${network}: $(describe_holder "${environment_lock}")" >&2
    return 1
  }
}

acquire_mutation() {
  local network="$1" owner="${2:-${default_owner}}" purpose="${3:-mutation}"
  local timeout="${ATTACKNET_LOCK_WAIT_SECONDS:-900}" deadline token waited=false
  [[ "${timeout}" =~ ^[0-9]+$ ]] || {
    echo 'ATTACKNET_LOCK_WAIT_SECONDS must be a non-negative integer' >&2
    return 2
  }
  assert_environment "${network}"
  token="$(node -e 'console.log(require("node:crypto").randomUUID())')"
  deadline=$((SECONDS + timeout))
  while ! "${kubectl_bin}" -n "${namespace}" create configmap "${mutation_lock}" \
    "--from-literal=network=${network}" "--from-literal=owner=${owner}" \
    "--from-literal=purpose=${purpose}" "--from-literal=token=${token}" \
    "--from-literal=acquiredAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1; do
    if [ "${waited}" = false ]; then
      echo "Waiting for attacknet mutation lease: $(describe_holder "${mutation_lock}")" >&2
      waited=true
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "Timed out waiting for mutation lease after ${timeout}s: $(describe_holder "${mutation_lock}")" >&2
      return 1
    fi
    sleep 2
  done
  printf '%s\n' "${token}"
}

release_mutation() {
  local network="$1" token="$2" held_network held_token
  held_network="$(field "${mutation_lock}" network || true)"
  held_token="$(field "${mutation_lock}" token || true)"
  [ -z "${held_token}" ] && return 0
  if [ "${held_network}" != "${network}" ] || [ "${held_token}" != "${token}" ]; then
    echo "Will not release another mutation holder: $(describe_holder "${mutation_lock}")" >&2
    return 1
  fi
  "${kubectl_bin}" -n "${namespace}" delete configmap "${mutation_lock}" \
    --ignore-not-found >/dev/null
}

assert_mutation() {
  local network="$1" token="$2"
  assert_environment "${network}"
  [ "$(field "${mutation_lock}" network || true)" = "${network}" ] \
    && [ "$(field "${mutation_lock}" token || true)" = "${token}" ] || {
      echo "Mutation lease mismatch: $(describe_holder "${mutation_lock}")" >&2
      return 1
    }
}

status() {
  local env_network mutation_network
  env_network="$(field "${environment_lock}" network || true)"
  mutation_network="$(field "${mutation_lock}" network || true)"
  ENV_NETWORK="${env_network}" ENV_HOLDER="$(describe_holder "${environment_lock}")" \
    MUTATION_NETWORK="${mutation_network}" MUTATION_HOLDER="$(describe_holder "${mutation_lock}")" \
    node -e '
      console.log(JSON.stringify({
        environment: process.env.ENV_NETWORK ? {active:true, description:process.env.ENV_HOLDER} : {active:false},
        mutation: process.env.MUTATION_NETWORK ? {active:true, description:process.env.MUTATION_HOLDER} : {active:false},
      }, null, 2));
    '
}

case "${1:-}" in
  claim) claim_environment "${2:?network required}" "${3:-}" "${4:-}" ;;
  release) release_environment "${2:?network required}" ;;
  status) status ;;
  environment-assert) assert_environment "${2:?network required}" ;;
  mutation-acquire) acquire_mutation "${2:?network required}" "${3:-}" "${4:-}" ;;
  mutation-release) release_mutation "${2:?network required}" "${3:?token required}" ;;
  assert) assert_mutation "${2:?network required}" "${3:?token required}" ;;
  run)
    network="${2:?network required}"; owner="${3:-${default_owner}}"; purpose="${4:-mutation}"
    [ "${5:-}" = -- ] || { usage; exit 2; }
    shift 5
    token="$(acquire_mutation "${network}" "${owner}" "${purpose}")"
    trap 'release_mutation "${network}" "${token}"' EXIT INT TERM
    ATTACKNET_MUTATION_TOKEN="${token}" ATTACKNET_ENVIRONMENT_NETWORK="${network}" "$@"
    ;;
  *) usage; exit 2 ;;
esac
