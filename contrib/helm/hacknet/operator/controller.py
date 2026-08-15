#!/usr/bin/env python3
"""A small, dependency-free Kubernetes controller for disposable Stacks testnets.

The controller is deliberately namespace-scoped and models one process/failure
domain per StatefulSet.  It uses only the in-cluster Kubernetes HTTP API so the
image has no third-party runtime dependencies.  Pure resource builders are kept
separate from API orchestration to make the security-sensitive desired state
easy to unit test.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import http.server
import json
import logging
import os
import re
import signal
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


GROUP = "testing.stacks.org"
VERSION = "v1alpha1"
PLURAL = "stacksnetworks"
MANAGED_BY = "hacknet-operator"
NETWORK_LABEL = "testing.stacks.org/network"
ACTOR_LABEL = "testing.stacks.org/actor"
ROLE_LABEL = "testing.stacks.org/role"
MANAGED_LABEL = "app.kubernetes.io/managed-by"
APPLY_CONFLICT_ATTEMPTS = 3
CONFIG_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DNS_LABEL_RE = re.compile(r"^[a-z]([-a-z0-9]*[a-z0-9])?$")
PLACEHOLDER_RE = re.compile(r"\$\{(NETWORK|NAMESPACE|ACTOR|SERVICE:([a-z][-a-z0-9]*[a-z0-9]))\}")


class ValidationError(ValueError):
    """The custom resource cannot be translated into safe Kubernetes objects."""


class ApiError(RuntimeError):
    def __init__(self, status: int, method: str, path: str, body: str):
        super().__init__(f"Kubernetes API {method} {path} returned {status}: {body[:500]}")
        self.status = status
        self.method = method
        self.path = path
        self.body = body


class OwnershipError(RuntimeError):
    """A desired resource name is already owned by something else."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def deep_merge(base: dict[str, Any] | None, override: dict[str, Any] | None) -> dict[str, Any]:
    result = copy.deepcopy(base or {})
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def stable_name(network: str, actor: str) -> str:
    candidate = f"{network}-{actor}"
    if len(candidate) <= 63:
        return candidate
    digest = hashlib.sha256(candidate.encode()).hexdigest()[:8]
    return f"{candidate[:54].rstrip('-')}-{digest}"


def managed_labels(network: str, actor: dict[str, Any]) -> dict[str, str]:
    labels = dict(actor.get("labels") or {})
    labels.update(
        {
            "app.kubernetes.io/name": "stacks-hacknet-actor",
            "app.kubernetes.io/instance": network,
            MANAGED_LABEL: MANAGED_BY,
            NETWORK_LABEL: network,
            ACTOR_LABEL: actor["name"],
            ROLE_LABEL: actor["role"],
        }
    )
    return labels


def owner_reference(network: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = network["metadata"]
    return [
        {
            "apiVersion": f"{GROUP}/{VERSION}",
            "kind": "StacksNetwork",
            "name": metadata["name"],
            "uid": metadata["uid"],
            "controller": True,
        }
    ]


def role_ports(role: str) -> list[dict[str, Any]]:
    if role == "signer":
        return [
            {"name": "events", "containerPort": 30000},
            {"name": "metrics", "containerPort": 31000},
        ]
    if role == "burnchain":
        return [
            {"name": "rpc", "containerPort": 18443},
            {"name": "p2p", "containerPort": 18444},
        ]
    if role in {"miner", "companion", "follower", "adversary"}:
        return [
            {"name": "rpc", "containerPort": 20443},
            {"name": "p2p", "containerPort": 20444},
            {"name": "metrics", "containerPort": 20446},
        ]
    return []


def config_key(actor: dict[str, Any]) -> str:
    config = actor.get("config") or {}
    if config.get("key"):
        return config["key"]
    return "signer.toml" if actor["role"] == "signer" else "Config.toml"


def config_mount_path(actor: dict[str, Any]) -> str:
    return (actor.get("config") or {}).get("mountPath", "/etc/stacks")


def actor_image(spec: dict[str, Any], actor: dict[str, Any]) -> str:
    if actor.get("image"):
        return actor["image"]
    defaults = spec.get("defaults") or {}
    role = actor["role"]
    if role == "signer":
        return defaults.get("signerImage", "")
    if role == "burnchain":
        return defaults.get("burnchainImage", "bitcoin/bitcoin:25.2")
    return defaults.get("nodeImage", "")


def actor_command(actor: dict[str, Any]) -> tuple[list[str] | None, list[str] | None]:
    if "command" in actor or "args" in actor:
        return actor.get("command"), actor.get("args")
    key = config_key(actor)
    path = f"{config_mount_path(actor).rstrip('/')}/{key}"
    if actor["role"] == "signer":
        return ["stacks-signer"], ["run", "--config", path]
    if actor["role"] in {"miner", "companion", "follower", "adversary"}:
        return ["stacks-node"], ["start", "--config", path]
    return None, None


def storage_settings(spec: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
    defaults = {
        "enabled": True,
        "size": "1Gi",
        "mountPath": "/data",
        "accessModes": ["ReadWriteOnce"],
    }
    defaults = deep_merge(defaults, (spec.get("defaults") or {}).get("storage"))
    return deep_merge(defaults, actor.get("storage"))


def telemetry_settings(spec: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
    defaults = {
        "enabled": False,
        "image": "ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.158.0",
        "imagePullPolicy": "IfNotPresent",
        "resources": {
            "requests": {"cpu": "10m", "memory": "32Mi"},
            "limits": {"cpu": "200m", "memory": "160Mi"},
        },
    }
    settings = deep_merge(defaults, spec.get("telemetry"))
    return deep_merge(settings, actor.get("telemetry"))


def probe_settings(spec: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
    """Resolve the trusted probe independently from actor-controlled runtime data."""
    defaults = {
        "enabled": False,
        "image": "stacks-hacknet-probe:dev",
        "imagePullPolicy": "IfNotPresent",
        "resources": {
            "requests": {"cpu": "5m", "memory": "24Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"},
        },
    }
    settings = deep_merge(defaults, spec.get("probe"))
    return deep_merge(settings, actor.get("probe"))


def expand_text(
    value: str,
    *,
    network: str,
    namespace: str,
    actor: str,
    services: dict[str, str],
) -> str:
    def replace(match: re.Match[str]) -> str:
        token, service_actor = match.group(1), match.group(2)
        if token == "NETWORK":
            return network
        if token == "NAMESPACE":
            return namespace
        if token == "ACTOR":
            return actor
        if service_actor not in services:
            raise ValidationError(f"placeholder references unknown actor {service_actor!r}")
        return services[service_actor]

    return PLACEHOLDER_RE.sub(replace, value)


def expand_value(value: Any, **context: Any) -> Any:
    if isinstance(value, str):
        return expand_text(value, **context)
    if isinstance(value, list):
        return [expand_value(item, **context) for item in value]
    if isinstance(value, dict):
        return {key: expand_value(item, **context) for key, item in value.items()}
    return value


def validate_network(network: dict[str, Any]) -> None:
    metadata = network.get("metadata") or {}
    spec = network.get("spec") or {}
    name = metadata.get("name", "")
    if not name or not metadata.get("namespace") or not metadata.get("uid"):
        raise ValidationError("metadata.name, metadata.namespace, and metadata.uid are required")
    actors = spec.get("actors") or []
    if not 1 <= len(actors) <= 100:
        raise ValidationError("spec.actors must contain between 1 and 100 actors")
    names: set[str] = set()
    for actor in actors:
        actor_name = actor.get("name", "")
        if not DNS_LABEL_RE.fullmatch(actor_name) or len(actor_name) > 40:
            raise ValidationError(f"invalid actor name {actor_name!r}")
        if actor_name in names:
            raise ValidationError(f"duplicate actor name {actor_name!r}")
        names.add(actor_name)
        role = actor.get("role")
        if role not in {"burnchain", "miner", "signer", "companion", "follower", "adversary", "infrastructure"}:
            raise ValidationError(f"actor {actor_name!r} has invalid role {role!r}")
        if not actor_image(spec, actor):
            raise ValidationError(f"actor {actor_name!r} has no image and no applicable default image")
        config = actor.get("config") or {}
        sources = sum(key in config for key in ("inline", "files", "configMapRef", "secretRef"))
        if sources > 1:
            raise ValidationError(f"actor {actor_name!r} config must use exactly one source")
        if role in {"miner", "signer", "companion", "follower"} and sources != 1:
            raise ValidationError(f"Stacks actor {actor_name!r} requires a config source")
        key = config_key(actor)
        if not CONFIG_KEY_RE.fullmatch(key):
            raise ValidationError(f"actor {actor_name!r} has invalid ConfigMap key {key!r}")
        for file_name, contents in (config.get("files") or {}).items():
            if not CONFIG_KEY_RE.fullmatch(file_name):
                raise ValidationError(f"actor {actor_name!r} has invalid ConfigMap key {file_name!r}")
            if not isinstance(contents, str):
                raise ValidationError(f"actor {actor_name!r} config file {file_name!r} must be text")
        runtime_policy = actor.get("runtimePolicy") or {}
        if runtime_policy:
            config_map_name = (runtime_policy.get("configMapRef") or {}).get("name", "")
            if not DNS_LABEL_RE.fullmatch(config_map_name) or len(config_map_name) > 63:
                raise ValidationError(f"actor {actor_name!r} has invalid runtime policy ConfigMap name")
        if actor.get("runtimeExposure", "ready") not in {"ready", "reachable"}:
            raise ValidationError(f"actor {actor_name!r} has invalid runtimeExposure")
        port_names: set[str] = set()
        port_numbers: set[tuple[int, str]] = set()
        for port in actor.get("ports") or role_ports(role):
            port_name = port.get("name", "")
            protocol = port.get("protocol", "TCP")
            number = port.get("containerPort")
            if not DNS_LABEL_RE.fullmatch(port_name) or len(port_name) > 15:
                raise ValidationError(f"actor {actor_name!r} has invalid port name {port_name!r}")
            if port_name in port_names or (number, protocol) in port_numbers:
                raise ValidationError(f"actor {actor_name!r} has duplicate port {port_name!r}/{number}")
            port_names.add(port_name)
            port_numbers.add((number, protocol))
        telemetry = telemetry_settings(spec, actor)
        if telemetry.get("enabled") and not telemetry.get("exporterEndpoint"):
            raise ValidationError(f"actor {actor_name!r} enables telemetry without exporterEndpoint")
        probe = probe_settings(spec, actor)
        if probe.get("enabled") and not probe.get("image"):
            raise ValidationError(f"actor {actor_name!r} enables the trusted probe without an image")
    for actor in actors:
        for dependency in actor.get("dependencies") or []:
            target = dependency.get("actor")
            if target not in names:
                raise ValidationError(f"actor {actor['name']!r} depends on unknown actor {target!r}")
            if target == actor["name"]:
                raise ValidationError(f"actor {actor['name']!r} cannot depend on itself")
            target_actor = next(item for item in actors if item["name"] == target)
            exposed_ports = {port["servicePort"] for port in effective_ports(target_actor)}
            if dependency["port"] not in exposed_ports:
                raise ValidationError(
                    f"actor {actor['name']!r} dependency {target!r} uses port "
                    f"{dependency['port']}, which the target does not expose"
                )


def otel_config(actor: dict[str, Any], telemetry: dict[str, Any]) -> str:
    metrics_port = telemetry.get("metricsPort")
    if metrics_port is None:
        metrics_port = 31000 if actor["role"] == "signer" else 20446
    token = telemetry.get("tokenSecretRef")
    headers = ""
    if token:
        headers = '    headers:\n      Authorization: "Bearer ${env:STACKS_FEDERATION_TOKEN}"\n'
    return f"""extensions:
  health_check:
    endpoint: 0.0.0.0:13133

receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: stacks-actor
          scrape_interval: 5s
          scrape_timeout: 2s
          static_configs:
            - targets: ["127.0.0.1:{metrics_port}"]

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 128
    spike_limit_mib: 32
  resource/actor:
    attributes:
      - key: service.name
        action: upsert
        value: {"stacks-signer" if actor["role"] == "signer" else "stacks-node"}
      - key: stacks.actor.name
        action: upsert
        value: {actor["name"]}
      - key: stacks.actor.role
        action: upsert
        value: {actor["role"]}
  batch:
    timeout: 2s

exporters:
  otlp_http/federation:
    endpoint: "${{env:STACKS_FEDERATION_ENDPOINT}}"
{headers}    compression: gzip
    sending_queue:
      enabled: true
      queue_size: 500
    retry_on_failure:
      enabled: true
      max_elapsed_time: 60s

service:
  extensions: [health_check]
  pipelines:
    metrics:
      receivers: [prometheus]
      processors: [memory_limiter, resource/actor, batch]
      exporters: [otlp_http/federation]
"""


@dataclass(frozen=True)
class ActorContext:
    network: dict[str, Any]
    actor: dict[str, Any]
    resource_name: str
    services: dict[str, str]

    @property
    def spec(self) -> dict[str, Any]:
        return self.network["spec"]

    @property
    def namespace(self) -> str:
        return self.network["metadata"]["namespace"]

    @property
    def network_name(self) -> str:
        return self.network["metadata"]["name"]

    def expand(self, value: Any) -> Any:
        return expand_value(
            value,
            network=self.network_name,
            namespace=self.namespace,
            actor=self.actor["name"],
            services=self.services,
        )


def object_metadata(context: ActorContext, *, annotations: dict[str, str] | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "name": context.resource_name,
        "namespace": context.namespace,
        "labels": managed_labels(context.network_name, context.actor),
        "ownerReferences": owner_reference(context.network),
    }
    if annotations:
        metadata["annotations"] = annotations
    return metadata


def build_config_map(context: ActorContext) -> dict[str, Any] | None:
    config = context.actor.get("config") or {}
    telemetry = telemetry_settings(context.spec, context.actor)
    data: dict[str, str] = {}
    if "inline" in config:
        data[config_key(context.actor)] = context.expand(config["inline"])
    if "files" in config:
        data.update({key: context.expand(value) for key, value in config["files"].items()})
    if telemetry.get("enabled"):
        data["otelcol.yaml"] = otel_config(context.actor, telemetry)
    if not data:
        return None
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": object_metadata(context),
        "data": data,
    }


def effective_ports(actor: dict[str, Any]) -> list[dict[str, Any]]:
    ports = copy.deepcopy(actor.get("ports") or role_ports(actor["role"]))
    for port in ports:
        port.setdefault("servicePort", port["containerPort"])
        port.setdefault("protocol", "TCP")
    return ports


def build_service(context: ActorContext) -> dict[str, Any]:
    ports = effective_ports(context.actor)
    runtime_exposure = context.actor.get("runtimeExposure", "ready")
    # StatefulSets use a headless governing Service for stable actor identity.
    # Headless Services may validly omit ports, which matters for helper actors
    # such as a burn-block cadence process that never accepts inbound traffic.
    spec: dict[str, Any] = {
        "type": "ClusterIP",
        "clusterIP": "None",
        # Runtime endpoint publication is a target-actor property, distinct
        # from the per-edge dependency gate implemented by init containers.
        "publishNotReadyAddresses": runtime_exposure == "reachable",
        "selector": {
            NETWORK_LABEL: context.network_name,
            ACTOR_LABEL: context.actor["name"],
        },
    }
    if ports:
        spec["ports"] = [
            {
                "name": port["name"],
                "port": port["servicePort"],
                "targetPort": port["name"],
                "protocol": port["protocol"],
            }
            for port in ports
        ]
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": object_metadata(context),
        "spec": spec,
    }


def default_readiness_probe(actor: dict[str, Any]) -> dict[str, Any] | None:
    role = actor["role"]
    if role == "signer":
        return {"tcpSocket": {"port": "events"}, "periodSeconds": 5, "failureThreshold": 30}
    if role == "burnchain":
        return {"tcpSocket": {"port": "rpc"}, "periodSeconds": 5, "failureThreshold": 30}
    if role in {"miner", "companion", "follower", "adversary"}:
        return {
            "httpGet": {"path": "/v2/info", "port": "rpc"},
            "periodSeconds": 5,
            "failureThreshold": 90,
        }
    return None


def config_volume(context: ActorContext) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    config = context.actor.get("config") or {}
    if "inline" in config or "files" in config:
        source = {"configMap": {"name": context.resource_name}}
    elif config.get("configMapRef"):
        source = {"configMap": {"name": config["configMapRef"]["name"]}}
    elif config.get("secretRef"):
        source = {"secret": {"secretName": config["secretRef"]["name"]}}
    else:
        return None, None
    return {"name": "actor-config", **source}, {"name": "actor-config", "mountPath": config_mount_path(context.actor), "readOnly": True}


def build_telemetry_container(context: ActorContext, telemetry: dict[str, Any]) -> dict[str, Any]:
    env: list[dict[str, Any]] = [
        {"name": "STACKS_FEDERATION_ENDPOINT", "value": context.expand(telemetry["exporterEndpoint"])},
    ]
    if telemetry.get("tokenSecretRef"):
        secret = telemetry["tokenSecretRef"]
        env.append(
            {
                "name": "STACKS_FEDERATION_TOKEN",
                "valueFrom": {"secretKeyRef": {"name": secret["name"], "key": secret["key"]}},
            }
        )
    return {
        "name": "telemetry",
        "image": telemetry["image"],
        "imagePullPolicy": telemetry.get("imagePullPolicy", "IfNotPresent"),
        "args": ["--config=/etc/otelcol-contrib/config.yaml"],
        "env": env,
        "ports": [{"name": "otel-health", "containerPort": 13133, "protocol": "TCP"}],
        "readinessProbe": {"httpGet": {"path": "/", "port": "otel-health"}, "periodSeconds": 5},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": True,
        },
        "resources": telemetry.get("resources", {}),
        "volumeMounts": [
            {
                "name": "generated-config",
                "mountPath": "/etc/otelcol-contrib/config.yaml",
                "subPath": "otelcol.yaml",
                "readOnly": True,
            },
            {"name": "telemetry-tmp", "mountPath": "/tmp"},
        ],
    }


def build_probe_container(
    context: ActorContext,
    probe: dict[str, Any],
    storage: dict[str, Any],
) -> dict[str, Any]:
    peers = {
        actor["name"]: {
            "host": f"{context.services[actor['name']]}.{context.namespace}.svc.cluster.local",
            "ports": {port["name"]: port["servicePort"] for port in effective_ports(actor)},
        }
        for actor in context.spec["actors"]
    }
    # The probe receives no Kubernetes token and no actor-provided result
    # channel. Its peer/port allowlist is generated solely from the admitted
    # StacksNetwork inventory.
    return {
        "name": "attacknet-probe",
        "image": probe["image"],
        "imagePullPolicy": probe.get("imagePullPolicy", "IfNotPresent"),
        "env": [
            {"name": "PROBE_ACTOR", "value": context.actor["name"]},
            {"name": "PROBE_PORT", "value": "18080"},
            {"name": "PROBE_DATA_ROOT", "value": storage["mountPath"]},
            {"name": "PROBE_DNS_CONTROL", "value": "kubernetes.default.svc.cluster.local"},
            {"name": "PROBE_PEERS_JSON", "value": json.dumps(peers, sort_keys=True, separators=(",", ":"))},
        ],
        "ports": [{"name": "probe", "containerPort": 18080, "protocol": "TCP"}],
        "readinessProbe": {
            "httpGet": {"path": "/healthz", "port": "probe"},
            "periodSeconds": 5,
            "failureThreshold": 6,
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            # DNSChaos must create /etc/resolv.conf.chaos.bak inside the
            # selected container. The trusted probe is part of the disposable
            # data plane and must experience the same fault it measures, so it
            # intentionally keeps a writable overlay while retaining non-root
            # execution, dropped capabilities, seccomp, and no ServiceAccount
            # token. Operator/control-plane containers remain read-only.
            "readOnlyRootFilesystem": False,
            "runAsNonRoot": True,
            "runAsUser": 65532,
            "runAsGroup": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "resources": probe.get("resources", {}),
        # Mount the actor volume at the same container-visible path. IOChaos
        # path matching can then target the probe and actor with one path.
        "volumeMounts": [{"name": "data", "mountPath": storage["mountPath"]}],
    }


def build_stateful_set(context: ActorContext) -> dict[str, Any]:
    actor = context.actor
    spec = context.spec
    defaults = spec.get("defaults") or {}
    telemetry = telemetry_settings(spec, actor)
    trusted_probe = probe_settings(spec, actor)
    storage = storage_settings(spec, actor)
    ports = effective_ports(actor)
    command, args = actor_command(actor)
    command = context.expand(command) if command is not None else None
    args = context.expand(args) if args is not None else None
    config = actor.get("config") or {}
    config_digest = hashlib.sha256(
        json.dumps(
            {
                "config": config,
                "telemetry": telemetry if telemetry.get("enabled") else None,
                "probe": trusted_probe if trusted_probe.get("enabled") else None,
                "command": command,
                "args": args,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    annotations = dict(actor.get("annotations") or {})
    annotations["testing.stacks.org/config-hash"] = config_digest
    labels = managed_labels(context.network_name, actor)
    actor_env = [
        {"name": "HACKNET_NETWORK", "value": context.network_name},
        {"name": "HACKNET_ACTOR", "value": actor["name"]},
        {"name": "HACKNET_ROLE", "value": actor["role"]},
    ] + context.expand(actor.get("env") or [])
    main_container: dict[str, Any] = {
        "name": "actor",
        "image": actor_image(spec, actor),
        "imagePullPolicy": actor.get("imagePullPolicy", defaults.get("imagePullPolicy", "IfNotPresent")),
        "env": actor_env,
        "ports": [
            {"name": port["name"], "containerPort": port["containerPort"], "protocol": port["protocol"]}
            for port in ports
        ],
        "resources": deep_merge(defaults.get("resources"), actor.get("resources")),
        "securityContext": deep_merge(defaults.get("containerSecurityContext"), actor.get("containerSecurityContext")),
        "volumeMounts": [{"name": "data", "mountPath": storage["mountPath"]}],
    }
    if command is not None:
        main_container["command"] = command
    if args is not None:
        main_container["args"] = args
    probe = actor.get("readinessProbe") if "readinessProbe" in actor else default_readiness_probe(actor)
    if probe:
        main_container["readinessProbe"] = probe
    if actor.get("livenessProbe"):
        main_container["livenessProbe"] = actor["livenessProbe"]
    if actor.get("startupProbe"):
        main_container["startupProbe"] = actor["startupProbe"]
    if actor.get("workingDir"):
        main_container["workingDir"] = actor["workingDir"]
    volumes: list[dict[str, Any]] = []
    config_source, config_mount = config_volume(context)
    if config_source and config_mount:
        volumes.append(config_source)
        main_container["volumeMounts"].append(config_mount)
    runtime_policy = actor.get("runtimePolicy") or {}
    if runtime_policy:
        volumes.append({
            "name": "runtime-policy",
            "configMap": {
                "name": runtime_policy["configMapRef"]["name"],
                "optional": runtime_policy.get("optional", False),
            },
        })
        main_container["volumeMounts"].append({
            "name": "runtime-policy",
            "mountPath": runtime_policy.get("mountPath", "/run/hacknet-policy"),
            "readOnly": True,
        })
    containers = [main_container]
    if telemetry.get("enabled"):
        if not any(volume["name"] == "generated-config" for volume in volumes):
            volumes.append({"name": "generated-config", "configMap": {"name": context.resource_name}})
        elif config_source and config_source.get("configMap", {}).get("name") == context.resource_name:
            # The inline actor config and generated OTel config share one ConfigMap.
            config_source["name"] = "generated-config"
            config_mount["name"] = "generated-config"
        else:
            volumes.append({"name": "generated-config", "configMap": {"name": context.resource_name}})
        volumes.append({"name": "telemetry-tmp", "emptyDir": {}})
        containers.append(build_telemetry_container(context, telemetry))
    if trusted_probe.get("enabled"):
        containers.append(build_probe_container(context, trusted_probe, storage))
    volume_claim_templates: list[dict[str, Any]] = []
    if storage.get("enabled", True):
        claim_spec: dict[str, Any] = {
            "accessModes": storage.get("accessModes", ["ReadWriteOnce"]),
            "resources": {"requests": {"storage": storage.get("size", "1Gi")}},
        }
        if storage.get("storageClassName") is not None:
            claim_spec["storageClassName"] = storage["storageClassName"]
        volume_claim_templates.append({"metadata": {"name": "data", "labels": labels}, "spec": claim_spec})
    else:
        volumes.append({"name": "data", "emptyDir": {}})
    init_containers: list[dict[str, Any]] = []
    dependencies = actor.get("dependencies") or []
    if dependencies:
        checks = [f"until nc -z {context.services[item['actor']]} {item['port']}; do sleep 1; done" for item in dependencies]
        init_containers.append(
            {
                "name": "wait-for-dependencies",
                "image": defaults.get("dependencyImage", "busybox:1.36.1"),
                "command": ["sh", "-ec", "; ".join(checks)],
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            }
        )
    pod_security_context = deep_merge(defaults.get("podSecurityContext"), actor.get("podSecurityContext"))
    if trusted_probe.get("enabled") and "fsGroup" not in pod_security_context:
        # Ensure the non-root probe can create its private directory on a PVC.
        # This is opt-in with the probe and does not alter baseline actor Pods.
        pod_security_context["fsGroup"] = 65532
        pod_security_context["fsGroupChangePolicy"] = "OnRootMismatch"
    pod_spec: dict[str, Any] = {
        "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": actor.get(
            "terminationGracePeriodSeconds",
            defaults.get("terminationGracePeriodSeconds", 30),
        ),
        "securityContext": pod_security_context,
        "containers": containers,
        # Keep the empty list explicit: merge-patch retains an omitted field,
        # which would leave a removed dependency gate in the live Pod template.
        "initContainers": init_containers,
        "volumes": volumes,
    }
    if defaults.get("imagePullSecrets"):
        pod_spec["imagePullSecrets"] = defaults["imagePullSecrets"]
    for field in ("nodeSelector", "affinity", "tolerations", "topologySpreadConstraints"):
        value = actor[field] if field in actor else defaults.get(field)
        if value:
            pod_spec[field] = context.expand(value)
    stateful_spec: dict[str, Any] = {
        "serviceName": context.resource_name,
        "replicas": 0 if spec.get("suspended", False) or actor.get("suspended", False) else 1,
        "podManagementPolicy": "Parallel",
        # A deleted/pruned actor must not silently donate old chainstate to a
        # later test run. Suspension is reversible, so scale-to-zero retains it.
        "persistentVolumeClaimRetentionPolicy": {"whenDeleted": "Delete", "whenScaled": "Retain"},
        "updateStrategy": {"type": "RollingUpdate"},
        "selector": {"matchLabels": {NETWORK_LABEL: context.network_name, ACTOR_LABEL: actor["name"]}},
        "template": {"metadata": {"labels": labels, "annotations": annotations}, "spec": pod_spec},
    }
    if volume_claim_templates:
        stateful_spec["volumeClaimTemplates"] = volume_claim_templates
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": object_metadata(context),
        "spec": stateful_spec,
    }


def build_resources(network: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    validate_network(network)
    name = network["metadata"]["name"]
    actors = network["spec"]["actors"]
    services = {actor["name"]: stable_name(name, actor["name"]) for actor in actors}
    resources: dict[str, list[dict[str, Any]]] = {"configmaps": [], "services": [], "statefulsets": []}
    for actor in actors:
        context = ActorContext(network, actor, services[actor["name"]], services)
        config_map = build_config_map(context)
        if config_map:
            resources["configmaps"].append(config_map)
        resources["services"].append(build_service(context))
        resources["statefulsets"].append(build_stateful_set(context))
    return resources


class OperatorMetrics:
    """Small dependency-free Prometheus registry for control-plane attribution."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.process_start_time = time.time()
        self.api_requests: dict[tuple[str, str], int] = {}
        self.api_duration_count = 0
        self.api_duration_sum = 0.0
        self.reconciles: dict[str, int] = {}
        self.reconcile_duration_count = 0
        self.reconcile_duration_sum = 0.0
        self.reconcile_duration_max = 0.0
        self.reconcile_last_duration = 0.0
        self.reconcile_last_api_requests = 0
        self.managed_networks = 0

    def api_total(self) -> int:
        with self.lock:
            return sum(self.api_requests.values())

    def observe_api(self, method: str, code: str, duration: float) -> None:
        bounded_code = code if re.fullmatch(r"[1-5][0-9][0-9]", code) else "error"
        key = (method.upper(), bounded_code)
        with self.lock:
            self.api_requests[key] = self.api_requests.get(key, 0) + 1
            self.api_duration_count += 1
            self.api_duration_sum += max(0.0, duration)

    def observe_reconcile(self, outcome: str, duration: float, api_requests: int) -> None:
        with self.lock:
            self.reconciles[outcome] = self.reconciles.get(outcome, 0) + 1
            self.reconcile_duration_count += 1
            self.reconcile_duration_sum += max(0.0, duration)
            self.reconcile_duration_max = max(self.reconcile_duration_max, duration)
            self.reconcile_last_duration = max(0.0, duration)
            self.reconcile_last_api_requests = max(0, api_requests)

    def set_managed_networks(self, count: int) -> None:
        with self.lock:
            self.managed_networks = max(0, count)

    def render(self) -> bytes:
        with self.lock:
            lines = [
                "# HELP hacknet_operator_api_requests_total Kubernetes API requests made by the operator.",
                "# TYPE hacknet_operator_api_requests_total counter",
            ]
            for (method, code), count in sorted(self.api_requests.items()):
                lines.append(f'hacknet_operator_api_requests_total{{method="{method}",code="{code}"}} {count}')
            lines.extend([
                "# HELP hacknet_operator_process_start_time_seconds Operator process start time since Unix epoch.",
                "# TYPE hacknet_operator_process_start_time_seconds gauge",
                f"hacknet_operator_process_start_time_seconds {self.process_start_time:.6f}",
                "# TYPE hacknet_operator_api_request_duration_seconds_sum counter",
                f"hacknet_operator_api_request_duration_seconds_sum {self.api_duration_sum:.9f}",
                "# TYPE hacknet_operator_api_request_duration_seconds_count counter",
                f"hacknet_operator_api_request_duration_seconds_count {self.api_duration_count}",
                "# HELP hacknet_operator_reconciliations_total Completed StacksNetwork reconciliations.",
                "# TYPE hacknet_operator_reconciliations_total counter",
            ])
            for outcome, count in sorted(self.reconciles.items()):
                lines.append(f'hacknet_operator_reconciliations_total{{outcome="{outcome}"}} {count}')
            lines.extend([
                "# TYPE hacknet_operator_reconcile_duration_seconds_sum counter",
                f"hacknet_operator_reconcile_duration_seconds_sum {self.reconcile_duration_sum:.9f}",
                "# TYPE hacknet_operator_reconcile_duration_seconds_count counter",
                f"hacknet_operator_reconcile_duration_seconds_count {self.reconcile_duration_count}",
                "# TYPE hacknet_operator_reconcile_duration_seconds_max gauge",
                f"hacknet_operator_reconcile_duration_seconds_max {self.reconcile_duration_max:.9f}",
                "# TYPE hacknet_operator_reconcile_last_duration_seconds gauge",
                f"hacknet_operator_reconcile_last_duration_seconds {self.reconcile_last_duration:.9f}",
                "# TYPE hacknet_operator_reconcile_last_api_requests gauge",
                f"hacknet_operator_reconcile_last_api_requests {self.reconcile_last_api_requests}",
                "# TYPE hacknet_operator_managed_networks gauge",
                f"hacknet_operator_managed_networks {self.managed_networks}",
            ])
            return ("\n".join(lines) + "\n").encode()


class KubernetesClient:
    def __init__(self, progress_callback: Any = None, request_callback: Any = None) -> None:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if not host:
            raise RuntimeError("KUBERNETES_SERVICE_HOST is not set; the controller must run in a Pod")
        self.base_url = f"https://{host}:{port}"
        self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.ssl_context = ssl.create_default_context(cafile=ca_path)
        self.progress_callback = progress_callback
        self.request_callback = request_callback

    def _read_token(self) -> str:
        # Projected service-account tokens rotate in place. Reading the small
        # local file per request prevents a long-lived controller from caching
        # an expired bearer token.
        with open(self.token_path, encoding="utf-8") as handle:
            token = handle.read().strip()
        if not token:
            raise RuntimeError("projected Kubernetes service-account token is empty")
        return token

    def _mark_progress(self) -> None:
        if self.progress_callback is not None:
            self.progress_callback()

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        content_type: str = "application/json",
    ) -> dict[str, Any] | None:
        started = time.monotonic()
        response_code = "error"
        self._mark_progress()
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._read_token()}",
                "Accept": "application/json",
                "Content-Type": content_type,
            },
        )
        try:
            with urllib.request.urlopen(request, context=self.ssl_context, timeout=30) as response:
                response_code = str(getattr(response, "status", 200))
                payload = response.read()
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            response_code = str(error.code)
            body_text = error.read().decode(errors="replace")
            raise ApiError(error.code, method, path, body_text) from error
        finally:
            callback = getattr(self, "request_callback", None)
            if callback is not None:
                callback(method, response_code, time.monotonic() - started)
            self._mark_progress()

    @staticmethod
    def collection_path(kind: str, namespace: str) -> str:
        if kind == "statefulsets":
            return f"/apis/apps/v1/namespaces/{namespace}/statefulsets"
        return f"/api/v1/namespaces/{namespace}/{kind}"

    def list_networks(self, namespace: str) -> list[dict[str, Any]]:
        result = self.request("GET", f"/apis/{GROUP}/{VERSION}/namespaces/{namespace}/{PLURAL}") or {}
        return result.get("items", [])

    @staticmethod
    def _controller_uid(resource: dict[str, Any]) -> str | None:
        references = (resource.get("metadata") or {}).get("ownerReferences") or []
        owner = next((reference for reference in references if reference.get("controller") is True), None)
        return owner.get("uid") if owner else None

    @classmethod
    def _assert_owned(cls, current: dict[str, Any], desired: dict[str, Any]) -> None:
        current_uid = cls._controller_uid(current)
        desired_uid = cls._controller_uid(desired)
        if not desired_uid or current_uid != desired_uid:
            metadata = desired.get("metadata") or {}
            raise OwnershipError(
                f"refusing to adopt {metadata.get('namespace')}/{metadata.get('name')}: "
                f"existing controller uid {current_uid!r} does not match desired uid {desired_uid!r}"
            )

    def apply_resource(self, kind: str, resource: dict[str, Any]) -> None:
        namespace = resource["metadata"]["namespace"]
        name = resource["metadata"]["name"]
        path = f"{self.collection_path(kind, namespace)}/{name}"
        for attempt in range(APPLY_CONFLICT_ATTEMPTS):
            try:
                current = self.request("GET", path) or {}
            except ApiError as error:
                if error.status != 404:
                    raise
                try:
                    self.request("POST", self.collection_path(kind, namespace), resource)
                    return
                except ApiError as create_error:
                    if create_error.status != 409 or attempt == APPLY_CONFLICT_ATTEMPTS - 1:
                        raise
                    # A competing creator won. Re-read it on the next attempt
                    # and only update it if it belongs to this exact CR uid.
                    continue
            self._assert_owned(current, resource)
            try:
                if kind == "configmaps":
                    # Merge Patch retains omitted map keys. Replace ConfigMaps
                    # so changing config.key cannot leave stale owned files.
                    replacement = copy.deepcopy(resource)
                    replacement["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
                    self.request("PUT", path, replacement)
                else:
                    self.request("PATCH", path, resource, content_type="application/merge-patch+json")
                return
            except ApiError as update_error:
                if update_error.status != 409 or attempt == APPLY_CONFLICT_ATTEMPTS - 1:
                    raise
                # A debugger or another API client modified the object between
                # GET and update. Re-GET and retry with fresh resourceVersion.
        raise RuntimeError(f"unreachable: exhausted apply attempts for {namespace}/{name}")

    def list_managed(self, kind: str, namespace: str, network: str) -> list[dict[str, Any]]:
        selector = urllib.parse.quote(f"{MANAGED_LABEL}={MANAGED_BY},{NETWORK_LABEL}={network}")
        result = self.request("GET", f"{self.collection_path(kind, namespace)}?labelSelector={selector}") or {}
        return result.get("items", [])

    def delete_resource(self, kind: str, namespace: str, name: str) -> None:
        path = f"{self.collection_path(kind, namespace)}/{name}"
        try:
            self.request("DELETE", path, {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background"})
        except ApiError as error:
            if error.status != 404:
                raise

    def get_stateful_set(self, namespace: str, name: str) -> dict[str, Any] | None:
        path = f"{self.collection_path('statefulsets', namespace)}/{name}"
        try:
            return self.request("GET", path)
        except ApiError as error:
            if error.status == 404:
                return None
            raise

    def patch_status(self, namespace: str, name: str, status: dict[str, Any]) -> None:
        path = f"/apis/{GROUP}/{VERSION}/namespaces/{namespace}/{PLURAL}/{name}/status"
        self.request("PATCH", path, {"status": status}, content_type="application/merge-patch+json")


def condition(
    condition_type: str,
    status: str,
    reason: str,
    message: str,
    previous: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    prior = next((item for item in (previous or []) if item.get("type") == condition_type), None)
    transition = utc_now()
    if prior and prior.get("status") == status and prior.get("reason") == reason and prior.get("message") == message:
        transition = prior.get("lastTransitionTime", transition)
    return {
        "type": condition_type,
        "status": status,
        "reason": reason,
        "message": message,
        "lastTransitionTime": transition,
    }


def build_status(network: dict[str, Any], api: Any) -> dict[str, Any]:
    metadata = network["metadata"]
    suspended = network["spec"].get("suspended", False)
    actor_statuses: list[dict[str, Any]] = []
    ready = 0
    for actor in network["spec"]["actors"]:
        resource_name = stable_name(metadata["name"], actor["name"])
        stateful_set = api.get_stateful_set(metadata["namespace"], resource_name)
        stateful_metadata = (stateful_set or {}).get("metadata") or {}
        stateful_status = (stateful_set or {}).get("status") or {}
        stateful_generation = int(stateful_metadata.get("generation", 0))
        observed_generation = int(stateful_status.get("observedGeneration", 0))
        ready_replicas = int(stateful_status.get("readyReplicas", 0))
        updated_replicas = int(stateful_status.get("updatedReplicas", 0))
        current_revision = stateful_status.get("currentRevision")
        update_revision = stateful_status.get("updateRevision")
        rollout_current = (
            stateful_generation > 0
            and observed_generation >= stateful_generation
            and ready_replicas >= 1
            and updated_replicas >= 1
            and bool(current_revision)
            and current_revision == update_revision
        )
        is_ready = not suspended and rollout_current
        ready += int(is_ready)
        actor_statuses.append(
            {
                "name": actor["name"],
                "role": actor["role"],
                "resourceName": resource_name,
                "image": actor_image(network["spec"], actor),
                "ready": is_ready,
                "readyReplicas": ready_replicas,
                "updatedReplicas": updated_replicas,
                "generation": stateful_generation,
                "observedGeneration": observed_generation,
                "currentRevision": current_revision,
                "updateRevision": update_revision,
            }
        )
    desired = len(actor_statuses)
    if suspended:
        phase, ready_condition, reason = "Suspended", "False", "NetworkSuspended"
        message = "All actor StatefulSets are intentionally scaled to zero"
    elif ready == desired:
        phase, ready_condition, reason = "Ready", "True", "AllActorsReady"
        message = f"All {desired} actors are ready"
    else:
        phase, ready_condition, reason = "Progressing", "False", "ActorsNotReady"
        message = f"{ready} of {desired} actors are ready"
    previous = (network.get("status") or {}).get("conditions")
    return {
        "observedGeneration": metadata.get("generation", 0),
        "phase": phase,
        "desiredActors": desired,
        "readyActors": ready,
        "readySummary": f"{ready}/{desired}",
        "actors": actor_statuses,
        "conditions": [condition("Ready", ready_condition, reason, message, previous)],
    }


def degraded_status(network: dict[str, Any], error: Exception) -> dict[str, Any]:
    metadata = network.get("metadata") or {}
    previous = (network.get("status") or {}).get("conditions")
    desired = len((network.get("spec") or {}).get("actors") or [])
    message = str(error)[:1000]
    return {
        "observedGeneration": metadata.get("generation", 0),
        "phase": "Degraded",
        "desiredActors": desired,
        "readyActors": 0,
        "readySummary": f"0/{desired}",
        "actors": [],
        "conditions": [condition("Ready", "False", "ReconcileFailed", message, previous)],
    }


def materially_equal(left: dict[str, Any] | None, right: dict[str, Any]) -> bool:
    return (left or {}) == right


class Reconciler:
    def __init__(self, api: Any, metrics: OperatorMetrics | None = None):
        self.api = api
        self.metrics = metrics

    def reconcile(self, network: dict[str, Any]) -> None:
        metadata = network["metadata"]
        namespace, name = metadata["namespace"], metadata["name"]
        started = time.monotonic()
        api_before = self.metrics.api_total() if self.metrics is not None else 0
        outcome = "ready"
        try:
            resources = build_resources(network)
            for kind in ("configmaps", "services", "statefulsets"):
                for resource in resources[kind]:
                    self.api.apply_resource(kind, resource)
                desired = {resource["metadata"]["name"] for resource in resources[kind]}
                for existing in self.api.list_managed(kind, namespace, name):
                    existing_name = existing["metadata"]["name"]
                    if existing_name not in desired:
                        self.api.delete_resource(kind, namespace, existing_name)
            status = build_status(network, self.api)
            outcome = status["phase"].lower()
        except Exception as error:
            logging.exception("failed to reconcile StacksNetwork %s/%s", namespace, name)
            status = degraded_status(network, error)
            outcome = "degraded"
        try:
            if not materially_equal(network.get("status"), status):
                self.api.patch_status(namespace, name, status)
        except Exception:
            outcome = "error"
            raise
        finally:
            if self.metrics is not None:
                self.metrics.observe_reconcile(
                    outcome,
                    time.monotonic() - started,
                    self.metrics.api_total() - api_before,
                )


class HealthState:
    def __init__(self, liveness_timeout_seconds: float, clock: Any = time.monotonic) -> None:
        self.ready = False
        self.running = True
        self.liveness_timeout_seconds = liveness_timeout_seconds
        self.clock = clock
        self.last_progress_at = clock()

    def mark_progress(self) -> None:
        self.last_progress_at = self.clock()

    def is_live(self) -> bool:
        return self.running and self.clock() - self.last_progress_at <= self.liveness_timeout_seconds


class HealthHandler(http.server.BaseHTTPRequestHandler):
    state: HealthState
    metrics: OperatorMetrics

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/metrics":
            payload = self.metrics.render()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/healthz" and self.state.is_live():
            self.send_response(200)
        elif self.path == "/readyz" and self.state.ready:
            self.send_response(200)
        else:
            self.send_response(503)
        self.end_headers()

    def log_message(self, format_string: str, *args: Any) -> None:
        logging.debug("health server: " + format_string, *args)


def run_health_server(state: HealthState, metrics: OperatorMetrics) -> None:
    handler = type("BoundHealthHandler", (HealthHandler,), {"state": state, "metrics": metrics})
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), handler)
    server.serve_forever()


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    namespace = os.environ.get("WATCH_NAMESPACE", "").strip()
    if not namespace:
        namespace_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        with open(namespace_path, encoding="utf-8") as handle:
            namespace = handle.read().strip()
    interval = max(1, min(300, int(os.environ.get("RECONCILE_INTERVAL_SECONDS", "5"))))
    # Liveness detects a controller loop that has stopped making progress. API
    # failures affect readiness, not liveness: restarting every controller Pod
    # during an API-server outage would be an unhelpful restart storm.
    liveness_timeout = max(90.0, interval * 3.0 + 30.0)
    state = HealthState(liveness_timeout)
    metrics = OperatorMetrics()
    threading.Thread(target=run_health_server, args=(state, metrics), daemon=True).start()

    def stop(_signum: int, _frame: Any) -> None:
        state.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    api = KubernetesClient(progress_callback=state.mark_progress, request_callback=metrics.observe_api)
    reconciler = Reconciler(api, metrics)
    logging.info("watching StacksNetwork resources in namespace %s", namespace)
    while state.running:
        state.mark_progress()
        try:
            networks = api.list_networks(namespace)
            metrics.set_managed_networks(len(networks))
            state.ready = True
            for network in networks:
                if not (network.get("metadata") or {}).get("deletionTimestamp"):
                    reconciler.reconcile(network)
        except Exception:
            state.ready = False
            logging.exception("controller reconciliation pass failed")
        finally:
            state.mark_progress()
        deadline = time.monotonic() + interval
        while state.running and time.monotonic() < deadline:
            time.sleep(min(0.25, deadline - time.monotonic()))
    logging.info("controller stopped")


if __name__ == "__main__":
    main()
