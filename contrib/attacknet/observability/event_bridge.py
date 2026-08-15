#!/usr/bin/env python3
"""Durable, authenticated attacknet event journal with Prometheus projection."""

from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
import math
import os
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse


SCHEMA_VERSION = 1
ALLOWED_KINDS = frozenset(
    {
        "run.started",
        "run.finished",
        "policy.changed",
        "fault.scheduled",
        "fault.injected",
        "fault.cleared",
        "invariant.observed",
        "actor.state",
        "recovery.complete",
        "incident.opened",
        "note",
    }
)
ALLOWED_PHASES = frozenset(
    {
        "setup", "bootstrap", "baseline", "injecting", "fault-active",
        "recovering", "verification", "capture", "incident", "teardown", "complete",
    }
)
MAX_BODY_BYTES = 256 * 1024
MAX_LABEL_LENGTH = 128


def _now_rfc3339() -> str:
    timestamp = time.time()
    seconds = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(timestamp))
    millis = int(timestamp % 1 * 1000)
    return f"{seconds}.{millis:03d}Z"


def _metric_escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**values: Any) -> str:
    present = ((key, value) for key, value in values.items() if value not in (None, ""))
    return ",".join(f'{key}="{_metric_escape(value)}"' for key, value in sorted(present))


def _bounded_label(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not value or len(value) > MAX_LABEL_LENGTH:
        raise ValueError(f"{field_name} must contain 1..{MAX_LABEL_LENGTH} characters")
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def validate_event(candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError("event must be a JSON object")
    event = dict(candidate)
    event["kind"] = _bounded_label(event.get("kind"), "kind")
    if event["kind"] not in ALLOWED_KINDS:
        raise ValueError(f"unsupported event kind {event['kind']!r}")
    event["network"] = _bounded_label(event.get("network"), "network")
    event["runId"] = _bounded_label(event.get("runId"), "runId")
    event["phase"] = _bounded_label(event.get("phase", "baseline"), "phase")
    if event["phase"] not in ALLOWED_PHASES:
        raise ValueError(f"unsupported phase {event['phase']!r}")
    for optional in ("eventId", "instructionId", "campaign", "actor", "role", "faultType", "outcome"):
        if optional in event and event[optional] is not None:
            event[optional] = _bounded_label(event[optional], optional)
    details = event.get("details", {})
    if not isinstance(details, dict):
        raise ValueError("details must be a JSON object")
    # Bound arbitrary detail fields because the complete record is retained and
    # served to humans. Prometheus labels only use the explicitly bounded fields.
    encoded_details = json.dumps(details, separators=(",", ":"), ensure_ascii=False)
    if len(encoded_details.encode()) > 64 * 1024:
        raise ValueError("details exceeds 64 KiB")
    event["details"] = details
    occurred_at = event.get("occurredAt")
    if occurred_at is not None:
        event["occurredAt"] = _bounded_label(occurred_at, "occurredAt")
        try:
            timestamp = dt.datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("occurredAt must be an RFC3339 timestamp") from error
        if timestamp.tzinfo is None:
            raise ValueError("occurredAt must include a timezone")
    kind = event["kind"]
    if kind == "run.started":
        # The canonical run descriptor treats the seed as an opaque string;
        # decimal, hex, and human-selected reproducibility seeds are all valid.
        # Keep it bounded because it is projected into attacknet_run_info.
        _bounded_label(details.get("seed"), "run.started details.seed")
    if kind == "run.finished":
        status = details.get("status")
        if status not in ("passed", "failed", "aborted"):
            raise ValueError("run.finished details.status must be passed, failed, or aborted")
    if kind == "policy.changed":
        if details.get("mode") not in ("run", "pause"):
            raise ValueError("policy.changed details.mode must be run or pause")
        if not isinstance(details.get("generation"), int) or details["generation"] < 0:
            raise ValueError("policy.changed details.generation must be a non-negative integer")
        if _finite_number(details.get("intervalSeconds"), -1) < 0:
            raise ValueError("policy.changed details.intervalSeconds must be non-negative")
    if kind in ("fault.scheduled", "fault.injected", "fault.cleared"):
        if not event.get("campaign") or not event.get("faultType"):
            raise ValueError(f"{kind} requires campaign and faultType")
        if kind in ("fault.injected", "fault.cleared") and not event.get("actor"):
            raise ValueError(f"{kind} requires actor")
    if kind == "invariant.observed":
        _bounded_label(details.get("name"), "details.name")
        if not isinstance(details.get("passed"), bool):
            raise ValueError("invariant.observed details.passed must be boolean")
        if "value" in details and not math.isfinite(_finite_number(details["value"], math.nan)):
            raise ValueError("invariant.observed details.value must be finite")
    if kind == "actor.state":
        if not event.get("actor"):
            raise ValueError("actor.state requires actor")
        if not isinstance(details.get("ready"), bool):
            raise ValueError("actor.state details.ready must be boolean")
        restarts = details.get("restarts", 0)
        if not isinstance(restarts, int) or restarts < 0:
            raise ValueError("actor.state details.restarts must be a non-negative integer")
    if kind == "recovery.complete":
        if not event.get("campaign"):
            raise ValueError("recovery.complete requires campaign")
        if _finite_number(details.get("durationSeconds"), -1) < 0:
            raise ValueError("recovery.complete details.durationSeconds must be non-negative")
    if kind == "incident.opened":
        reason = details.get("reason")
        if not isinstance(reason, str) or not reason or len(reason) > 2048:
            raise ValueError("incident.opened details.reason must contain 1..2048 characters")
    return event


@dataclass
class Journal:
    path: Path
    lock: threading.RLock = field(default_factory=threading.RLock)
    events: list[dict[str, Any]] = field(default_factory=list)
    event_ids: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise RuntimeError(f"invalid journal line {line_number}: {error}") from error
                self.events.append(event)
                if event.get("eventId"):
                    self.event_ids[event["eventId"]] = event["sequence"]

    def append(self, candidate: Any) -> tuple[dict[str, Any], bool]:
        event = validate_event(candidate)
        with self.lock:
            event_id = event.get("eventId")
            if event_id and event_id in self.event_ids:
                sequence = self.event_ids[event_id]
                return self.events[sequence - 1], False
            event["schemaVersion"] = SCHEMA_VERSION
            event["sequence"] = len(self.events) + 1
            event["recordedAt"] = _now_rfc3339()
            event.setdefault("occurredAt", event["recordedAt"])
            payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as destination:
                destination.write(payload)
                destination.write("\n")
                destination.flush()
                os.fsync(destination.fileno())
            self.events.append(event)
            if event_id:
                self.event_ids[event_id] = event["sequence"]
            return event, True

    def snapshot(self, after: int = 0, limit: int = 10_000) -> list[dict[str, Any]]:
        with self.lock:
            return [event for event in self.events if event["sequence"] > after][:limit]

    def prometheus(self) -> str:
        with self.lock:
            events = list(self.events)
        lines = [
            "# HELP attacknet_journal_events_total Durable orchestrator-observed events by bounded classification.",
            "# TYPE attacknet_journal_events_total counter",
        ]
        totals = Counter(
            (
                event["network"], event["kind"], event["phase"], event.get("campaign", ""),
                event.get("actor", ""), event.get("outcome", ""),
            )
            for event in events
        )
        for key, value in sorted(totals.items()):
            network, kind, phase, campaign, actor, outcome = key
            label_set = _labels(network=network, kind=kind, phase=phase, campaign=campaign, actor=actor, outcome=outcome, evidence_source="orchestrator_observed")
            lines.append(f"attacknet_journal_events_total{{{label_set}}} {value}")

        latest_run: dict[str, dict[str, Any]] = {}
        run_seeds: dict[tuple[str, str], str] = {}
        for event in events:
            network = event["network"]
            latest_run[network] = event
            details = event["details"]
            if event["kind"] == "run.started" and details.get("seed"):
                run_seeds[(network, event["runId"])] = str(details["seed"])[:MAX_LABEL_LENGTH]
        fault_states: dict[tuple[str, str, str, str], tuple[int, float]] = {}
        policy_states: dict[str, dict[str, Any]] = {}
        invariant_states: dict[tuple[str, str, str], tuple[int, float]] = {}
        actor_states: dict[tuple[str, str], tuple[int, float]] = {}
        recovery: dict[tuple[str, str], float] = {}
        for event in events:
            network = event["network"]
            if event["runId"] != latest_run[network]["runId"]:
                continue
            details = event["details"]
            timestamp = _parse_epoch(event["occurredAt"])
            if event["kind"] in ("fault.injected", "fault.cleared"):
                key = (network, event.get("campaign", ""), event.get("faultType", ""), event.get("actor", ""))
                fault_states[key] = (1 if event["kind"] == "fault.injected" else 0, timestamp)
            elif event["kind"] == "policy.changed":
                policy_states[network] = event
            elif event["kind"] == "invariant.observed":
                name = str(details.get("name", "unknown"))[:MAX_LABEL_LENGTH]
                status = 1 if details.get("passed") is True else 0
                value = _finite_number(details.get("value"), status)
                invariant_states[(network, name, event.get("actor", ""))] = (status, value)
            elif event["kind"] == "actor.state":
                ready = 1 if details.get("ready") is True else 0
                restarts = _finite_number(details.get("restarts"), 0)
                actor_states[(network, event.get("actor", "unknown"))] = (ready, restarts)
            elif event["kind"] == "recovery.complete":
                recovery[(network, event.get("campaign", ""))] = _finite_number(details.get("durationSeconds"), 0)

        lines.extend([
            "# HELP attacknet_fault_active Whether an injected fault is currently active.",
            "# TYPE attacknet_fault_active gauge",
            "# HELP attacknet_fault_last_transition_timestamp_seconds Event occurrence time of the latest fault state transition.",
            "# TYPE attacknet_fault_last_transition_timestamp_seconds gauge",
        ])
        for (network, campaign, fault_type, actor), (active, changed_at) in sorted(fault_states.items()):
            labels = _labels(network=network, campaign=campaign, fault_type=fault_type, actor=actor, evidence_source="orchestrator_observed")
            lines.append(f"attacknet_fault_active{{{labels}}} {active}")
            lines.append(f"attacknet_fault_last_transition_timestamp_seconds{{{labels}}} {changed_at}")

        lines.extend([
            "# HELP attacknet_invariant_pass Whether the latest invariant observation passed.",
            "# TYPE attacknet_invariant_pass gauge",
            "# HELP attacknet_invariant_value Numeric value attached to the latest invariant observation.",
            "# TYPE attacknet_invariant_value gauge",
        ])
        for (network, name, actor), (passed, value) in sorted(invariant_states.items()):
            labels = _labels(network=network, invariant=name, actor=actor, evidence_source="orchestrator_observed")
            lines.append(f"attacknet_invariant_pass{{{labels}}} {passed}")
            lines.append(f"attacknet_invariant_value{{{labels}}} {value}")

        lines.extend([
            "# HELP attacknet_actor_ready Orchestrator-observed actor readiness.",
            "# TYPE attacknet_actor_ready gauge",
            "# HELP attacknet_actor_restarts Orchestrator-observed container restart count.",
            "# TYPE attacknet_actor_restarts gauge",
        ])
        for (network, actor), (ready, restarts) in sorted(actor_states.items()):
            labels = _labels(network=network, actor=actor, evidence_source="orchestrator_observed")
            lines.append(f"attacknet_actor_ready{{{labels}}} {ready}")
            lines.append(f"attacknet_actor_restarts{{{labels}}} {restarts}")

        lines.extend(["# HELP attacknet_recovery_duration_seconds Observed time from fault clearance to invariant recovery.", "# TYPE attacknet_recovery_duration_seconds gauge"])
        for (network, campaign), duration in sorted(recovery.items()):
            lines.append(f"attacknet_recovery_duration_seconds{{{_labels(network=network, campaign=campaign, evidence_source='orchestrator_observed')}}} {duration}")

        lines.extend([
            "# HELP attacknet_burnchain_policy_info Current external burnchain cadence policy.",
            "# TYPE attacknet_burnchain_policy_info gauge",
            "# HELP attacknet_burnchain_policy_interval_seconds Applied external burnchain cadence interval.",
            "# TYPE attacknet_burnchain_policy_interval_seconds gauge",
        ])
        for network, event in sorted(policy_states.items()):
            details = event["details"]
            labels = _labels(network=network, mode=details.get("mode", "unknown"), generation=details.get("generation", "unknown"), evidence_source="orchestrator_observed")
            lines.append(f"attacknet_burnchain_policy_info{{{labels}}} 1")
            lines.append(f"attacknet_burnchain_policy_interval_seconds{{{_labels(network=network, evidence_source='orchestrator_observed')}}} {_finite_number(details.get('intervalSeconds'), 0)}")

        lines.extend([
            "# HELP attacknet_run_info Active or latest recorded run identity and replay seed.",
            "# TYPE attacknet_run_info gauge",
            "# HELP attacknet_journal_last_event_timestamp_seconds Occurrence time of the latest event for the current run.",
            "# TYPE attacknet_journal_last_event_timestamp_seconds gauge",
        ])
        for network, event in sorted(latest_run.items()):
            seed = run_seeds.get((network, event["runId"]), "unknown")
            labels = _labels(network=network, run_id=event["runId"], seed=seed, phase=event["phase"], evidence_source="orchestrator_observed")
            lines.append(f"attacknet_run_info{{{labels}}} 1")
            lines.append(f"attacknet_journal_last_event_timestamp_seconds{{{_labels(network=network, run_id=event['runId'], evidence_source='orchestrator_observed')}}} {_parse_epoch(event['occurredAt'])}")
        lines.append("")
        return "\n".join(lines)


def _parse_epoch(value: str) -> float:
    try:
        # Python's parser accepts the RFC3339 Z form after this substitution.
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return time.time()


def _finite_number(value: Any, fallback: float) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else float(fallback)
    except (TypeError, ValueError):
        return float(fallback)


class EventServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], journal: Journal, token: str | Callable[[], str]):
        super().__init__(address, EventHandler)
        self.journal = journal
        self._token = token if callable(token) else lambda: token

    def current_token(self) -> str:
        token = self._token().strip()
        if len(token) < 32:
            raise RuntimeError("event token must contain at least 32 characters")
        return token


class EventHandler(BaseHTTPRequestHandler):
    server: EventServer

    def log_message(self, message_format: str, *args: Any) -> None:
        print(f"event-bridge {self.address_string()} {message_format % args}", flush=True)

    def _json(self, status: HTTPStatus, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "events": len(self.server.journal.events)})
            return
        if parsed.path == "/metrics":
            body = self.server.journal.prometheus().encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/v1/events":
            query = parse_qs(parsed.query)
            try:
                after = max(0, int(query.get("after", ["0"])[0]))
                limit = min(10_000, max(1, int(query.get("limit", ["1000"])[0])))
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "after and limit must be integers"})
                return
            self._json(HTTPStatus.OK, {"schemaVersion": SCHEMA_VERSION, "events": self.server.journal.snapshot(after, limit)})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/api/v1/events":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        authorization = self.headers.get("Authorization", "")
        try:
            # Kubernetes updates mounted Secret contents in place. Resolve the
            # token for every write so rotation does not wedge a long run.
            expected = f"Bearer {self.server.current_token()}"
        except (OSError, RuntimeError) as error:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error)})
            return
        if not hmac.compare_digest(authorization, expected):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid bearer token"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body must be within 1..256 KiB"})
            return
        try:
            candidate = json.loads(
                self.rfile.read(length),
                parse_constant=_reject_json_constant,
            )
            event, inserted = self.server.journal.append(candidate)
        except (json.JSONDecodeError, ValueError) as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        self._json(HTTPStatus.CREATED if inserted else HTTPStatus.OK, {"inserted": inserted, "event": event})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default=os.environ.get("ATTACKNET_EVENT_LISTEN", "0.0.0.0:9464"))
    parser.add_argument("--journal", default=os.environ.get("ATTACKNET_EVENT_JOURNAL", "/data/timeline.jsonl"))
    parser.add_argument("--token-file", default=os.environ.get("ATTACKNET_EVENT_TOKEN_FILE", "/run/secrets/attacknet/token"))
    arguments = parser.parse_args()
    host, port_text = arguments.listen.rsplit(":", 1)
    token_path = Path(arguments.token_file)
    # Validate startup eagerly, then resolve per request for projected-Secret
    # rotation. The token is deliberately never copied into actor Pods.
    if len(token_path.read_text(encoding="utf-8").strip()) < 32:
        raise SystemExit("event token must contain at least 32 characters")
    server = EventServer(
        (host, int(port_text)),
        Journal(Path(arguments.journal)),
        lambda: token_path.read_text(encoding="utf-8"),
    )
    print(f"attacknet event bridge listening on {host}:{port_text}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
