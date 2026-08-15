import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from event_bridge import EventServer, Journal


TOKEN = "a" * 64


class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "timeline.jsonl"
        self.server = EventServer(("127.0.0.1", 0), Journal(self.path), TOKEN)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, payload=None, token=TOKEN):
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request) as response:
            return response.status, response.read().decode(), dict(response.headers)

    def event(self, **overrides):
        value = {
            "eventId": "campaign-1/injected/miner-1",
            "runId": "run-123",
            "network": "attacknet",
            "kind": "fault.injected",
            "phase": "fault-active",
            "campaign": "delay-miner",
            "actor": "miner-1",
            "role": "miner",
            "faultType": "network",
            "details": {"delayMs": 500},
        }
        value.update(overrides)
        return value

    def test_authenticated_idempotent_append_survives_restart(self):
        status, body, _ = self.request("POST", "/api/v1/events", self.event())
        self.assertEqual(status, 201)
        first = json.loads(body)["event"]
        self.assertEqual(first["sequence"], 1)

        status, body, _ = self.request("POST", "/api/v1/events", self.event())
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["inserted"])
        self.assertEqual(len(self.server.journal.events), 1)

        reloaded = Journal(self.path)
        self.assertEqual(reloaded.events, self.server.journal.events)
        _, inserted = reloaded.append(self.event())
        self.assertFalse(inserted)

    def test_unauthenticated_writer_cannot_forge_timeline(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("POST", "/api/v1/events", self.event(), token=None)
        self.assertEqual(context.exception.code, 401)
        context.exception.close()
        self.assertEqual(self.server.journal.events, [])

    def test_writer_token_is_resolved_per_request(self):
        current = {"token": TOKEN}
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = EventServer(("127.0.0.1", 0), Journal(self.path), lambda: current["token"])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.request("POST", "/api/v1/events", self.event(eventId="before-rotation"))
        current["token"] = "b" * 64
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("POST", "/api/v1/events", self.event(eventId="stale-token"), token=TOKEN)
        self.assertEqual(context.exception.code, 401)
        context.exception.close()
        status, _, _ = self.request("POST", "/api/v1/events", self.event(eventId="after-rotation"), token=current["token"])
        self.assertEqual(status, 201)

    def test_metrics_project_fault_policy_invariant_actor_and_recovery_state(self):
        events = [
            self.event(eventId="run", kind="run.started", phase="setup", actor=None, campaign=None, faultType=None, details={"seed": "12" * 32}),
            self.event(eventId="policy", kind="policy.changed", phase="baseline", actor=None, campaign=None, faultType=None, details={"mode": "run", "generation": 7, "intervalSeconds": 20}),
            self.event(eventId="invariant", kind="invariant.observed", phase="verification", actor="signer-1", campaign=None, faultType=None, outcome="pass", details={"name": "height-cohort", "passed": True, "value": 10}),
            self.event(
                eventId="actor", kind="actor.state", phase="baseline", actor="signer-1",
                role="signer", campaign=None, faultType=None,
                details={
                    "ready": True, "restarts": 2, "node": "worker-2", "phase": "Running",
                    "containers": [
                        {"name": "telemetry", "requestedImage": "collector:1", "imageId": "sha256:sidecar"},
                        {
                            "name": "actor", "requestedImage": "stacks-signer:4.0.2",
                            "imageId": "sha256:resolved", "ready": True, "restarts": 2,
                        },
                    ],
                },
            ),
            self.event(eventId="clear", kind="fault.cleared", phase="recovering"),
            self.event(eventId="recovery", kind="recovery.complete", phase="verification", actor=None, faultType=None, details={"durationSeconds": 8.5}),
        ]
        for event in events:
            self.request("POST", "/api/v1/events", event)
        status, metrics, headers = self.request("GET", "/metrics", token=None)
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers["Content-Type"])
        self.assertIn('attacknet_fault_active{actor="miner-1",campaign="delay-miner"', metrics)
        self.assertIn('attacknet_invariant_pass{actor="signer-1",evidence_source="orchestrator_observed",invariant="height-cohort",network="attacknet"} 1', metrics)
        self.assertIn('attacknet_actor_restarts{actor="signer-1",evidence_source="orchestrator_observed",network="attacknet"} 2.0', metrics)
        self.assertIn('attacknet_actor_info{actor="signer-1",evidence_source="orchestrator_observed",image_id="sha256:resolved",network="attacknet",node="worker-2",phase="Running",requested_image="stacks-signer:4.0.2",role="signer"} 1', metrics)
        self.assertIn('attacknet_recovery_duration_seconds{campaign="delay-miner",evidence_source="orchestrator_observed",network="attacknet"} 8.5', metrics)
        self.assertIn('attacknet_burnchain_policy_info{evidence_source="orchestrator_observed",generation="7",mode="run",network="attacknet"} 1', metrics)
        self.assertIn('attacknet_run_info{evidence_source="orchestrator_observed",network="attacknet",phase="verification",run_id="run-123",seed="' + "12" * 32 + '"} 1', metrics)

    def test_projected_state_does_not_leak_from_an_older_run(self):
        self.request("POST", "/api/v1/events", self.event(eventId="old-injection"))
        self.request("POST", "/api/v1/events", self.event(
            eventId="new-run",
            runId="run-456",
            kind="run.started",
            phase="setup",
            actor=None,
            campaign=None,
            faultType=None,
            details={"seed": "34" * 32},
        ))
        _, metrics, _ = self.request("GET", "/metrics", token=None)
        self.assertNotIn("attacknet_fault_active{", metrics)
        self.assertIn('run_id="run-456"', metrics)

    def test_invalid_observation_time_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("POST", "/api/v1/events", self.event(occurredAt="yesterday-ish"))
        self.assertEqual(context.exception.code, 400)
        context.exception.close()

    def test_run_seed_matches_the_canonical_opaque_seed_contract(self):
        event = self.event(
            eventId="run-decimal-seed",
            kind="run.started",
            phase="setup",
            actor=None,
            campaign=None,
            faultType=None,
            details={"seed": "18446744073709551615"},
        )
        status, _, _ = self.request("POST", "/api/v1/events", event)
        self.assertEqual(status, 201)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("POST", "/api/v1/events", self.event(
                eventId="run-empty-seed", kind="run.started", phase="setup",
                actor=None, campaign=None, faultType=None, details={"seed": ""},
            ))
        self.assertEqual(context.exception.code, 400)
        context.exception.close()

    def test_lifecycle_and_incident_events_use_bounded_active_harness_phases(self):
        lifecycle = self.event(
            eventId="run-finished", kind="run.finished", phase="teardown",
            actor=None, campaign=None, faultType=None, outcome="aborted",
            details={"status": "aborted"},
        )
        incident = self.event(
            eventId="incident", kind="incident.opened", phase="incident",
            actor=None, campaign=None, faultType=None,
            details={"reason": "post-chaos progress failed"},
        )
        self.assertEqual(self.request("POST", "/api/v1/events", lifecycle)[0], 201)
        self.assertEqual(self.request("POST", "/api/v1/events", incident)[0], 201)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("POST", "/api/v1/events", self.event(
                eventId="bad-phase", kind="note", phase="agent-invented", details={},
            ))
        self.assertEqual(context.exception.code, 400)
        context.exception.close()

    def test_validation_rejects_unbounded_or_unknown_labels(self):
        bad = self.event(kind="totally.unknown")
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("POST", "/api/v1/events", bad)
        self.assertEqual(context.exception.code, 400)
        context.exception.close()
        self.assertEqual(self.server.journal.events, [])


if __name__ == "__main__":
    unittest.main()
