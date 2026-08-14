import copy
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(pathlib.Path(__file__).parent))
import controller  # noqa: E402


OWNER_UID = "00000000-0000-0000-0000-000000000001"


def owned_metadata(name, resource_version=None):
    metadata = {
        "name": name,
        "namespace": "hacknet",
        "ownerReferences": [{"controller": True, "uid": OWNER_UID}],
    }
    if resource_version is not None:
        metadata["resourceVersion"] = resource_version
    return metadata


def network_fixture():
    return {
        "apiVersion": "testing.stacks.org/v1alpha1",
        "kind": "StacksNetwork",
        "metadata": {
            "name": "demo",
            "namespace": "hacknet",
            "uid": OWNER_UID,
            "generation": 3,
        },
        "spec": {
            "defaults": {
                "nodeImage": "stacks-core:test",
                "signerImage": "stacks-signer:test",
                "imagePullPolicy": "Never",
                "storage": {"enabled": True, "size": "2Gi"},
            },
            "telemetry": {
                "enabled": True,
                "exporterEndpoint": "http://collector:4318",
                "tokenSecretRef": {"name": "federation-token", "key": "token"},
            },
            "actors": [
                {
                    "name": "miner-1",
                    "role": "miner",
                    "config": {
                        "inline": '[node]\nname = "${ACTOR}"\nbootstrap = "${SERVICE:companion-1}"\n',
                    },
                },
                {
                    "name": "companion-1",
                    "role": "companion",
                    "config": {"secretRef": {"name": "companion-config"}},
                    "dependencies": [{"actor": "miner-1", "port": 20443}],
                    "storage": {"enabled": False},
                },
                {
                    "name": "signer-1",
                    "role": "signer",
                    "image": "stacks-signer:old-version",
                    "config": {"configMapRef": {"name": "signer-config"}},
                    "telemetry": {"metricsPort": 31000},
                    "dependencies": [{"actor": "companion-1", "port": 20443}],
                },
            ],
        },
    }


class ResourceBuilderTests(unittest.TestCase):
    def test_builds_one_service_and_statefulset_per_actor(self):
        resources = controller.build_resources(network_fixture())
        self.assertEqual(len(resources["services"]), 3)
        self.assertEqual(len(resources["statefulsets"]), 3)
        self.assertTrue(all(service["spec"]["clusterIP"] == "None" for service in resources["services"]))
        # All actors have generated telemetry configuration, while miner-1 also
        # carries its inline Stacks config in the same generated ConfigMap.
        self.assertEqual(len(resources["configmaps"]), 3)
        miner_config = resources["configmaps"][0]
        self.assertIn('name = "miner-1"', miner_config["data"]["Config.toml"])
        self.assertIn('bootstrap = "demo-companion-1"', miner_config["data"]["Config.toml"])

    def test_no_port_actor_gets_a_valid_headless_service(self):
        fixture = network_fixture()
        fixture["spec"]["telemetry"]["enabled"] = False
        fixture["spec"]["actors"].append(
            {
                "name": "cadence",
                "role": "infrastructure",
                "image": "busybox:1.36.1",
                "command": ["sleep"],
                "args": ["infinity"],
            }
        )
        service = controller.build_resources(fixture)["services"][-1]
        self.assertEqual(service["spec"]["clusterIP"], "None")
        self.assertFalse(service["spec"]["publishNotReadyAddresses"])
        self.assertNotIn("ports", service["spec"])

    def test_runtime_exposure_can_publish_an_endpoint_before_readiness(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][2]["runtimeExposure"] = "reachable"
        service = controller.build_resources(fixture)["services"][2]
        self.assertTrue(service["spec"]["publishNotReadyAddresses"])

    def test_removed_dependencies_render_an_explicit_empty_init_container_list(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][0]["dependencies"] = []
        pod_spec = controller.build_resources(fixture)["statefulsets"][0]["spec"]["template"]["spec"]
        self.assertEqual(pod_spec["initContainers"], [])

    def test_actor_workload_has_identity_labels_persistence_and_sidecar(self):
        resources = controller.build_resources(network_fixture())
        miner = resources["statefulsets"][0]
        template = miner["spec"]["template"]
        self.assertEqual(template["metadata"]["labels"][controller.ROLE_LABEL], "miner")
        self.assertEqual(template["spec"]["containers"][0]["image"], "stacks-core:test")
        self.assertEqual(template["spec"]["containers"][1]["name"], "telemetry")
        self.assertEqual(
            template["spec"]["containers"][1]["env"][1]["valueFrom"]["secretKeyRef"]["name"],
            "federation-token",
        )
        self.assertEqual(miner["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"], "2Gi")
        self.assertEqual(
            miner["spec"]["persistentVolumeClaimRetentionPolicy"],
            {"whenDeleted": "Delete", "whenScaled": "Retain"},
        )
        self.assertFalse(template["spec"]["automountServiceAccountToken"])
        owner = miner["metadata"]["ownerReferences"][0]
        self.assertTrue(owner["controller"])
        self.assertNotIn("blockOwnerDeletion", owner)

    def test_secret_config_is_mounted_without_operator_read_access(self):
        fixture = network_fixture()
        fixture["spec"]["telemetry"]["enabled"] = False
        resources = controller.build_resources(fixture)
        companion = resources["statefulsets"][1]
        volumes = companion["spec"]["template"]["spec"]["volumes"]
        self.assertIn({"name": "actor-config", "secret": {"secretName": "companion-config"}}, volumes)
        self.assertNotIn("secrets", " ".join(controller.KubernetesClient.collection_path(kind, "ns") for kind in ("services", "configmaps")))

    def test_multi_file_config_and_scheduler_controls_are_preserved(self):
        fixture = network_fixture()
        fixture["spec"]["defaults"].update({
            "nodeSelector": {"kubernetes.io/os": "linux"},
            "topologySpreadConstraints": [{
                "maxSkew": 1,
                "topologyKey": "kubernetes.io/hostname",
                "whenUnsatisfiable": "ScheduleAnyway",
                "labelSelector": {"matchLabels": {controller.NETWORK_LABEL: "demo"}},
            }],
        })
        actor = fixture["spec"]["actors"][0]
        actor["config"] = {
            "files": {
                "Config.toml": 'name = "${ACTOR}"',
                "start.sh": '#!/bin/sh\necho "${SERVICE:companion-1}"\n',
            },
            "key": "Config.toml",
            "mountPath": "/opt/hacknet",
        }
        actor["command"] = ["sh", "/opt/hacknet/start.sh"]
        actor["workingDir"] = "/opt/hacknet"
        actor["startupProbe"] = {"exec": {"command": ["test", "-f", "/opt/hacknet/start.sh"]}}
        actor["terminationGracePeriodSeconds"] = 45

        resources = controller.build_resources(fixture)
        config = resources["configmaps"][0]
        self.assertEqual(config["data"]["Config.toml"], 'name = "miner-1"')
        self.assertIn("demo-companion-1", config["data"]["start.sh"])
        pod = resources["statefulsets"][0]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(container["workingDir"], "/opt/hacknet")
        self.assertIn("startupProbe", container)
        self.assertEqual(pod["terminationGracePeriodSeconds"], 45)
        self.assertEqual(pod["nodeSelector"], {"kubernetes.io/os": "linux"})
        self.assertEqual(pod["topologySpreadConstraints"][0]["maxSkew"], 1)

    def test_multi_file_config_rejects_invalid_keys_and_non_text_values(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][0]["config"] = {"files": {"../start.sh": "echo no"}}
        with self.assertRaisesRegex(controller.ValidationError, "invalid ConfigMap key"):
            controller.build_resources(fixture)
        fixture["spec"]["actors"][0]["config"] = {"files": {"start.sh": 7}}
        with self.assertRaisesRegex(controller.ValidationError, "must be text"):
            controller.build_resources(fixture)

    def test_runtime_policy_is_a_separate_hot_reloadable_config_map(self):
        fixture = network_fixture()
        actor = fixture["spec"]["actors"][0]
        actor["runtimePolicy"] = {
            "configMapRef": {"name": "demo-burnchain-policy"},
            "mountPath": "/run/policy",
        }
        pod = controller.build_resources(fixture)["statefulsets"][0]["spec"]["template"]["spec"]
        self.assertIn({
            "name": "runtime-policy",
            "configMap": {"name": "demo-burnchain-policy", "optional": False},
        }, pod["volumes"])
        self.assertIn({
            "name": "runtime-policy", "mountPath": "/run/policy", "readOnly": True,
        }, pod["containers"][0]["volumeMounts"])

        actor["runtimePolicy"]["configMapRef"]["name"] = "../operator-source"
        with self.assertRaisesRegex(controller.ValidationError, "invalid runtime policy"):
            controller.build_resources(fixture)

    def test_dependency_init_container_uses_stable_service_name(self):
        resources = controller.build_resources(network_fixture())
        signer = resources["statefulsets"][2]
        init = signer["spec"]["template"]["spec"]["initContainers"][0]
        self.assertIn("nc -z demo-companion-1 20443", init["command"][2])

    def test_mixed_version_override_is_preserved(self):
        resources = controller.build_resources(network_fixture())
        signer = resources["statefulsets"][2]
        self.assertEqual(signer["spec"]["template"]["spec"]["containers"][0]["image"], "stacks-signer:old-version")

    def test_suspension_scales_to_zero(self):
        fixture = network_fixture()
        fixture["spec"]["suspended"] = True
        resources = controller.build_resources(fixture)
        self.assertTrue(all(item["spec"]["replicas"] == 0 for item in resources["statefulsets"]))

    def test_rejects_ambiguous_config_source(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][0]["config"]["secretRef"] = {"name": "also-secret"}
        with self.assertRaisesRegex(controller.ValidationError, "exactly one source"):
            controller.build_resources(fixture)

    def test_rejects_unknown_dependency_and_missing_telemetry_endpoint(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][1]["dependencies"] = [{"actor": "ghost", "port": 1}]
        with self.assertRaisesRegex(controller.ValidationError, "unknown actor"):
            controller.build_resources(fixture)
        fixture = network_fixture()
        del fixture["spec"]["telemetry"]["exporterEndpoint"]
        with self.assertRaisesRegex(controller.ValidationError, "without exporterEndpoint"):
            controller.build_resources(fixture)

    def test_rejects_dependency_port_not_exposed_by_target(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][1]["dependencies"] = [{"actor": "miner-1", "port": 9}]
        with self.assertRaisesRegex(controller.ValidationError, "target does not expose"):
            controller.build_resources(fixture)

    def test_stable_name_is_bounded_and_deterministic(self):
        first = controller.stable_name("n" * 63, "a" * 40)
        second = controller.stable_name("n" * 63, "a" * 40)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 63)


class FakeApi:
    def __init__(self):
        self.objects = {kind: {} for kind in ("configmaps", "services", "statefulsets")}
        self.ready = set()
        self.statuses = []
        self.deleted = []

    def apply_resource(self, kind, resource):
        self.objects[kind][resource["metadata"]["name"]] = copy.deepcopy(resource)

    def list_managed(self, kind, _namespace, network):
        return [
            item
            for item in self.objects[kind].values()
            if item["metadata"]["labels"].get(controller.NETWORK_LABEL) == network
        ]

    def delete_resource(self, kind, _namespace, name):
        self.deleted.append((kind, name))
        self.objects[kind].pop(name, None)

    def get_stateful_set(self, _namespace, name):
        item = copy.deepcopy(self.objects["statefulsets"].get(name))
        if item is not None:
            item["metadata"]["generation"] = 1
            revision = f"{name}-revision"
            item["status"] = {
                "observedGeneration": 1,
                "readyReplicas": 1 if name in self.ready else 0,
                "updatedReplicas": 1 if name in self.ready else 0,
                "currentRevision": revision if name in self.ready else None,
                "updateRevision": revision,
            }
        return item

    def patch_status(self, _namespace, _name, status):
        self.statuses.append(copy.deepcopy(status))


class ReconcilerTests(unittest.TestCase):
    def test_reconcile_applies_prunes_and_reports_readiness(self):
        fixture = network_fixture()
        api = FakeApi()
        stale = {
            "metadata": {
                "name": "demo-stale",
                "labels": {
                    controller.NETWORK_LABEL: "demo",
                    controller.MANAGED_LABEL: controller.MANAGED_BY,
                },
            }
        }
        api.objects["services"]["demo-stale"] = stale
        reconciler = controller.Reconciler(api)
        reconciler.reconcile(fixture)
        self.assertIn(("services", "demo-stale"), api.deleted)
        self.assertEqual(api.statuses[-1]["phase"], "Progressing")
        self.assertEqual(api.statuses[-1]["readySummary"], "0/3")

        api.ready.update(api.objects["statefulsets"])
        fixture["status"] = api.statuses[-1]
        reconciler.reconcile(fixture)
        self.assertEqual(api.statuses[-1]["phase"], "Ready")
        self.assertEqual(api.statuses[-1]["readySummary"], "3/3")

    def test_invalid_resource_is_reported_as_degraded(self):
        fixture = network_fixture()
        fixture["spec"]["actors"][0]["image"] = ""
        del fixture["spec"]["defaults"]["nodeImage"]
        api = FakeApi()
        with self.assertLogs(level="ERROR"):
            controller.Reconciler(api).reconcile(fixture)
        self.assertEqual(api.statuses[-1]["phase"], "Degraded")
        self.assertEqual(api.statuses[-1]["conditions"][0]["reason"], "ReconcileFailed")

    def test_unchanged_condition_preserves_transition_time(self):
        previous = [{
            "type": "Ready",
            "status": "False",
            "reason": "ActorsNotReady",
            "message": "0 of 3 actors are ready",
            "lastTransitionTime": "2026-01-01T00:00:00Z",
        }]
        current = controller.condition("Ready", "False", "ActorsNotReady", "0 of 3 actors are ready", previous)
        self.assertEqual(current["lastTransitionTime"], "2026-01-01T00:00:00Z")

    def test_ready_replicas_from_a_previous_revision_do_not_report_ready(self):
        fixture = network_fixture()
        api = FakeApi()
        for resource in controller.build_resources(fixture)["statefulsets"]:
            api.objects["statefulsets"][resource["metadata"]["name"]] = resource
        api.ready.update(api.objects["statefulsets"])
        original = api.get_stateful_set

        def stale_rollout(namespace, name):
            item = original(namespace, name)
            item["metadata"]["generation"] = 2
            item["status"]["observedGeneration"] = 1
            item["status"]["currentRevision"] = f"{name}-old"
            item["status"]["updateRevision"] = f"{name}-new"
            return item

        api.get_stateful_set = stale_rollout
        status = controller.build_status(fixture, api)
        self.assertEqual(status["phase"], "Progressing")
        self.assertEqual(status["readyActors"], 0)


class RecordingKubernetesClient(controller.KubernetesClient):
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, path, body=None, *, content_type="application/json"):
        self.requests.append((method, path, copy.deepcopy(body), content_type))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)


class KubernetesClientTests(unittest.TestCase):
    def test_existing_configmap_is_replaced_to_remove_stale_keys(self):
        client = RecordingKubernetesClient([
            {"metadata": owned_metadata("demo-config", "17"), "data": {"stale": "value"}},
            {},
        ])
        resource = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": owned_metadata("demo-config"),
            "data": {"current": "value"},
        }
        client.apply_resource("configmaps", resource)
        method, _path, replacement, _content_type = client.requests[-1]
        self.assertEqual(method, "PUT")
        self.assertEqual(replacement["metadata"]["resourceVersion"], "17")
        self.assertNotIn("stale", replacement["data"])

    def test_missing_resource_is_created(self):
        not_found = controller.ApiError(404, "GET", "/missing", "not found")
        client = RecordingKubernetesClient([not_found, {}])
        resource = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": owned_metadata("demo"),
            "spec": {"ports": []},
        }
        client.apply_resource("services", resource)
        self.assertEqual([request[0] for request in client.requests], ["GET", "POST"])

    def test_create_conflict_retries_and_updates_the_winner(self):
        conflict = controller.ApiError(409, "POST", "/services", "already exists")
        not_found = controller.ApiError(404, "GET", "/demo", "not found")
        client = RecordingKubernetesClient([
            not_found,
            conflict,
            {"metadata": owned_metadata("demo", "18")},
            {},
        ])
        resource = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": owned_metadata("demo"),
            "spec": {"ports": []},
        }
        client.apply_resource("services", resource)
        self.assertEqual([request[0] for request in client.requests], ["GET", "POST", "GET", "PATCH"])

    def test_configmap_update_conflict_reloads_resource_version(self):
        conflict = controller.ApiError(409, "PUT", "/config", "resource version changed")
        client = RecordingKubernetesClient([
            {"metadata": owned_metadata("demo-config", "17")},
            conflict,
            {"metadata": owned_metadata("demo-config", "18")},
            {},
        ])
        resource = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": owned_metadata("demo-config"),
            "data": {"current": "value"},
        }
        client.apply_resource("configmaps", resource)
        self.assertEqual([request[0] for request in client.requests], ["GET", "PUT", "GET", "PUT"])
        self.assertEqual(client.requests[-1][2]["metadata"]["resourceVersion"], "18")

    def test_refuses_to_adopt_a_name_collision(self):
        client = RecordingKubernetesClient([
            {"metadata": {"name": "demo", "namespace": "hacknet"}},
        ])
        resource = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": owned_metadata("demo"),
            "spec": {"ports": []},
        }
        with self.assertRaisesRegex(controller.OwnershipError, "refusing to adopt"):
            client.apply_resource("services", resource)

    def test_dev_source_configmap_name_collision_cannot_replace_operator_source(self):
        # Helm release `hacknet` owns this ConfigMap. A StacksNetwork named
        # `hacknet` with actor `development-source` resolves to the same name.
        # The owner-UID guard is therefore a security boundary, not merely a
        # same-name recreation convenience.
        client = RecordingKubernetesClient([
            {
                "metadata": {
                    "name": "hacknet-development-source",
                    "namespace": "hacknet",
                    "labels": {"app.kubernetes.io/managed-by": "Helm"},
                },
                "data": {"controller.py": "trusted chart source"},
            },
        ])
        resource = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": owned_metadata("hacknet-development-source"),
            "data": {"Config.toml": "attacker-controlled actor config"},
        }
        with self.assertRaisesRegex(controller.OwnershipError, "refusing to adopt"):
            client.apply_resource("configmaps", resource)
        self.assertEqual([request[0] for request in client.requests], ["GET"])

    def test_request_reads_rotated_service_account_token_each_time(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"{}"

        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as token_file:
            token_file.write("first-token")
            token_file.flush()
            client = object.__new__(controller.KubernetesClient)
            client.base_url = "https://kubernetes.invalid"
            client.token_path = token_file.name
            client.ssl_context = None
            client.progress_callback = None
            with mock.patch.object(controller.urllib.request, "urlopen", side_effect=[Response(), Response()]) as urlopen:
                client.request("GET", "/first")
                token_file.seek(0)
                token_file.truncate()
                token_file.write("second-token")
                token_file.flush()
                client.request("GET", "/second")
            first_request = urlopen.call_args_list[0].args[0]
            second_request = urlopen.call_args_list[1].args[0]
            self.assertEqual(first_request.get_header("Authorization"), "Bearer first-token")
            self.assertEqual(second_request.get_header("Authorization"), "Bearer second-token")


class HealthStateTests(unittest.TestCase):
    def test_liveness_tracks_loop_progress_not_api_readiness(self):
        now = [100.0]
        state = controller.HealthState(30.0, clock=lambda: now[0])
        state.ready = False
        self.assertTrue(state.is_live())
        now[0] = 131.0
        self.assertFalse(state.is_live())
        state.mark_progress()
        self.assertTrue(state.is_live())
        state.running = False
        self.assertFalse(state.is_live())


if __name__ == "__main__":
    unittest.main()
