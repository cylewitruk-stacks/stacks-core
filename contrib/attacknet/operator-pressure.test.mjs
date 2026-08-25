import assert from 'node:assert/strict';
import test from 'node:test';

import {pressureDelta} from './operator-pressure.mjs';

const metrics = ({get, patch, throttled = 0, count, duration, last, started = 1000}) => `
hacknet_operator_process_start_time_seconds ${started}
hacknet_operator_api_requests_total{method="GET",code="200"} ${get}
hacknet_operator_api_requests_total{method="PATCH",code="200"} ${patch}
hacknet_operator_api_requests_total{method="GET",code="429"} ${throttled}
hacknet_operator_api_request_duration_seconds_count ${get + patch + throttled}
hacknet_operator_api_request_duration_seconds_sum ${(get + patch + throttled) / 10}
hacknet_operator_reconcile_duration_seconds_count ${count}
hacknet_operator_reconcile_duration_seconds_sum ${duration}
hacknet_operator_reconcile_duration_seconds_max 1.5
hacknet_operator_reconcile_last_duration_seconds ${last}
hacknet_operator_reconcile_last_api_requests 7
`;

test('reports bounded API and reconcile deltas for one capacity stage', () => {
  const result = pressureDelta(
    metrics({get: 10, patch: 2, count: 2, duration: 1, last: 0.4}),
    metrics({get: 30, patch: 7, count: 5, duration: 4, last: 0.8}),
  );
  assert.equal(result.ok, true);
  assert.equal(result.api.requestCount, 25);
  assert.equal(result.process.stable, true);
  assert.equal(result.api.meanDurationSeconds, 0.1);
  assert.equal(result.reconcile.count, 3);
  assert.equal(result.reconcile.meanDurationSeconds, 1);
  assert.equal(result.reconcile.lastApiRequests, 7);
});

test('an operator restart invalidates counter deltas for the stage', () => {
  const result = pressureDelta(
    metrics({get: 10, patch: 2, count: 2, duration: 1, last: 0.4, started: 1000}),
    metrics({get: 2, patch: 1, count: 1, duration: 0.5, last: 0.5, started: 2000}),
  );
  assert.equal(result.ok, false);
  assert.equal(result.process.stable, false);
});

test('429, 5xx, or transport errors fail the pressure gate', () => {
  const before = metrics({get: 0, patch: 0, count: 0, duration: 0, last: 0});
  const after = `${metrics({get: 1, patch: 0, throttled: 1, count: 1, duration: 1, last: 1})}
hacknet_operator_api_requests_total{method="GET",code="503"} 2
hacknet_operator_api_requests_total{method="GET",code="error"} 1
`;
  const result = pressureDelta(before, after);
  assert.equal(result.ok, false);
  assert.equal(result.api.throttled, 1);
  assert.equal(result.api.serverErrors, 2);
  assert.equal(result.api.transportErrors, 1);
});

const controllerRuntimeMetrics = ({get, patch, throttled = 0, errors = 0, count, duration, started = 1000}) => `
process_start_time_seconds ${started}
rest_client_requests_total{method="GET",code="200",host="kubernetes.default.svc"} ${get}
rest_client_requests_total{method="PATCH",code="200",host="kubernetes.default.svc"} ${patch}
rest_client_requests_total{method="GET",code="429",host="kubernetes.default.svc"} ${throttled}
rest_client_requests_total{method="GET",code="<error>",host="kubernetes.default.svc"} ${errors}
controller_runtime_reconcile_time_seconds_count{controller="stacksnetwork"} ${count}
controller_runtime_reconcile_time_seconds_sum{controller="stacksnetwork"} ${duration}
`;

test('uses controller-runtime metrics without inventing unavailable diagnostics', () => {
  const result = pressureDelta(
    controllerRuntimeMetrics({get: 10, patch: 2, count: 2, duration: 1}),
    controllerRuntimeMetrics({get: 30, patch: 7, count: 5, duration: 4}),
  );
  assert.equal(result.ok, true);
  assert.equal(result.metricContract, 'controller-runtime');
  assert.equal(result.api.requestCount, 25);
  assert.equal(result.api.durationObserved, false);
  assert.equal(result.api.durationSeconds, null);
  assert.equal(result.reconcile.count, 3);
  assert.equal(result.reconcile.meanDurationSeconds, 1);
  assert.equal(result.reconcile.lastApiRequests, null);
});

test('aggregates controller-runtime API counters across bounded hosts', () => {
  const before = `${controllerRuntimeMetrics({get: 1, patch: 0, count: 0, duration: 0})}
rest_client_requests_total{method="GET",code="200",host="other"} 2
`;
  const after = `${controllerRuntimeMetrics({get: 4, patch: 0, count: 1, duration: 0.5})}
rest_client_requests_total{method="GET",code="200",host="other"} 7
`;
  assert.equal(pressureDelta(before, after).api.byMethodCode['GET:200'], 8);
});
