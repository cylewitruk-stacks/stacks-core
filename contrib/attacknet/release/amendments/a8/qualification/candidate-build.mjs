const immutableDigest = /^sha256:[0-9a-f]{64}$/;

export const A8_BUILD_PURPOSES = Object.freeze([
  'topology-operator', 'run-operator', 'burnchain-clock', 'probe', 'io-pressure', 'stacks-core',
]);

export const A8_INSTALLED_PURPOSES = Object.freeze([
  'topology-operator', 'run-operator', 'burnchain-clock', 'probe', 'io-pressure',
]);

const installedPurposes = new Set(A8_INSTALLED_PURPOSES);

function fail(message) {
  throw new Error(message);
}

function indexedImages(images, label) {
  if (!Array.isArray(images)) fail(`${label} does not contain images`);
  const result = new Map();
  for (const image of images) {
    if (!A8_BUILD_PURPOSES.includes(image?.purpose) || result.has(image.purpose)) {
      fail(`${label} contains an unknown or duplicate image purpose`);
    }
    const id = image.id ?? image.immutableID;
    if (!immutableDigest.test(id ?? '')) fail(`${label} ${image.purpose} image ID is not immutable`);
    result.set(image.purpose, id);
  }
  return result;
}

function validateKindLoad(load, expectedRefs, expectedNodes = undefined) {
  if (load?.schemaVersion !== 'stacks-attacknet-kind-image-load/v1'
    || load.outcome !== 'Loaded' || load.nodes?.length !== 3
    || load.nodes.some(node => node.architecture !== 'arm64')
    || !Array.isArray(load.images) || load.images.some(image => image.verified !== true)) {
    fail('candidate build receipt does not prove image admission on all three arm64 kind nodes');
  }
  const nodes = new Set(load.nodes.map(node => node.name));
  if (nodes.size !== load.nodes.length
    || (expectedNodes && (nodes.size !== expectedNodes.size || [...nodes].some(node => !expectedNodes.has(node))))) {
    fail('candidate build receipt contains an inconsistent kind node inventory');
  }
  const expectedPairs = new Set([...nodes].flatMap(node => [...expectedRefs].map(ref => `${node}\0${ref}`)));
  const observedPairs = new Set();
  const runtimeByRef = new Map();
  for (const image of load.images) {
    const key = `${image.node}\0${image.requestedRef}`;
    if (!expectedPairs.has(key) || observedPairs.has(key)
      || !immutableDigest.test(image.runtimeImageID ?? '')) {
      fail('candidate build receipt contains unknown, duplicate, or mismatched kind image admission');
    }
    const observedRuntime = runtimeByRef.get(image.requestedRef);
    if (observedRuntime && observedRuntime !== image.runtimeImageID) {
      fail('candidate build receipt contains inconsistent runtime image identity across kind nodes');
    }
    runtimeByRef.set(image.requestedRef, image.runtimeImageID);
    observedPairs.add(key);
  }
  if (observedPairs.size !== expectedPairs.size) {
    fail('candidate build receipt has incomplete kind image admission');
  }
  return {nodes, runtimeByRef};
}

function validateReceipt(value, qualifiedTree) {
  if (value?.schemaVersion !== 'stacks-attacknet-a8-candidate-build/v1'
    || value.qualifiedTree !== qualifiedTree
    || !Number.isFinite(Date.parse(value.capturedAt ?? ''))) {
    fail('candidate build receipt does not pin the qualified tree');
  }
  if (value.build?.schemaVersion !== 'stacks-attacknet-local-build/v1'
    || value.install?.schemaVersion !== 'stacks-attacknet-local-install/v1') {
    fail('candidate build receipt does not contain supported build and install receipts');
  }
  const built = indexedImages(value.build.images, 'candidate build');
  const installed = indexedImages(value.install.images, 'candidate install');
  if (built.size !== A8_BUILD_PURPOSES.length || installed.size !== installedPurposes.size) {
    fail('candidate build receipt has an incomplete image inventory');
  }
  for (const purpose of installedPurposes) {
    if (installed.get(purpose) !== built.get(purpose)) {
      fail(`candidate install did not use the built ${purpose} image`);
    }
  }
  const installLoad = validateKindLoad(
    value.install.kindImageLoad,
    new Set(value.install.images.map(image => image.deploymentRef)),
  );
  const stacks = value.actorImage;
  if (stacks?.purpose !== 'stacks-core' || stacks.ref !== builtImage(value.build.images, 'stacks-core')?.ref
    || stacks.immutableID !== built.get('stacks-core')) {
    fail('candidate build receipt does not bind the Stacks actor image');
  }
  const actorLoad = validateKindLoad(value.actorImageLoad, new Set([stacks.ref]), installLoad.nodes);
  const runOperatorImageID = built.get('run-operator');
  if (value.runOperatorImageID !== runOperatorImageID) {
    fail('candidate build receipt has an inconsistent run-operator image ID');
  }
  return {installLoad, actorLoad};
}

/** Validate the exact image build and kind admission used by qualification. */
export function validateCandidateBuildReceipt(value, qualifiedTree) {
  validateReceipt(value, qualifiedTree);
  return value;
}

/** Resolve each purpose to its uniform admitted platform image identity. */
export function candidateRuntimeImageIDs(value, qualifiedTree) {
  const {installLoad, actorLoad} = validateReceipt(value, qualifiedTree);
  const result = new Map(value.install.images.map(image => [
    image.purpose, installLoad.runtimeByRef.get(image.deploymentRef),
  ]));
  result.set('stacks-core', actorLoad.runtimeByRef.get(value.actorImage.ref));
  return result;
}

function builtImage(images, purpose) {
  return images.find(image => image.purpose === purpose);
}
