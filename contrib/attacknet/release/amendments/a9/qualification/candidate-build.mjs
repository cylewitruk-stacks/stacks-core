const immutableDigest = /^sha256:[0-9a-f]{64}$/;

export const A9_BUILD_PURPOSES = Object.freeze([
  'topology-operator', 'run-operator', 'burnchain-clock', 'probe', 'io-pressure',
  'stacker', 'stacks-core',
]);

export const A9_INSTALLED_PURPOSES = Object.freeze([
  'topology-operator', 'run-operator', 'burnchain-clock', 'probe', 'io-pressure',
]);

function fail(message) {
  throw new Error(message);
}

function indexedImages(images, expected, label) {
  if (!Array.isArray(images)) fail(`${label} does not contain images`);
  const result = new Map();
  for (const image of images) {
    if (!expected.includes(image?.purpose) || result.has(image.purpose)) {
      fail(`${label} contains an unknown or duplicate image purpose`);
    }
    const id = image.id ?? image.immutableID;
    if (!immutableDigest.test(id ?? '')) fail(`${label} ${image.purpose} image ID is not immutable`);
    result.set(image.purpose, {id, ref: image.ref ?? image.deploymentRef});
  }
  if (result.size !== expected.length) fail(`${label} has an incomplete image inventory`);
  return result;
}

function validateKindLoad(load, expectedRefs, expectedNodes = undefined) {
  if (load?.schemaVersion !== 'stacks-attacknet-kind-image-load/v1'
    || load.outcome !== 'Loaded' || load.nodes?.length !== 3
    || load.nodes.some(node => node.architecture !== 'arm64')
    || !Array.isArray(load.images) || load.images.some(image => image.verified !== true)) {
    fail('candidate receipt does not prove image admission on three arm64 kind nodes');
  }
  const nodes = new Set(load.nodes.map(node => node.name));
  if (nodes.size !== 3
    || (expectedNodes && (nodes.size !== expectedNodes.size
      || [...nodes].some(node => !expectedNodes.has(node))))) {
    fail('candidate receipt contains an inconsistent kind node inventory');
  }
  const expectedPairs = new Set([...nodes].flatMap(node => [...expectedRefs].map(ref => `${node}\0${ref}`)));
  const observedPairs = new Set();
  const runtimeByRef = new Map();
  for (const image of load.images) {
    const key = `${image.node}\0${image.requestedRef}`;
    if (!expectedPairs.has(key) || observedPairs.has(key)
      || !immutableDigest.test(image.runtimeImageID ?? '')) {
      fail('candidate receipt contains an unknown, duplicate, or mutable image admission');
    }
    const current = runtimeByRef.get(image.requestedRef);
    if (current && current !== image.runtimeImageID) fail('runtime image identity differs across kind nodes');
    runtimeByRef.set(image.requestedRef, image.runtimeImageID);
    observedPairs.add(key);
  }
  if (observedPairs.size !== expectedPairs.size) fail('kind image admission is incomplete');
  return {nodes, runtimeByRef};
}

/** Validate the exact image build and kind admission used by A9 qualification. */
export function validateA9CandidateBuild(value, qualifiedTree) {
  if (value?.schemaVersion !== 'stacks-attacknet-a9-candidate-build/v1'
    || value.qualifiedTree !== qualifiedTree
    || !Number.isFinite(Date.parse(value.capturedAt ?? ''))
    || value.build?.schemaVersion !== 'stacks-attacknet-local-build/v1'
    || value.install?.schemaVersion !== 'stacks-attacknet-local-install/v1') {
    fail('A9 candidate build does not pin the qualified tree');
  }
  const built = indexedImages(value.build.images, A9_BUILD_PURPOSES, 'candidate build');
  const installed = indexedImages(value.install.images, A9_INSTALLED_PURPOSES, 'candidate install');
  for (const purpose of A9_INSTALLED_PURPOSES) {
    if (installed.get(purpose).id !== built.get(purpose).id) {
      fail(`candidate install did not use built ${purpose}`);
    }
  }
  const installLoad = validateKindLoad(
    value.install.kindImageLoad,
    new Set(value.install.images.map(image => image.deploymentRef)),
  );
  const actors = new Map((value.actorImages ?? []).map(image => [image?.purpose, image]));
  if (actors.size !== 2 || !actors.has('stacks-core') || !actors.has('stacker')) {
    fail('candidate receipt must contain Stacks and stacker actor images');
  }
  const actorRefs = new Set();
  for (const purpose of ['stacks-core', 'stacker']) {
    const actor = actors.get(purpose);
    if (actor.ref !== built.get(purpose).ref || actor.immutableID !== built.get(purpose).id) {
      fail(`candidate receipt does not bind ${purpose}`);
    }
    actorRefs.add(actor.ref);
  }
  const actorLoad = validateKindLoad(value.actorImageLoad, actorRefs, installLoad.nodes);
  if (value.runOperatorImageID !== built.get('run-operator').id) {
    fail('candidate receipt has an inconsistent run-operator image ID');
  }
  return {built, installLoad, actorLoad};
}

/** Resolve each purpose to its uniform admitted platform image identity. */
export function a9RuntimeImageIDs(value, qualifiedTree) {
  const {built, installLoad, actorLoad} = validateA9CandidateBuild(value, qualifiedTree);
  const result = new Map(value.install.images.map(image => [
    image.purpose, installLoad.runtimeByRef.get(image.deploymentRef),
  ]));
  for (const purpose of ['stacks-core', 'stacker']) {
    result.set(purpose, actorLoad.runtimeByRef.get(built.get(purpose).ref));
  }
  return result;
}
