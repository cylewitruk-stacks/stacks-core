import {readFileSync} from 'node:fs';

const SUPPORTED_TYPES = new Set(['object', 'array', 'string', 'integer', 'boolean']);
const ANNOTATION_KEYWORDS = new Set(['$schema', '$id', 'title', 'description', '$comment']);
const SUPPORTED_KEYWORDS = new Set([
  ...ANNOTATION_KEYWORDS,
  '$defs', '$ref', 'const', 'enum', 'type',
  'additionalProperties', 'required', 'properties',
  'items', 'minItems', 'maxItems', 'uniqueItems',
  'minLength', 'pattern', 'minimum',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonical(value) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error('schema values must be canonical JSON');
}

function resolveRef(root, ref) {
  if (!ref.startsWith('#/')) throw new Error(`unsupported schema reference ${ref}`);
  const resolved = ref.slice(2).split('/').reduce((value, key) => {
    if (!isObject(value)) return undefined;
    return value[key.replaceAll('~1', '/').replaceAll('~0', '~')];
  }, root);
  if (!isObject(resolved)) throw new Error(`schema reference ${ref} does not resolve to a schema object`);
  return resolved;
}

function requireType(schema, keywords, type, field) {
  const present = keywords.filter(keyword => Object.hasOwn(schema, keyword));
  if (present.length > 0 && schema.type !== type) {
    throw new Error(`${field}.${present[0]} requires explicit type ${type}`);
  }
}

function requireNonNegativeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} must be a non-negative integer`);
}

function validateSchemaDefinition(schema, root, field = 'schema') {
  if (!isObject(schema)) throw new Error(`${field} must be a schema object`);
  for (const keyword of Object.keys(schema)) {
    if (!SUPPORTED_KEYWORDS.has(keyword)) throw new Error(`${field} uses unsupported schema keyword ${keyword}`);
  }

  for (const keyword of ANNOTATION_KEYWORDS) {
    if (Object.hasOwn(schema, keyword) && typeof schema[keyword] !== 'string') {
      throw new Error(`${field}.${keyword} must be a string`);
    }
  }
  if (Object.hasOwn(schema, 'type') && !SUPPORTED_TYPES.has(schema.type)) {
    throw new Error(`${field}.type ${JSON.stringify(schema.type)} is unsupported`);
  }
  requireType(schema, ['properties', 'required', 'additionalProperties'], 'object', field);
  requireType(schema, ['items', 'minItems', 'maxItems', 'uniqueItems'], 'array', field);
  requireType(schema, ['minLength', 'pattern'], 'string', field);
  requireType(schema, ['minimum'], 'integer', field);

  if (Object.hasOwn(schema, '$ref')) {
    if (typeof schema.$ref !== 'string') throw new Error(`${field}.$ref must be a string`);
    resolveRef(root, schema.$ref);
  }
  if (Object.hasOwn(schema, '$defs')) {
    if (!isObject(schema.$defs)) throw new Error(`${field}.$defs must be an object`);
    for (const [name, child] of Object.entries(schema.$defs)) {
      validateSchemaDefinition(child, root, `${field}.$defs.${name}`);
    }
  }
  if (Object.hasOwn(schema, 'properties')) {
    if (!isObject(schema.properties)) throw new Error(`${field}.properties must be an object`);
    for (const [name, child] of Object.entries(schema.properties)) {
      validateSchemaDefinition(child, root, `${field}.properties.${name}`);
    }
  }
  if (Object.hasOwn(schema, 'items')) validateSchemaDefinition(schema.items, root, `${field}.items`);

  if (Object.hasOwn(schema, 'required')) {
    if (!Array.isArray(schema.required) || schema.required.some(item => typeof item !== 'string')) {
      throw new Error(`${field}.required must be an array of strings`);
    }
    if (new Set(schema.required).size !== schema.required.length) throw new Error(`${field}.required contains duplicates`);
  }
  if (Object.hasOwn(schema, 'additionalProperties') && typeof schema.additionalProperties !== 'boolean') {
    throw new Error(`${field}.additionalProperties must be boolean`);
  }
  if (Object.hasOwn(schema, 'enum')) {
    if (!Array.isArray(schema.enum) || schema.enum.length === 0) throw new Error(`${field}.enum must be a non-empty array`);
    const values = schema.enum.map(canonical);
    if (new Set(values).size !== values.length) throw new Error(`${field}.enum contains duplicates`);
  }
  if (Object.hasOwn(schema, 'const')) canonical(schema.const);
  for (const keyword of ['minItems', 'maxItems', 'minLength']) {
    if (Object.hasOwn(schema, keyword)) requireNonNegativeInteger(schema[keyword], `${field}.${keyword}`);
  }
  if (schema.minItems !== undefined && schema.maxItems !== undefined && schema.minItems > schema.maxItems) {
    throw new Error(`${field}.minItems cannot exceed maxItems`);
  }
  if (Object.hasOwn(schema, 'uniqueItems') && typeof schema.uniqueItems !== 'boolean') {
    throw new Error(`${field}.uniqueItems must be boolean`);
  }
  if (Object.hasOwn(schema, 'pattern')) {
    if (typeof schema.pattern !== 'string') throw new Error(`${field}.pattern must be a string`);
    try {
      new RegExp(schema.pattern);
    } catch (error) {
      throw new Error(`${field}.pattern is invalid: ${error.message}`);
    }
  }
  if (Object.hasOwn(schema, 'minimum') && (typeof schema.minimum !== 'number' || !Number.isFinite(schema.minimum))) {
    throw new Error(`${field}.minimum must be a finite number`);
  }
}

function validateNode(value, schema, root, field) {
  if (schema.$ref) validateNode(value, resolveRef(root, schema.$ref), root, field);
  if (Object.hasOwn(schema, 'const') && canonical(value) !== canonical(schema.const)) {
    throw new Error(`${field} must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.some(item => canonical(item) === canonical(value))) {
    throw new Error(`${field} must be one of ${schema.enum.join(', ')}`);
  }
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${field} must be an object`);
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) throw new Error(`${field}.${required} is required`);
    }
    if (schema.additionalProperties === false) {
      const known = new Set(Object.keys(schema.properties ?? {}));
      for (const key of Object.keys(value)) if (!known.has(key)) throw new Error(`${field}.${key} is not allowed`);
    }
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateNode(value[key], child, root, `${field}.${key}`);
    }
  } else if (schema.type === 'array') {
    if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
    if (schema.minItems !== undefined && value.length < schema.minItems) throw new Error(`${field} must contain at least ${schema.minItems} items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) throw new Error(`${field} must contain at most ${schema.maxItems} items`);
    if (schema.uniqueItems) {
      const items = value.map(canonical);
      if (new Set(items).size !== items.length) throw new Error(`${field} contains duplicates`);
    }
    value.forEach((item, index) => validateNode(item, schema.items ?? {}, root, `${field}[${index}]`));
  } else if (schema.type === 'string') {
    if (typeof value !== 'string') throw new Error(`${field} must be a string`);
    if (schema.minLength !== undefined && value.length < schema.minLength) throw new Error(`${field} is too short`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) throw new Error(`${field} does not match ${schema.pattern}`);
  } else if (schema.type === 'integer') {
    if (!Number.isSafeInteger(value)) throw new Error(`${field} must be an integer`);
    if (schema.minimum !== undefined && value < schema.minimum) throw new Error(`${field} must be at least ${schema.minimum}`);
  } else if (schema.type === 'boolean' && typeof value !== 'boolean') {
    throw new Error(`${field} must be boolean`);
  }
}

export function loadSchema(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function validateSchema(value, schema, field = 'document') {
  validateSchemaDefinition(schema, schema);
  validateNode(value, schema, schema, field);
  return true;
}
