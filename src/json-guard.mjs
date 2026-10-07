// Standalone JSON boundary. No application engine or network reference resolution.
export function assertSafeJson(root, { maxNodes = 5000, schema = false } = {}) {
  const pending = [[root, 0]];
  let count = 0;
  const reject = code => { throw new Error(code); };
  const regex = text => {
    if (text.length > 256) reject('regex_limit_exceeded');
    if (/\\[1-9]|\\k<|\(\?<[=!]/u.test(text) || /\([^)]*[+*][^)]*\)(?:[+*]|\{\d*,?\d*\})/u.test(text)) reject('unsafe_regex');
    try { new RegExp(text, 'u'); } catch { reject('invalid_regex'); }
  };
  while (pending.length) {
    const [value, depth] = pending.pop();
    if (++count > maxNodes) reject('node_limit_exceeded');
    if (depth > 32) reject('depth_limit_exceeded');
    if (value === null || typeof value === 'boolean') continue;
    if (typeof value === 'string') {
      if (value.length > 32768) reject('string_limit_exceeded');
      continue;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) reject('non_json_number');
      continue;
    }
    if (typeof value !== 'object') reject('non_json_value');
    if (Array.isArray(value)) {
      if (value.length > 2000) reject('array_limit_exceeded');
      for (const child of value) pending.push([child, depth + 1]);
      continue;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) reject('unsafe_object_prototype');
    const entries = Object.entries(value);
    if (entries.length > 768) reject('property_limit_exceeded');
    for (const [name, child] of entries) {
      if (['__proto__', 'prototype', 'constructor'].includes(name)) reject('unsafe_property_name');
      if (schema && ['$ref', '$dynamicRef'].includes(name) && typeof child === 'string' && !child.startsWith('#')) reject('external_schema_reference');
      if (schema && name === 'pattern' && typeof child === 'string') regex(child);
      if (schema && name === 'patternProperties' && child && typeof child === 'object' && !Array.isArray(child)) Object.keys(child).forEach(regex);
      pending.push([child, depth + 1]);
    }
  }
}
