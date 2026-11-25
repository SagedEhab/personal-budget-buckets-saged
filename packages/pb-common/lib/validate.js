// Small schema validator used by every service.
//   validate(body, schema, { partial })  -> returns a clean object or throws 400 VALIDATION_ERROR
// Rules supported per field: type (string|number|integer|boolean), required, min, max,
// minLength, maxLength, enum, pattern, trim, lower.
// Unknown fields are REJECTED (prevents mass assignment, e.g. sending "role": "admin").
const { errors } = require('./errors');

function checkField(name, value, rule) {
  switch (rule.type) {
    case 'string': {
      if (typeof value !== 'string') return `${name} must be a string.`;
      const v = rule.trim === false ? value : value.trim();
      if (rule.minLength !== undefined && v.length < rule.minLength) return `${name} must be at least ${rule.minLength} characters.`;
      if (rule.maxLength !== undefined && v.length > rule.maxLength) return `${name} must be at most ${rule.maxLength} characters.`;
      if (rule.pattern && !rule.pattern.test(v)) return rule.patternMessage || `${name} has an invalid format.`;
      if (rule.enum && !rule.enum.includes(v)) return `${name} must be one of: ${rule.enum.join(', ')}.`;
      return null;
    }
    case 'number':
    case 'integer': {
      if (typeof value !== 'number' || !Number.isFinite(value)) return `${name} must be a number.`;
      if (rule.type === 'integer' && !Number.isInteger(value)) return `${name} must be a whole number.`;
      if (rule.min !== undefined && value < rule.min) return `${name} must be at least ${rule.min}.`;
      if (rule.max !== undefined && value > rule.max) return `${name} must be at most ${rule.max}.`;
      if (rule.decimals !== undefined) {
        const factor = 10 ** rule.decimals;
        if (Math.abs(Math.round(value * factor) - value * factor) > 1e-6) return `${name} may have at most ${rule.decimals} decimal places.`;
      }
      return null;
    }
    case 'boolean':
      return typeof value === 'boolean' ? null : `${name} must be true or false.`;
    default:
      return `${name} has an unsupported type.`;
  }
}

function validate(body, schema, { partial = false } = {}) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw errors.badRequest('Request body must be a JSON object.');
  }
  const problems = [];
  for (const key of Object.keys(body)) {
    if (!Object.prototype.hasOwnProperty.call(schema, key)) problems.push(`${key} is not an allowed field.`);
  }
  const clean = {};
  for (const [name, rule] of Object.entries(schema)) {
    const value = body[name];
    if (value === undefined || value === null || value === '') {
      if (rule.required && !partial) problems.push(`${name} is required.`);
      else if (!partial && rule.default !== undefined) clean[name] = rule.default;
      continue;
    }
    const problem = checkField(name, value, rule);
    if (problem) { problems.push(problem); continue; }
    let v = value;
    if (typeof v === 'string') {
      if (rule.trim !== false) v = v.trim();
      if (rule.lower) v = v.toLowerCase();
      if (rule.upper) v = v.toUpperCase();
    }
    clean[name] = v;
  }
  if (partial && Object.keys(clean).length === 0 && problems.length === 0) {
    problems.push('At least one field must be provided.');
  }
  if (problems.length) throw errors.badRequest(problems[0], problems);
  return clean;
}

// Query-string helpers (query values are always strings)
function queryInt(value, name, { min, max, def }) {
  if (value === undefined || value === '') return def;
  if (!/^\d+$/.test(String(value))) throw errors.badRequest(`${name} must be a whole number.`);
  const n = Number(value);
  if (n < min || n > max) throw errors.badRequest(`${name} must be between ${min} and ${max}.`);
  return n;
}

function queryEnum(value, name, allowed) {
  if (value === undefined || value === '') return undefined;
  if (!allowed.includes(value)) throw errors.badRequest(`${name} must be one of: ${allowed.join(', ')}.`);
  return value;
}

const ID_PATTERN = /^[A-Za-z0-9_-]{6,64}$/;
function checkId(value, what = 'id') {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) throw errors.badRequest(`${what} is not valid.`);
  return value;
}

module.exports = { validate, queryInt, queryEnum, checkId, ID_PATTERN };
