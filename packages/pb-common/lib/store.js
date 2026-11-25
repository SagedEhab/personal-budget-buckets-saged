// Persistent storage. Every table uses the same key design:
//   pk (partition key, e.g. "USER#<userId>")  +  sk (sort key, e.g. "BUCKET#<id>")
// so one user's items are read with a single Query (no Scan), and a user can only ever
// reach items under their own pk: ownership is built into the key design.
//
//   <TABLE_ENV> set (e.g. BUCKETS_TABLE=PBBuckets) -> Amazon DynamoDB (Floci or AWS)
//   not set, NODE_ENV != production               -> in-memory store, optionally saved to a JSON file
//   not set, NODE_ENV == production               -> refuses to start (no silent data loss)
const fs = require('fs');
const path = require('path');

// ---------- DynamoDB ----------
function createDynamoStore(table) {
  const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
  const {
    DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand, DeleteCommand, ScanCommand
  } = require('@aws-sdk/lib-dynamodb');
  // No keys in code: Lambda uses its IAM role; a PC uses the "floci" AWS profile.
  const db = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
    marshallOptions: { removeUndefinedValues: true }
  });

  return {
    kind: 'dynamodb',
    table,
    async get(pk, sk) {
      const r = await db.send(new GetCommand({ TableName: table, Key: { pk, sk } }));
      return r.Item || null;
    },
    async put(item, { ifNotExists = false } = {}) {
      try {
        await db.send(new PutCommand({
          TableName: table,
          Item: item,
          ...(ifNotExists ? { ConditionExpression: 'attribute_not_exists(pk)' } : {})
        }));
        return true;
      } catch (error) {
        if (error.name === 'ConditionalCheckFailedException') return false;
        throw error;
      }
    },
    async query(pk, { prefix, between, limit, desc = false } = {}) {
      const names = { '#pk': 'pk' };
      const values = { ':pk': pk };
      let condition = '#pk = :pk';
      if (between) {
        names['#sk'] = 'sk';
        values[':a'] = between[0];
        values[':b'] = between[1];
        condition += ' AND #sk BETWEEN :a AND :b';
      } else if (prefix) {
        names['#sk'] = 'sk';
        values[':p'] = prefix;
        condition += ' AND begins_with(#sk, :p)';
      }
      const items = [];
      let startKey;
      do {
        const r = await db.send(new QueryCommand({
          TableName: table,
          KeyConditionExpression: condition,
          ExpressionAttributeNames: names,
          ExpressionAttributeValues: values,
          ScanIndexForward: !desc,
          ExclusiveStartKey: startKey,
          ...(limit ? { Limit: limit - items.length } : {})
        }));
        items.push(...(r.Items || []));
        startKey = r.LastEvaluatedKey;
      } while (startKey && (!limit || items.length < limit));
      return items;
    },
    async update(pk, sk, fields) {
      const names = {};
      const values = {};
      const sets = Object.entries(fields).map(([k, v], i) => {
        names[`#f${i}`] = k;
        values[`:v${i}`] = v;
        return `#f${i} = :v${i}`;
      });
      try {
        const r = await db.send(new UpdateCommand({
          TableName: table,
          Key: { pk, sk },
          UpdateExpression: `SET ${sets.join(', ')}`,
          ConditionExpression: 'attribute_exists(pk)',
          ExpressionAttributeNames: names,
          ExpressionAttributeValues: values,
          ReturnValues: 'ALL_NEW'
        }));
        return r.Attributes;
      } catch (error) {
        if (error.name === 'ConditionalCheckFailedException') return null;
        throw error;
      }
    },
    async remove(pk, sk) {
      const r = await db.send(new DeleteCommand({ TableName: table, Key: { pk, sk }, ReturnValues: 'ALL_OLD' }));
      return r.Attributes || null;
    },
    // Admin statistics only (Scan reads the whole table: acceptable at coursework scale).
    async scan({ prefix } = {}) {
      const items = [];
      let startKey;
      do {
        const r = await db.send(new ScanCommand({
          TableName: table,
          ExclusiveStartKey: startKey,
          ...(prefix ? {
            FilterExpression: 'begins_with(#sk, :p)',
            ExpressionAttributeNames: { '#sk': 'sk' },
            ExpressionAttributeValues: { ':p': prefix }
          } : {})
        }));
        items.push(...(r.Items || []));
        startKey = r.LastEvaluatedKey;
      } while (startKey);
      return items;
    }
  };
}

// ---------- In-memory (local development and automated tests) ----------
function createMemoryStore(name, file) {
  const data = new Map();
  const key = (pk, sk) => `${pk}\u0000${sk}`;
  if (file && fs.existsSync(file)) {
    for (const item of JSON.parse(fs.readFileSync(file, 'utf8'))) data.set(key(item.pk, item.sk), item);
  }
  const save = () => {
    if (!file) return;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify([...data.values()], null, 2));
  };
  const copy = (x) => (x ? JSON.parse(JSON.stringify(x)) : x);

  return {
    kind: 'memory',
    table: name,
    async get(pk, sk) { return copy(data.get(key(pk, sk)) || null); },
    async put(item, { ifNotExists = false } = {}) {
      if (ifNotExists && data.has(key(item.pk, item.sk))) return false;
      data.set(key(item.pk, item.sk), copy(item));
      save();
      return true;
    },
    async query(pk, { prefix, between, limit, desc = false } = {}) {
      let items = [...data.values()].filter((i) => i.pk === pk);
      if (between) items = items.filter((i) => i.sk >= between[0] && i.sk <= between[1]);
      else if (prefix) items = items.filter((i) => i.sk.startsWith(prefix));
      items.sort((a, b) => (a.sk < b.sk ? -1 : a.sk > b.sk ? 1 : 0));
      if (desc) items.reverse();
      if (limit) items = items.slice(0, limit);
      return items.map(copy);
    },
    async update(pk, sk, fields) {
      const existing = data.get(key(pk, sk));
      if (!existing) return null;
      const updated = { ...existing, ...copy(fields) };
      data.set(key(pk, sk), updated);
      save();
      return copy(updated);
    },
    async remove(pk, sk) {
      const existing = data.get(key(pk, sk));
      data.delete(key(pk, sk));
      save();
      return copy(existing || null);
    },
    async scan({ prefix } = {}) {
      return [...data.values()].filter((i) => !prefix || i.sk.startsWith(prefix)).map(copy);
    },
    _clear() { data.clear(); save(); }
  };
}

function createStore(envName) {
  const table = (process.env[envName] || '').trim();
  if (table) return createDynamoStore(table);
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${envName} is not set: refusing to use temporary storage in production.`);
  }
  const file = process.env.LOCAL_DATA_DIR ? path.join(process.env.LOCAL_DATA_DIR, `${envName}.json`) : undefined;
  return createMemoryStore(envName, file);
}

module.exports = { createStore, createMemoryStore, createDynamoStore };
