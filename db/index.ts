import { getDatabase } from '@netlify/database';
import { drizzle } from 'drizzle-orm/netlify-db';
import * as schema from './schema.js';

function connect() {
  return drizzle({ client: getDatabase(), schema });
}

let client: ReturnType<typeof connect> | undefined;
export function getDB() {
  return client ??= connect();
}
