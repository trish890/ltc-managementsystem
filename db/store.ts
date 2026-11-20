import { getStore } from '@netlify/blobs';
import { and, eq } from 'drizzle-orm';
import { getDB } from './index.js';
import { accountSessions, loginLimits, sharedBundles } from './schema.js';

function bundleValue(row: typeof sharedBundles.$inferSelect | undefined) {
  if (!row) return null;
  return { users: row.users, profiles: row.profiles, enc: row.enc, revision: row.revision };
}

export const sharedStore = {
  async get(key: string) {
    const db = getDB();
    if (key === 'shared-bundle') {
      const [current] = await db.select().from(sharedBundles).where(eq(sharedBundles.id, 1));
      if (current) return bundleValue(current);

      // Import the existing deployment once. Never fall back to empty state on a service error.
      const legacy = await getStore({ name: 'luwas-shared-state', consistency: 'strong' })
        .get('shared-bundle', { type: 'json' });
      if (!legacy) return null;
      await this.createBundle(legacy);
      const [imported] = await db.select().from(sharedBundles).where(eq(sharedBundles.id, 1));
      return bundleValue(imported);
    }
    if (key.startsWith('session-')) {
      const [session] = await db.select().from(accountSessions).where(eq(accountSessions.id, key));
      return session || null;
    }
    const [limit] = await db.select().from(loginLimits).where(eq(loginLimits.id, key));
    return limit || null;
  },

  async createBundle(bundle: { users: unknown; profiles?: unknown; enc: string; revision: number }) {
    const db = getDB();
    const rows = await db.insert(sharedBundles).values({ id: 1, ...bundle })
      .onConflictDoNothing().returning();
    return rows.length === 1;
  },

  async updateBundle(
    revision: number,
    bundle: { users: unknown; profiles: unknown; enc: string; revision: number },
    session?: { key: string; userId: string; role: string; credentialDigest: string; expiresAt: number },
  ) {
    const db = getDB();
    return db.transaction(async tx => {
      const rows = await tx.update(sharedBundles).set({ ...bundle, updatedAt: new Date() })
        .where(and(eq(sharedBundles.id, 1), eq(sharedBundles.revision, revision)))
        .returning({ id: sharedBundles.id });
      if (!rows.length) return false;
      if (session) {
        const { key, ...value } = session;
        await tx.update(accountSessions).set(value).where(eq(accountSessions.id, key));
      }
      return true;
    });
  },

  async setJSON(key: string, value: any) {
    const db = getDB();
    if (key.startsWith('session-')) {
      await db.insert(accountSessions).values({ id: key, ...value })
        .onConflictDoUpdate({ target: accountSessions.id, set: value });
      return;
    }
    await db.insert(loginLimits).values({ id: key, ...value })
      .onConflictDoUpdate({ target: loginLimits.id, set: value });
  },

  async delete(key: string) {
    const db = getDB();
    if (key.startsWith('session-')) {
      await db.delete(accountSessions).where(eq(accountSessions.id, key));
    } else {
      await db.delete(loginLimits).where(eq(loginLimits.id, key));
    }
  },
};
