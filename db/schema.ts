import { bigint, integer, jsonb, pgTable, text, timestamp } from 'drizzle-orm/pg-core';

// Preserve the application's encrypted format while making saves transactional.
export const sharedBundles = pgTable('shared_bundles', {
  id: integer('id').primaryKey(),
  users: jsonb('users').notNull(),
  profiles: jsonb('profiles'),
  enc: text('enc').notNull(),
  revision: integer('revision').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const accountSessions = pgTable('account_sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  role: text('role').notNull(),
  credentialDigest: text('credential_digest').notNull(),
  expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
});

export const loginLimits = pgTable('login_limits', {
  id: text('id').primaryKey(),
  count: integer('count').notNull(),
  windowStarted: bigint('window_started', { mode: 'number' }).notNull(),
  blockedUntil: bigint('blocked_until', { mode: 'number' }).notNull(),
});
