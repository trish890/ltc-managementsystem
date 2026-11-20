CREATE TABLE "account_sessions" (
	"id" text PRIMARY KEY,
	"user_id" text NOT NULL,
	"role" text NOT NULL,
	"credential_digest" text NOT NULL,
	"expires_at" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "login_limits" (
	"id" text PRIMARY KEY,
	"count" integer NOT NULL,
	"window_started" bigint NOT NULL,
	"blocked_until" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "shared_bundles" (
	"id" integer PRIMARY KEY,
	"users" jsonb NOT NULL,
	"profiles" jsonb,
	"enc" text NOT NULL,
	"revision" integer NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
