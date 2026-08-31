import { applyD1Migrations, env } from "cloudflare:test";

// Runs once per test file: bring the isolated test D1 up to the real schema.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
