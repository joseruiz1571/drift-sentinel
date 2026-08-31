import path from "node:path";
import {
	defineWorkersConfig,
	readD1Migrations,
} from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig(async () => {
	// Read D1 migrations so tests run against the real schema, not a mock.
	const migrations = await readD1Migrations(path.join(__dirname, "migrations"));

	return {
		test: {
			setupFiles: ["./test/apply-migrations.ts"],
			poolOptions: {
				workers: {
					wrangler: { configPath: "./wrangler.jsonc" },
					miniflare: {
						bindings: {
							TEST_MIGRATIONS: migrations,
							CF_API_TOKEN: "test-token",
							SCAN_SECRET: "test-secret",
						},
					},
				},
			},
		},
	};
});
