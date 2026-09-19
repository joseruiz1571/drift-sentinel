import {
	createExecutionContext,
	createScheduledController,
	env,
	fetchMock,
	SELF,
	waitOnExecutionContext,
} from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import worker, {
	clearReportCache,
	REPORT_CACHE_TTL_ASOF_SECONDS,
	REPORT_CACHE_TTL_LATEST_SECONDS,
} from "../src/index";
import { PUBLIC_ERROR_DETAIL, renderReportHTML, type ReportSummary } from "../src/report";
import { scanZone } from "../src/scan";

const WORKER = "https://drift-sentinel.test";
const AUTH = { Authorization: "Bearer test-secret" };

// Healthy responses for all six controls. Tests override single paths to
// simulate drift and API errors.
const HEALTHY: Record<string, unknown> = {
	"settings/min_tls_version": { value: "1.3" },
	"settings/always_use_https": { value: "on" },
	"settings/security_level": { value: "high" },
	"settings/browser_check": { value: "on" },
	dnssec: { status: "active" },
	rulesets: [{ phase: "http_request_firewall_managed" }],
};

// Register one-shot intercepts for every control endpoint, with optional
// per-path overrides: { result } replaces the payload, { fail } returns a
// Cloudflare error envelope.
function mockCfApi(
	overrides: Record<string, { result?: unknown; fail?: string }> = {},
) {
	const origin = fetchMock.get("https://api.cloudflare.com");
	for (const [path, healthy] of Object.entries(HEALTHY)) {
		const override = overrides[path];
		const intercept = origin.intercept({
			method: "GET",
			path: `/client/v4/zones/${env.ZONE_ID}/${path}`,
		});
		if (override?.fail) {
			intercept.reply(
				403,
				JSON.stringify({
					success: false,
					result: null,
					errors: [{ code: 9109, message: override.fail }],
				}),
			);
		} else {
			intercept.reply(
				200,
				JSON.stringify({ success: true, result: override?.result ?? healthy }),
			);
		}
	}
}

async function seedRow(
	scanId: string,
	timestamp: number,
	controlId: string,
	observed: string,
	status: string,
) {
	await env.DB.prepare(
		`INSERT INTO snapshots (id, scan_id, scan_timestamp, control_id, observed, expected, status, detail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	)
		.bind(`${scanId}:${controlId}`, scanId, timestamp, controlId, observed, "x", status, null)
		.run();
}

beforeAll(() => {
	fetchMock.activate();
	fetchMock.disableNetConnect();
});

afterEach(() => {
	fetchMock.assertNoPendingInterceptors();
	clearReportCache();
});

describe("routing", () => {
	it("returns 404 with a hint on unknown routes", async () => {
		const res = await SELF.fetch(`${WORKER}/nope`);
		expect(res.status).toBe(404);
		expect(await res.text()).toContain("/report");
	});
});

describe("POST /scan", () => {
	it("rejects GET with 405", async () => {
		const res = await SELF.fetch(`${WORKER}/scan`);
		expect(res.status).toBe(405);
	});

	it("rejects a missing bearer token with 401 when SCAN_SECRET is set", async () => {
		const res = await SELF.fetch(`${WORKER}/scan`, { method: "POST" });
		expect(res.status).toBe(401);
	});

	it("rejects a wrong bearer token with 401", async () => {
		const res = await SELF.fetch(`${WORKER}/scan`, {
			method: "POST",
			headers: { Authorization: "Bearer wrong" },
		});
		expect(res.status).toBe(401);
	});

	it("fails closed with 503 and writes nothing when SCAN_SECRET is unset", async () => {
		const before = await env.DB.prepare("SELECT COUNT(*) AS total FROM snapshots").first<{
			total: number;
		}>();
		const ctx = createExecutionContext();
		const res = await worker.fetch(
			new Request(`${WORKER}/scan`, { method: "POST" }),
			{ ...env, SCAN_SECRET: "" },
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(503);
		expect(await res.text()).toContain("SCAN_SECRET");
		const after = await env.DB.prepare("SELECT COUNT(*) AS total FROM snapshots").first<{
			total: number;
		}>();
		expect(after?.total).toBe(before?.total ?? 0);
	});

	it("cron scheduled() scans without any secret", async () => {
		mockCfApi();
		const ctx = createExecutionContext();
		await worker.scheduled(createScheduledController({ cron: "0 */6 * * *" }), env, ctx);
		await waitOnExecutionContext(ctx);
		const rows = await env.DB.prepare("SELECT COUNT(*) AS total FROM snapshots").first<{
			total: number;
		}>();
		expect(rows?.total).toBeGreaterThanOrEqual(6);
	});

	it("scans a healthy zone: six controls pass and persist with non-null ids", async () => {
		mockCfApi();
		const res = await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });
		expect(res.status).toBe(200);

		const snapshot = (await res.json()) as { scan_id: string; results: { status: string }[] };
		expect(snapshot.results).toHaveLength(6);
		expect(snapshot.results.every((r) => r.status === "pass")).toBe(true);

		const rows = await env.DB.prepare(
			"SELECT COUNT(*) AS total, SUM(CASE WHEN id IS NULL THEN 1 ELSE 0 END) AS null_ids FROM snapshots",
		).first<{ total: number; null_ids: number }>();
		expect(rows?.total).toBe(6);
		expect(rows?.null_ids).toBe(0);
	});

	it("flags drift when an observed value falls outside the baseline", async () => {
		mockCfApi({ "settings/min_tls_version": { result: { value: "1.0" } } });
		const res = await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });
		const snapshot = (await res.json()) as {
			results: { id: string; status: string; observed: string }[];
		};
		const tls = snapshot.results.find((r) => r.id === "CTL-01");
		expect(tls?.status).toBe("drift");
		expect(tls?.observed).toBe("1.0");
	});

	it("records a fetch timeout as status=error, never as pass", async () => {
		const origin = fetchMock.get("https://api.cloudflare.com");
		for (const path of Object.keys(HEALTHY)) {
			origin
				.intercept({
					method: "GET",
					path: `/client/v4/zones/${env.ZONE_ID}/${path}`,
				})
				.reply(200, JSON.stringify({ success: true, result: HEALTHY[path] }))
				.delay(150);
		}
		const snapshot = await scanZone(env, { fetchTimeoutMs: 20 });
		expect(snapshot.results).toHaveLength(6);
		expect(snapshot.results.every((r) => r.status === "error")).toBe(true);
		expect(snapshot.results.some((r) => r.status === "pass")).toBe(false);
		expect(snapshot.results.every((r) => r.detail)).toBe(true);
	});

	it("records an API failure as status=error with detail, never as pass", async () => {
		mockCfApi({ "settings/security_level": { fail: "Unauthorized to access this zone" } });
		const res = await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });
		const snapshot = (await res.json()) as {
			results: { id: string; status: string; detail?: string }[];
		};
		const ctl = snapshot.results.find((r) => r.id === "CTL-03");
		expect(ctl?.status).toBe("error");
		expect(ctl?.detail).toContain("Unauthorized");
	});
});

describe("append-only snapshots", () => {
	it("still accepts INSERT", async () => {
		await seedRow("scan-ins", 10, "CTL-01", "1.2", "pass");
		const row = await env.DB.prepare(
			"SELECT observed FROM snapshots WHERE scan_id = ?",
		)
			.bind("scan-ins")
			.first<{ observed: string }>();
		expect(row?.observed).toBe("1.2");
	});

	it("aborts UPDATE and leaves the row unchanged", async () => {
		await seedRow("scan-upd", 11, "CTL-01", "1.2", "pass");
		await expect(
			env.DB.prepare("UPDATE snapshots SET observed = 'tamper' WHERE scan_id = ?")
				.bind("scan-upd")
				.run(),
		).rejects.toThrow();
		const row = await env.DB.prepare(
			"SELECT observed FROM snapshots WHERE scan_id = ?",
		)
			.bind("scan-upd")
			.first<{ observed: string }>();
		expect(row?.observed).toBe("1.2");
	});

	it("aborts DELETE and leaves the row in place", async () => {
		await seedRow("scan-del", 12, "CTL-01", "1.2", "pass");
		await expect(
			env.DB.prepare("DELETE FROM snapshots WHERE scan_id = ?").bind("scan-del").run(),
		).rejects.toThrow();
		const row = await env.DB.prepare(
			"SELECT scan_id FROM snapshots WHERE scan_id = ?",
		)
			.bind("scan-del")
			.first<{ scan_id: string }>();
		expect(row?.scan_id).toBe("scan-del");
	});
});

describe("GET /report", () => {
	it("returns 404 when no scans exist", async () => {
		const res = await SELF.fetch(`${WORKER}/report`);
		expect(res.status).toBe(404);
	});

	it("returns 400 on a malformed asof parameter", async () => {
		const res = await SELF.fetch(`${WORKER}/report?asof=garbage`);
		expect(res.status).toBe(400);
	});

	it("reports the latest scan with summary counts and baseline metadata", async () => {
		mockCfApi({ "settings/always_use_https": { result: { value: "off" } } });
		await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });

		const res = await SELF.fetch(`${WORKER}/report`);
		expect(res.status).toBe(200);
		const report = (await res.json()) as ReportSummary;
		expect(report.summary).toEqual({ total: 6, pass: 5, drift: 1, error: 0 });

		const https = report.controls.find((c) => c.id === "CTL-02");
		expect(https?.status).toBe("drift");
		expect(https?.name).toBe("Always Use HTTPS");
		expect(https?.citation).toContain("SOC 2 CC6.7");
	});

	it("renders HTML when asked for it", async () => {
		mockCfApi();
		await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });

		const res = await SELF.fetch(`${WORKER}/report?format=html`);
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toContain("text/html");
		const html = await res.text();
		expect(html).toContain("Drift Sentinel Report");
		expect(html).toContain("CTL-06");
		expect(html).toContain('<html lang="en">');
	});

	it("sets hardening headers on HTML and nosniff on JSON", async () => {
		mockCfApi();
		await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });

		const html = await SELF.fetch(`${WORKER}/report?format=html`);
		expect(html.headers.get("Content-Security-Policy")).toBe(
			"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
		);
		expect(html.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(html.headers.get("Referrer-Policy")).toBe("no-referrer");

		const json = await SELF.fetch(`${WORKER}/report`);
		expect(json.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("redacts raw API error text on /report and keeps it on /scan", async () => {
		const leak = "Unauthorized to access this zone";
		mockCfApi({ "settings/security_level": { fail: leak } });
		const scanRes = await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });
		const snapshot = (await scanRes.json()) as {
			results: { id: string; status: string; detail?: string }[];
		};
		const scanCtl = snapshot.results.find((r) => r.id === "CTL-03");
		expect(scanCtl?.status).toBe("error");
		expect(scanCtl?.detail).toContain(leak);

		const stored = await env.DB.prepare(
			"SELECT detail FROM snapshots WHERE control_id = ? ORDER BY scan_timestamp DESC LIMIT 1",
		)
			.bind("CTL-03")
			.first<{ detail: string }>();
		expect(stored?.detail).toContain(leak);

		const reportRes = await SELF.fetch(`${WORKER}/report`);
		const report = (await reportRes.json()) as ReportSummary;
		const reportCtl = report.controls.find((c) => c.id === "CTL-03");
		expect(reportCtl?.status).toBe("error");
		expect(reportCtl?.detail).toBe(PUBLIC_ERROR_DETAIL);
		expect(JSON.stringify(report)).not.toContain(leak);

		const html = await (await SELF.fetch(`${WORKER}/report?format=html`)).text();
		expect(html).toContain(PUBLIC_ERROR_DETAIL);
		expect(html).not.toContain(leak);
	});

	it("serves a repeated /report from cache without another D1 read", async () => {
		mockCfApi();
		await SELF.fetch(`${WORKER}/scan`, { method: "POST", headers: AUTH });

		const first = await SELF.fetch(`${WORKER}/report`);
		expect(first.status).toBe(200);
		expect(first.headers.get("Cache-Control")).toBe(
			`public, s-maxage=${REPORT_CACHE_TTL_LATEST_SECONDS}`,
		);
		const original = (await first.json()) as ReportSummary;

		await seedRow("scan-after-cache", Date.now() + 1_000, "CTL-01", "9.9", "drift");

		const second = await SELF.fetch(`${WORKER}/report`);
		const cached = (await second.json()) as ReportSummary;
		expect(cached.scan_id).toBe(original.scan_id);
		expect(cached.controls.find((c) => c.id === "CTL-01")?.observed).not.toBe("9.9");
	});

	it("caches past point-in-time reports longer than latest", async () => {
		await seedRow("scan-1000", 1000, "CTL-01", "1.2", "pass");
		const asof = new Date(1500).toISOString();
		const res = await SELF.fetch(`${WORKER}/report?asof=${asof}`);
		expect(res.status).toBe(200);
		expect(res.headers.get("Cache-Control")).toBe(
			`public, s-maxage=${REPORT_CACHE_TTL_ASOF_SECONDS}`,
		);
	});

	it("answers point-in-time queries from the row that was true at that time", async () => {
		await seedRow("scan-1000", 1000, "CTL-01", "1.2", "pass");
		await seedRow("scan-2000", 2000, "CTL-01", "1.0", "drift");

		const between = new Date(1500).toISOString();
		const res = await SELF.fetch(`${WORKER}/report?asof=${between}`);
		const report = (await res.json()) as ReportSummary;
		expect(report.scan_id).toBe("scan-1000");
		expect(report.controls[0].observed).toBe("1.2");
	});
});

describe("renderReportHTML", () => {
	it("escapes hostile observed values so the report cannot XSS itself", () => {
		const report: ReportSummary = {
			scan_id: "scan-1",
			scanned_at: new Date(0).toISOString(),
			controls: [
				{
					id: "CTL-01",
					name: "Minimum TLS version",
					status: "error",
					observed: '<script>alert("x")</script>',
					expected: "1.2,1.3",
					severity: "high",
					citation: "SOC 2 CC6.7",
					detail: "boom & bust",
				},
			],
			summary: { total: 1, pass: 0, drift: 0, error: 1 },
		};
		const html = renderReportHTML(report);
		expect(html).not.toContain("<script>alert");
		expect(html).toContain("&lt;script&gt;");
		expect(html).toContain("boom &amp; bust");
	});
});
