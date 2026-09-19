# Security Policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository. Open **Security** → **Report a vulnerability** on github.com/joseruiz1571/drift-sentinel. Do not file a public issue for security reports.

## Scope

In scope:

- This Worker (`src/`, its D1 evidence store, and the `/scan` and `/report` handlers)
- Authentication on `POST /scan`
- Leakage of secrets, tokens, or raw Cloudflare API error text through `/report`
- Tampering with append-only snapshot evidence via the application

Out of scope:

- The eggrollindex.com zone itself (DNS, TLS, and dashboard settings)
- Cloudflare platform availability or D1/Workers infrastructure
- Social engineering or physical attacks
- Findings that require a leaked write-capable Cloudflare token you created yourself

## API token

The Cloudflare API token used by this Worker is **read-only** and scoped to a single zone. A leaked token cannot change zone settings. `SCAN_SECRET` only authorizes a scan; it is not a Cloudflare credential.
