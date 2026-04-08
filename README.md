# secret-hunter

Fast, pipeline-friendly CLI for hunting hardcoded secrets in JavaScript files. Built in Go — single binary, no dependencies.

Fits directly into recon pipelines: `subfinder → httpx → secret-hunter`

---

## Install

```bash
git clone https://github.com/xcriminal/secret-hunter
cd secret-hunter
go build -o secret-hunter .
```

---

## Usage

```
secret-hunter [flags]
```

---

## Flags

### Input

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--domain` | `-d` | — | Target domain(s) to crawl |
| `--url` | `-u` | — | Target URL(s) to crawl |
| `--list` | `-l` | — | File with domains/URLs to crawl (one per line) |
| `--js` | — | — | JS URL(s) to scan directly, no crawling |
| `--js-list` | — | — | File of JS URLs to scan directly (one per line, no crawling) |
| `--stdin` | — | false | Read targets from stdin (one per line) |

### Crawler

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--crawler` | — | `builtin` | Crawler backend: `builtin`, `katana`, `hakrawler` |
| `--depth` | — | `3` | Crawl depth |
| `--concurrency` | `-c` | `15` | Number of parallel workers |
| `--headless` | — | false | Use headless browser (katana only) |
| `--scope` | — | — | Additional in-scope domains |

### HTTP

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--header` | `-H` | — | Custom HTTP header (`'Name: Value'`, repeatable) |
| `--proxy` | — | — | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--skip-tls` | — | false | Skip TLS certificate verification |
| `--timeout` | — | `15` | HTTP request timeout in seconds |

### Output

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `text` | Output format: `text`, `json`, `table` |
| `--output` | `-o` | — | Write output to file |
| `--no-color` | — | false | Disable colored output |
| `--silent` | `-s` | false | Suppress banner and status messages |
| `--verbose` | `-v` | false | Show each scanned URL + live progress |

### Scan

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--severity` | — | — | Severity filter (see below) |
| `--show-secrets` | — | false | Print full unredacted secret values |

**Severity filter:**
- Single threshold — match that level and above: `--severity HIGH` (matches HIGH + CRITICAL)
- Exact list — match only specified levels: `--severity HIGH,CRITICAL`
- Valid levels: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

## Examples

### Crawl a single domain
```bash
secret-hunter -d example.com
```

### Crawl multiple domains
```bash
secret-hunter -d example.com -d sub.example.com
```

### Crawl from a file of domains
```bash
secret-hunter -l domains.txt
```

### Scan specific JS URLs directly (no crawling)
```bash
secret-hunter --js https://example.com/app.js
secret-hunter --js https://example.com/app.js --js https://example.com/chunk.js
```

### Scan a file of JS URLs (no crawling, parallel)
```bash
secret-hunter --js-list js_urls.txt
```

### Scan a JS URL file with 50 parallel workers and live progress
```bash
secret-hunter --js-list js_urls.txt -c 50 -v
```

### Pipe from subfinder + httpx
```bash
subfinder -d example.com -silent | httpx -silent | secret-hunter --stdin
```

### Full recon pipeline
```bash
subfinder -d example.com -silent \
  | httpx -silent \
  | secret-hunter --stdin -c 30 -f json -o results.json
```

### Use katana as the crawler
```bash
secret-hunter -d example.com --crawler katana
```

### Use katana with headless browser (SPA support)
```bash
secret-hunter -d example.com --crawler katana --headless
```

### Use hakrawler as the crawler
```bash
secret-hunter -d example.com --crawler hakrawler
```

### Output as JSON to file
```bash
secret-hunter -d example.com -f json -o results.json
```

### Output as table
```bash
secret-hunter -d example.com -f table
```

### Filter by severity threshold (HIGH and above)
```bash
secret-hunter -d example.com --severity HIGH
```

### Filter for exact severity levels only
```bash
secret-hunter -d example.com --severity HIGH,CRITICAL
```

### Show full unredacted secret values
```bash
secret-hunter -d example.com --show-secrets
```

### Custom headers (e.g. authenticated scan)
```bash
secret-hunter -d example.com -H 'Authorization: Bearer <token>' -H 'X-Api-Key: abc123'
```

### Route traffic through Burp Suite proxy
```bash
secret-hunter -d example.com --proxy http://127.0.0.1:8080 --skip-tls
```

### Increase crawl depth
```bash
secret-hunter -d example.com --depth 5
```

### Silent mode (findings only, no banner/status)
```bash
secret-hunter -d example.com -s
```

### Silent + JSON — clean output for piping
```bash
secret-hunter --js-list js_urls.txt -s -f json | jq '.[] | select(.severity=="CRITICAL")'
```

### Scan with scope restriction (only follow in-scope domains)
```bash
secret-hunter -d example.com --scope api.example.com --scope cdn.example.com
```

---

## Pipeline Integration

secret-hunter is designed to be the last stage of a JS recon pipeline. Combine with `valla.sh` to harvest JS URLs first:

```bash
# 1. Harvest JS URLs from a list of hosts
./valla.sh hosts.txt js_urls.txt

# 2. Scan harvested URLs for secrets
secret-hunter --js-list js_urls.txt -c 50 -f json -o secrets.json -s

# 3. Filter critical findings
jq '.[] | select(.severity=="CRITICAL")' secrets.json
```

Full automated pipeline:
```bash
subfinder -d example.com -silent \
  | httpx -silent \
  | tee hosts.txt \
  | secret-hunter --stdin -c 30 --severity HIGH -f json -o secrets.json
```

---

## Supported Secret Types

**Cloud**
AWS (Access Key ID, Secret Key, Session tokens), Google API/OAuth, Firebase, Azure (Storage, SAS, AD Client Secret), Cloudflare, DigitalOcean, Heroku, Alibaba Cloud

**AI / LLM**
OpenAI, Anthropic, HuggingFace

**Version Control & CI/CD**
GitHub (classic PAT, fine-grained PAT, OAuth, App, Refresh), GitLab (PAT, CI/CD job, deploy, runner, pipeline trigger, OAuth app secret, agent), CircleCI, Travis CI, Jenkins

**Communication**
Slack (bot, app, user, legacy, webhook), Discord (webhook, bot), Telegram, Twilio, SendGrid, Sendinblue/Brevo, Mailgun, Mailchimp, Microsoft Teams Webhook

**Payments**
Stripe (live/test secret, publishable, restricted), PayPal Braintree, Square, Shopify

**Social**
Facebook (app secret, access token), Twitter/X (bearer, API key/secret), LinkedIn

**Auth & Tokens**
JWT, Basic Auth in URLs, Bearer tokens, OAuth2 access/refresh tokens

**Private Keys**
RSA, DSA, EC, OpenSSH, PGP, generic PEM headers

**Databases & Infra**
MongoDB, PostgreSQL, MySQL, Redis connection strings, Databricks, HashiCorp Vault, PlanetScale

**Observability**
Sentry (DSN, auth token), New Relic, Grafana (API key, Cloud token, service account), Datadog, Dynatrace, Bugsnag

**Developer Tools**
NPM, PyPI, Airtable, HubSpot, Notion, Linear, Doppler, Fly.io, Pulumi, Postman, Typeform, Okta, Algolia, Dropbox, Zendesk, PagerDuty, Mapbox, Cloudinary

---

## False Positive Reduction

Three layers run on every match before reporting:

1. **Shannon entropy gate** — generic patterns (API key, password, token assignments) require minimum entropy. Low-entropy strings like `YOUR_KEY_HERE` are skipped automatically.
2. **Context regex** — some patterns (Twitter bearer, Telegram) require a relevant keyword on the same line before firing.
3. **Placeholder blocklist** — strings containing `EXAMPLE`, `YOUR_`, `PLACEHOLDER`, `XXXX`, `test_key`, etc. are discarded.

Secrets are redacted by default (`abc123****xyz`). Use `--show-secrets` to see full values.
