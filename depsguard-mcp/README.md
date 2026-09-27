# depsguard-mcp

An MCP server that lets AI agents audit software dependencies for **known security vulnerabilities** in real time — powered by [OSV.dev](https://osv.dev), Google's authoritative, free, open-source vulnerability database.

A coding agent cannot know whether `lodash@4.17.20` or `django==3.2.0` is affected by a CVE that was published *after* its training cutoff. DepsGuard answers that question with live, authoritative data — and can scan an entire `package.json` / `requirements.txt` / `Cargo.toml` / `go.mod` / `pom.xml` in one call.

## What it does

| Tool | Purpose |
|------|---------|
| `check_dependency` | Check one package (ecosystem + name + optional version) for known vulns → severity, aliases (CVE/GHSA), fixed versions |
| `audit_manifest` | Paste a full manifest (`package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`, `pom.xml`) → auto-parse all deps, batch-scan, return a severity-sorted report |
| `vulnerability_detail` | Full detail for one vuln id (`CVE-...` / `GHSA-...`) → summary, description, CWE, affected ranges, fix versions, references |

Supported ecosystems: `npm`, `PyPI`, `Go`, `Maven`, `crates.io`, `RubyGems`, `NuGet`, `Packagist`, `Hex`, `Pub`, and more (see [OSV docs](https://google.github.io/osv.dev/)).

## Why it exists

- **Live facts, not training data.** Vulnerabilities are published daily; a model cannot self-check them.
- **Batch, not one-by-one.** `audit_manifest` scans a whole dependency file in a single call.
- **Severity + fix, not just "yes/no".** Each finding includes severity (CVSS-derived), CVE/GHSA aliases, and the fixed version you should upgrade to.

## Quick start (self-host, free)

Zero dependencies — Python 3 standard library only.

```bash
git clone https://github.com/jayniebingyu-cyber/nomad-toolkit.git
cd nomad-toolkit/depsguard-mcp

# stdio transport (Claude Desktop / Cursor / WorkBuddy / any MCP client)
python3 depsguard_mcp.py

# streamable HTTP transport
python3 depsguard_mcp.py --http 8977
```

### MCP client config (stdio)

```json
{
  "mcpServers": {
    "depsguard": {
      "command": "python3",
      "args": ["/absolute/path/to/depsguard_mcp.py"]
    }
  }
}
```

### Example calls

`tools/call` → `check_dependency`:

```json
{ "ecosystem": "npm", "name": "lodash", "version": "4.17.20" }
```

```json
{ "ecosystem": "PyPI", "name": "django", "version": "3.2.0" }
```

`tools/call` → `audit_manifest` (paste the raw file text):

```json
{ "manifest": "django==3.2.0\nrequests==2.25.0\nurllib3==1.26.4\n" }
```

`tools/call` → `vulnerability_detail`:

```json
{ "vuln_id": "CVE-2020-28500" }
```

## Hosted API (paid, zero-install)

Prefer not to self-host? Use the managed API — a 30-day key with 100 calls/day, running 24/7 on a Singapore node:

**👉 [Get a DepsGuard API key](https://niebingyu.gumroad.com/l/depsguard-api) — $9 / 30 days**

```
GET  http://43.160.199.215/depsguard/v1/check?ecosystem=npm&name=lodash&version=4.17.20&key=YOUR_KEY
GET  http://43.160.199.215/depsguard/v1/vuln?id=CVE-2020-28500&key=YOUR_KEY
POST http://43.160.199.215/depsguard/v1/audit?key=YOUR_KEY   body: {"manifest": "..."}
GET  http://43.160.199.215/depsguard/v1/health                (free)
```

Your key is delivered by email automatically after purchase.

## Data source & limits

- Data: [OSV.dev](https://osv.dev) (Google's open-source vulnerability database) — free, authoritative, aggregates CVE + GHSA + ecosystem-specific advisories.
- No API key required for the underlying OSV data; the hosted API adds auth + rate limiting + 24/7 uptime.
- License: MIT.

## Credits

Built by [Nomad Toolkit](https://github.com/jayniebingyu-cyber). Contact: niebingyu@qq.com
