# phishguard-mcp

Phishing & malicious URL detection for AI agents (MCP server, zero-dependency Python stdlib).

Agents doing "safe browsing" **cannot know from training data** whether a URL is in a live phishing blacklist, whether a shortlink hides a malicious target, or whether a domain is a brand-new impersonation site. PhishGuard answers that in one call.

## What it does

| Tool | Purpose |
|------|---------|
| `check_url` | Full scan: 0–100 risk score + `safe`/`suspicious`/`malicious` verdict + OpenPhish feed hit + heuristic rules + domain registration age + shortlink expansion |
| `lookup_feed` | Exact / domain-level match against the OpenPhish threat feed |
| `expand_url` | Expand shortlinks (bit.ly / t.co / tinyurl / lnk.ink …) and see the full redirect chain |
| `analyze_domain` | Domain reputation: registration age, suspicious TLD, IDN/punycode, brand impersonation |

## Data sources (free & authoritative, no key required)

- **OpenPhish community feed** (`https://openphish.com/feed.txt`, daily) — cached locally, refreshed every 30 min.
- **IANA RDAP** — authoritative domain registration data (registration date → new-registration detection).
- **Local heuristic engine** — IP-literal host, IDN/punycode homograph, suspicious/abusive TLDs (.tk/.zip/.top …), brand impersonation (30+ brands), sensitive keywords (login/verify/account …), `@`-obfuscation, overlong subdomains, non-standard ports.

## Run it

```bash
# stdio mode (Claude Desktop / WorkBuddy / Cursor …)
python3 phishguard_mcp.py

# streamable HTTP mode
python3 phishguard_mcp.py --http 8981
```

Protocol: MCP (JSON-RPC 2.0), version `2024-11-05`. Zero third-party dependencies — Python 3.8+ stdlib only.

## MCP client config (example)

```json
{
  "mcpServers": {
    "phishguard": {
      "command": "python3",
      "args": ["/path/to/phishguard_mcp.py"]
    }
  }
}
```

## Example

```
check_url("https://paypal.com.verify-account.tk/login")
→ risk_score 100, verdict "malicious",
  heuristic_rules [brand_impersonation, suspicious_tld, sensitive_keyword],
  domain "verify-account.tk", domain_age_days 2
```

## Self-host vs hosted

- **Self-host (free):** this repo — clone it, run it, no key needed.
- **Hosted API (paid):** a managed endpoint with rate limits and always-updated feeds, no server to maintain.
  → [PhishGuard API on Gumroad](https://niebingyu.gumroad.com/l/phishguard-api) — $9 / 30 days, 100 calls/day.

## License

MIT. See [LICENSE](LICENSE).
