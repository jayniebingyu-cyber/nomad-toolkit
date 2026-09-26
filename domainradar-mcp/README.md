# DomainRadar MCP — Domain & Brand Availability Intelligence for AI Agents

Give your agents real-time domain intelligence they **cannot** derive from training data:
whether a domain is available *right now*, who owns it, when it expires, and which brand
names are actually free to register.

Zero dependencies (Python stdlib only). Works as a **stdio MCP server** or a **streamable HTTP server**.

## Why this exists

A model cannot answer "is `mytool.io` still available?" — domains get registered every
second. It also cannot recall a domain's registrar, expiry date, or DNS records. These are
live, authoritative facts. DomainRadar fetches them from:

| Data | Source | Notes |
|------|--------|-------|
| Domain availability & WHOIS | IANA RDAP bootstrap → per-TLD RDAP (RFC 7483) | `200` = registered, `404` = available |
| DNS records | Cloudflare DNS-over-HTTPS | A/AAAA/CNAME/MX/NS/TXT… |
| Brand names | built-in generator + RDAP availability | no external API key needed |

## Tools

### 1. `domain_available`
Batch-check whether domains are free to register.
```
domains: "mytool.com, mytool.io, 我的品牌.cn"   (comma-separated or JSON array, max 50)
```
Returns per-domain status: `available` / `registered` (with expiry) / `unknown`.

### 2. `whois_lookup`
RDAP WHOIS for a registered domain: registrar, IANA registrar ID, created / updated /
expiry dates, status flags, nameservers, redaction flag, plus `days_until_expiry`.
```
domain: "google.com"
```

### 3. `brand_names`
Feed it a keyword, get ~18 brand-name candidates with live availability across
`.com .io .ai .co .app` (or your own TLD list), returning only registrable names.
```
keyword: "coffee"
tlds: "com,io,ai,co,app"   (optional)
```

### 4. `dns_records`
Live DNS resolution of any record type.
```
domain: "example.com"
type: "A"   (A/AAAA/CNAME/MX/NS/TXT…)
```

## Run it yourself (free, self-hosted)

### stdio mode (Claude Desktop / Cursor / WorkBuddy / etc.)
```bash
python3 domainradar_mcp.py
```
MCP client config example (Claude Desktop `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "domainradar": {
      "command": "python3",
      "args": ["/absolute/path/to/domainradar_mcp.py"]
    }
  }
}
```

### streamable HTTP mode (Smithery / remote registries)
```bash
python3 domainradar_mcp.py --http 8976
# GET  http://127.0.0.1:8976  → { "service": "domainradar-mcp", "transport": "streamable-http" }
```

### MCP handshake (any client)
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cli","version":"0"}}}' | python3 domainradar_mcp.py
```

## Zero-install hosted API (paid)

Skip the server setup — call our Singapore-hosted API 24/7 from any network:

**Get a 30-day key (100 calls/day) → https://niebingyu.gumroad.com/l/domainradar-api**

```
Base:  http://43.160.199.215/domainradar
GET /v1/available?domains=a.com,b.io&key=YOUR_KEY
GET /v1/whois?domain=google.com&key=YOUR_KEY
GET /v1/brand?keyword=coffee&tlds=com,io&key=YOUR_KEY
GET /v1/dns?domain=example.com&type=A&key=YOUR_KEY
GET /v1/health   (free, no key)
```
Your API key is emailed automatically after purchase (usually within minutes).

## License

MIT — see [LICENSE](LICENSE).
