# sitewatch-mcp

Stateful web-page change monitoring for AI agents. Snapshot any URL, then diff it against the live page later to see *exactly what changed* — added/removed lines, similarity %, title change.

## Why this exists

Agents are **stateless**. After a conversation ends, the model forgets what it saw. So it can't answer *"did this pricing page / job listing / policy page change since last time I looked?"* — that requires keeping a snapshot across sessions and diffing it against a fresh fetch. This tool does exactly that.

## What it monitors

- **Product / pricing pages** — price up, price down, sold out (e-commerce & competitor-tracking agents)
- **Job listings & company pages** — new postings, changed JDs
- **Policy / announcement / legal pages** — updated terms (compliance agents)
- **Any JSON API** — response shape / field changes (API-monitoring agents)
- **Competitor landing pages** — copy, price, contact changes (growth / SEO agents)

## Install & run

Pure Python standard library, zero third-party dependencies.

```bash
# stdio transport (Claude Desktop / WorkBuddy / Cursor / any MCP client)
python3 sitewatch_mcp.py

# or streamable HTTP transport
python3 sitewatch_mcp.py --http 8980
```

### MCP client config (stdio)

```json
{
  "mcpServers": {
    "sitewatch": {
      "command": "python3",
      "args": ["/path/to/sitewatch_mcp.py"]
    }
  }
}
```

## Tools

| Tool | What it does |
|------|--------------|
| `watch_url(url)` | Fetch a URL, save a normalized (title + body text) snapshot to disk, return a `watch_id`. |
| `check_change(watch_id \| url)` | Re-fetch the URL, diff against the snapshot, report changed / similarity / added & removed lines / title change. Updates the snapshot as the new baseline. |
| `list_watches()` | List all monitored URLs with title, hash, last-checked time. |
| `remove_watch(watch_id)` | Remove a watch point. |

Snapshots persist to `sitewatch_snapshots.json` (override path with env var `SITEWATCH_SNAPSHOT`), so state survives across sessions and restarts.

## Example (JSON-RPC over stdio)

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"watch_url","arguments":{"url":"https://example.com/pricing"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_change","arguments":{"watch_id":"<id-from-watch_url>"}}}
```

## Managed (paid) hosted API

Don't want to self-host? A managed endpoint is available:

- **Base:** `http://43.160.199.215/sitewatch`
- **30-day key, 100 calls/day:** [get it on Gumroad](https://niebingyu.gumroad.com/l/sitewatch-api)

```
GET /v1/watch?url=https://example.com/pricing&key=YOUR_KEY
GET /v1/change?watch_id=xxxx&key=YOUR_KEY
GET /v1/list?key=YOUR_KEY
GET /v1/remove?watch_id=xxxx&key=YOUR_KEY
GET /v1/health
```

## License

MIT — see [LICENSE](LICENSE).
