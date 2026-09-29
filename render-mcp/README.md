# render-mcp — Headless Web Rendering Engine for AI Agents

Give your agent a pair of eyes. `render-mcp` is a zero-dependency MCP server that renders any URL in a real headless Chromium and returns **screenshots, PDFs, fully-rendered HTML, or clean text** — so an agent that has no browser can still *see* pages, archive them as PDF, scrape JS-driven sites, and turn pages into text for analysis.

## Why this exists

AI agents do not ship with a browser. A text-only agent cannot:

- see what a page looks like (screenshot / visual regression)
- archive or deliver a page as a PDF
- read the content of a JavaScript-rendered SPA (plain `urllib`/`requests` returns an empty shell)
- extract clean body text without fighting HTML parsing

`render-mcp` fills that gap with one lightweight call.

## Tools

| Tool | What it does |
|------|--------------|
| `render_screenshot` | URL → PNG/JPEG screenshot (base64). Full-page, custom viewport, wait-for-selector, wait time, `wait_until` (load/domcontentloaded/networkidle/commit) |
| `render_pdf` | URL → PDF (base64). A4/A3/A5/Letter/Legal/Tabloid, landscape, print background |
| `render_html` | URL → fully-rendered HTML after JS execution (SPA / dynamic content) |
| `render_text` | URL → clean body text (optional CSS selector), ready to feed a model |

Every result includes `title`, `final_url`, and sizes, so the caller knows what actually rendered.

## Security

Built-in **SSRF protection**: requests to loopback, private (10.x / 172.16-31.x / 192.168.x), link-local, reserved, multicast, and cloud-metadata (169.254.169.254) addresses are rejected — both the initial URL and the final URL after redirects. Only `http(s)` schemes are allowed.

## Usage

### Self-hosted (free)

```bash
# 1. install deps
pip install playwright
playwright install chromium

# 2. run as stdio MCP server (Claude Desktop / Cursor / WorkBuddy ...)
python3 render_mcp.py

# or as a streamable HTTP MCP server
python3 render_mcp.py --http 8982
```

Add it to your MCP client config as a stdio server:

```json
{
  "mcpServers": {
    "render-mcp": {
      "command": "python3",
      "args": ["/path/to/render_mcp.py"]
    }
  }
}
```

### Hosted API (paid, zero-setup)

Don't want to maintain a browser? Use the hosted REST API:

```
Base: http://43.160.199.215/render

GET /v1/health                                  (free)
GET /v1/screenshot?url=https://example.com&key=YOUR_KEY
GET /v1/pdf?url=https://example.com&key=YOUR_KEY
GET /v1/html?url=https://example.com&key=YOUR_KEY
GET /v1/text?url=https://example.com&key=YOUR_KEY
```

Get a 30-day key (100 calls/day) at: **https://niebingyu.gumroad.com/l/render-api**

## Protocol

MCP (JSON-RPC 2.0), protocol version `2024-11-05`, implementing `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`, over both stdio and streamable HTTP transports.

## License

MIT
