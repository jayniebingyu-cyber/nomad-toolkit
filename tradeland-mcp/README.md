# TradeLand MCP — Cross-border Landed Cost for AI Agents

A zero-dependency MCP server that gives AI agents something their training data cannot: **live foreign-exchange rates, per-country import rules, and a runnable landed-cost engine**.

When a sourcing / e-commerce / dropshipping / trading agent needs to answer *"what does it really cost to land this product in Germany vs. the US?"*, it can't do the math reliably — FX rates move daily, VAT/GST and de-minimis (tax-free) thresholds differ across 40+ markets, and the landed-cost formula needs live data. TradeLand closes that gap.

## What it does

Three tools, all pure Python stdlib (no third-party dependencies):

| Tool | Purpose |
|------|---------|
| `landed_cost` | Full landed-cost breakdown: EXW → FX → freight → insurance → CIF → duty → VAT/GST → total. Returns line items in local + USD currency, plus a de-minimis (tax-free threshold) check. |
| `fx_convert` | Live FX conversion across **160+ currencies** (multi-target). Falls back to ECB then a static table if upstream is down. |
| `import_rules` | Import rules for **40+ markets**: VAT/GST rate, de-minimis threshold, currency & symbol, policy notes. |

## Quick start

### Run locally (stdio)

```bash
python3 server.py
```

Then register it in your MCP client (Claude Desktop, Cursor, WorkBuddy, etc.):

```json
{
  "mcpServers": {
    "tradeland": {
      "command": "python3",
      "args": ["/absolute/path/to/server.py"]
    }
  }
}
```

### Run as a streamable HTTP server (for remote/hosted MCP)

```bash
python3 server.py --http 8976
```

## Example

Ask your agent: *"A widget costs ¥50 ex-works in China. What's the landed cost to sell it in Germany, category electronics, 0.5 kg, express shipping?"*

`landed_cost` returns structured JSON:

```json
{
  "dest_country": "德国",
  "currency": "EUR",
  "breakdown": {
    "exw_dest": 6.47,
    "freight": 7.79,
    "insurance": 0.07,
    "cif": 14.33,
    "duty": 0.43,
    "vat": 2.81,
    "landed": 17.57
  },
  "landed_cost_usd": 19.1,
  "over_de_minimis": false
}
```

## Hosted API (zero-install, paid)

Prefer not to self-host? Use the hosted version — a 24/7 API on a Singapore node, reachable from any network (including cross-border checks). 30-day access key, 100 calls/day.

- **Get a key:** https://niebingyu.gumroad.com/l/tradeland-api ($9 / 30 days)
- **Base URL:** `http://43.160.199.215/tradeland`

```
GET /v1/health                                                        (free)
GET /v1/landed?exw_price=50&dest=US&category=electronics&weight_kg=0.5&key=YOUR_KEY
GET /v1/fx?amount=100&from=USD&to=CNY,EUR&key=YOUR_KEY
GET /v1/rules?country=DE&key=YOUR_KEY
```

## Disclaimer

Duty and VAT/GST figures are **reference values** drawn from public, general knowledge. Tax-free thresholds and tariff policy change frequently (notably the US de-minimis rules for low-value parcels). Always confirm final figures with the destination customs authority or a freight forwarder.

## License

MIT
