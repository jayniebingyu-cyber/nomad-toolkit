# VerifID MCP — Entity & Account Identifier Validation

An MCP server that gives AI agents **authoritative, real-time validation** of the business and
account identifiers that agents cannot verify from training data alone.

Doing cross-border payments, tax/compliance, enterprise due-diligence, or fraud review? Your agent
needs to know *right now*:

- Is this EU VAT number currently valid — and which company does it belong to?
- Is this China Unified Social Credit Code real, or a forged/typo'd string?
- Will this IBAN actually settle, or will the transfer bounce?
- Is this BIC/SWIFT code well-formed and legally valid?

**These are real-time, authoritative facts.** LLM training data cannot answer them — it has no
live view of the EU VIES registry, and it routinely gets checksum math (GB 32100-2015, ISO 13616
mod-97) wrong. VerifID closes that gap.

## Tools

| Tool | What it does | Source |
|------|--------------|--------|
| `vat_validate` | Live-validate an EU VAT number, returns validity + company name & address | Official EU VIES REST API (ec.europa.eu) |
| `uscc_validate` | Validate a China Unified Social Credit Code (18-digit), decode registry dept / entity type / province | GB 32100-2015 checksum algorithm (local, no network) |
| `iban_validate` | Validate an IBAN (mod-97 checksum + 80+ country BBAN length rules), decode bank/branch/account | ISO 13616 (local) |
| `bic_validate` | Validate a BIC/SWIFT code (8/11-digit structure + ISO 3166-1 country code) | ISO 9362 (local) |

## Quick start (stdio)

```bash
python3 verifid_mcp.py
```

Add it to any MCP client (Claude Desktop, Cursor, WorkBuddy, etc.):

```json
{
  "mcpServers": {
    "verifid": {
      "command": "python3",
      "args": ["/path/to/verifid_mcp.py"]
    }
  }
}
```

Streamable HTTP transport (for Smithery / registries):

```bash
python3 verifid_mcp.py --http 8979
```

## Example outputs

`vat_validate` → `{"vat_number":"IE6388047V","is_valid":true,"company_name":"GOOGLE IRELAND LIMITED",...}`

`uscc_validate` → `{"is_valid":true,"province":"广东省","entity_type":"企业法人","registration_dept":"工商",...}`

`iban_validate` → `{"is_valid":true,"country_code":"DE","mod97":1,"bank_code":"37040044",...}`

`bic_validate` → `{"is_valid":true,"bank_code":"DEUT","country_code":"DE","location_code":"FF",...}`

## Zero dependencies

Pure Python standard library (`urllib`, `json`, `http.server`, `re`). No third-party packages.
No API key required — VIES is the official free EU endpoint; the checksum algorithms are public
international/national standards computed locally.

## Hosted API (paid)

Prefer not to self-host? A managed API with keys, rate limiting, and email delivery is available:

- **$9 / 30 days, 100 calls/day** — https://niebingyu.gumroad.com/l/verifid-api
- Base URL: `http://43.160.199.215/verifid`

```
GET /v1/health
GET /v1/vat?vat_number=IE6388047V&key=YOUR_KEY
GET /v1/uscc?uscc=91440300708461136T&key=YOUR_KEY
GET /v1/iban?iban=DE89370400440532013000&key=YOUR_KEY
GET /v1/bic?bic=DEUTDEFF&key=YOUR_KEY
```

## License

MIT
