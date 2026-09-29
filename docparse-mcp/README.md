# docparse-mcp — Document Parsing Engine for AI Agents

A zero-setup **document intelligence** capability for AI agents. Agents are text-native: they cannot read the *inside* of a PDF or a scanned image on their own. `docparse-mcp` turns any PDF (or image) into clean, structured data the agent can actually reason over.

> **Why this exists:** an agent has no PDF library, no OCR engine, and no vision of the page layout inside a binary document. This MCP server is the bridge that converts **document → structured text / tables / metadata / form fields / links / OCR text**.

## What it can do

| Tool | Input | Output |
|------|-------|--------|
| `parse_document` | PDF | metadata + text + tables + form fields + links (one call) |
| `extract_text` | PDF | clean text, per-page markers, optional layout/coordinate mode |
| `extract_tables` | PDF | tables as JSON (2D arrays) or CSV text |
| `extract_metadata` | PDF | title / author / page count / encryption / file size + fillable form fields |
| `extract_links` | PDF | deduplicated embedded URIs with page numbers |
| `ocr_document` | scanned PDF / image | OCR text (English + Chinese, tesseract) |

Input can be supplied three ways (any tool): a **URL**, **base64** content, or a **local path**.

## Why agents need this

- **Contracts / invoices / financial reports / resumes**: an agent that processes documents needs structured text and tables, not a blob it can't open.
- **Scanned receipts & statements**: OCR is the only way to read them — agents can't do OCR without an engine.
- **Due diligence**: extract clauses, embedded links, form fields, and confirm document metadata (is it encrypted? when was it created?).

## Quick start (MCP, stdio)

Requires Python 3.10+ and `pymupdf` (OCR additionally needs `tesseract-ocr`).

```bash
pip install pymupdf
# optional OCR:
#   apt install tesseract-ocr tesseract-ocr-chi-sim   (Debian/Ubuntu)
python3 docparse_mcp.py            # stdio mode
python3 docparse_mcp.py --http 8983   # streamable HTTP mode
```

Configure in Claude Desktop / Cursor / WorkBuddy:

```json
{
  "mcpServers": {
    "docparse": {
      "command": "python3",
      "args": ["/absolute/path/to/docparse_mcp.py"]
    }
  }
}
```

### Example calls

```json
{"method":"tools/call","params":{"name":"extract_tables","arguments":{"source":"https://example.com/report.pdf"}}}
{"method":"tools/call","params":{"name":"extract_text","arguments":{"source":"<base64>","source_type":"base64","pages":"1-3"}}}
{"method":"tools/call","params":{"name":"ocr_document","arguments":{"source":"https://example.com/scan.png","lang":"eng"}}}
```

Protocol: MCP (JSON-RPC 2.0), version `2024-11-05`. Implements `initialize`, `tools/list`, `tools/call`.

## Security

- **SSRF protection**: URL fetching rejects loopback / private / link-local / cloud-metadata addresses (initial URL *and* after redirects).
- **No external API keys** required: PyMuPDF + tesseract run locally.
- **Rate limiting** is enforced on the hosted version (see below).

## Hosted API (paid, managed)

Prefer not to install and maintain the dependencies? Use the managed API — your agent gets the same six tools over a simple HTTPS endpoint with key auth (30-day key, 100 calls/day):

```
Base: https://<host>/docparse
GET  /v1/health
POST /v1/parse      {"key":"...","source":"...","source_type":"url|base64|path"}
POST /v1/text       {"key":"...","source":"...","pages":"1-3"}
POST /v1/tables     {"key":"...","source":"...","format":"json|csv"}
POST /v1/metadata   {"key":"...","source":"..."}
POST /v1/links      {"key":"...","source":"..."}
POST /v1/ocr        {"key":"...","source":"...","lang":"eng|chi_sim"}
```

Get a key: **https://niebingyu.gumroad.com/l/docparse-api**

## License

MIT — see [LICENSE](LICENSE).
