# ipintel-mcp — IP & ASN Intelligence for AI Agents

A zero-dependency MCP server that answers the questions a model **cannot answer from its training data**:

- **Who owns this IP?** country, network name, handle, registration dates — from authoritative RDAP (RFC 7483).
- **Which ASN / organization?** autonomous system number, AS name, ISP, org — cross-checked with ipwho.is.
- **Is it a datacenter / cloud IP or residential broadband?** a verdict agents doing anti-fraud / security / ops need.
- **What is this ASN?** name, country, organization, remarks — from RDAP autnum.

All data sources are **public, authoritative, free and key-less**:

| Data | Source |
|------|--------|
| IP registry data (country / network / handle / CIDR / events) | IANA RDAP bootstrap → RIR RDAP (ARIN / RIPE / APNIC / LACNIC / AFRINIC) |
| IP → ASN / AS name / ISP / org | ipwho.is (free, no key) |
| ASN details | IANA RDAP `asn.json` bootstrap → RIR autnum |

Pure Python standard library (`urllib` / `json` / `http.server` / `concurrent.futures` / `ipaddress`). No pip installs.

## Tools

| Tool | What it does |
|------|--------------|
| `ip_lookup` | Full intel for one IP: country, ASN, AS name, org, network name, CIDR, registration dates, datacenter verdict |
| `ip_batch` | Batch lookup up to 50 IPs (concurrent) |
| `asn_lookup` | Details for an AS number (name / country / org / remarks) |
| `ip_classify` | Verdict-oriented: address class, cloud-vs-residential, country (incl. China flag), risk flags |

## Run it

**stdio** (Claude Desktop / WorkBuddy / Cursor / any MCP client):

```bash
python3 ipintel_mcp.py
```

**Streamable HTTP** (Smithery / official registry):

```bash
python3 ipintel_mcp.py --http 8978
```

### Claude Desktop config (example)

```json
{
  "mcpServers": {
    "ipintel": {
      "command": "python3",
      "args": ["/path/to/ipintel_mcp.py"]
    }
  }
}
```

## Example output

```json
{
  "ip": "8.8.8.8",
  "ip_version": 4,
  "country": "US",
  "asn": 15169,
  "as_name": "Google LLC",
  "org": "Google LLC",
  "network_name": "GOGL",
  "cidrs": ["8.8.8.0/24"],
  "category": "cloud_datacenter",
  "is_datacenter": true,
  "class": "公网地址"
}
```

## Self-host vs. paid hosted API

You can self-host this for free (it's all open source). If you don't want to run a server, use the hosted API:

- **Paid hosted API** (30 days, 100 calls/day): [ipintel-api on Gumroad](https://niebingyu.gumroad.com/l/ipintel-api)
- **Base URL**: `http://43.160.199.215/ipintel`

```bash
curl "http://43.160.199.215/ipintel/v1/lookup?ip=8.8.8.8&key=YOUR_KEY"
curl "http://43.160.199.215/ipintel/v1/classify?ip=8.8.8.8&key=YOUR_KEY"
curl "http://43.160.199.215/ipintel/v1/asn?asn=15169&key=YOUR_KEY"
curl "http://43.160.199.215/ipintel/v1/health"   # free
```

## License

MIT
