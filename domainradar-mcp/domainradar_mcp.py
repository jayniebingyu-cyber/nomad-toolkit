#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domainradar-mcp — 域名与品牌智能引擎（给 AI Agent 用）

解决的问题：帮用户起名/创业/建站/选品/做品牌营销的 Agent，在「选域名、注册域名、
查域名归属与到期时间、做品牌命名」时，无法凭训练知识可靠得出——
  1. 域名实时可用性：某个域名此刻是否已被注册，模型不知道（域名随时被人抢注）；
  2. Whois/注册信息：域名注册商是谁、何时注册、何时到期、状态如何、用哪个 NS，
     这些是实时权威数据（RDAP），模型无法自查；
  3. 品牌命名 + 批量可用性：生成 20 个品牌名后逐个查可用性，繁琐且易漏，
     需要工具一次批量打通。

数据源全部为公开权威、免费、无 key：
  - IANA RDAP bootstrap（data.iana.org/rdap/dns.json）→ 各 TLD 的 RDAP 服务器；
  - RDAP（RFC 7483）注册数据：200=已注册、404=可注册，含 registrar/events/nameservers；
  - DNS over HTTPS（Cloudflare）→ 任意记录类型解析。

纯标准库实现（urllib/json/http.server/concurrent.futures），零第三方依赖。

用法：
  python3 domainradar_mcp.py              # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 domainradar_mcp.py --http 8976  # streamable HTTP 模式（Smithery / 官方 registry）

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, datetime, time, urllib.request, urllib.parse, urllib.error, re
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'domainradar-mcp/1.0 (domain intel; contact niebingyu@qq.com)'}

CACHE = {}          # {key: (ts, val)} 通用缓存
CACHE_TTL = 300     # 域名可用性缓存 5 分钟
BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
_bootstrap = None   # {tld: [rdap_url, ...]}
_bootstrap_ts = 0.0

# 品牌命名默认要检查的主流 TLD（按商业价值排序，均可用 RDAP 权威查询）
DEFAULT_TLDS = ['com', 'io', 'ai', 'app', 'net']

# 内置补充 RDAP 映射：IANA bootstrap（dns.json）只覆盖 gTLD 及已登记的 ccTLD，
# 部分热门 ccTLD（io/tv/cc/us/uk/de/fr…）未登记，但注册局已提供 RDAP，这里手动补上。
# 已逐一实测 HTTP 200/404 可用；查不到的 TLD 诚实返回 unknown（宁缺毋滥）。
EXTRA_TLD_RDAP = {
    'io': ['https://rdap.identitydigital.services/rdap/'],
    'tv': ['https://rdap.identitydigital.services/rdap/'],
    'cc': ['https://rdap.identitydigital.services/rdap/'],
    'me': ['https://rdap.identitydigital.services/rdap/'],
    'sh': ['https://rdap.identitydigital.services/rdap/'],
    'gg': ['https://rdap.identitydigital.services/rdap/'],
    'us': ['https://rdap.nic.us/'],
    'uk': ['https://rdap.nominet.uk/uk/'],
    'de': ['https://rdap.denic.de/'],
    'fr': ['https://rdap.nic.fr/'],
    'xyz': ['https://rdap.centralnic.com/xyz/'],
    'ly': ['https://rdap.nic.ly/'],
    'nl': ['https://rdap.sidn.nl/'],
}

# =====================================================================
# 一、基础 HTTP + 缓存
# =====================================================================
def _fetch_json(url, timeout=15):
    req = urllib.request.Request(url, headers=dict(UA))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))

def _cached(key, fn, ttl=CACHE_TTL):
    now = time.time()
    if key in CACHE and now - CACHE[key][0] < ttl:
        return CACHE[key][1]
    val = fn()
    CACHE[key] = (now, val)
    return val

def _load_bootstrap():
    """加载 IANA RDAP bootstrap：{tld: [rdap_base_url, ...]}，缓存 24h。"""
    global _bootstrap, _bootstrap_ts
    now = time.time()
    if _bootstrap and now - _bootstrap_ts < 86400:
        return _bootstrap
    data = _fetch_json(BOOTSTRAP_URL, timeout=20)
    m = {}
    for svc in data.get('services', []):
        tlds, urls = svc[0], svc[1]
        for t in tlds:
            m[t] = urls
    _bootstrap = m
    _bootstrap_ts = now
    return m

# =====================================================================
# 二、域名清洗与校验
# =====================================================================
def _normalize_domain(d):
    """清洗输入：去协议/前缀/路径/尾点，转小写，IDN 转 punycode。"""
    d = (d or '').strip().lower()
    d = re.sub(r'^[a-z]+://', '', d)          # 去 http:// https://
    d = re.sub(r'^www\.', '', d)
    d = d.split('/')[0].split(':')[0].rstrip('.')
    try:
        if any(ord(c) > 127 for c in d):
            d = d.encode('idna').decode('ascii')  # 中文域名 → xn--
    except Exception:
        pass
    return d

def _split_tld(domain):
    """取最后一段作为 TLD（.com/.io；co.uk 这种取 uk，交给 ccTLD RDAP）。"""
    parts = domain.split('.')
    return parts[-1] if len(parts) > 1 else ''

_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')

def _is_valid_domain(d):
    return bool(_DOMAIN_RE.match(d))

# =====================================================================
# 三、RDAP 查询（域名可用性 + whois 信息）
# =====================================================================
def _rdap_query(domain):
    """查询域名 RDAP。返回 (status_code:int|None, payload:dict|None, error:str|None)。
    status=200 已注册；status=404 可注册；None 表示无法判定（无 RDAP 服务器或网络错误）。"""
    tld = _split_tld(domain)
    if not tld:
        return None, None, 'no tld'
    m = _load_bootstrap()
    urls = m.get(tld) or EXTRA_TLD_RDAP.get(tld)
    if not urls:
        return None, None, 'no rdap server for tld: ' + tld
    last_err = None
    for base in urls:
        url = base.rstrip('/') + '/domain/' + urllib.parse.quote(domain)
        try:
            req = urllib.request.Request(url, headers=dict(UA))
            with urllib.request.urlopen(req, timeout=25) as r:
                payload = json.loads(r.read().decode('utf-8', 'ignore'))
                # 少数 RDAP 对未注册域名返回 200 + errorCode=404
                if payload and isinstance(payload, dict) and payload.get('errorCode') == 404:
                    return 404, None, None
                return r.status, payload, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, None, None
            last_err = 'http %d' % e.code
        except Exception as e:
            last_err = repr(e)
    return None, None, last_err

def _check_single(domain):
    """单个域名可用性判定。返回 dict。"""
    d = _normalize_domain(domain)
    if not d or not _is_valid_domain(d):
        return {'domain': domain, 'status': 'invalid', 'available': False,
                'note': '非法域名格式'}
    code, payload, err = _rdap_query(d)
    if code == 404:
        return {'domain': d, 'status': 'available', 'available': True,
                'tld': _split_tld(d)}
    if code == 200 and payload:
        events = {e.get('eventAction'): e.get('eventDate') for e in payload.get('events', [])}
        return {'domain': d, 'status': 'registered', 'available': False,
                'tld': _split_tld(d), 'expires': events.get('expiration'),
                'created': events.get('registration')}
    return {'domain': d, 'status': 'unknown', 'available': False,
            'tld': _split_tld(d) or None, 'note': err or '无法判定（无 RDAP 或网络错误）'}

def _parse_whois(payload, domain):
    """从 RDAP payload 提取结构化 whois 信息（隐私脱敏）。"""
    out = {
        'domain': (payload.get('ldhName') or domain).lower(),
        'status': payload.get('status', []),
        'registrar': None,
        'registrar_iana_id': None,
        'created': None,
        'updated': None,
        'expires': None,
        'nameservers': [],
        'redacted': False,
    }
    if isinstance(payload.get('rdapConformance'), list) and 'redacted' in payload['rdapConformance']:
        out['redacted'] = True
    for e in payload.get('events', []):
        a = e.get('eventAction', '')
        if a == 'registration':
            out['created'] = e.get('eventDate')
        elif a == 'expiration':
            out['expires'] = e.get('eventDate')
        elif a == 'last changed':
            out['updated'] = e.get('eventDate')
    for ent in payload.get('entities', []):
        roles = ent.get('roles', [])
        vcard = ent.get('vcardArray', [None, []])
        items = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        fn = ''
        for it in items:
            if isinstance(it, list) and len(it) > 3 and it[0] == 'fn':
                fn = it[3]
        if 'registrar' in roles and not out['registrar']:
            out['registrar'] = fn
            for pid in ent.get('publicIds', []):
                if pid.get('type') == 'IANA Registrar ID':
                    out['registrar_iana_id'] = pid.get('identifier')
    ns = payload.get('nameservers', [])
    if isinstance(ns, list):
        out['nameservers'] = [n.get('ldhName') for n in ns if isinstance(n, dict) and n.get('ldhName')]
    return out

# =====================================================================
# 四、DNS 查询（DoH）
# =====================================================================
def _dns_query(domain, rtype='A'):
    """DNS 查询（DoH），Cloudflare 优先，失败回退 Google DoH。"""
    servers = [
        ('https://cloudflare-dns.com/dns-query?name={n}&type={t}',
         {'Accept': 'application/dns-json'}),
        ('https://dns.google/resolve?name={n}&type={t}', {}),
    ]
    last_err = None
    for tmpl, extra in servers:
        url = tmpl.format(n=urllib.parse.quote(domain), t=urllib.parse.quote(rtype))
        hdr = {'User-Agent': UA['User-Agent']}
        hdr.update(extra)
        try:
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode('utf-8', 'ignore'))
        except Exception as e:
            last_err = repr(e)
    raise RuntimeError('DNS DoH 均不可用: ' + str(last_err))

# =====================================================================
# 五、品牌命名引擎
# =====================================================================
_SUFFIXES = ['hq', 'lab', 'hub', 'app', 'ai', 'co', 'pro', 'ly', 'base', 'kit',
             'up', 'now', 'go', 'live', 'fy', 'io', 'stack', 'works']
_PREFIXES = ['get', 'try', 'my', 'go', 'hey', 'use', 'the', 'super']

def _gen_variants(keyword):
    """根据关键词生成品牌名候选（去元音/叠字/前后缀/词形变化）。"""
    kw = re.sub(r'[^a-z0-9]', '', keyword.lower())
    if not kw:
        return []
    seen, out = set(), []
    # 原词
    cands = [kw]
    # 原词 + 后缀
    cands += [kw + s for s in _SUFFIXES]
    # 前缀 + 原词
    cands += [p + kw for p in _PREFIXES]
    # 去元音（保守：只对长词）
    if len(kw) >= 5:
        no_vowel = re.sub(r'[aeiou]', '', kw)
        if len(no_vowel) >= 3:
            cands.append(no_vowel)
            cands += [no_vowel + s for s in ['io', 'ai', 'co', 'ly']]
    # 双写尾字母（如 coffee→coffeee 太怪，改用 +ly/+ify 词形）
    if not kw.endswith('y') and len(kw) <= 8:
        cands.append(kw + kw[-1] + 'y')          # → coffeey 之类，慎用，仅作候选
    cands += [kw + 'ify', kw + 'able']
    for c in cands:
        c = c.strip().lower()
        if 3 <= len(c) <= 24 and re.match(r'^[a-z][a-z0-9]*$', c) and c not in seen:
            seen.add(c)
            out.append(c)
    return out[:18]  # 控制数量，避免查询过载

# =====================================================================
# 六、MCP 工具实现
# =====================================================================
def tool_domain_available(args):
    """批量域名可用性检查。"""
    domains = args.get('domains', '')
    if isinstance(domains, list):
        items = domains
    else:
        items = [x.strip() for x in str(domains).split(',') if x.strip()]
    if not items:
        return {'ok': False, 'error': '请提供 domains（逗号分隔或数组）'}
    items = items[:50]  # 单次上限 50
    results = []
    for d in items:
        results.append(_cached('avail:' + _normalize_domain(d), lambda d=d: _check_single(d)))
    available = [r['domain'] for r in results if r.get('available')]
    return {'ok': True, 'queried': len(results),
            'available_count': len(available), 'available': available, 'results': results}

def tool_whois_lookup(args):
    """RDAP Whois 查询。"""
    domain = _normalize_domain(args.get('domain', ''))
    if not domain or not _is_valid_domain(domain):
        return {'ok': False, 'error': '非法域名：' + str(args.get('domain'))}
    code, payload, err = _rdap_query(domain)
    if code == 404:
        return {'ok': True, 'domain': domain, 'status': 'available',
                'note': '域名未注册（无 whois 数据）'}
    if code == 200 and payload:
        info = _parse_whois(payload, domain)
        info['ok'] = True
        # 附带到期倒计时
        if info.get('expires'):
            try:
                exp = datetime.datetime.fromisoformat(info['expires'].replace('Z', '+00:00'))
                days_left = (exp.date() - datetime.date.today()).days
                info['days_until_expiry'] = days_left
            except Exception:
                pass
        return info
    return {'ok': False, 'error': err or '查询失败'}

def tool_brand_names(args):
    """品牌命名 + 可用性引擎。"""
    keyword = (args.get('keyword') or '').strip()
    if not keyword:
        return {'ok': False, 'error': '请提供 keyword'}
    tlds = [t.strip().lower().lstrip('.') for t in str(args.get('tlds', '')).split(',') if t.strip()]
    if not tlds:
        tlds = DEFAULT_TLDS
    tlds = [t for t in tlds if re.match(r'^[a-z0-9-]+$', t)][:6]
    variants = _gen_variants(keyword)
    # 打平所有 (变体 × TLD) 组合，全局并发查询，显著提速
    combos = [(v, t) for v in variants for t in tlds]
    avail_map = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(_check_single, v + '.' + t): (v, t) for v, t in combos}
        for f in futs:
            v, t = futs[f]
            try:
                if f.result().get('available'):
                    avail_map.setdefault(v, []).append(t)
            except Exception:
                pass
    # 按 TLD 优先级顺序排列（com/io/ai 优先）
    rank = {t: i for i, t in enumerate(tlds)}
    results = []
    for v in variants:
        avail = sorted(avail_map.get(v, []), key=lambda x: rank.get(x, 99))
        results.append({'name': v, 'available_tlds': avail,
                        'best_domain': (v + '.' + avail[0]) if avail else None})
    registrable = [r for r in results if r['available_tlds']]
    return {'ok': True, 'keyword': keyword, 'tlds_checked': tlds,
            'candidates': len(results), 'registrable_count': len(registrable),
            'registrable': registrable,
            'note': '仅列出至少一个 TLD 可注册的候选；com 优先。域名可用性实时变化，注册前请复核。'}

def tool_dns_records(args):
    """DNS 记录查询（DoH）。"""
    domain = _normalize_domain(args.get('domain', ''))
    if not domain or not _is_valid_domain(domain):
        return {'ok': False, 'error': '非法域名：' + str(args.get('domain'))}
    rtype = (args.get('type') or 'A').upper()
    if not re.match(r'^[A-Z]{1,10}$', rtype):
        return {'ok': False, 'error': '非法记录类型'}
    data = _dns_query(domain, rtype)
    answers = data.get('Answer', []) or []
    records = [{'name': a.get('name'), 'type': a.get('type'), 'ttl': a.get('TTL'),
                'value': a.get('data')} for a in answers]
    return {'ok': True, 'domain': domain, 'type': rtype,
            'status': data.get('Status'), 'records': records}

# =====================================================================
# 七、MCP 协议定义
# =====================================================================
TOOLS = [
 {'name': 'domain_available',
  'description': '批量检查域名是否可注册（实时权威判定）。输入一个或多个域名（逗号分隔或数组），返回每个域名的状态：available(可注册)/registered(已注册，附到期时间)/unknown(无法判定)。给创业/建站/选品/品牌 Agent 判断「这个域名现在能不能注册」。基于 IANA RDAP（RFC 7483）权威数据，非猜测。',
  'inputSchema': {'type': 'object', 'properties': {
      'domains': {'type': 'string', 'description': '要检查的域名，逗号分隔（如 "mytool.com, mytool.io, 我的品牌.cn"），或 JSON 数组。最多 50 个'}},
      'required': ['domains']}},
 {'name': 'whois_lookup',
  'description': '查询域名注册信息（RDAP Whois）：注册商、注册时间、到期时间、状态、DNS 服务器、是否隐私保护，附「距到期天数」。给品牌/域名管理 Agent 判断某域名归属、是否快到期需续费。域名未注册时返回 available。',
  'inputSchema': {'type': 'object', 'properties': {
      'domain': {'type': 'string', 'description': '域名，如 "google.com"'}},
      'required': ['domain']}},
 {'name': 'brand_names',
  'description': '品牌命名引擎：输入一个关键词（如 "coffee"），生成约 18 个品牌名候选（前后缀/去元音/词形变化），并实时批量检查每个候选在主流 TLD（.com/.io/.ai/.co/.app）下的可用性，返回「可注册」的品牌名+可用域名。给品牌营销/命名/创业 Agent 一站式起名+查可用性。',
  'inputSchema': {'type': 'object', 'properties': {
      'keyword': {'type': 'string', 'description': '品牌关键词（英文，如 coffee/fitness/cloud）'},
      'tlds': {'type': 'string', 'description': '要检查的 TLD，逗号分隔（默认 com,io,ai,co,app）'}},
      'required': ['keyword']}},
 {'name': 'dns_records',
  'description': '查询域名 DNS 记录（A/AAAA/CNAME/MX/NS/TXT 等），通过 Cloudflare DoH 实时解析。给运维/部署/排查 Agent 查某域名的解析结果、MX 邮件服务器、TXT 验证记录等。',
  'inputSchema': {'type': 'object', 'properties': {
      'domain': {'type': 'string', 'description': '域名，如 "example.com"'},
      'type': {'type': 'string', 'description': '记录类型（A/AAAA/CNAME/MX/NS/TXT，默认 A）'}},
      'required': ['domain']}},
]

def handle_request(req):
    method = req.get('method', '')
    rid = req.get('id')
    def ok(result):
        return {'jsonrpc': '2.0', 'id': rid, 'result': result}
    def err(code, message):
        return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': code, 'message': message}}
    if method == 'initialize':
        return ok({'protocolVersion': PROTOCOL_VERSION,
                   'capabilities': {'tools': {}},
                   'serverInfo': {'name': 'domainradar-mcp', 'version': '1.0.0'}})
    elif method == 'notifications/initialized':
        return None
    elif method == 'ping':
        return ok({})
    elif method == 'tools/list':
        return ok({'tools': TOOLS})
    elif method == 'tools/call':
        name = req.get('params', {}).get('name', '')
        args = req.get('params', {}).get('arguments', {}) or {}
        try:
            if name == 'domain_available':
                data = tool_domain_available(args)
            elif name == 'whois_lookup':
                data = tool_whois_lookup(args)
            elif name == 'brand_names':
                data = tool_brand_names(args)
            elif name == 'dns_records':
                data = tool_dns_records(args)
            else:
                return err(-32601, 'unknown tool: ' + name)
            return ok({'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=False, indent=1)}],
                       'isError': False})
        except Exception as e:
            return err(-32000, repr(e))
    elif rid is not None:
        return err(-32601, 'method not found: ' + method)
    return None

# ---------- stdio 模式 ----------
def main_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle_request(req)
        if resp:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + '\n')
            sys.stdout.flush()

# ---------- HTTP 模式（streamable HTTP transport） ----------
class MCPHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, Authorization, Last-Event-ID')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, DELETE')
        self.send_header('Access-Control-Expose-Headers', 'Mcp-Session-Id')

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_GET(self):
        self.send_response(200); self._cors()
        self.send_header('Content-Type', 'application/json'); self.end_headers()
        self.wfile.write(json.dumps({'service': 'domainradar-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

    def do_DELETE(self):
        self.send_response(200); self._cors(); self.end_headers()

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(n)
        try:
            req = json.loads(body.decode('utf-8'))
        except Exception:
            self.send_response(400); self._cors(); self.end_headers(); return
        resp = handle_request(req)
        accept = self.headers.get('Accept', 'application/json')
        self.send_response(200); self._cors()
        if 'text/event-stream' in accept and resp is not None:
            self.send_header('Content-Type', 'text/event-stream'); self.end_headers()
            self.wfile.write(('data: ' + json.dumps(resp, ensure_ascii=False) + '\n\n').encode())
        else:
            self.send_header('Content-Type', 'application/json'); self.end_headers()
            if resp is not None:
                self.wfile.write(json.dumps(resp, ensure_ascii=False).encode())

    def log_message(self, *a):
        pass

def main_http(port):
    print('domainradar-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8976
        main_http(port)
    else:
        main_stdio()
