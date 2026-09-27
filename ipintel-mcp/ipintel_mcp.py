#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ipintel-mcp — IP 与 ASN 网络情报引擎（给 AI Agent 用）

解决的问题：做安全分析 / 反欺诈 / 网络运维 / 数据合规的 Agent，在「某个 IP 此刻
属于谁、在哪个国家、是云厂商机房还是住宅宽带、这个 ASN 是什么组织」时，无法凭
训练知识可靠得出——
  1. IP 归属：某个 IP 此刻属于哪个国家 / 网络 / 自治系统(ASN)，模型不知道
     （IP 段的归属与再分配实时变化，训练数据早已过期）；
  2. 数据中心 / 云厂商判定：判断一个 IP 是云服务器（AWS / 阿里云 / 腾讯云…）还是
     住宅宽带，反欺诈 Agent 要靠它判断「注册 / 登录 IP 是不是机房 IP / 代理」；
  3. ASN 详情：某个 AS 号是哪个组织、在哪个国家、分配了哪些网段，模型无法自查。

数据源全部为公开权威、免费、无 key：
  - IANA RDAP bootstrap（data.iana.org/rdap/ipv4.json + ipv6.json）→ 各 RIR 的 RDAP 服务器；
  - RDAP（RFC 7483）IP 注册数据：country / 网络名 / type / handle / CIDR / events / status；
  - IANA RDAP asn.json bootstrap → 各 RIR autnum → ASN 详情（名称/国家/描述）；
  - ipwho.is（免费无 key）→ IP 的 ASN / AS 名称 / ISP / 组织（IP→ASN 补充）。

纯标准库实现（urllib / json / http.server / concurrent.futures / ipaddress），零第三方依赖。

用法：
  python3 ipintel_mcp.py              # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 ipintel_mcp.py --http 8978  # streamable HTTP 模式（Smithery / 官方 registry）

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, datetime, time, urllib.request, urllib.parse, urllib.error, re
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'ipintel-mcp/1.0 (IP & ASN intel; contact niebingyu@qq.com)'}

CACHE = {}          # {key: (ts, val)} 通用缓存
CACHE_TTL = 86400   # IP/ASN 归属数据稳定，缓存 24 小时
IPV4_BOOTSTRAP_URL = 'https://data.iana.org/rdap/ipv4.json'
IPV6_BOOTSTRAP_URL = 'https://data.iana.org/rdap/ipv6.json'
ASN_BOOTSTRAP_URL = 'https://data.iana.org/rdap/asn.json'
_bootstrap_v4 = None   # [(ip_network, [url, ...]), ...]
_bootstrap_v6 = None
_bootstrap_asn = None  # [(lo, hi, [url, ...]), ...]
_bootstrap_ts = 0.0

# 云厂商 / 数据中心 / 托管机房 关键词（用于判定 IP 是否为"机房 IP"，反欺诈常用）。
# 匹配对象：AS 名称 + RDAP 网络名 + ipwho.is 的 org/isp，全部转小写后做子串匹配。
CLOUD_KEYWORDS = [
    'amazon', 'aws', 'google', 'microsoft', 'azure', 'digitalocean', 'ovh',
    'hetzner', 'linode', 'akamai', 'cloudflare', 'alibaba', 'aliyun', 'alisoft',
    'tencent', 'huawei', 'oracle', 'vultr', 'choopa', 'baidu', 'contabo',
    'leaseweb', 'godaddy', 'softlayer', 'rackspace', 'scaleway', 'upcloud',
    'fastly', 'datacenter', 'hosting', 'colo', 'server', 'psychz', 'quadranet',
    'vps', 'kimsufi', 'cloud', 'cogent', 'level3', 'he.net', 'hurricane',
    'paloalto', 'zayo', 'equinix',
]
# 住宅 / 移动宽带 ISP 关键词（用于辅助判定"住宅宽带"）
ISP_KEYWORDS = [
    'broadband', 'telecom', 'fiber', 'dsl', 'cable', 'mobile', 'wireless',
    'verizon', 'comcast', 'xfinity', 'att', 'charter', 'spectrum', 'vodafone',
    'orange', 'telefonica', 'deutsche telekom', 'bt', 'kddi', 'ntt', 'softbank',
    'docomo', 'chinamobile', 'china unicom', 'china telecom', '中国移动',
    '中国联通', '中国电信', 't-mobile', 'sprint', 'sky', 'virgin', 'three',
    'rogers', 'bell', 'telus', 'optus', 'telstra', 'singtel', 'starhub',
]

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

def _load_ip_bootstrap(v6=False):
    """加载 IANA RDAP IP bootstrap：返回 [(ip_network, [url,...]), ...]，缓存 24h。"""
    global _bootstrap_v4, _bootstrap_v6, _bootstrap_ts
    now = time.time()
    target = _bootstrap_v6 if v6 else _bootstrap_v4
    if target and now - _bootstrap_ts < 86400:
        return target
    url = IPV6_BOOTSTRAP_URL if v6 else IPV4_BOOTSTRAP_URL
    data = _fetch_json(url, timeout=20)
    out = []
    for svc in data.get('services', []):
        cidrs, urls = svc[0], svc[1]
        for c in cidrs:
            try:
                out.append((ipaddress.ip_network(c), urls))
            except Exception:
                pass
    if v6:
        _bootstrap_v6 = out
    else:
        _bootstrap_v4 = out
    _bootstrap_ts = now
    return out

def _load_asn_bootstrap():
    """加载 IANA RDAP asn bootstrap：返回 [(lo, hi, [url,...]), ...]，缓存 24h。"""
    global _bootstrap_asn, _bootstrap_ts
    now = time.time()
    if _bootstrap_asn and now - _bootstrap_ts < 86400:
        return _bootstrap_asn
    data = _fetch_json(ASN_BOOTSTRAP_URL, timeout=20)
    out = []
    for svc in data.get('services', []):
        ranges, urls = svc[0], svc[1]
        for r in ranges:
            # 范围形如 "15169-15169" 或 "64512-65534"
            m = re.match(r'^(\d+)-(\d+)$', r)
            if m:
                out.append((int(m.group(1)), int(m.group(2)), urls))
    _bootstrap_asn = out
    _bootstrap_ts = now
    return out

# =====================================================================
# 二、IP 地址识别与校验（ipaddress 标准库）
# =====================================================================
def _parse_ip(s):
    """解析 IP 字符串，非法返回 None。"""
    s = (s or '').strip()
    # 去协议前缀 / 端口 / CIDR
    s = re.sub(r'^[a-z]+://', '', s)
    s = s.split('/')[0].split(':')[0] if s.count('.') == 3 else s  # 仅对 IPv4 去端口
    try:
        return ipaddress.ip_address(s)
    except Exception:
        return None

_SPECIAL_NAMES = {
    'is_private': '私网(内网)地址',
    'is_loopback': '回环地址(127.0.0.1 / ::1)',
    'is_link_local': '链路本地地址(169.254/fe80)',
    'is_multicast': '组播地址',
    'is_reserved': '保留地址',
    'is_unspecified': '未指定地址(0.0.0.0 / ::)',
    'is_global': '公网地址',
}

def _classify_address(ip):
    """对 IP 做 RFC 分类（私网/回环/链路本地/组播/保留/公网）。返回 dict。"""
    out = {}
    for attr, label in _SPECIAL_NAMES.items():
        try:
            out[attr] = bool(getattr(ip, attr))
        except Exception:
            out[attr] = False
    # 文档地址（TEST-NET / 192.0.2 等）归为"保留/文档"
    if ip.version == 4:
        a = int(ip)
        doc = ((a >= 0xC0000200 and a <= 0xC00002FF) or   # 192.0.2.0/24
               (a >= 0xC6120000 and a <= 0xC613FFFF) or   # 198.51.100.0/24
               (a >= 0xCB007100 and a <= 0xCB0071FF))      # 203.0.113.0/24
        if doc:
            out['is_documentation'] = True
            out['is_global'] = False
    else:
        if ip in ipaddress.ip_network('2001:db8::/32'):
            out['is_documentation'] = True
            out['is_global'] = False
    # 标签：判定主要类别
    labels = []
    for attr, label in _SPECIAL_NAMES.items():
        if out.get(attr):
            labels.append(label)
    out['class'] = labels[0] if labels else '公网地址'
    out['is_public'] = out.get('is_global', False) and not out.get('is_documentation', False)
    return out

# =====================================================================
# 三、RDAP 查询（IP 权威归属）
# =====================================================================
def _rdap_ip(ip):
    """查询 IP 的 RDAP 注册数据。返回 (payload:dict|None, error:str|None)。"""
    urls = None
    boot = _load_ip_bootstrap(ip.version == 6)
    for net, u in boot:
        if ip in net:
            urls = u
            break
    if not urls:
        return None, 'no rdap server (私有/保留地址或未分配段)'
    last_err = None
    for base in urls:
        # 统一拼接：base 以 /registry/ 或 /rdap/ 结尾，直接拼 /ip/{ip}
        url = base.rstrip('/') + '/ip/' + str(ip)
        try:
            req = urllib.request.Request(url, headers=dict(UA))
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read().decode('utf-8', 'ignore')), None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, 'not found in rdap'
            last_err = 'http %d' % e.code
        except Exception as e:
            last_err = repr(e)
    return None, last_err

def _extract_country(payload):
    """提取国家代码。RIPE/APNIC/LACNIC/AFRINIC 直接给 country 字段；ARIN 无，
    从 entities 的 vcard `adr` 属性兜底提取（取最后一个 2 字母大写段）。"""
    c = payload.get('country')
    if c:
        return c.upper()
    for ent in payload.get('entities', []):
        vcard = ent.get('vcardArray', [None, []])
        items = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        for it in items:
            if isinstance(it, list) and len(it) > 1 and it[0] == 'adr':
                adr = it[3] if len(it) > 3 else None
                seq = adr if isinstance(adr, list) else [adr]
                for x in reversed(seq):
                    if isinstance(x, str) and re.match(r'^[A-Z]{2}$', x.strip()):
                        return x.strip()
                if isinstance(adr, str):
                    for part in reversed([p.strip() for p in adr.split(',')]):
                        if re.match(r'^[A-Z]{2}$', part):
                            return part
    return None

def _extract_org(payload):
    """提取组织名（entities 里 role 含 registrant 的 entity 的 fn）。"""
    for ent in payload.get('entities', []):
        roles = ent.get('roles', [])
        vcard = ent.get('vcardArray', [None, []])
        items = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        fn = ''
        for it in items:
            if isinstance(it, list) and len(it) > 3 and it[0] == 'fn':
                fn = it[3]
        if 'registrant' in roles and fn:
            return fn
    return None

def _parse_rdap_ip(payload, ip):
    """从 RDAP IP payload 提取结构化信息。"""
    events = {e.get('eventAction'): e.get('eventDate') for e in payload.get('events', [])}
    cidrs = []
    for k, arr in payload.items():
        if isinstance(arr, list) and k.endswith('_cidrs'):
            for c in arr:
                if isinstance(c, dict):
                    pre = c.get('v4prefix') or c.get('v6prefix')
                    ln = c.get('length')
                    if pre:
                        cidrs.append('%s/%s' % (pre, ln))
    return {
        'ip': str(ip),
        'ip_version': ip.version,
        'network_name': payload.get('name'),
        'handle': payload.get('handle'),
        'type': payload.get('type'),
        'country': _extract_country(payload),
        'org': _extract_org(payload),
        'status': payload.get('status', []),
        'cidrs': cidrs,
        'start_address': payload.get('startAddress'),
        'end_address': payload.get('endAddress'),
        'registered': events.get('registration'),
        'last_changed': events.get('last changed'),
        'parent_handle': payload.get('parentHandle'),
    }

# =====================================================================
# 四、ipwho.is（IP→ASN / 组织 补充）
# =====================================================================
def _ipwhois(ip):
    """查 ipwho.is 获取 ASN / AS 名称 / ISP / 组织。返回 dict 或 None。"""
    url = 'https://ipwho.is/' + urllib.parse.quote(str(ip))
    try:
        req = urllib.request.Request(url, headers=dict(UA))
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode('utf-8', 'ignore'))
    except Exception:
        return None
    if not d or d.get('success') is not True:
        return None
    conn = d.get('connection') or {}
    return {
        'asn': conn.get('asn'),
        'as_name': conn.get('org') or conn.get('isp'),
        'isp': conn.get('isp'),
        'org': conn.get('org'),
        'domain': conn.get('domain'),
        'city': d.get('city'),
        'region': d.get('region'),
        'continent': d.get('continent'),
        'country_code': d.get('country_code'),
        'is_eu': d.get('is_eu'),
    }

# =====================================================================
# 五、数据中心 / 云厂商 判定
# =====================================================================
def _match_keywords(text, keywords):
    """文本是否命中关键词（子串匹配，忽略大小写）。"""
    t = (text or '').lower()
    return any(k in t for k in keywords)

def _judge_category(rdap, whois):
    """综合判定 IP 类别：cloud_datacenter / residential_isp / business / unknown。"""
    # 汇总所有可匹配的文本
    texts = ' '.join(filter(None, [
        whois.get('as_name'), whois.get('org'), whois.get('isp'),
        rdap.get('network_name'), rdap.get('org'),
    ]))
    if not texts.strip():
        return 'unknown'
    if _match_keywords(texts, CLOUD_KEYWORDS):
        return 'cloud_datacenter'
    if _match_keywords(texts, ISP_KEYWORDS):
        return 'residential_isp'
    return 'business'

# =====================================================================
# 六、工具实现
# =====================================================================
def _lookup_one(ip_str):
    """查单个 IP，返回完整情报 dict。"""
    ip = _parse_ip(ip_str)
    if ip is None:
        return {'ip': ip_str, 'ok': False, 'error': '非法 IP 地址'}
    out = {'ip': str(ip), 'ip_version': ip.version, 'ok': True}
    out.update(_classify_address(ip))
    # 公网地址才查 RDAP / ipwho.is；私网/保留地址直接返回分类结论
    if out.get('is_public'):
        payload, err = _rdap_ip(ip)
        if payload:
            rdap = _parse_rdap_ip(payload, ip)
            out.update(rdap)
            out['rdap_ok'] = True
        else:
            out['rdap_ok'] = False
            out['rdap_error'] = err
        w = _ipwhois(ip)
        if w:
            out['asn'] = w['asn']
            out['as_name'] = w['as_name']
            out['isp'] = w['isp']
            out['org'] = w.get('org')
            out['city'] = w.get('city')
            out['region'] = w.get('region')
            out['continent'] = w.get('continent')
            # ARIN 的 IP 网络对象不直接给 country，用 ipwho.is 的 country_code 兜底
            out['country'] = out.get('country') or w.get('country_code')
        # 数据中心/云厂商判定（基于 RDAP 网络名 + whois 组织名）
        rdap_for_judge = {'network_name': out.get('network_name'), 'org': out.get('org')}
        out['category'] = _judge_category(rdap_for_judge, out)
        out['is_datacenter'] = (out['category'] == 'cloud_datacenter')
    else:
        out['category'] = 'special_address'
        out['is_datacenter'] = False
        out['note'] = '私有/保留/特殊地址，无公网 RDAP 归属信息'
    return out

def tool_ip_lookup(args):
    """单个 IP 情报查询。"""
    ip = (args.get('ip') or '').strip()
    if not ip:
        return {'ok': False, 'error': '请提供 ip'}
    return _cached('ip:' + ip, lambda: _lookup_one(ip))

def tool_ip_batch(args):
    """批量 IP 情报查询（并发）。"""
    ips = args.get('ips', '')
    if isinstance(ips, list):
        items = [str(x).strip() for x in ips if str(x).strip()]
    else:
        items = [x.strip() for x in str(ips).split(',') if x.strip()]
    if not items:
        return {'ok': False, 'error': '请提供 ips（逗号分隔或数组）'}
    items = items[:50]  # 单次上限 50
    results = [None] * len(items)
    def _run(i, ip):
        return i, _cached('ip:' + ip, lambda: _lookup_one(ip))
    with ThreadPoolExecutor(max_workers=20) as ex:
        for i, r in ex.map(lambda p: _run(*p), enumerate(items)):
            results[i] = r
    return {'ok': True, 'queried': len(items), 'results': results}

def tool_asn_lookup(args):
    """ASN 详情查询（RDAP autnum）。"""
    raw = str(args.get('asn') or '').strip()
    m = re.match(r'^(?:AS)?(\d+)$', raw, re.IGNORECASE)
    if not m:
        return {'ok': False, 'error': '非法 ASN，格式如 15169 或 AS15169'}
    asn = int(m.group(1))
    return _cached('asn:' + str(asn), lambda: _lookup_asn(asn))

def _lookup_asn(asn):
    """查 ASN 详情。"""
    urls = None
    for lo, hi, u in _load_asn_bootstrap():
        if lo <= asn <= hi:
            urls = u
            break
    if not urls:
        return {'ok': False, 'asn': asn, 'error': '未分配的 ASN 号段'}
    last_err = None
    for base in urls:
        url = base.rstrip('/') + '/autnum/' + str(asn)
        try:
            req = urllib.request.Request(url, headers=dict(UA))
            with urllib.request.urlopen(req, timeout=20) as r:
                payload = json.loads(r.read().decode('utf-8', 'ignore'))
            events = {e.get('eventAction'): e.get('eventDate') for e in payload.get('events', [])}
            return {
                'ok': True, 'asn': asn,
                'handle': payload.get('handle'),
                'name': payload.get('name'),
                'country': (payload.get('country') or '').upper() or None,
                'type': payload.get('type'),
                'org': _extract_org(payload),
                'registered': events.get('registration'),
                'last_changed': events.get('last changed'),
                'status': payload.get('status', []),
                'remarks': [r.get('description') for r in payload.get('remarks', [])
                            if isinstance(r, dict) and r.get('description')][:3],
            }
        except urllib.error.HTTPError as e:
            last_err = 'http %d' % e.code
        except Exception as e:
            last_err = repr(e)
    return {'ok': False, 'asn': asn, 'error': last_err or '查询失败'}

def tool_ip_classify(args):
    """IP 深度分类（结论版）：私网类型 + 云/住宅判定 + 风险提示。"""
    data = tool_ip_lookup(args)
    if not data.get('ok'):
        return data
    risk = []
    if data.get('is_datacenter'):
        risk.append('机房/云厂商 IP：可能是服务器、代理或爬虫出口')
    if data.get('is_private') or data.get('is_loopback'):
        risk.append('内网/回环地址：非公网来源，无法做地域归属')
    if data.get('is_reserved') or data.get('is_documentation'):
        risk.append('保留/文档地址：通常见于伪造的日志或测试数据')
    country = data.get('country') or data.get('country_code')
    in_cn = country == 'CN'
    summary = {
        'ip': data.get('ip'),
        'class': data.get('class'),
        'category': data.get('category'),
        'is_datacenter': data.get('is_datacenter'),
        'country': country,
        'asn': data.get('asn'),
        'as_name': data.get('as_name'),
        'org': data.get('org') or data.get('network_name'),
        'in_china': in_cn,
        'risk_flags': risk,
        'verdict': ('可信公网来源' if not risk and data.get('is_public')
                    else ('需人工复核' if risk else '特殊地址')),
    }
    return {'ok': True, **summary}

# =====================================================================
# 七、MCP 协议定义
# =====================================================================
TOOLS = [
 {'name': 'ip_lookup',
  'description': '查询单个 IP 的完整网络情报：国家/地区、自治系统(ASN)、AS 名称、组织、网络名、网段(CIDR)、注册时间、以及是否机房/云厂商 IP。给安全分析、反欺诈、网络运维、数据合规 Agent 判断「这个 IP 是谁的、在哪个国家、是不是云服务器」。基于 IANA RDAP（RFC 7483）权威注册数据 + ipwho.is ASN 补充，非猜测。',
  'inputSchema': {'type': 'object', 'properties': {
      'ip': {'type': 'string', 'description': 'IP 地址，如 "8.8.8.8" 或 "2001:4860:4860::8888"'}},
      'required': ['ip']}},
 {'name': 'ip_batch',
  'description': '批量查询多个 IP 的网络情报（并发，最多 50 个）。输入逗号分隔或数组，返回每个 IP 的国家/ASN/组织/网段/机房判定。给批量分析日志、攻击来源列表、注册用户 IP 的 Agent 一次性打通。',
  'inputSchema': {'type': 'object', 'properties': {
      'ips': {'type': 'string', 'description': 'IP 列表，逗号分隔（如 "8.8.8.8, 223.5.5.5, 1.1.1.1"）或 JSON 数组。最多 50 个'}},
      'required': ['ips']}},
 {'name': 'asn_lookup',
  'description': '查询自治系统号(ASN)详情：AS 名称、所属国家、组织、注册时间、备注。输入 AS 号（如 15169 或 AS15169）。给网络运维/安全 Agent 判断「这个 AS 是谁的、在哪、是什么类型的网络」。基于 IANA RDAP autnum 权威数据。',
  'inputSchema': {'type': 'object', 'properties': {
      'asn': {'type': 'string', 'description': 'AS 号，如 "15169" 或 "AS15169"'}},
      'required': ['asn']}},
 {'name': 'ip_classify',
  'description': 'IP 深度分类（结论版）：一次性给出 IP 的类别（公网/私网/回环/保留）、是否机房云厂商 IP、所属国家（是否中国境内）、ASN，并输出风险提示与综合判定。给反欺诈/风控 Agent 快速判断一个 IP 是否可疑来源。',
  'inputSchema': {'type': 'object', 'properties': {
      'ip': {'type': 'string', 'description': 'IP 地址，如 "8.8.8.8"'}},
      'required': ['ip']}},
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
                   'serverInfo': {'name': 'ipintel-mcp', 'version': '1.0.0'}})
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
            if name == 'ip_lookup':
                data = tool_ip_lookup(args)
            elif name == 'ip_batch':
                data = tool_ip_batch(args)
            elif name == 'asn_lookup':
                data = tool_asn_lookup(args)
            elif name == 'ip_classify':
                data = tool_ip_classify(args)
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
        self.wfile.write(json.dumps({'service': 'ipintel-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('ipintel-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8978
        main_http(port)
    else:
        main_stdio()
