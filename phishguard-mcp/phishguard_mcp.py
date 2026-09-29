#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phishguard-mcp — URL 钓鱼 / 恶意链接检测引擎（给 AI Agent 用）

解决的问题：Agent 在做「安全浏览 / 点击链接前校验 / 反钓鱼 / 邮件链接检查」时，
无法凭训练知识判断「这个 URL 此刻是否在钓鱼黑名单里、是否伪造品牌、是否 IDN 同形字、
短链背后到底指向哪、域名是不是刚注册的马甲站」——这些都是实时权威事实 + 需本地引擎计算。

本工具给 Agent 提供：
  1. check_url：对一个 URL 做综合检测，返回风险评分(0-100) + 结论(safe/suspicious/malicious)
     + 是否命中 OpenPhish 钓鱼黑名单 + 命中的启发式规则 + 域名注册年龄 + 短链展开后的真实目标；
  2. lookup_feed：在 OpenPhish 权威钓鱼黑名单里做精确 / 域名级匹配；
  3. expand_url：展开短链（bit.ly / t.co / tinyurl 等），跟随重定向，返回真实落地 URL 与跳转链；
  4. analyze_domain：域名信誉——注册年龄、是否新注册、可疑 TLD、品牌仿冒判定。

典型付费场景（模型无法凭训练数据自查）：
  - 邮件/客服 Agent：用户发来的链接是不是钓鱼？
  - 安全浏览 Agent：在抓取/访问一个 URL 前，先判断它是否恶意、短链指向哪里；
  - 反欺诈 Agent：域名是不是刚注册 3 天的马甲站、是否仿冒 paypal/银行/交易所品牌。

数据源（全部免费、权威、无 key）：
  - OpenPhish 社区钓鱼黑名单 feed（https://openphish.com/feed.txt，每日更新，本地缓存 + 30 分钟刷新）；
  - IANA RDAP（域名注册时间 / 注册局权威数据，复用 nomad-toolkit 已验证的 RDAP 逻辑）；
  - 本地启发式规则引擎（IP 主机、IDN/punycode、可疑 TLD、品牌仿冒、敏感词、超长子域名、@ 伪装等）。

纯标准库实现（urllib / json / re / hashlib / http.server），零第三方依赖。

用法：
  python3 phishguard_mcp.py                # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 phishguard_mcp.py --http 8981    # streamable HTTP 模式

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, os, re, time, hashlib, datetime, urllib.request, urllib.parse, urllib.error, socket
from http.server import BaseHTTPRequestHandler, HTTPServer

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'Mozilla/5.0 (compatible; phishguard-mcp/1.0; +https://github.com/jayniebingyu-cyber/nomad-toolkit)'}

# OpenPhish 黑名单本地缓存文件
FEED_FILE = os.environ.get('PHISHGUARD_FEED', '/home/ubuntu/auto-income-cloud/phishguard_feed.json')
FEED_URL = 'https://openphish.com/feed.txt'
FEED_TTL = 1800  # 30 分钟刷新一次（免费 feed 每日更新，本地缓存降低延迟）

# =====================================================================
# 一、OpenPhish 黑名单 feed：下载 + 缓存 + 刷新
# =====================================================================
_feed_urls = None      # set: 规范化后的完整 URL
_feed_hosts = None     # set: 规范化后的 hostname（域名级模糊匹配）
_feed_ts = 0.0

def _fetch_text(url, timeout=30):
    req = urllib.request.Request(url, headers=dict(UA))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', 'ignore')

def _norm_host(host):
    return (host or '').strip().lower().rstrip('.')

def _norm_url(u):
    """规范化 URL：小写 scheme/host、去默认端口、去 fragment、保留路径（供精确匹配）。"""
    u = (u or '').strip()
    if not u:
        return ''
    # 去 fragment
    u = u.split('#')[0]
    m = re.match(r'^([a-z][a-z0-9+.-]*://)([^/]*)(.*)$', u, re.I)
    if not m:
        return u.lower()
    scheme, netloc, path = m.group(1).lower(), m.group(2).lower(), m.group(3)
    # 去默认端口
    netloc = re.sub(r':(80|443)$', '', netloc)
    return scheme + netloc + path

def _extract_host(url):
    """从 URL 提取 hostname（处理 user@host 伪装、IPv6、端口）。"""
    m = re.match(r'^[a-z][a-z0-9+.-]*://([^/]+)', url, re.I)
    if not m:
        return ''
    netloc = m.group(1)
    # userinfo@host —— 钓鱼常用 user@host 伪装
    if '@' in netloc:
        netloc = netloc.rsplit('@', 1)[-1]
    # IPv6 [::1]
    if netloc.startswith('['):
        netloc = netloc[1:].split(']')[0]
    netloc = netloc.split(':')[0]
    return _norm_host(netloc)

def _load_feed(force=False):
    """加载 OpenPhish feed。返回 (urls_set, hosts_set)。缓存 30 分钟。"""
    global _feed_urls, _feed_hosts, _feed_ts
    now = time.time()
    if _feed_urls is not None and not force and now - _feed_ts < FEED_TTL:
        return _feed_urls, _feed_hosts
    # 尝试从本地缓存文件加载
    try:
        with open(FEED_FILE, 'r', encoding='utf-8') as f:
            d = json.load(f)
            _feed_urls = set(d.get('urls', []))
            _feed_hosts = set(d.get('hosts', []))
            _feed_ts = d.get('ts', 0)
            if now - _feed_ts < FEED_TTL:
                return _feed_urls, _feed_hosts
    except Exception:
        pass
    # 重新下载
    urls, hosts = set(), set()
    try:
        text = _fetch_text(FEED_URL, timeout=30)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if re.match(r'^https?://', line, re.I):
                urls.add(_norm_url(line))
                h = _extract_host(line)
                if h:
                    hosts.add(h)
        # 落盘缓存（原子写）
        tmp = FEED_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump({'urls': sorted(urls), 'hosts': sorted(hosts), 'ts': time.time()}, f)
        os.replace(tmp, FEED_FILE)
        _feed_urls, _feed_hosts, _feed_ts = urls, hosts, time.time()
    except Exception as e:
        # 下载失败：沿用旧缓存或空集
        if _feed_urls is None:
            _feed_urls, _feed_hosts, _feed_ts = set(), set(), time.time()
    return _feed_urls, _feed_hosts

def _feed_stats():
    urls, hosts = _load_feed()
    return {'url_count': len(urls), 'host_count': len(hosts), 'source': FEED_URL}

# =====================================================================
# 二、启发式规则引擎
# =====================================================================
# 常见易滥用/免费/一次性 TLD（钓鱼高发区）
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'top', 'work', 'live', 'click', 'link',
    'country', 'stream', 'gdn', 'kim', 'loan', 'men', 'review', 'racing', 'accountant',
    'science', 'date', 'download', 'party', 'bid', 'trade', 'webcam', 'win', 'rest', 'monster',
    'quest', 'cyou', 'icu', 'xyz', 'vip', 'club', 'site', 'online', 'space', 'website',
    'fun', 'lol', 'bar', 'cloudns', 'beauty', 'hair', 'makeup', 'cfd', 'sbs', 'bond',
}
# 敏感表单/账号类关键词（出现在域名里是弱到中的钓鱼信号）
SENSITIVE_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'update', 'password',
    'passwd', 'secure', 'security', 'confirm', 'billing', 'invoice', 'recover', 'unlock',
    'auth', 'wallet', 'webscr', 'suspended', 'reactivate', 'validate',
]
# 知名品牌（仿冒检测用）——小写
BRANDS = [
    'google', 'paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram', 'whatsapp',
    'netflix', 'coinbase', 'binance', 'metamask', 'blockchain', 'openai', 'chatgpt', 'dropbox',
    'linkedin', 'twitter', 'ebay', 'alibaba', 'taobao', 'alipay', 'wechat', 'chase', 'wellsfargo',
    'citibank', 'hsbc', 'dbs', 'ocbc', 'dhl', 'fedex', 'ups', 'usps', 'steam', 'roblox', 'epicgames',
    'tiktok', 'snapchat', 'telegram', 'youtube', 'gmail', 'outlook', 'office365', 'icloud',
]
# 官方域名白名单（这些域名的子域名不算仿冒）
OFFICIAL_DOMAINS = {
    'google.com', 'paypal.com', 'apple.com', 'microsoft.com', 'microsoftonline.com', 'live.com',
    'amazon.com', 'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'netflix.com',
    'coinbase.com', 'binance.com', 'metamask.io', 'openai.com', 'chatgpt.com', 'dropbox.com',
    'linkedin.com', 'twitter.com', 'x.com', 'ebay.com', 'alibaba.com', 'taobao.com', 'alipay.com',
    'wechat.com', 'qq.com', 'chase.com', 'wellsfargo.com', 'citibank.com', 'citibankonline.com',
    'hsbc.com', 'dbs.com', 'ocbc.com', 'dhl.com', 'fedex.com', 'ups.com', 'usps.com', 'steampowered.com',
    'roblox.com', 'epicgames.com', 'tiktok.com', 'snapchat.com', 'telegram.org', 'youtube.com',
    'gmail.com', 'googlemail.com', 'outlook.com', 'icloud.com',
}
# 常见短链服务域名（expand_url 用）
SHORTLINK_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'lnk.ink', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'cutt.ly', 'rb.gy', 's.id', 'shorturl.at', 'tiny.cc', 'bitly.com',
    't2m.io', 'shorte.st', 'shortest.link', 'b23.tv', 'v.gd', 'surl.li', 'gg.gg',
}

def _registered_domain(host):
    """近似提取注册域名（eTLD+1 / 二级 ccTLD +1）。"""
    host = _norm_host(host)
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    # 常见二级 ccTLD：co.uk / com.cn / com.au / co.jp 等 → 取最后 3 段
    two_level = {'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.cn', 'net.cn', 'org.cn', 'com.au',
                 'net.au', 'org.au', 'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'or.kr', 'com.br',
                 'com.mx', 'co.nz', 'org.nz', 'com.sg', 'com.hk', 'com.tw', 'co.in', 'firm.in'}
    last3 = '.'.join(parts[-3:])
    if '.'.join(parts[-2:]) in two_level and len(parts) >= 3:
        return last3
    return '.'.join(parts[-2:])

def _has_punycode(host):
    """是否含 punycode（xn--）标签——IDN 域名的编码形态。"""
    return any(lbl.startswith('xn--') for lbl in host.split('.'))

def _heuristics(url):
    """对 URL 跑启发式规则，返回 [(rule_name, weight), ...]。weight 为正表示风险加分。"""
    hits = []
    host = _extract_host(url)
    if not host:
        return hits, {'host': '', 'registered_domain': ''}

    reg = _registered_domain(host)
    labels = host.split('.')

    # 1) IP 地址作为主机（http://192.168.1.1/ 或 0x7f000001）
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        hits.append(('ip_literal_host', 60))
    elif re.match(r'^0x[0-9a-f]+$', host, re.I):
        hits.append(('ip_literal_host', 60))

    # 2) IDN / punycode 同形字（xn-- 前缀，钓鱼常用 Cyrillic/希腊字母伪装品牌）
    if _has_punycode(host):
        hits.append(('idn_punycode', 55))
    elif any(ord(c) > 127 for c in host):
        hits.append(('idn_non_ascii', 40))

    # 3) 可疑 / 易滥用 TLD
    tld = labels[-1] if labels else ''
    if tld in SUSPICIOUS_TLDS:
        hits.append(('suspicious_tld', 35))

    # 4) 品牌仿冒：域名/子域名里含品牌词，但注册域名不是官方域名
    brand_in_host = [b for b in BRANDS if b in host]
    if brand_in_host:
        if reg not in OFFICIAL_DOMAINS:
            # 品牌词出现在子域名（如 paypal.com.verify.tk）比出现在注册域名更危险
            sub = '.'.join(labels[:-1]) if len(labels) > 1 else ''
            brand_in_sub = any(b in sub for b in brand_in_host)
            w = 70 if brand_in_sub else 50
            hits.append(('brand_impersonation', w))
        else:
            # 官方域名的子域名，但含敏感词（如 login.paypal.com 是正常的）→ 不加分
            pass

    # 5) 敏感表单/账号类关键词
    kw = [k for k in SENSITIVE_KEYWORDS if k in host]
    if kw:
        # 敏感词 + 可疑 TLD 组合，风险更高
        if tld in SUSPICIOUS_TLDS:
            hits.append(('sensitive_kw_suspicious_tld', 30))
        elif reg not in OFFICIAL_DOMAINS and brand_in_host:
            hits.append(('sensitive_kw_with_brand', 25))
        else:
            hits.append(('sensitive_keyword', 15))

    # 6) 超长子域名 / 超长域名（垃圾注册域名常用）
    if len(host) > 50:
        hits.append(('overlong_host', 20))
    if len(labels) > 5:
        hits.append(('many_subdomains', 15))

    # 7) @ 符号伪装（http://paypal.com@evil.com/）
    m = re.match(r'^[a-z][a-z0-9+.-]*://([^/]+)', url, re.I)
    if m and '@' in m.group(1):
        hits.append(('at_sign_obfuscation', 45))

    # 8) 非标准端口（弱信号）
    if re.search(r':\d{2,5}/', url):
        port = re.search(r':(\d{2,5})/', url)
        if port:
            p = int(port.group(1))
            if p not in (80, 443, 8080, 8443):
                hits.append(('nonstandard_port', 10))

    # 9) 域名里大量连字符+数字混排（垃圾域名）
    if re.search(r'[a-z]{2,}-\d{2,}', host) or len(re.findall(r'-', host)) >= 2:
        hits.append(('hyphen_digit_mix', 15))

    return hits, {'host': host, 'registered_domain': reg, 'tld': tld}

# =====================================================================
# 三、RDAP 域名注册年龄
# =====================================================================
_RDAP_BOOTSTRAP = None
_RDAP_TS = 0.0
EXTRA_TLD_RDAP = {
    'io': ['https://rdap.identitydigital.services/rdap/'],
    'tv': ['https://rdap.identitydigital.services/rdap/'],
    'cc': ['https://rdap.identitydigital.services/rdap/'],
    'me': ['https://rdap.identitydigital.services/rdap/'],
    'sh': ['https://rdap.identitydigital.services/rdap/'],
    'gg': ['https://rdap.identitydigital.services/rdap/'],
    'us': ['https://rdap.nic.us/'], 'uk': ['https://rdap.nominet.uk/uk/'],
    'de': ['https://rdap.denic.de/'], 'fr': ['https://rdap.nic.fr/'],
    'xyz': ['https://rdap.centralnic.com/xyz/'], 'nl': ['https://rdap.sidn.nl/'],
}

def _load_bootstrap():
    global _RDAP_BOOTSTRAP, _RDAP_TS
    now = time.time()
    if _RDAP_BOOTSTRAP and now - _RDAP_TS < 86400:
        return _RDAP_BOOTSTRAP
    try:
        data = json.loads(_fetch_text('https://data.iana.org/rdap/dns.json', timeout=20))
        m = {}
        for svc in data.get('services', []):
            tlds, urls = svc[0], svc[1]
            for t in tlds:
                m[t] = urls
        _RDAP_BOOTSTRAP = m
        _RDAP_TS = now
    except Exception:
        _RDAP_BOOTSTRAP = _RDAP_BOOTSTRAP or {}
    return _RDAP_BOOTSTRAP

def _domain_age(domain):
    """查询域名注册时间，返回 {'status': registered/available/unknown, 'created': ..., 'age_days': int|None}。"""
    domain = _norm_host(domain)
    parts = domain.split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    if not tld:
        return {'status': 'invalid', 'created': None, 'age_days': None}
    m = _load_bootstrap()
    urls = m.get(tld) or EXTRA_TLD_RDAP.get(tld)
    if not urls:
        return {'status': 'unknown', 'created': None, 'age_days': None, 'note': 'no rdap for tld ' + tld}
    for base in urls:
        url = base.rstrip('/') + '/domain/' + urllib.parse.quote(domain)
        try:
            req = urllib.request.Request(url, headers=dict(UA))
            with urllib.request.urlopen(req, timeout=15) as r:
                payload = json.loads(r.read().decode('utf-8', 'ignore'))
                if payload.get('errorCode') == 404:
                    return {'status': 'available', 'created': None, 'age_days': None}
                created = None
                for e in payload.get('events', []):
                    if e.get('eventAction') == 'registration':
                        created = e.get('eventDate')
                if created:
                    created = created.split('T')[0]
                    try:
                        cd = datetime.date.fromisoformat(created)
                        age = (datetime.date.today() - cd).days
                    except Exception:
                        age = None
                    return {'status': 'registered', 'created': created, 'age_days': age}
                return {'status': 'registered', 'created': None, 'age_days': None}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {'status': 'available', 'created': None, 'age_days': None}
        except Exception:
            continue
    return {'status': 'unknown', 'created': None, 'age_days': None, 'note': 'rdap network error'}

# =====================================================================
# 四、短链展开
# =====================================================================
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

_no_redirect_opener = urllib.request.build_opener(_NoRedirect)

def _expand(url, max_hops=6):
    """跟随重定向展开短链，返回 {'final_url': ..., 'chain': [...], 'hops': int, 'expanded': bool}。"""
    chain = [url]
    cur = url
    for _ in range(max_hops):
        try:
            req = urllib.request.Request(cur, headers=dict(UA), method='GET')
            with _no_redirect_opener.open(req, timeout=15) as r:
                loc = r.headers.get('Location') or r.headers.get('location')
                if r.status in (301, 302, 303, 307, 308) and loc:
                    nxt = urllib.parse.urljoin(cur, loc)
                    chain.append(nxt)
                    cur = nxt
                    continue
                # 非重定向，到达终点
                return {'final_url': cur, 'chain': chain, 'hops': len(chain) - 1,
                        'expanded': cur != url, 'status': r.status}
        except urllib.error.HTTPError as e:
            loc = e.headers.get('Location') if e.headers else None
            if e.code in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(cur, loc)
                chain.append(nxt)
                cur = nxt
                continue
            return {'final_url': cur, 'chain': chain, 'hops': len(chain) - 1,
                    'expanded': cur != url, 'status': e.code}
        except Exception as e:
            return {'final_url': cur, 'chain': chain, 'hops': len(chain) - 1,
                    'expanded': cur != url, 'status': None, 'error': repr(e)}
    return {'final_url': cur, 'chain': chain, 'hops': len(chain) - 1,
            'expanded': cur != url, 'status': None, 'note': 'max hops reached'}

# =====================================================================
# 五、工具实现
# =====================================================================
def tool_check_url(args):
    """综合检测一个 URL，返回风险评分 + 结论 + 命中详情。"""
    url = (args.get('url') or '').strip()
    if not url:
        return {'ok': False, 'error': '请提供 url'}
    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url

    norm = _norm_url(url)
    host = _extract_host(url)

    # 1) 短链展开
    expand = {'expanded': False, 'final_url': url, 'chain': [url], 'hops': 0}
    if host and host in SHORTLINK_DOMAINS:
        expand = _expand(url)

    # 2) 黑名单匹配（对展开后的最终 URL 也查一遍）
    urls_set, hosts_set = _load_feed()
    in_feed = False
    feed_match = None
    for candidate in [norm, _norm_url(expand['final_url'])]:
        if candidate in urls_set:
            in_feed = True
            feed_match = candidate
            break
    final_host = _extract_host(expand['final_url'])
    host_in_feed = bool(final_host and final_host in hosts_set)

    # 3) 启发式（对最终落地 URL 跑）
    hits, meta = _heuristics(expand['final_url'])
    rule_names = [h[0] for h in hits]
    heur_score = sum(w for _, w in hits)
    # 去重 + 封顶单规则总分
    heur_score = min(heur_score, 100)

    # 4) 域名注册年龄（对最终域名）
    age_info = {'status': 'unknown', 'age_days': None}
    if final_host:
        age_info = _domain_age(meta.get('registered_domain') or final_host)

    # 5) 综合评分与结论
    score = 0
    reasons = []
    if in_feed:
        score = 100
        reasons.append('URL 命中 OpenPhish 权威钓鱼黑名单（精确匹配）')
    elif host_in_feed:
        score = max(score, 85)
        reasons.append('域名命中 OpenPhish 黑名单（该域名的其他路径曾被报告为钓鱼）')
    # 启发式加权
    score = max(score, heur_score)
    for name, w in hits:
        reasons.append('命中启发式规则 %s（权重 %d）' % (name, w))
    # 域名新注册叠加
    if age_info.get('status') == 'registered' and age_info.get('age_days') is not None:
        if age_info['age_days'] < 30:
            add = 40 if ('brand_impersonation' not in rule_names) else 30
            score = min(100, score + (add if score < 70 else 10))
            reasons.append('域名注册仅 %d 天（新注册马甲站，高风险）' % age_info['age_days'])
        elif age_info['age_days'] < 90:
            score = min(100, score + 10)
            reasons.append('域名注册 %d 天（较新）' % age_info['age_days'])

    if score >= 70:
        verdict = 'malicious'
    elif score >= 35:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    return {
        'ok': True,
        'url': url,
        'final_url': expand['final_url'],
        'expanded': expand['expanded'],
        'redirect_chain': expand.get('chain'),
        'verdict': verdict,
        'risk_score': score,
        'in_feed': in_feed,
        'host_in_feed': host_in_feed,
        'heuristic_rules': [{'rule': n, 'weight': w} for n, w in hits],
        'domain': meta.get('registered_domain'),
        'domain_registered': age_info.get('status') == 'registered',
        'domain_created': age_info.get('created'),
        'domain_age_days': age_info.get('age_days'),
        'reasons': reasons,
        'suggestion': _suggestion(verdict, in_feed, host_in_feed, age_info),
    }

def _suggestion(verdict, in_feed, host_in_feed, age_info):
    if verdict == 'malicious':
        return '高度危险：请勿访问、勿点击、勿输入任何凭据。若来自邮件/短信，直接标记为钓鱼并上报。'
    if verdict == 'suspicious':
        return '可疑：建议人工确认后再访问；不要在页面上输入账号密码或支付信息。'
    return '未发现明显风险。仍需谨慎：仅凭黑名单与启发式，无法保证 100% 安全。'

def tool_lookup_feed(args):
    """在 OpenPhish 黑名单里匹配 URL。"""
    url = (args.get('url') or '').strip()
    if not url:
        return {'ok': False, 'error': '请提供 url'}
    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url
    norm = _norm_url(url)
    host = _extract_host(url)
    urls_set, hosts_set = _load_feed()
    exact = norm in urls_set
    host_hit = bool(host and host in hosts_set)
    return {
        'ok': True,
        'url': url,
        'exact_match': exact,
        'host_match': host_hit,
        'in_feed': exact or host_hit,
        'feed_stats': _feed_stats(),
    }

def tool_expand_url(args):
    """展开短链，返回真实落地 URL 与跳转链。"""
    url = (args.get('url') or '').strip()
    if not url:
        return {'ok': False, 'error': '请提供 url'}
    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url
    host = _extract_host(url)
    is_short = host in SHORTLINK_DOMAINS
    result = _expand(url)
    result['ok'] = True
    result['is_shortlink'] = is_short
    return result

def tool_analyze_domain(args):
    """域名信誉分析：注册年龄、可疑 TLD、品牌仿冒。"""
    domain = (args.get('domain') or '').strip()
    if not domain:
        return {'ok': False, 'error': '请提供 domain'}
    domain = _norm_host(domain)
    if not domain or '.' not in domain:
        return {'ok': False, 'error': '非法域名格式'}
    reg = _registered_domain(domain)
    age = _domain_age(reg)
    labels = domain.split('.')
    tld = labels[-1]
    brand_in = [b for b in BRANDS if b in domain]
    impersonation = bool(brand_in) and reg not in OFFICIAL_DOMAINS
    return {
        'ok': True,
        'domain': domain,
        'registered_domain': reg,
        'tld': tld,
        'suspicious_tld': tld in SUSPICIOUS_TLDS,
        'is_punycode': _has_punycode(domain),
        'registered': age.get('status') == 'registered',
        'created': age.get('created'),
        'age_days': age.get('age_days'),
        'new_registration': bool(age.get('age_days') is not None and age['age_days'] < 30),
        'brands_detected': brand_in,
        'brand_impersonation': impersonation,
        'suggestion': _domain_suggestion(age, tld, impersonation),
    }

def _domain_suggestion(age, tld, impersonation):
    risks = []
    if age.get('status') == 'registered' and age.get('age_days') is not None and age['age_days'] < 30:
        risks.append('新注册（%d 天）' % age['age_days'])
    if tld in SUSPICIOUS_TLDS:
        risks.append('可疑 TLD（.%s）' % tld)
    if impersonation:
        risks.append('品牌仿冒')
    if risks:
        return '高风险域名：' + '、'.join(risks) + '。建议谨慎访问。'
    return '未发现明显风险。'

# =====================================================================
# 六、MCP 协议定义
# =====================================================================
TOOLS = [
    {'name': 'check_url',
     'description': '综合检测一个 URL 是否钓鱼/恶意。返回风险评分(0-100)+结论(safe/suspicious/malicious)+是否命中OpenPhish钓鱼黑名单+命中的启发式规则(IP主机/IDN同形字/可疑TLD/品牌仿冒/敏感词/超长子域名/@伪装等)+域名注册年龄+短链展开后的真实落地URL与跳转链。给「点击链接前校验/安全浏览/反钓鱼」的Agent用。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要检测的 URL，如 "http://bit.ly/xxx" 或 "https://paypal.com.verify-account.tk/login"'}},
         'required': ['url']}},
    {'name': 'lookup_feed',
     'description': '在 OpenPhish 权威钓鱼黑名单里精确/域名级匹配一个 URL，返回是否命中及黑名单规模。给需要「查这个链接是不是已在已知钓鱼库里」的Agent用。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要查询的 URL'}},
         'required': ['url']}},
    {'name': 'expand_url',
     'description': '展开短链(bit.ly/t.co/tinyurl/lnk.ink等)，跟随重定向，返回真实落地URL、完整跳转链、跳数。给需要「看清短链背后到底指向哪里」的Agent用。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '短链 URL'}},
         'required': ['url']}},
    {'name': 'analyze_domain',
     'description': '分析域名信誉：注册年龄(是否新注册马甲站)、是否可疑TLD(.tk/.zip/.top等)、是否IDN/punycode、是否仿冒知名品牌。给反欺诈/尽调Agent用。',
     'inputSchema': {'type': 'object', 'properties': {
         'domain': {'type': 'string', 'description': '域名，如 "paypal-verify.tk" 或 "example.com"'}},
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
                   'serverInfo': {'name': 'phishguard-mcp', 'version': '1.0.0'}})
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
            if name == 'check_url':
                data = tool_check_url(args)
            elif name == 'lookup_feed':
                data = tool_lookup_feed(args)
            elif name == 'expand_url':
                data = tool_expand_url(args)
            elif name == 'analyze_domain':
                data = tool_analyze_domain(args)
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
        self.wfile.write(json.dumps({'service': 'phishguard-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('phishguard-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8981
        main_http(port)
    else:
        main_stdio()
