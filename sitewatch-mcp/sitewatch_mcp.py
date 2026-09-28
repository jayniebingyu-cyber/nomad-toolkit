#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sitewatch-mcp — 站点变更监控引擎（给 AI Agent 用）

解决的问题：Agent 是「无状态」的——每次对话结束它就忘了上次看到的东西，
无法回答「这个网页/API/价格页 / 招聘页 / 政策页 相比我上次看，到底变了什么」。

本工具给 Agent 提供「跨会话、有状态」的网页快照与差异对比能力：
  1. watch_url：抓取一个 URL，把「标题 + 正文文本」做哈希快照存下来（落盘持久化）；
  2. check_change：重新抓取同一个 URL，与上次快照做行级 diff，返回「变了没有 /
     变了多少 / 新增了哪些行 / 删除了哪些行 / 相似度百分比」；
  3. list_watches：列出所有已监控的 URL 及其快照时间；
  4. remove_watch：移除某个监控点。

典型付费场景（模型无法凭训练数据自查，必须实时抓取 + 跨时间对比）：
  - 商品价格页：涨价/降价/下架了没有（电商选品、竞品比价 Agent）；
  - 招聘页/公司官网：某个职位是不是新发布了、JD 是不是改了；
  - 政策/法规/公告页：条款有没有更新（合规 Agent）；
  - 任意 JSON API：返回结构/字段是否变化（API 监控 Agent）；
  - 竞品落地页：文案、价格、联系方式是否变化（增长/SEO Agent）。

数据源：任意可公开访问的 URL（纯 urllib 抓取，无需任何 key）。
纯标准库实现（urllib / html.parser / hashlib / difflib / json / http.server），零第三方依赖。

用法：
  python3 sitewatch_mcp.py                # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 sitewatch_mcp.py --http 8980    # streamable HTTP 模式

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, os, re, time, hashlib, datetime, urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'Mozilla/5.0 (compatible; sitewatch-mcp/1.0; +https://github.com/jayniebingyu-cyber/nomad-toolkit)'}

# 快照持久化文件（跨会话、跨进程保留监控状态）
SNAPSHOT_FILE = os.environ.get('SITEWATCH_SNAPSHOT', '/home/ubuntu/auto-income-cloud/sitewatch_snapshots.json')

# =====================================================================
# 一、快照持久化（落盘，跨会话有状态）
# =====================================================================
def _load_snapshots():
    try:
        with open(SNAPSHOT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_snapshots(snaps):
    # 原子写：先写临时文件再替换，避免并发写坏
    tmp = SNAPSHOT_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(snaps, f, ensure_ascii=False, indent=1)
    os.replace(tmp, SNAPSHOT_FILE)

def _watch_id(url):
    """用 URL 规范化后的 sha256 前 16 位作为稳定监控点 ID（同一 URL 重复 watch 幂等）。"""
    norm = re.sub(r'https?://', '', url.strip()).rstrip('/')
    return hashlib.sha256(norm.encode('utf-8')).hexdigest()[:16]

# =====================================================================
# 二、HTTP 抓取 + HTML 文本提取
# =====================================================================
def _fetch(url, timeout=25):
    """抓取 URL，返回 (text, content_type)。文本含标题行 + 正文。"""
    req = urllib.request.Request(url, headers=dict(UA))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        ctype = r.headers.get('Content-Type', '')
        # 从 charset 推断编码，默认 utf-8，兜底 latin-1（不会抛解码错误）
        charset = 'utf-8'
        m = re.search(r'charset=["\']?([\w\-]+)', ctype, re.I)
        if m:
            charset = m.group(1)
        for enc in (charset, 'utf-8', 'latin-1'):
            try:
                return raw.decode(enc), ctype
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode('utf-8', 'ignore'), ctype

class _TextExtractor(HTMLParser):
    """从 HTML 提取 title + meta 描述 + 正文纯文本（剔除 script/style）。"""
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.in_style = False
        self.in_title = False
        self.title = ''
        self.meta_desc = ''
        self.parts = []

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == 'script':
            self.in_script = True
        elif t == 'style':
            self.in_style = True
        elif t == 'title':
            self.in_title = True
        elif t == 'meta':
            d = dict(attrs)
            name = (d.get('name') or '').lower()
            if name in ('description', 'keywords') and not self.meta_desc:
                self.meta_desc = d.get('content', '') or ''

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == 'script':
            self.in_script = False
        elif t == 'style':
            self.in_style = False
        elif t == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_script or self.in_style:
            return
        if self.in_title:
            self.title += data
        self.parts.append(data)

def _extract_text(raw_text, content_type):
    """把抓取到的原始文本规整成可 diff 的「行列表 + 标题」。
    HTML → 提取纯文本；JSON/纯文本 → 保留原文。"""
    title = ''
    if 'html' in content_type.lower():
        p = _TextExtractor()
        try:
            p.feed(raw_text)
        except Exception:
            pass
        p.close()
        title = p.title.strip()
        body = ' '.join(p.parts)
        # 压缩空白，按句子/段落切行
        body = re.sub(r'\s+', ' ', body).strip()
        lines = [l.strip() for l in re.split(r'(?<=[。！？.!?])\s*|(?<=</?p>)\s*', body) if l.strip()]
        if not lines and body:
            lines = [body]
        desc = p.meta_desc.strip()
        if desc:
            lines.insert(0, 'META: ' + desc)
    elif content_type.strip().startswith(('application/json', 'text/plain', 'application/xml', 'text/xml')):
        lines = [l.rstrip() for l in raw_text.splitlines() if l.strip()]
    else:
        body = re.sub(r'\s+', ' ', raw_text).strip()
        lines = [l.strip() for l in re.split(r'(?<=[。！？.!?])\s*', body) if l.strip()]
    return title, lines

def _normalize_lines(lines):
    """去掉时间戳、session id 等高频动态片段，降低误报。"""
    out = []
    for l in lines:
        l = re.sub(r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b', 'DATE', l)
        l = re.sub(r'\b\d{1,2}:\d{2}(:\d{2})?\b', 'TIME', l)
        l = re.sub(r'\b[a-f0-9]{32,}\b', 'HASH', l)
        l = re.sub(r'[\s]+', ' ', l).strip()
        if l:
            out.append(l)
    return out

# =====================================================================
# 三、差异计算
# =====================================================================
def _compute_diff(old_lines, new_lines):
    """行级 diff，返回 (ratio, added, removed)。ratio=相似度(0~1)。"""
    import difflib
    sm = difflib.SequenceMatcher(None, old_lines, new_lines)
    added, removed = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'insert':
            added.extend(new_lines[j1:j2])
        elif tag == 'delete':
            removed.extend(old_lines[i1:i2])
        elif tag == 'replace':
            removed.extend(old_lines[i1:i2])
            added.extend(new_lines[j1:j2])
    return sm.ratio(), added, removed

# =====================================================================
# 四、工具实现
# =====================================================================
def tool_watch_url(args):
    """抓取 URL 并建立/刷新监控快照。"""
    url = (args.get('url') or '').strip()
    if not url:
        return {'ok': False, 'error': '请提供 url'}
    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url
    try:
        text, ctype = _fetch(url)
    except Exception as e:
        return {'ok': False, 'error': '抓取失败: %s' % repr(e)}

    title, lines = _extract_text(text, ctype)
    lines = _normalize_lines(lines)
    full_text = '\n'.join([title, *lines])
    digest = hashlib.sha256(full_text.encode('utf-8')).hexdigest()

    wid = _watch_id(url)
    snaps = _load_snapshots()
    first_time = wid not in snaps
    snaps[wid] = {
        'watch_id': wid,
        'url': url,
        'title': title[:200],
        'content_hash': digest,
        'content': full_text[:60000],  # 截断存储，防超大页面撑爆 JSON
        'line_count': len(lines),
        'created': datetime.datetime.utcnow().isoformat() + 'Z',
        'last_checked': datetime.datetime.utcnow().isoformat() + 'Z',
    }
    _save_snapshots(snaps)

    return {
        'ok': True,
        'watch_id': wid,
        'url': url,
        'title': title[:200],
        'content_hash': digest,
        'line_count': len(lines),
        'snapshot': '新建' if first_time else '已刷新',
        'note': '已保存快照。之后用 check_change(watch_id=%s) 对比最新内容与本次快照的差异。' % wid,
    }

def tool_check_change(args):
    """重新抓取 URL 并与快照 diff。"""
    wid = (args.get('watch_id') or '').strip()
    url = (args.get('url') or '').strip()
    snaps = _load_snapshots()

    # 用 watch_id 定位；没有则用 url 反推
    if wid:
        snap = next((v for k, v in snaps.items() if v.get('watch_id') == wid), None)
    elif url:
        if not re.match(r'^https?://', url, re.I):
            url = 'https://' + url
        wid = _watch_id(url)
        snap = snaps.get(wid)
    else:
        return {'ok': False, 'error': '请提供 watch_id 或 url'}

    if not snap:
        return {'ok': False, 'error': '未找到监控点（watch_id=%s）。请先调用 watch_url 建立快照。' % (wid or url)}

    if not url:
        url = snap['url']
    try:
        text, ctype = _fetch(url)
    except Exception as e:
        return {'ok': False, 'error': '抓取失败: %s' % repr(e), 'watch_id': wid}

    title, lines = _extract_text(text, ctype)
    lines = _normalize_lines(lines)
    new_full = '\n'.join([title, *lines])
    new_digest = hashlib.sha256(new_full.encode('utf-8')).hexdigest()

    old_lines = snap.get('content', '').split('\n')
    ratio, added, removed = _compute_diff(old_lines, [title, *lines])

    changed = new_digest != snap.get('content_hash')
    result = {
        'ok': True,
        'watch_id': wid,
        'url': url,
        'changed': changed,
        'similarity': round(ratio, 4),           # 0~1，1=完全相同
        'change_ratio': round(1 - ratio, 4),     # 0~1，变化占比
        'old_hash': snap.get('content_hash'),
        'new_hash': new_digest,
        'old_title': snap.get('title'),
        'new_title': title[:200],
        'added_count': len(added),
        'removed_count': len(removed),
        'added': [l[:300] for l in added[:20]],     # 最多展示前 20 条
        'removed': [l[:300] for l in removed[:20]],
        'checked_at': datetime.datetime.utcnow().isoformat() + 'Z',
    }
    # 更新快照为当前状态，作为下次对比基线
    snaps[wid] = {
        'watch_id': wid, 'url': url, 'title': title[:200],
        'content_hash': new_digest, 'content': new_full[:60000],
        'line_count': len(lines),
        'created': snap.get('created', datetime.datetime.utcnow().isoformat() + 'Z'),
        'last_checked': datetime.datetime.utcnow().isoformat() + 'Z',
    }
    _save_snapshots(snaps)
    return result

def tool_list_watches(args):
    """列出所有监控点。"""
    snaps = _load_snapshots()
    items = []
    for k, v in snaps.items():
        items.append({
            'watch_id': v.get('watch_id', k),
            'url': v.get('url'),
            'title': v.get('title'),
            'content_hash': v.get('content_hash'),
            'line_count': v.get('line_count'),
            'last_checked': v.get('last_checked'),
        })
    items.sort(key=lambda x: x.get('last_checked') or '', reverse=True)
    return {'ok': True, 'count': len(items), 'watches': items}

def tool_remove_watch(args):
    """移除监控点。"""
    wid = (args.get('watch_id') or '').strip()
    if not wid:
        return {'ok': False, 'error': '请提供 watch_id'}
    snaps = _load_snapshots()
    if wid not in snaps:
        return {'ok': False, 'error': '未找到监控点 watch_id=%s' % wid}
    del snaps[wid]
    _save_snapshots(snaps)
    return {'ok': True, 'removed': wid, 'remaining': len(snaps)}

# =====================================================================
# 五、MCP 协议定义
# =====================================================================
TOOLS = [
    {'name': 'watch_url',
     'description': '抓取一个网页/API 的当前内容，保存「标题+正文」快照（落盘持久化，跨会话有效），返回监控点 watch_id。给需要「记住某页面现在长什么样、之后对比是否变化」的 Agent 使用。可监控商品价格页、招聘页、政策公告页、竞品落地页、任意 JSON API。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要监控的 URL，如 "https://example.com/pricing" 或 "https://api.example.com/v1/status"'}},
         'required': ['url']}},
    {'name': 'check_change',
     'description': '重新抓取监控点对应的 URL，与上次快照做行级 diff，返回：是否变化、相似度百分比、新增了哪些行、删除了哪些行、标题是否变化。抓取后会把快照更新为当前状态（作为下次对比基线）。给监控类 Agent 判断「自上次以来，这个页面/API 到底变了什么」。',
     'inputSchema': {'type': 'object', 'properties': {
         'watch_id': {'type': 'string', 'description': 'watch_url 返回的监控点 ID（优先用这个）'},
         'url': {'type': 'string', 'description': '或直接给 URL（若已 watch 过，会自动定位到该监控点）'}},
         'required': []}},
    {'name': 'list_watches',
     'description': '列出所有已建立的监控点及其 URL、标题、快照时间、内容哈希。给 Agent 查看「我目前盯了哪些页面」。',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'remove_watch',
     'description': '移除一个监控点，释放存储。给 Agent 停止监控某页面时使用。',
     'inputSchema': {'type': 'object', 'properties': {
         'watch_id': {'type': 'string', 'description': 'watch_url 返回的监控点 ID'}},
         'required': ['watch_id']}},
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
                   'serverInfo': {'name': 'sitewatch-mcp', 'version': '1.0.0'}})
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
            if name == 'watch_url':
                data = tool_watch_url(args)
            elif name == 'check_change':
                data = tool_check_change(args)
            elif name == 'list_watches':
                data = tool_list_watches(args)
            elif name == 'remove_watch':
                data = tool_remove_watch(args)
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
        self.wfile.write(json.dumps({'service': 'sitewatch-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('sitewatch-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8980
        main_http(port)
    else:
        main_stdio()
