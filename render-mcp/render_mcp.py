#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""render-mcp — 网页渲染引擎（给 AI Agent 用）

解决的问题：Agent 本身没有浏览器渲染引擎。纯文本 Agent 无法「看到」一个网页长什么样、
无法把 SPA（JS 动态渲染）页面转成可读内容、无法生成截图给用户看、无法把页面转成 PDF 归档。
即使多模态 Agent 能看图，它在沙箱里也常常没有浏览器环境。本工具提供「远程渲染」能力：

  1. render_screenshot：URL → PNG/JPEG 截图（支持全页、自定义视口、等待选择器/等待时长），返回 base64 图片；
  2. render_pdf：URL → PDF（支持 A4/Letter/Legal、横向、是否打印背景），返回 base64 PDF；
  3. render_html：URL → 等待 JS 执行后的完整渲染后 HTML（支持 SPA / 动态内容），返回 HTML 文本；
  4. render_text：URL → 渲染后的正文文本（可指定 CSS 选择器，默认 body），返回干净文本供模型分析。

典型付费场景（模型无法凭训练数据自查 / 无法自己执行）：
  - 报告 Agent：把某个网页截图放进报告 / 转成 PDF 交付；
  - 爬取/分析 Agent：SPA 站点只有渲染后才有内容，直接抓 HTML 拿不到正文；
  - 前端测试 Agent：看某个页面的真实渲染结果 / 视觉回归；
  - 内容 Agent：把任意 URL 转成干净正文喂给模型，省去自己装浏览器环境的麻烦。

引擎：Playwright + Chromium（本地 headless，零外部 key，已在托管服务器装好）。

安全：内置 SSRF 防护——拒绝渲染回环/内网/链路本地/云元数据地址，防止公网托管 API 被滥用为内网探测。

用法：
  python3 render_mcp.py                # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 render_mcp.py --http 8982    # streamable HTTP 模式

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, os, base64, socket, ipaddress
from urllib.parse import urlparse

PROTOCOL_VERSION = '2024-11-05'
SERVER_NAME = 'render-mcp'
SERVER_VERSION = '1.0.0'
UA = 'Mozilla/5.0 (compatible; render-mcp/1.0; +https://github.com/jayniebingyu-cyber/nomad-toolkit)'

NAV_TIMEOUT = int(os.environ.get('RENDER_NAV_TIMEOUT', '30000'))      # 导航超时(ms)
SELECTOR_TIMEOUT = int(os.environ.get('RENDER_SELECTOR_TIMEOUT', '10000'))  # 等待选择器超时(ms)
MAX_WAIT_TIME = int(os.environ.get('RENDER_MAX_WAIT', '15000'))      # 最大显式等待(ms)
MAX_FULLPAGE_HEIGHT = int(os.environ.get('RENDER_MAX_FULLPAGE', '20000'))   # 全页截图最大高度(px)

ALLOWED_SCHEMES = ('http', 'https')


# =====================================================================
# 一、SSRF 防护：阻止渲染内网 / 回环 / 链路本地 / 云元数据地址
# =====================================================================
def _is_blocked_ip(ip):
    """判断 IP 是否属于不应被公网渲染服务访问的地址段。"""
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def _host_to_ip(host):
    """把 host 解析为 IP（字面量直接解析，域名走 DNS）。返回 None 表示无法解析。"""
    host = (host or '').strip().lower().rstrip('.')
    if host.startswith('['):
        host = host[1:].split(']')[0]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        return None

def _is_blocked_host(host):
    """综合判断 host 是否被 SSRF 防护拦截。"""
    host = (host or '').strip().lower().rstrip('.')
    if not host:
        return True
    if host.startswith('['):
        host = host[1:].split(']')[0]
    if ':' in host:
        host = host.split(':')[0]
    if host in ('localhost', 'localhost.localdomain') or host.endswith('.localhost'):
        return True
    ip = _host_to_ip(host)
    if ip is None:
        return False  # 解析失败不拦截，渲染阶段会自然报错
    return _is_blocked_ip(ip)

def _validate_url(raw):
    """校验并规范化 URL，SSRF 拦截。返回规范化 URL 或抛 ValueError。"""
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('empty url')
    if '://' not in raw:
        raw = 'https://' + raw
    u = urlparse(raw)
    if u.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError('only http/https allowed, got: %s' % u.scheme)
    if not u.hostname:
        raise ValueError('invalid url (no host): %s' % raw)
    if _is_blocked_host(u.hostname):
        raise ValueError('blocked host for SSRF protection: %s' % u.hostname)
    return raw


# =====================================================================
# 二、Playwright 渲染核心
# =====================================================================
def _launch(p):
    """启动 Chromium；失败则回退到 --no-sandbox（systemd/容器环境常见）。"""
    try:
        return p.chromium.launch(headless=True)
    except Exception:
        return p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])

def _clamp(v, lo, hi, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))

def _parse_viewport(args):
    w = _clamp(args.get('width'), 320, 3840, 1280)
    h = _clamp(args.get('height'), 240, 2160, 800)
    return {'width': w, 'height': h}

def _wait_until(args):
    wu = (args.get('wait_until') or 'load').lower()
    if wu not in ('load', 'domcontentloaded', 'networkidle', 'commit'):
        wu = 'load'
    return wu

def _new_page(browser, args):
    """创建页面并完成导航 + 等待。返回 page。"""
    page = browser.new_page(viewport=_parse_viewport(args),
                            user_agent=UA, locale='en-US')
    url = _validate_url(args.get('url', ''))
    page.goto(url, wait_until=_wait_until(args), timeout=NAV_TIMEOUT)
    final_host = urlparse(page.url).hostname
    if final_host and _is_blocked_host(final_host):
        raise ValueError('redirect blocked for SSRF protection: %s' % final_host)
    sel = (args.get('wait_selector') or '').strip()
    if sel:
        page.wait_for_selector(sel, timeout=SELECTOR_TIMEOUT)
    wt = _clamp(args.get('wait_time'), 0, MAX_WAIT_TIME, 0)
    if wt > 0:
        page.wait_for_timeout(wt)
    return page

def _with_page(args, fn):
    """统一浏览器生命周期：launch → 渲染 → 附加元信息 → 关闭。fn 返回 dict。"""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = _launch(p)
        try:
            page = _new_page(browser, args)
            try:
                result = fn(page)
                if not isinstance(result, dict):
                    result = {}
                result['final_url'] = page.url
                try:
                    result['title'] = page.title()
                except Exception:
                    result['title'] = ''
                return result
            finally:
                page.close()
        finally:
            browser.close()


# ---------- 工具 1：截图 ----------
def tool_render_screenshot(args):
    url = _validate_url(args.get('url', ''))
    fmt = (args.get('format') or 'png').lower()
    if fmt not in ('png', 'jpeg', 'jpg'):
        fmt = 'png'
    full_page = bool(args.get('full_page', False))
    quality = _clamp(args.get('quality'), 1, 100, 80) if fmt in ('jpeg', 'jpg') else None
    out_fmt = 'jpeg' if fmt in ('jpeg', 'jpg') else 'png'

    def do(page):
        clipped = False
        if full_page:
            h = page.evaluate('document.body.scrollHeight')
            if h > MAX_FULLPAGE_HEIGHT:
                clipped = True
        shot = page.screenshot(type=out_fmt, quality=quality, full_page=(full_page and not clipped))
        return {'image_base64': base64.b64encode(shot).decode('ascii'),
                'size_bytes': len(shot),
                'format': out_fmt,
                'full_page': full_page and not clipped,
                'clipped': clipped}

    r = _with_page(args, do)
    r.update({'ok': True, 'url': url})
    return r


# ---------- 工具 2：PDF ----------
def tool_render_pdf(args):
    url = _validate_url(args.get('url', ''))
    fmt = (args.get('format') or 'A4').upper()
    if fmt not in ('A4', 'A3', 'A5', 'Letter', 'Legal', 'Tabloid'):
        fmt = 'A4'
    landscape = bool(args.get('landscape', False))
    print_background = bool(args.get('print_background', True))

    def do(page):
        data = page.pdf(format=fmt, landscape=landscape,
                        print_background=print_background,
                        margin={'top': '10mm', 'bottom': '10mm', 'left': '10mm', 'right': '10mm'})
        return {'pdf_base64': base64.b64encode(data).decode('ascii'),
                'size_bytes': len(data),
                'format': fmt,
                'landscape': landscape}

    r = _with_page(args, do)
    r.update({'ok': True, 'url': url})
    return r


# ---------- 工具 3：渲染后 HTML ----------
def tool_render_html(args):
    url = _validate_url(args.get('url', ''))

    def do(page):
        html = page.content()
        return {'html_length': len(html), 'html': html}

    r = _with_page(args, do)
    r.update({'ok': True, 'url': url})
    return r


# ---------- 工具 4：正文文本 ----------
def tool_render_text(args):
    url = _validate_url(args.get('url', ''))
    selector = (args.get('selector') or 'body').strip() or 'body'

    def do(page):
        page.wait_for_selector(selector, timeout=SELECTOR_TIMEOUT)
        text = page.inner_text(selector)
        return {'selector': selector, 'text_length': len(text), 'text': text}

    r = _with_page(args, do)
    r.update({'ok': True, 'url': url})
    return r


# =====================================================================
# 三、MCP 协议：initialize / tools/list / tools/call
# =====================================================================
TOOLS = [
    {'name': 'render_screenshot',
     'description': '把任意 URL 渲染成截图。返回 PNG/JPEG 的 base64 图片 + 标题/最终URL/尺寸。支持全页截图(full_page)、自定义视口(width/height)、等待某选择器出现(wait_selector)、额外等待毫秒(wait_time)、等待策略(wait_until: load/domcontentloaded/networkidle/commit)。给「要把网页变成图片放进报告/给用户看/做视觉回归」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要渲染的 URL'},
         'full_page': {'type': 'boolean', 'description': '是否全页截图，默认 false（仅视口）'},
         'width': {'type': 'integer', 'description': '视口宽度 px，默认 1280'},
         'height': {'type': 'integer', 'description': '视口高度 px，默认 800'},
         'format': {'type': 'string', 'description': 'png 或 jpeg，默认 png'},
         'quality': {'type': 'integer', 'description': 'jpeg 质量 1-100，默认 80（仅 jpeg 有效）'},
         'wait_until': {'type': 'string', 'description': 'load/domcontentloaded/networkidle/commit，默认 load'},
         'wait_selector': {'type': 'string', 'description': '可选，等待该 CSS 选择器出现后再截图'},
         'wait_time': {'type': 'integer', 'description': '可选，额外等待毫秒'}},
         'required': ['url']}},
    {'name': 'render_pdf',
     'description': '把任意 URL 渲染成 PDF。返回 base64 PDF + 标题/最终URL/尺寸。支持纸张格式(A4/A3/A5/Letter/Legal/Tabloid)、横向(landscape)、是否打印背景(print_background)、等待策略。给「要把网页存档/交付 PDF 报告」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要渲染的 URL'},
         'format': {'type': 'string', 'description': 'A4/A3/A5/Letter/Legal/Tabloid，默认 A4'},
         'landscape': {'type': 'boolean', 'description': '是否横向，默认 false'},
         'print_background': {'type': 'boolean', 'description': '是否打印背景，默认 true'},
         'wait_until': {'type': 'string', 'description': 'load/domcontentloaded/networkidle/commit，默认 load'},
         'wait_selector': {'type': 'string', 'description': '可选，等待该 CSS 选择器出现'},
         'wait_time': {'type': 'integer', 'description': '可选，额外等待毫秒'}},
         'required': ['url']}},
    {'name': 'render_html',
     'description': '把任意 URL 渲染后返回完整 HTML（等待 JS 执行后的 DOM，支持 SPA/动态内容）。给「需要抓取 JS 渲染站点真实 DOM」的 Agent 用——普通 urllib/requests 拿不到 SPA 动态内容。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要渲染的 URL'},
         'wait_until': {'type': 'string', 'description': 'load/domcontentloaded/networkidle/commit，默认 load'},
         'wait_selector': {'type': 'string', 'description': '可选，等待该 CSS 选择器出现'},
         'wait_time': {'type': 'integer', 'description': '可选，额外等待毫秒'}},
         'required': ['url']}},
    {'name': 'render_text',
     'description': '把任意 URL 渲染后提取正文文本（等待 JS 执行，可指定 CSS 选择器，默认 body）。给「要把网页转成干净文本喂给模型分析/摘要/提取」的 Agent 用，省去自己解析 HTML 的麻烦。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要渲染的 URL'},
         'selector': {'type': 'string', 'description': '要提取文本的 CSS 选择器，默认 body'},
         'wait_until': {'type': 'string', 'description': 'load/domcontentloaded/networkidle/commit，默认 load'},
         'wait_selector': {'type': 'string', 'description': '可选，等待该 CSS 选择器出现'},
         'wait_time': {'type': 'integer', 'description': '可选，额外等待毫秒'}},
         'required': ['url']}},
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
                   'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION}})
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
            if name == 'render_screenshot':
                data = tool_render_screenshot(args)
            elif name == 'render_pdf':
                data = tool_render_pdf(args)
            elif name == 'render_html':
                data = tool_render_html(args)
            elif name == 'render_text':
                data = tool_render_text(args)
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
from http.server import BaseHTTPRequestHandler, HTTPServer

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
        self.wfile.write(json.dumps({'service': SERVER_NAME, 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('render-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()


if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8982
        main_http(port)
    else:
        main_stdio()
