#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""docparse-mcp — 文档解析引擎（给 AI Agent 用）

解决的问题：Agent 无法「读」二进制文档。纯文本 / 语言模型 Agent 拿不到 PDF 的正文、
表格、表单字段、链接，更读不了「扫描件 / 图片里的文字」。即使多模态 Agent 能看图，
在沙箱里也常没有 PDF 解析库、没有 OCR 引擎、没有 tesseract。本工具把「文档 → 结构化数据」
这一步做成一个可调用能力：

  1. parse_document：一键综合解析（元数据 + 正文 + 表格 + 表单字段 + 链接）；
  2. extract_text：PDF → 干净正文文本（支持分页 / 指定页 / 布局模式）；
  3. extract_tables：PDF → 表格（返回 JSON 结构，或 CSV 文本）；
  4. extract_metadata：文档元数据（标题/作者/页数/是否加密/文件大小/PDF版本 + 可填写表单字段）；
  5. extract_links：提取文档内嵌的 URI / 超链接；
  6. ocr_document：扫描件 / 图片 OCR（PDF 逐页光栅化或直接图片，tesseract 引擎，支持中英文）。

典型付费场景（模型无法凭训练数据自查 / 无法自己执行）：
  - 合同 / 发票 / 财报 / 简历 / 学术论文处理 Agent：把 PDF 变成可分析的正文与表格；
  - 报销 / 财务 Agent：从扫描发票、对账单里 OCR 出金额与明细；
  - 法律 / 尽调 Agent：从合同 PDF 提取条款、链接、表单字段；
  - 招聘 Agent：批量解析简历 PDF，提取结构化字段。

引擎：PyMuPDF (fitz) 负责 PDF 文本/表格/元数据/表单/链接 + 页面光栅化；
      tesseract-ocr 负责扫描件 / 图片文字识别（本地安装，零外部 key）。

安全：内置 SSRF 防护——URL 拉取时拒绝回环 / 内网 / 链路本地 / 云元数据地址。

输入三种方式（任一工具通用）：
  - source_type="url"     ：从 URL 拉取 PDF/图片（带 SSRF 防护）；
  - source_type="base64"  ：base64 编码的 PDF/图片内容；
  - source_type="path"    ：托管机本地文件路径（stdio 本地模式常用）；
  - source_type="auto"（默认）：按前缀自动判断（http/https→url，存在文件→path，否则 base64）。

用法：
  python3 docparse_mcp.py                # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 docparse_mcp.py --http 8983    # streamable HTTP 模式

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
依赖：PyMuPDF（pip install pymupdf），tesseract-ocr（apt install tesseract-ocr[-chi-sim]）。
"""
import json, sys, os, base64, socket, ipaddress, subprocess, shutil, tempfile, csv, io
from urllib.parse import urlparse
from urllib.request import urlopen, Request

PROTOCOL_VERSION = '2024-11-05'
SERVER_NAME = 'docparse-mcp'
SERVER_VERSION = '1.0.0'
UA = 'Mozilla/5.0 (compatible; docparse-mcp/1.0; +https://github.com/jayniebingyu-cyber/nomad-toolkit)'

MAX_TEXT_CHARS = int(os.environ.get('DOCPARSE_MAX_TEXT', '500000'))   # 正文截断上限（防超大响应）
MAX_OCR_PAGES = int(os.environ.get('DOCPARSE_MAX_OCR_PAGES', '50'))   # OCR 最大页数
OCR_DPI = int(os.environ.get('DOCPARSE_OCR_DPI', '200'))              # OCR 光栅化 DPI
URL_TIMEOUT = int(os.environ.get('DOCPARSE_URL_TIMEOUT', '30'))       # URL 拉取超时(秒)

ALLOWED_SCHEMES = ('http', 'https')

try:
    import pymupdf as fitz  # PyMuPDF（新版命名）
except ImportError:
    try:
        import fitz  # 旧版命名（1.24 之前）
    except Exception:
        fitz = None


# =====================================================================
# 一、SSRF 防护（与 render-mcp 同款）
# =====================================================================
def _is_blocked_ip(ip):
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def _host_to_ip(host):
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
        return False
    return _is_blocked_ip(ip)

def _validate_url(raw):
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
# 二、输入加载：url / base64 / path → bytes
# =====================================================================
def _load_bytes(args):
    """按 source_type 把输入统一成 bytes。返回 (bytes, name_hint)。"""
    source = (args.get('source') or '').strip()
    if not source:
        raise ValueError('missing "source" argument')
    st = (args.get('source_type') or 'auto').strip().lower()
    # 自动判断
    if st == 'auto':
        if source.startswith('http://') or source.startswith('https://'):
            st = 'url'
        elif os.path.isfile(source):
            st = 'path'
        else:
            st = 'base64'
    if st == 'url':
        url = _validate_url(source)
        req = Request(url, headers={'User-Agent': UA})
        with urlopen(req, timeout=URL_TIMEOUT) as r:
            data = r.read()
        # 重定向后的最终地址 SSRF 复检
        final = getattr(r, 'url', url) or url
        final_host = urlparse(final).hostname
        if final_host and _is_blocked_host(final_host):
            raise ValueError('redirect blocked for SSRF protection: %s' % final_host)
        return data, url.split('/')[-1].split('?')[0] or 'doc'
    elif st == 'path':
        if not os.path.isfile(source):
            raise ValueError('file not found: %s' % source)
        with open(source, 'rb') as f:
            return f.read(), os.path.basename(source)
    elif st == 'base64':
        s = source
        # 容忍 data: URI 前缀与空白
        if ',' in s and s[:5].lower() in ('data:',):
            s = s.split(',', 1)[1]
        s = ''.join(s.split())
        try:
            data = base64.b64decode(s, validate=False)
        except Exception:
            data = base64.b64decode(s + '=' * (-len(s) % 4))
        return data, 'doc'
    else:
        raise ValueError('unknown source_type: %s (use url/base64/path/auto)' % st)


def _open_doc(data):
    """用 PyMuPDF 打开 PDF 字节流。返回 fitz.Document 或抛异常。"""
    if fitz is None:
        raise RuntimeError('PyMuPDF not installed (pip install pymupdf)')
    if not data.startswith(b'%PDF') and not data[:4] == b'\x00\x00\x00\x00':
        # 非 PDF 头（可能是图片 / 其他），仍尝试；失败会抛
        pass
    doc = fitz.open(stream=data, filetype='pdf')
    return doc


def _parse_pages(spec, page_count):
    """把 '1-3,5' / 'all' 解析成 0-based 页索引列表。"""
    if spec in (None, '', 'all', '*'):
        return list(range(page_count))
    idx = []
    for part in str(spec).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            for p in range(a, b + 1):
                if 1 <= p <= page_count and (p - 1) not in idx:
                    idx.append(p - 1)
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if 1 <= p <= page_count and (p - 1) not in idx:
                idx.append(p - 1)
    return idx


def _truncate(text):
    if len(text) > MAX_TEXT_CHARS:
        return text[:MAX_TEXT_CHARS], True
    return text, False


# =====================================================================
# 三、核心工具实现
# =====================================================================
def _extract_text(doc, pages_idx, layout=False):
    parts = []
    for pno in pages_idx:
        page = doc[pno]
        if layout:
            # 布局模式：按 block 输出，带块类型与坐标（更接近排版）
            blocks = page.get_text('blocks')
            lines = []
            for b in blocks:
                x0, y0, x1, y1, text, bno, btype = b[0], b[1], b[2], b[3], b[4], b[5], b[6]
                if text.strip():
                    lines.append('%.0f,%.0f|%s' % (x0, y0, text.strip()))
            parts.append('\n'.join(lines))
        else:
            parts.append(page.get_text('text').strip())
    return parts


def tool_extract_text(args):
    data, name = _load_bytes(args)
    doc = _open_doc(data)
    page_count = doc.page_count
    pages_idx = _parse_pages(args.get('pages'), page_count)
    layout = bool(args.get('layout', False))
    parts = _extract_text(doc, pages_idx, layout)
    full = ('\n\n'.join('[Page %d]\n%s' % (i + 1, t) for i, t in zip(pages_idx, parts) if t)).strip()
    text, truncated = _truncate(full)
    return {'ok': True, 'source': name, 'page_count': page_count,
            'pages': [i + 1 for i in pages_idx], 'layout': layout,
            'text_length': len(text), 'truncated': truncated, 'text': text}


def tool_extract_tables(args):
    data, name = _load_bytes(args)
    doc = _open_doc(data)
    page_count = doc.page_count
    pages_idx = _parse_pages(args.get('pages'), page_count)
    fmt = (args.get('format') or 'json').lower()
    if fmt not in ('json', 'csv'):
        fmt = 'json'
    tables = []
    for pno in pages_idx:
        page = doc[pno]
        try:
            found = page.find_tables()
        except Exception:
            found = []
        if not found:
            continue
        for t in found.tables:
            rows = t.extract()
            if not rows:
                continue
            # 清洗单元格（None→''，去首尾空白）
            clean = [[('' if c is None else str(c).strip()) for c in row] for row in rows]
            tables.append({'page': pno + 1, 'rows': len(clean), 'cols': len(clean[0]) if clean else 0,
                           'data': clean})
    out = {'ok': True, 'source': name, 'page_count': page_count,
           'pages': [i + 1 for i in pages_idx], 'format': fmt,
           'table_count': len(tables), 'tables': tables}
    if fmt == 'csv':
        csvs = []
        for i, t in enumerate(tables):
            buf = io.StringIO()
            w = csv.writer(buf)
            for row in t['data']:
                w.writerow(row)
            csvs.append('-- Table %d (page %d) --\n%s' % (i + 1, t['page'], buf.getvalue().rstrip('\n')))
        out['csv'] = '\n\n'.join(csvs)
    return out


def tool_extract_metadata(args):
    data, name = _load_bytes(args)
    doc = _open_doc(data)
    meta = dict(doc.metadata or {})
    # 规范化日期字段
    for k in ('creationDate', 'modDate'):
        if k in meta and meta[k]:
            meta[k] = str(meta[k]).replace('D:', '').replace("'", '')[:19]
    form_fields = []
    try:
        for pno in range(doc.page_count):
            for w in (doc[pno].widgets() or []):
                form_fields.append({'page': pno + 1, 'name': w.field_name,
                                    'value': w.field_value, 'type': w.field_type_string})
    except Exception:
        pass
    return {'ok': True, 'source': name,
            'page_count': doc.page_count,
            'is_encrypted': bool(doc.is_encrypted),
            'needs_password': bool(doc.needs_pass),
            'file_size_bytes': len(data),
            'metadata': meta,
            'form_field_count': len(form_fields),
            'form_fields': form_fields}


def tool_extract_links(args):
    data, name = _load_bytes(args)
    doc = _open_doc(data)
    page_count = doc.page_count
    pages_idx = _parse_pages(args.get('pages'), page_count)
    links = []
    seen = set()
    for pno in pages_idx:
        for l in (doc[pno].get_links() or []):
            uri = l.get('uri')
            if uri:
                key = uri
                if key not in seen:
                    seen.add(key)
                    links.append({'page': pno + 1, 'uri': uri,
                                  'kind': l.get('kind', ''),
                                  'rect': l.get('from', '')})
    return {'ok': True, 'source': name, 'page_count': page_count,
            'pages': [i + 1 for i in pages_idx], 'link_count': len(links), 'links': links}


def tool_parse_document(args):
    """一键综合解析：元数据 + 正文 + 表格 + 表单字段 + 链接。"""
    data, name = _load_bytes(args)
    doc = _open_doc(data)
    page_count = doc.page_count
    pages_idx = _parse_pages(args.get('pages'), page_count)
    include_tables = bool(args.get('include_tables', True))

    meta = dict(doc.metadata or {})
    for k in ('creationDate', 'modDate'):
        if k in meta and meta[k]:
            meta[k] = str(meta[k]).replace('D:', '').replace("'", '')[:19]

    parts = _extract_text(doc, pages_idx, False)
    full = ('\n\n'.join('[Page %d]\n%s' % (i + 1, t) for i, t in zip(pages_idx, parts) if t)).strip()
    text, truncated = _truncate(full)

    tables = []
    if include_tables:
        for pno in pages_idx:
            try:
                found = doc[pno].find_tables()
            except Exception:
                found = []
            if not found:
                continue
            for t in found.tables:
                rows = t.extract()
                if not rows:
                    continue
                clean = [[('' if c is None else str(c).strip()) for c in row] for row in rows]
                tables.append({'page': pno + 1, 'rows': len(clean),
                               'cols': len(clean[0]) if clean else 0, 'data': clean})

    form_fields = []
    try:
        for pno in range(page_count):
            for w in (doc[pno].widgets() or []):
                form_fields.append({'page': pno + 1, 'name': w.field_name,
                                    'value': w.field_value, 'type': w.field_type_string})
    except Exception:
        pass

    links = []
    seen = set()
    for pno in pages_idx:
        for l in (doc[pno].get_links() or []):
            uri = l.get('uri')
            if uri and uri not in seen:
                seen.add(uri)
                links.append({'page': pno + 1, 'uri': uri})

    return {'ok': True, 'source': name, 'page_count': page_count,
            'is_encrypted': bool(doc.is_encrypted), 'needs_password': bool(doc.needs_pass),
            'file_size_bytes': len(data), 'metadata': meta,
            'text_length': len(text), 'truncated': truncated, 'text': text,
            'table_count': len(tables), 'tables': tables,
            'form_field_count': len(form_fields), 'form_fields': form_fields,
            'link_count': len(links), 'links': links}


# =====================================================================
# 四、OCR（扫描件 / 图片）
# =====================================================================
def _tesseract_available():
    return shutil.which('tesseract') is not None

def _ocr_image(image_bytes, lang):
    """对单张图片字节跑 tesseract。返回文本。"""
    fd, path = tempfile.mkstemp(suffix='.png')
    try:
        os.write(fd, image_bytes)
        os.close(fd)
        cmd = ['tesseract', path, 'stdout', '-l', lang, '--psm', '6']
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return out.stdout
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass

def tool_ocr_document(args):
    if not _tesseract_available():
        return {'ok': False, 'error': 'tesseract not installed on host (apt install tesseract-ocr[-chi-sim])'}
    data, name = _load_bytes(args)
    lang = (args.get('lang') or 'eng').strip()
    dpi = int(args.get('dpi') or OCR_DPI)
    dpi = max(72, min(dpi, 400))

    is_pdf = data.startswith(b'%PDF')
    results = []
    if is_pdf:
        doc = _open_doc(data)
        page_count = doc.page_count
        pages_idx = _parse_pages(args.get('pages'), page_count)
        if len(pages_idx) > MAX_OCR_PAGES:
            pages_idx = pages_idx[:MAX_OCR_PAGES]
        for pno in pages_idx:
            pix = doc[pno].get_pixmap(dpi=dpi)
            png = pix.tobytes('png')
            txt = _ocr_image(png, lang)
            results.append({'page': pno + 1, 'text': txt})
        return {'ok': True, 'source': name, 'mode': 'pdf', 'page_count': page_count,
                'ocr_pages': [i + 1 for i in pages_idx], 'lang': lang, 'dpi': dpi,
                'pages': results, 'text': '\n\n'.join('[Page %d]\n%s' % (r['page'], r['text']) for r in results)}
    else:
        txt = _ocr_image(data, lang)
        return {'ok': True, 'source': name, 'mode': 'image', 'lang': lang, 'dpi': dpi,
                'text': txt}


# =====================================================================
# 五、MCP 协议：initialize / tools/list / tools/call
# =====================================================================
_SOURCE_SCHEMA = {
    'source': {'type': 'string', 'description': '文档来源：URL、base64 编码内容，或本地文件路径（必填）'},
    'source_type': {'type': 'string', 'enum': ['url', 'base64', 'path', 'auto'],
                    'description': '输入类型，默认 auto 自动判断（http/https→url，存在文件→path，否则 base64）'},
}
_PAGES_SCHEMA = {
    'pages': {'type': 'string', 'description': '页范围，如 "1-3,5" 或 "all"（默认 all，1-based）'},
}

TOOLS = [
    {'name': 'parse_document',
     'description': '一键综合解析 PDF：返回元数据(标题/作者/页数/是否加密/文件大小) + 正文文本 + 表格(JSON) + 可填写表单字段 + 内嵌链接。给「要一次性读懂一份 PDF 合同/发票/财报/简历」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         **{'source': _SOURCE_SCHEMA['source'], 'source_type': _SOURCE_SCHEMA['source_type']},
         'pages': _PAGES_SCHEMA['pages'],
         'include_tables': {'type': 'boolean', 'description': '是否提取表格，默认 true'}},
         'required': ['source']}},
    {'name': 'extract_text',
     'description': '提取 PDF 正文文本。支持分页(page 标记)、指定页范围、布局模式(layout=true 时按块输出带坐标)。给「把 PDF 转成干净文本喂给模型做摘要/问答」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         **{'source': _SOURCE_SCHEMA['source'], 'source_type': _SOURCE_SCHEMA['source_type']},
         'pages': _PAGES_SCHEMA['pages'],
         'layout': {'type': 'boolean', 'description': '是否布局模式（按块输出带坐标），默认 false'}},
         'required': ['source']}},
    {'name': 'extract_tables',
     'description': '提取 PDF 表格。返回 JSON 结构（每表：页码/行数/列数/二维数组），或 format=csv 时返回 CSV 文本。给「要从 PDF 里抽表格数据（对账、报表、清单）」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         **{'source': _SOURCE_SCHEMA['source'], 'source_type': _SOURCE_SCHEMA['source_type']},
         'pages': _PAGES_SCHEMA['pages'],
         'format': {'type': 'string', 'enum': ['json', 'csv'], 'description': '输出格式，默认 json'}},
         'required': ['source']}},
    {'name': 'extract_metadata',
     'description': '提取 PDF 元数据：标题/作者/主题/关键词/生成器/创建修改时间/页数/是否加密/是否需要密码/文件大小，以及可填写表单字段(name/value/type)。给「要判断文档来源、真实性、是否被加密」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         **{'source': _SOURCE_SCHEMA['source'], 'source_type': _SOURCE_SCHEMA['source_type']}},
         'required': ['source']}},
    {'name': 'extract_links',
     'description': '提取 PDF 内嵌的超链接/URI（去重，带页码）。给「要从文档里收集引用链接、官网、来源」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         **{'source': _SOURCE_SCHEMA['source'], 'source_type': _SOURCE_SCHEMA['source_type']},
         'pages': _PAGES_SCHEMA['pages']},
         'required': ['source']}},
    {'name': 'ocr_document',
     'description': '对扫描件/图片做 OCR。输入可以是 PDF（逐页光栅化后识别）或图片（jpg/png/tiff，直接识别）。lang 支持 eng / chi_sim / eng+chi_sim 等（取决于主机已装语言包）。给「要读扫描发票、拍照合同、截图里的文字」的 Agent 用。',
     'inputSchema': {'type': 'object', 'properties': {
         **{'source': _SOURCE_SCHEMA['source'], 'source_type': _SOURCE_SCHEMA['source_type']},
         'pages': _PAGES_SCHEMA['pages'],
         'lang': {'type': 'string', 'description': 'OCR 语言，默认 eng，可 chi_sim / eng+chi_sim'},
         'dpi': {'type': 'integer', 'description': 'PDF 光栅化 DPI，默认 200'}},
         'required': ['source']}},
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
        dispatch = {'parse_document': tool_parse_document,
                    'extract_text': tool_extract_text,
                    'extract_tables': tool_extract_tables,
                    'extract_metadata': tool_extract_metadata,
                    'extract_links': tool_extract_links,
                    'ocr_document': tool_ocr_document}
        if name not in dispatch:
            return err(-32601, 'unknown tool: ' + name)
        try:
            data = dispatch[name](args)
            return ok({'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=False, indent=1)}],
                       'isError': False})
        except Exception as e:
            return err(-32000, repr(e))
    elif rid is not None:
        return err(-32601, 'method not found: ' + method)
    return None


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
    print('docparse-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()


if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8983
        main_http(port)
    else:
        main_stdio()
