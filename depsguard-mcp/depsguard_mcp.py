#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""depsguard-mcp — 依赖安全审计（给 AI Agent 用）

解决的问题：写代码 / 评审代码 / 迁移升级依赖的 Agent，在「选依赖、锁版本、判断
某版本是否有已知漏洞、该升级到哪个修复版本」时，无法凭训练知识可靠得出——
  1. 漏洞是实时更新的（每天都有新 CVE/GHSA），模型训练截止后新增的漏洞它一概不知；
  2. 「某包的某精确版本是否受影响、修复版本是多少」是权威事实，只能查漏洞库；
  3. 一份 package.json / requirements.txt 里几十个依赖，逐个查繁琐易漏，需要批量打通。

数据源：OSV.dev（Google 官方开源漏洞数据库，聚合 CVE/GHSA/npm/PyPI/Go/Maven/Rust
等 16+ 生态，免费、无 key、权威、实时）。协议：MCP (JSON-RPC 2.0)，2024-11-05。

纯标准库实现（urllib/json/http.server），零第三方依赖。

用法：
  python3 depsguard_mcp.py              # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 depsguard_mcp.py --http 8977  # streamable HTTP 模式（Smithery / 官方 registry）
"""
import json, sys, re, datetime, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'depsguard-mcp/1.0 (dependency vuln audit; contact niebingyu@qq.com)'}

OSV_QUERY = 'https://api.osv.dev/v1/query'
OSV_VULN = 'https://api.osv.dev/v1/vulns/'

CACHE = {}
CACHE_TTL = 600  # 漏洞查询缓存 10 分钟（漏洞库更新不频繁）

# OSV 支持的生态（名字必须与 OSV 完全一致）
SUPPORTED_ECOSYSTEMS = [
    'npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems', 'NuGet', 'Packagist',
    'Hex', 'Pub', 'SwiftURL', 'DWF', 'GSD', 'UVI', 'Bitnami', 'Linux',
]
# 常见别名归一化
ECOSYSTEM_ALIAS = {
    'node': 'npm', 'nodejs': 'npm', 'js': 'npm', 'javascript': 'npm', 'package.json': 'npm',
    'python': 'PyPI', 'pip': 'PyPI', 'pypi': 'PyPI', 'requirements': 'PyPI',
    'golang': 'Go', 'go': 'Go', 'gomod': 'Go',
    'java': 'Maven', 'maven': 'Maven', 'pom': 'Maven',
    'rust': 'crates.io', 'cargo': 'crates.io', 'crates': 'crates.io',
    'ruby': 'RubyGems', 'gem': 'RubyGems',
    'dotnet': 'NuGet', 'nuget': 'NuGet', '.net': 'NuGet',
    'php': 'Packagist', 'composer': 'Packagist',
    'elixir': 'Hex', 'hex': 'Hex',
    'dart': 'Pub', 'pub': 'Pub', 'flutter': 'Pub',
}

# =====================================================================
# 一、基础 HTTP + 缓存
# =====================================================================
def _post_json(url, payload, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                 headers=dict(UA, **{'Content-Type': 'application/json'}))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))

def _get_json(url, timeout=30):
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

# =====================================================================
# 二、CVSS 3.x 基础分计算 + 严重度判定
# =====================================================================
def _cvss3_score(vector):
    """解析 CVSS:3.x 向量串，计算基础分（CVSS 3.1 规范算法）。"""
    parts = {}
    for kv in vector.split('/')[1:]:
        if ':' in kv:
            k, v = kv.split(':', 1)
            parts[k] = v
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}.get(parts.get('AV', 'N'), 0.85)
    AC = {'L': 0.77, 'H': 0.44}.get(parts.get('AC', 'L'), 0.77)
    scope = parts.get('S', 'U')
    PR = ({'N': 0.85, 'L': 0.68, 'H': 0.5} if scope == 'C'
          else {'N': 0.85, 'L': 0.62, 'H': 0.27}).get(parts.get('PR', 'N'), 0.85)
    UI = {'N': 0.85, 'R': 0.62}.get(parts.get('UI', 'N'), 0.85)
    def _impact(v):
        return {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(v, 0.0)
    c, i, a = _impact(parts.get('C', 'N')), _impact(parts.get('I', 'N')), _impact(parts.get('A', 'N'))
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == 'C':
        imp = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        imp = 6.42 * iss
    exp = 8.22 * AV * AC * PR * UI
    if imp <= 0:
        return 0.0
    base = min(imp + exp, 10)
    # CVSS roundup：向上取整到 1 位小数（整值 0.1 倍数时保持不变）
    n = round(base * 100000)
    if n % 10000 == 0:
        return n / 100000.0
    return (n // 10000 + 1) / 10.0

def _severity(v):
    """从漏洞记录推导严重度标签：优先 GHSA database_specific.severity，否则算 CVSS 分。"""
    db = v.get('database_specific') or {}
    s = db.get('severity')
    if isinstance(s, str):
        s = s.upper()
        if s in ('CRITICAL', 'HIGH', 'MODERATE', 'LOW'):
            return s
    best = None
    for item in (v.get('severity') or []):
        vec = item.get('score') if isinstance(item, dict) else item
        if isinstance(vec, str) and vec.startswith('CVSS'):
            try:
                sc = _cvss3_score(vec)
                if best is None or sc > best:
                    best = sc
            except Exception:
                pass
    if best is not None:
        if best >= 9.0:
            return 'CRITICAL'
        if best >= 7.0:
            return 'HIGH'
        if best >= 4.0:
            return 'MODERATE'
        return 'LOW'
    return 'UNKNOWN'

SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MODERATE': 2, 'LOW': 3, 'UNKNOWN': 4}

# =====================================================================
# 三、漏洞提取工具
# =====================================================================
def _fixed_versions(v):
    """提取修复版本（fixed）与受影响起点（introduced）。"""
    fixed = set()
    for aff in v.get('affected', []):
        for r in aff.get('ranges', []):
            for ev in r.get('events', []):
                if 'fixed' in ev:
                    fixed.add(ev['fixed'])
    return sorted(fixed)

def _brief_vuln(v):
    """漏洞 → 精简结构化摘要（供 check_dependency / audit_manifest 输出）。"""
    return {
        'id': v.get('id'),
        'aliases': v.get('aliases') or [],
        'severity': _severity(v),
        'summary': (v.get('summary') or '').strip(),
        'fixed_versions': _fixed_versions(v),
    }

def _query_package(ecosystem, name, version=None):
    """查询单个包（可带版本）。返回 {vulns: [...], error: ...}"""
    # 注意：OSV 的 version 必须与 package 平级（顶层），放 package 内会被忽略导致返回该包全部漏洞
    payload = {'package': {'name': name, 'ecosystem': ecosystem}}
    if version:
        payload['version'] = version
    try:
        data = _post_json(OSV_QUERY, payload)
        return {'vulns': data.get('vulns', []) or []}
    except urllib.error.HTTPError as e:
        return {'vulns': [], 'error': 'OSV %d' % e.code}
    except Exception as e:
        return {'vulns': [], 'error': repr(e)}

def _batch_query(queries):
    """并发查询多个包（逐个走 /v1/query 完整接口，返回完整漏洞对象）。
    不用 /v1/querybatch：它只返回 {id, modified} 精简字段，缺 summary/severity/affected。
    """
    results = [None] * len(queries)
    def work(i):
        q = queries[i]
        return i, _query_package(q['ecosystem'], q['name'], q.get('version'))
    with ThreadPoolExecutor(max_workers=12) as ex:
        for i, res in ex.map(work, range(len(queries))):
            results[i] = res
    return results

# =====================================================================
# 四、清单解析（package.json / requirements.txt / Cargo.toml / go.mod / pom.xml）
# =====================================================================
def _strip_version_spec(v):
    """去掉版本前缀修饰符（^ ~ > < = >= <= 等），保留语义版本号。"""
    v = (v or '').strip()
    m = re.search(r'(\d+)(\.\d+){0,3}', v)
    return m.group(0) if m else v

def _detect_ecosystem(text):
    t = text.strip()
    if '<dependency>' in t:
        return 'Maven'
    if re.search(r'^\s*module\s', t, re.M) or 'require (' in t or 'require(' in t:
        return 'Go'
    if '[dependencies]' in t or '[package]' in t or '[dev-dependencies]' in t:
        return 'crates.io'
    if '"dependencies"' in t or '"devDependencies"' in t:
        return 'npm'
    # requirements.txt：以「包名 + 比较符 + 版本」为特征的纯文本行
    if re.search(r'^[A-Za-z0-9_.\-]+[~<>=!]+[0-9]', t, re.M):
        return 'PyPI'
    return None

def _parse_manifest(text, ecosystem):
    """解析清单文本 → [(ecosystem, name, version)]，去重、去无效。"""
    deps = []
    eco = ecosystem or _detect_ecosystem(text)
    if eco == 'npm':
        try:
            obj = json.loads(text)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            for section in ('dependencies', 'devDependencies'):
                for name, ver in (obj.get(section) or {}).items():
                    if isinstance(ver, str) and not ver.startswith(('file:', 'link:', 'workspace:', 'npm:')):
                        deps.append((eco, name, _strip_version_spec(ver)))
    elif eco == 'PyPI':
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '-', '--')):
                continue
            m = re.match(r'^\s*([A-Za-z0-9_.\-]+)\s*([~<>=!]+)\s*([^\s;]+)', line)
            if m:
                deps.append((eco, m.group(1), _strip_version_spec(m.group(3))))
    elif eco == 'crates.io':
        in_dep = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith('['):
                in_dep = 'dependencies' in s
                continue
            if in_dep:
                m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', s)
                if m:
                    deps.append((eco, m.group(1), _strip_version_spec(m.group(2))))
    elif eco == 'Go':
        # 处理 require ( ... ) 块与单行 require name v1.2.3
        for m in re.finditer(r'require\s*(?:\(\s*)?([A-Za-z0-9./_\-]+)\s+v?([0-9][^\s)]*)', text):
            deps.append((eco, m.group(1), _strip_version_spec(m.group(2))))
    elif eco == 'Maven':
        # 逐 <dependency> 块解析 groupId/artifactId/version
        for blk in re.findall(r'<dependency>(.*?)</dependency>', text, re.S):
            g = re.search(r'<groupId>([^<]+)</groupId>', blk)
            a = re.search(r'<artifactId>([^<]+)</artifactId>', blk)
            ver = re.search(r'<version>([^<]+)</version>', blk)
            if a and ver and '${' not in ver.group(1):
                name = (g.group(1) + ':' + a.group(1)) if g else a.group(1)
                deps.append((eco, name, _strip_version_spec(ver.group(1))))
    else:
        # 兜底：纯文本「name==version / name@version / name version」逐行
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            m = re.match(r'^([A-Za-z0-9_.:/\-]+)\s*(?:==|>=|<=|~=|@|:)\s*v?([0-9][^\s,]*)', line)
            if m:
                deps.append((eco or 'npm', m.group(1), _strip_version_spec(m.group(2))))
    # 去重（同名包保留第一个）
    seen, uniq = set(), []
    for e, n, v in deps:
        if not v or n in seen:
            continue
        seen.add(n)
        uniq.append((e, n, v))
    return uniq

# =====================================================================
# 五、MCP 工具实现
# =====================================================================
def tool_check_dependency(args):
    """单包漏洞检查。"""
    eco = _norm_eco(args.get('ecosystem', ''))
    name = (args.get('name') or '').strip()
    version = (args.get('version') or '').strip() or None
    if not eco:
        return {'ok': False, 'error': '请提供 ecosystem（如 npm / PyPI / Go / Maven / crates.io）'}
    if not name:
        return {'ok': False, 'error': '请提供包名 name'}
    key = 'q:' + eco + ':' + name + ':' + (version or '')
    res = _cached(key, lambda: _query_package(eco, name, version))
    vulns = res.get('vulns', [])
    vulns = sorted(vulns, key=lambda x: SEV_ORDER.get(_severity(x), 9))
    return {
        'ok': True, 'ecosystem': eco, 'name': name,
        'version': version or '(any)',
        'vulnerable': len(vulns) > 0, 'vuln_count': len(vulns),
        'vulns': [_brief_vuln(v) for v in vulns],
        'note': '版本未提供时返回影响该包任意版本的已知漏洞；提供精确版本则只返回影响该版本的漏洞。',
    }

def tool_audit_manifest(args):
    """解析清单并批量审计。"""
    text = args.get('manifest') or ''
    if not text.strip():
        return {'ok': False, 'error': '请提供 manifest 内容（package.json / requirements.txt / Cargo.toml / go.mod / pom.xml 全文）'}
    eco = _norm_eco(args.get('ecosystem', '') or '')
    deps = _parse_manifest(text, eco or None)
    if not deps:
        return {'ok': False, 'error': '未能从清单解析出任何依赖（格式不支持或内容为空）'}
    detected_eco = deps[0][0]
    queries = [{'name': n, 'ecosystem': e, 'version': v} for e, n, v in deps]
    results = _batch_query(queries)
    findings = []  # 汇总所有有漏洞的包
    per_pkg = []
    for (e, n, v), res in zip(deps, results):
        vulns = sorted(res.get('vulns', []) or [], key=lambda x: SEV_ORDER.get(_severity(x), 9))
        per_pkg.append({'name': n, 'ecosystem': e, 'version': v,
                        'vulnerable': len(vulns) > 0, 'vuln_count': len(vulns)})
        for vul in vulns:
            findings.append({'package': n, 'ecosystem': e, 'version': v, **_brief_vuln(vul)})
    findings.sort(key=lambda x: SEV_ORDER.get(x['severity'], 9))
    sev_count = {}
    for f in findings:
        sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1
    vulnerable_pkgs = [p['name'] for p in per_pkg if p['vulnerable']]
    return {
        'ok': True, 'ecosystem': detected_eco,
        'packages_scanned': len(deps),
        'vulnerable_packages': len(vulnerable_pkgs),
        'vulnerable_package_names': vulnerable_pkgs,
        'total_vulns': len(findings),
        'severity_breakdown': sev_count,
        'findings': findings,
        'per_package': per_pkg,
        'note': '漏洞库实时更新（OSV.dev），修复版本见 findings[].fixed_versions；建议优先处理 CRITICAL/HIGH。',
    }

def tool_vulnerability_detail(args):
    """漏洞详情查询。"""
    vid = (args.get('vuln_id') or args.get('id') or '').strip()
    if not vid:
        return {'ok': False, 'error': '请提供 vuln_id（如 CVE-2020-28500 或 GHSA-29mw-wpgm-hmr9）'}
    vid = vid.replace('https://osv.dev/vulnerability/', '')
    key = 'v:' + vid
    def _fetch():
        try:
            return _get_json(OSV_VULN + urllib.request.quote(vid, safe=''))
        except urllib.error.HTTPError as e:
            return {'__error': 'OSV %d' % e.code}
        except Exception as e:
            return {'__error': repr(e)}
    d = _cached(key, _fetch)
    if '__error' in d:
        return {'ok': False, 'error': d['__error']}
    affected = []
    for aff in d.get('affected', []):
        pkg = aff.get('package', {})
        fixed = []
        for r in aff.get('ranges', []):
            for ev in r.get('events', []):
                if 'fixed' in ev:
                    fixed.append(ev['fixed'])
        affected.append({
            'package': pkg.get('name'), 'ecosystem': pkg.get('ecosystem'),
            'fixed_versions': sorted(set(fixed)),
            'versions': (aff.get('versions') or [])[:20],
        })
    refs = [r.get('url') for r in (d.get('references') or [])][:10]
    db = d.get('database_specific') or {}
    return {
        'ok': True, 'id': d.get('id'), 'aliases': d.get('aliases') or [],
        'severity': _severity(d),
        'summary': (d.get('summary') or '').strip(),
        'details': (d.get('details') or '').strip(),
        'cwe_ids': db.get('cwe_ids') or [],
        'published': d.get('published'), 'modified': d.get('modified'),
        'affected': affected, 'references': refs,
    }

def _norm_eco(eco):
    """归一化生态名。"""
    e = (eco or '').strip()
    if e in SUPPORTED_ECOSYSTEMS:
        return e
    return ECOSYSTEM_ALIAS.get(e.lower(), e)

# =====================================================================
# 六、MCP 协议定义
# =====================================================================
TOOLS = [
 {'name': 'check_dependency',
  'description': '检查单个依赖包是否存在已知漏洞（实时查询 OSV.dev，Google 官方漏洞库，聚合 CVE/GHSA/npm/PyPI/Go/Maven/Rust 等 16+ 生态）。输入生态(ecosystem)+包名(name)+版本(version，可选)，返回是否受影响、漏洞数量、每个漏洞的 ID/别名/严重度/修复版本。给写代码/选依赖/评审依赖的 Agent 判断「这个包这个版本能不能用」。版本不填则返回影响该包任意版本的已知漏洞。',
  'inputSchema': {'type': 'object', 'properties': {
      'ecosystem': {'type': 'string', 'description': '包生态（npm / PyPI / Go / Maven / crates.io / RubyGems / NuGet / Packagist 等）'},
      'name': {'type': 'string', 'description': '包名，如 lodash / django / requests / github.com/gin-gonic/gin / org.apache.logging.log4j:log4j-core'},
      'version': {'type': 'string', 'description': '版本号（可选），如 4.17.20；不填则返回影响该包任意版本的漏洞'}},
      'required': ['ecosystem', 'name']}},
 {'name': 'audit_manifest',
  'description': '解析依赖清单并批量漏洞审计。输入 package.json / requirements.txt / Cargo.toml / go.mod / pom.xml 的完整文本（自动识别格式，也可用 ecosystem 显式指定），自动提取全部依赖并批量查询漏洞库，返回按严重度排序的漏洞清单（含修复版本）、受影响包列表、严重度分布。给写代码/做依赖升级/做安全评审的 Agent 一次性扫完整份依赖文件。',
  'inputSchema': {'type': 'object', 'properties': {
      'manifest': {'type': 'string', 'description': '依赖清单全文（package.json / requirements.txt / Cargo.toml / go.mod / pom.xml），直接粘贴文本'},
      'ecosystem': {'type': 'string', 'description': '生态（可选，默认自动识别）：npm / PyPI / Go / Maven / crates.io'}},
      'required': ['manifest']}},
 {'name': 'vulnerability_detail',
  'description': '查询单个漏洞的完整详情。输入漏洞 ID（如 CVE-2020-28500 或 GHSA-29mw-wpgm-hmr9），返回摘要、详细描述、严重度、CWE、受影响包与版本范围、修复版本、参考链接。给做安全分析/写漏洞报告/判断修复方案的 Agent 获取权威漏洞详情。',
  'inputSchema': {'type': 'object', 'properties': {
      'vuln_id': {'type': 'string', 'description': '漏洞 ID，如 CVE-2020-28500 / GHSA-29mw-wpgm-hmr9'}},
      'required': ['vuln_id']}},
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
                   'serverInfo': {'name': 'depsguard-mcp', 'version': '1.0.0'}})
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
            if name == 'check_dependency':
                data = tool_check_dependency(args)
            elif name == 'audit_manifest':
                data = tool_audit_manifest(args)
            elif name == 'vulnerability_detail':
                data = tool_vulnerability_detail(args)
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
        self.wfile.write(json.dumps({'service': 'depsguard-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('depsguard-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8977
        main_http(port)
    else:
        main_stdio()
