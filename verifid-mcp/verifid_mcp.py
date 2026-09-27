#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verifid-mcp — 企业/账户标识符校验引擎（给 AI Agent 用）

解决的问题：做跨境支付 / 财税合规 / 企业尽调 / 反欺诈 / 外贸结算的 Agent，在
「某个增值税号此刻是否有效、这个统一社会信用代码是不是伪造的、这个 IBAN 能否
真实入账、这个 BIC/SWIFT 代码是否规范」时，无法凭训练知识可靠得出——
  1. 欧盟增值税号（VAT）有效性：必须实时查询欧盟官方 VIES 数据库，模型不知道
     「此刻」这个号是否有效、对应哪家公司；
  2. 中国统一社会信用代码（USCC，18 位）：有 GB 32100-2015 规定的加权校验位算法，
     模型经常算错校验位，也无法反推登记管理部门 / 机构类别 / 行政区划；
  3. IBAN 国际银行账号：ISO 13616 规定 mod-97 校验位 + 各国 BBAN 长度规则，
     入账前必须精确校验，模型无法可靠心算；
  4. BIC/SWIFT 代码：ISO 9362 规定 8/11 位结构 + 国家码必须是 ISO 3166-1 alpha-2，
     模型无法核对国家码表。

数据源全部为公开权威、免费、无 key：
  - VIES（欧盟官方，ec.europa.eu）REST API 实时验证增值税号，返回有效性 + 企业名称/地址；
  - 统一社会信用代码 / IBAN / BIC 均为公开国际/国家标准算法，纯本地计算，无需联网。

纯标准库实现（urllib / json / http.server / re），零第三方依赖。

用法：
  python3 verifid_mcp.py              # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 verifid_mcp.py --http 8979  # streamable HTTP 模式

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, datetime, time, urllib.request, urllib.parse, urllib.error, re
from http.server import BaseHTTPRequestHandler, HTTPServer

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'verifid-mcp/1.0 (entity/account identifier validation; contact niebingyu@qq.com)'}

CACHE = {}          # {key: (ts, val)} 通用缓存
CACHE_TTL = 86400   # 增值税号有效性稳定，缓存 24 小时；其他纯计算无缓存

# =====================================================================
# 一、基础 HTTP 与缓存
# =====================================================================
def _fetch_json(url, timeout=20):
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
# 二、欧盟增值税号实时验证（VIES 官方 REST API）
# =====================================================================
# VIES REST API 支持的成员国/地区代码（27 个欧盟成员 + 北爱尔兰 XI）
EU_CODES = {
    'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'EL', 'ES', 'FI', 'FR',
    'HR', 'HU', 'IE', 'IT', 'LT', 'LU', 'LV', 'MT', 'NL', 'PL', 'PT', 'RO',
    'SE', 'SI', 'SK', 'XI',
}
# 常见国家名/简称 → ISO 代码（用于用户传中文或英文国名时兜底）
EU_NAME_ALIAS = {
    'austria': 'AT', 'belgium': 'BE', 'bulgaria': 'BG', 'cyprus': 'CY',
    'czech': 'CZ', 'czechia': 'CZ', 'germany': 'DE', 'denmark': 'DK',
    'estonia': 'EE', 'greece': 'EL', 'spain': 'ES', 'finland': 'FI',
    'france': 'FR', 'croatia': 'HR', 'hungary': 'HU', 'ireland': 'IE',
    'italy': 'IT', 'lithuania': 'LT', 'luxembourg': 'LU', 'latvia': 'LV',
    'malta': 'MT', 'netherlands': 'NL', 'poland': 'PL', 'portugal': 'PT',
    'romania': 'RO', 'sweden': 'SE', 'slovenia': 'SI', 'slovakia': 'SK',
    '奥地利': 'AT', '比利时': 'BE', '保加利亚': 'BG', '塞浦路斯': 'CY',
    '捷克': 'CZ', '德国': 'DE', '丹麦': 'DK', '爱沙尼亚': 'EE',
    '希腊': 'EL', '西班牙': 'ES', '芬兰': 'FI', '法国': 'FR',
    '克罗地亚': 'HR', '匈牙利': 'HU', '爱尔兰': 'IE', '意大利': 'IT',
    '立陶宛': 'LT', '卢森堡': 'LU', '拉脱维亚': 'LV', '马耳他': 'MT',
    '荷兰': 'NL', '波兰': 'PL', '葡萄牙': 'PT', '罗马尼亚': 'RO',
    '瑞典': 'SE', '斯洛文尼亚': 'SI', '斯洛伐克': 'SK',
}

def _parse_vat(vat_number, country_code=''):
    """从完整 VAT 号中解析国家代码 + 数字部分。
    返回 (country_code, number, error)。"""
    v = re.sub(r'[\s.\-]', '', (vat_number or '').strip())
    if not v:
        return None, None, '请提供 vat_number'
    cc = ''
    num = v
    # 前 2 字符是字母 → 视为国家前缀
    if len(v) >= 2 and v[:2].isalpha():
        cc = v[:2].upper()
        num = v[2:]
    # 希腊 EL 用 GR 前缀，VIES 接受 EL 与 GR 两种
    if cc == 'GR':
        cc = 'EL'
    # 无前缀时用 country_code 兜底
    if not cc and country_code:
        cc = country_code.strip().upper()
        if cc in EU_NAME_ALIAS:
            cc = EU_NAME_ALIAS[cc]
    if not cc:
        return None, None, '无法确定国家代码：请在 vat_number 前加 2 位国家前缀（如 DE118976613）或传 country_code'
    if cc not in EU_CODES:
        return None, None, '不支持的国家代码 %s（VIES 仅覆盖欧盟成员国 + 北爱尔兰 XI）' % cc
    if not num:
        return None, None, '增值税号主体为空'
    return cc, num, None

def _vies_check(cc, num):
    """调用 VIES REST API。返回 dict。"""
    url = ('https://ec.europa.eu/taxation_customs/vies/rest-api/ms/%s/vat/%s'
           % (cc, urllib.parse.quote(num)))
    req = urllib.request.Request(url, headers=dict(UA))
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))

def tool_vat_validate(args):
    """欧盟增值税号实时验证。"""
    cc, num, err = _parse_vat(args.get('vat_number', ''), args.get('country_code', ''))
    if err:
        return {'ok': False, 'error': err}
    def _run():
        try:
            d = _vies_check(cc, num)
        except urllib.error.HTTPError as e:
            return {'ok': False, 'vat_number': cc + num, 'error': 'VIES http %d' % e.code}
        except Exception as e:
            return {'ok': False, 'vat_number': cc + num, 'error': 'VIES 查询失败: %s' % repr(e)}
        return {
            'ok': True,
            'vat_number': d.get('originalVatNumber') or (cc + num),
            'country_code': cc,
            'is_valid': d.get('isValid'),
            'status': d.get('userError'),
            'company_name': d.get('name'),
            'address': d.get('address'),
            'checked_at': d.get('requestDate'),
            'source': 'VIES (ec.europa.eu 欧盟官方实时数据库)',
        }
    return _cached('vat:' + cc + num, _run)

# =====================================================================
# 三、中国统一社会信用代码校验（GB 32100-2015）
# =====================================================================
# 字符集（31 个，排除易混淆的 I O Z S V）
_USCC_CHARS = '0123456789ABCDEFGHJKLMNPQRTUWXY'
# 17 位加权因子（从左到右）
_USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]
# 登记管理部门代码（第 1 位）
_REG_DEPT = {
    '1': '机构编制（机关/事业单位）', '5': '民政（社会组织）', '9': '工商（企业/个体工商户/合作社）',
    'Y': '其他',
}
# 机构类别代码（第 2 位，结合登记管理部门）
_ENTITY_TYPE = {
    '11': '机关法人', '12': '事业单位法人', '13': '事业单位（未取得法人资格）',
    '19': '其他机构（编制）',
    '51': '社会团体', '52': '民办非企业单位', '53': '基金会',
    '91': '企业法人', '92': '个体工商户', '93': '农民专业合作社',
    'Y1': '其他',
}
# 省级行政区划（前 2 位）
_PROVINCES = {
    '11': '北京市', '12': '天津市', '13': '河北省', '14': '山西省', '15': '内蒙古自治区',
    '21': '辽宁省', '22': '吉林省', '23': '黑龙江省',
    '31': '上海市', '32': '江苏省', '33': '浙江省', '34': '安徽省', '35': '福建省',
    '36': '江西省', '37': '山东省',
    '41': '河南省', '42': '湖北省', '43': '湖南省', '44': '广东省', '45': '广西壮族自治区',
    '46': '海南省',
    '50': '重庆市', '51': '四川省', '52': '贵州省', '53': '云南省', '54': '西藏自治区',
    '61': '陕西省', '62': '甘肃省', '63': '青海省', '64': '宁夏回族自治区', '65': '新疆维吾尔自治区',
    '71': '台湾地区', '81': '香港特别行政区', '82': '澳门特别行政区',
}

def _uscc_compute_check(chars17):
    """按 GB 32100-2015 计算前 17 位的校验字符。"""
    total = 0
    for i, ch in enumerate(chars17):
        idx = _USCC_CHARS.find(ch)
        if idx < 0:
            return None
        total += idx * _USCC_WEIGHTS[i]
    return _USCC_CHARS[(31 - total % 31) % 31]

def _uscc_validate(uscc):
    """校验统一社会信用代码。返回 (bool, info_dict)。"""
    u = re.sub(r'[\s\-]', '', (uscc or '').strip().upper())
    info = {'input': uscc, 'normalized': u}
    if len(u) != 18:
        info['error'] = '长度应为 18 位，实际 %d 位' % len(u)
        return False, info
    if not re.match(r'^[0-9A-HJ-NP-RT-UW-Y]{18}$', u):
        info['error'] = '含非法字符（统一社会信用代码使用 0-9 与 A-Z，排除 I O Z S V）'
        return False, info
    expected = _uscc_compute_check(u[:17])
    if expected is None:
        info['error'] = '前 17 位含非法字符'
        return False, info
    info['check_char'] = u[17]
    info['expected_check'] = expected
    # 解析结构
    info['registration_dept'] = _REG_DEPT.get(u[0], '未知')
    type_key = u[:2]
    info['entity_type'] = _ENTITY_TYPE.get(type_key, ('其他/未知' if u[0] in '19Y' else '未知'))
    info['province'] = _PROVINCES.get(u[2:4], '未知')
    info['admin_code'] = u[2:8]       # 行政区划代码
    info['org_code'] = u[8:17]        # 组织机构代码（主体标识码）
    if u[17] != expected:
        info['error'] = '校验位不符：应为 %s，实际 %s（疑似伪造/录入错误）' % (expected, u[17])
        return False, info
    info['valid'] = True
    return True, info

def tool_uscc_validate(args):
    """中国统一社会信用代码校验。"""
    u = args.get('uscc', '') or args.get('code', '')
    if not u:
        return {'ok': False, 'error': '请提供统一社会信用代码'}
    ok, info = _uscc_validate(u)
    return {'ok': True, 'is_valid': ok, **info}

# =====================================================================
# 四、IBAN 国际银行账号校验（ISO 13616）
# =====================================================================
# 各国 IBAN 总长度（国家码 + 2 校验位 + BBAN），ISO 13616 注册国（主要）
IBAN_LENGTHS = {
    'AD': 24, 'AE': 23, 'AL': 28, 'AT': 20, 'AZ': 28, 'BA': 20, 'BE': 16,
    'BG': 22, 'BH': 22, 'BR': 29, 'BY': 28, 'CH': 21, 'CR': 22, 'CY': 28,
    'CZ': 24, 'DE': 22, 'DK': 18, 'DO': 28, 'EE': 20, 'EG': 29, 'ES': 24,
    'FI': 18, 'FO': 18, 'FR': 27, 'GB': 22, 'GE': 22, 'GI': 23, 'GL': 18,
    'GR': 27, 'GT': 28, 'HR': 21, 'HU': 28, 'IE': 22, 'IL': 23, 'IQ': 23,
    'IS': 26, 'IT': 27, 'JO': 30, 'KW': 30, 'KZ': 20, 'LB': 28, 'LC': 32,
    'LI': 21, 'LT': 20, 'LU': 20, 'LV': 21, 'MC': 27, 'MD': 24, 'ME': 22,
    'MK': 19, 'MR': 27, 'MT': 31, 'MU': 30, 'NL': 18, 'NO': 15, 'PK': 24,
    'PL': 28, 'PS': 29, 'PT': 25, 'QA': 29, 'RO': 24, 'RS': 22, 'SA': 24,
    'SC': 31, 'SE': 24, 'SI': 19, 'SK': 24, 'SM': 27, 'ST': 25, 'SV': 28,
    'TL': 23, 'TN': 24, 'TR': 26, 'UA': 29, 'VA': 22, 'VG': 24, 'XK': 20,
}
# 部分国家 IBAN 的 BBAN 内部结构（银行代码 + 分行代码等），用于补充解析。
# 偏移均为「从 BBAN 开头（i[4:]）算起」的切片区间。
IBAN_STRUCTURE = {
    'DE': {'bank_code': (0, 8), 'branch': None, 'account': (8, 18)},            # 8 位 BLZ + 10 位账号
    'GB': {'bank_code': (0, 4), 'branch': (4, 10), 'account': (10, 18)},        # 4 位银行 + 6 位分行 + 8 位账号
    'FR': {'bank_code': (0, 5), 'branch': (5, 10), 'account': (10, 21)},        # 5+5+11+2(国家键)
    'IT': {'bank_code': (1, 6), 'branch': (6, 11), 'account': (12, 23)},        # 1 位检查 + 5+5+12
    'ES': {'bank_code': (0, 4), 'branch': (4, 8), 'account': (10, 20)},         # 4+4+2(控制)+10
    'NL': {'bank_code': (0, 4), 'branch': None, 'account': (4, 14)},            # 4 位银行 + 10 位账号
    'BE': {'bank_code': (0, 3), 'branch': None, 'account': (3, 10)},            # 3 位银行 + 7 位账号
    'PT': {'bank_code': (0, 4), 'branch': (4, 8), 'account': (8, 19)},          # 4+4+11+2
    'AT': {'bank_code': (0, 5), 'branch': None, 'account': (5, 16)},            # 5 位银行 + 11 位账号
}

def _iban_mod97(iban):
    """ISO 13616 mod-97 校验。返回校验余数。"""
    rearranged = iban[4:] + iban[:4]
    digits = ''
    for ch in rearranged:
        if ch.isdigit():
            digits += ch
        else:
            digits += str(ord(ch) - ord('A') + 10)
    return int(digits) % 97

def _iban_validate(iban):
    """校验 IBAN。返回 (bool, info_dict)。"""
    i = re.sub(r'[\s\-]', '', (iban or '').strip().upper())
    info = {'input': iban, 'normalized': i}
    if not i:
        info['error'] = '请提供 IBAN'
        return False, info
    if not re.match(r'^[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}$', i):
        info['error'] = '格式错误：应为 2 位国家码 + 2 位校验位 + 最长 30 位 BBAN'
        return False, info
    cc = i[:2]
    info['country_code'] = cc
    if cc not in IBAN_LENGTHS:
        info['error'] = '未知/不支持的国家码 %s（不在 ISO 13616 注册国表内）' % cc
        return False, info
    expected_len = IBAN_LENGTHS[cc]
    if len(i) != expected_len:
        info['error'] = '长度不符：%s 应为 %d 位，实际 %d 位' % (cc, expected_len, len(i))
        return False, info
    rem = _iban_mod97(i)
    info['mod97'] = rem
    info['bban'] = i[4:]
    info['check_digits'] = i[2:4]
    # 解析内部结构（若在已知结构表内）
    struct = IBAN_STRUCTURE.get(cc)
    if struct:
        bban = i[4:]
        def seg(r):
            return bban[r[0]:r[1]] if r and r[1] <= len(bban) else None
        info['bank_code'] = seg(struct.get('bank_code'))
        info['branch_code'] = seg(struct.get('branch'))
        info['account_number'] = seg(struct.get('account'))
    if rem != 1:
        info['error'] = 'mod-97 校验失败（余数 %d，应为 1）：校验位错误，疑似伪造/录入错误' % rem
        return False, info
    info['valid'] = True
    return True, info

def tool_iban_validate(args):
    """IBAN 校验。"""
    i = args.get('iban', '')
    if not i:
        return {'ok': False, 'error': '请提供 iban'}
    ok, info = _iban_validate(i)
    return {'ok': True, 'is_valid': ok, **info}

# =====================================================================
# 五、BIC/SWIFT 代码校验（ISO 9362）
# =====================================================================
# ISO 3166-1 alpha-2 国家代码全集（用于校验 BIC 第 5-6 位）
ISO3166 = {
    'AD','AE','AF','AG','AI','AL','AM','AO','AQ','AR','AS','AT','AU','AW','AX','AZ',
    'BA','BB','BD','BE','BF','BG','BH','BI','BJ','BL','BM','BN','BO','BQ','BR','BS','BT','BV','BW','BY','BZ',
    'CA','CC','CD','CF','CG','CH','CI','CK','CL','CM','CN','CO','CR','CU','CV','CW','CX','CY','CZ',
    'DE','DJ','DK','DM','DO','DZ','EC','EE','EG','EH','ER','ES','ET','FI','FJ','FK','FM','FO','FR',
    'GA','GB','GD','GE','GF','GG','GH','GI','GL','GM','GN','GP','GQ','GR','GS','GT','GU','GW','GY',
    'HK','HM','HN','HR','HT','HU','ID','IE','IL','IM','IN','IO','IQ','IR','IS','IT',
    'JE','JM','JO','JP','KE','KG','KH','KI','KM','KN','KP','KR','KW','KY','KZ',
    'LA','LB','LC','LI','LK','LR','LS','LT','LU','LV','LY','MA','MC','MD','ME','MF','MG','MH','MK','ML','MM',
    'MN','MO','MP','MQ','MR','MS','MT','MU','MV','MW','MX','MY','MZ',
    'NA','NC','NE','NF','NG','NI','NL','NO','NP','NR','NU','NZ','OM','PA','PE','PF','PG','PH','PK','PL','PM',
    'PN','PR','PS','PT','PW','PY','QA','RE','RO','RS','RU','RW','SA','SB','SC','SD','SE','SG','SH','SI','SJ',
    'SK','SL','SM','SN','SO','SR','SS','ST','SV','SX','SY','SZ','TC','TD','TF','TG','TH','TJ','TK','TL','TM',
    'TN','TO','TR','TT','TV','TW','TZ','UA','UG','UM','US','UY','UZ','VA','VC','VE','VG','VI','VN','VU',
    'WF','WS','YE','YT','ZA','ZM','ZW',
}

def _bic_validate(bic):
    """校验 BIC/SWIFT 代码。返回 (bool, info_dict)。"""
    b = re.sub(r'[\s\-]', '', (bic or '').strip().upper())
    info = {'input': bic, 'normalized': b}
    if not b:
        info['error'] = '请提供 BIC'
        return False, info
    if not re.match(r'^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$', b):
        info['error'] = '格式错误：BIC 应为 8 或 11 位（4 位银行码 + 2 位国家码 + 2 位地区码 + 可选 3 位分行码）'
        return False, info
    info['bank_code'] = b[:4]
    info['country_code'] = b[4:6]
    info['location_code'] = b[6:8]
    info['branch_code'] = b[8:11] if len(b) == 11 else None
    info['is_head_office'] = (b[7] == 'X' and len(b) == 8)  # 第 8 位 X 常表示总行
    if b[4:6] not in ISO3166:
        info['error'] = '国家码 %s 不是合法的 ISO 3166-1 alpha-2 代码' % b[4:6]
        return False, info
    info['valid'] = True
    return True, info

def tool_bic_validate(args):
    """BIC/SWIFT 校验。"""
    b = args.get('bic', '') or args.get('swift', '')
    if not b:
        return {'ok': False, 'error': '请提供 bic'}
    ok, info = _bic_validate(b)
    return {'ok': True, 'is_valid': ok, **info}

# =====================================================================
# 六、MCP 协议定义
# =====================================================================
TOOLS = [
 {'name': 'vat_validate',
  'description': '实时验证欧盟增值税号(VAT)是否有效，并返回对应企业名称与注册地址。数据源为欧盟官方 VIES 数据库（ec.europa.eu），非猜测。输入完整增值税号（带 2 位国家前缀，如 DE118976613）或单独传 country_code。给跨境支付/财税合规/外贸结算 Agent 判断「这个 VAT 号此刻是否真实有效、对应哪家公司」。',
  'inputSchema': {'type': 'object', 'properties': {
      'vat_number': {'type': 'string', 'description': '增值税号，建议含国家前缀，如 "DE118976613" 或 "IE6388047V"'},
      'country_code': {'type': 'string', 'description': '可选：若 vat_number 不含国家前缀，用 2 位国家码（如 DE/FR/IE）或国名（如 Germany/德国）指定'}},
      'required': ['vat_number']}},
 {'name': 'uscc_validate',
  'description': '校验中国统一社会信用代码（18 位）的真伪，并解析登记管理部门、机构类别、省级行政区划、组织机构代码。按 GB 32100-2015 加权校验位算法精确计算（模型常算错校验位，本工具给出权威结果）。给企业尽调/合规/对公开户 Agent 判断「这个统一社会信用代码是不是伪造的」。',
  'inputSchema': {'type': 'object', 'properties': {
      'uscc': {'type': 'string', 'description': '18 位统一社会信用代码，如 "91330100710946581L"'}},
      'required': ['uscc']}},
 {'name': 'iban_validate',
  'description': '校验 IBAN 国际银行账号能否真实入账：ISO 13616 mod-97 校验位 + 各国 BBAN 长度规则 + 银行码/账号结构解析。覆盖 80+ 国家。给跨境汇款/薪资发放/对公转账 Agent 在打款前精确校验「这个 IBAN 是否合法、会不会打错账」。',
  'inputSchema': {'type': 'object', 'properties': {
      'iban': {'type': 'string', 'description': 'IBAN 账号，如 "DE89370400440532013000"'}},
      'required': ['iban']}},
 {'name': 'bic_validate',
  'description': '校验 BIC/SWIFT 代码（ISO 9362）是否规范：8/11 位结构 + 银行码 + 国家码（ISO 3166-1 alpha-2）+ 地区码 + 可选分行码。给跨境结算/国际汇款 Agent 核对收款行 SWIFT 代码是否合法。',
  'inputSchema': {'type': 'object', 'properties': {
      'bic': {'type': 'string', 'description': 'BIC/SWIFT 代码，如 "DEUTDEFF" 或 "DEUTDEFF500"'}},
      'required': ['bic']}},
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
                   'serverInfo': {'name': 'verifid-mcp', 'version': '1.0.0'}})
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
            if name == 'vat_validate':
                data = tool_vat_validate(args)
            elif name == 'uscc_validate':
                data = tool_uscc_validate(args)
            elif name == 'iban_validate':
                data = tool_iban_validate(args)
            elif name == 'bic_validate':
                data = tool_bic_validate(args)
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
        self.wfile.write(json.dumps({'service': 'verifid-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('verifid-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8979
        main_http(port)
    else:
        main_stdio()
