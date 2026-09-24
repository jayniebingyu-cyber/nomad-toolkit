#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tradeland-mcp — 跨境落地成本计算器（给 AI Agent 用）

解决的问题：电商/选品/外贸 Agent 在「估算商品到岸总成本、对比不同目的国、
判断是否超免税额度、做多币种报价」时，无法凭训练知识可靠得出——
  1. 实时汇率：训练数据是过期的，汇率天天变；
  2. 各国进口规则：增值税率 / GST / 免税额度(de minimis) / 关税参考区间，
     一个模型记不住 40+ 国的当前阈值，且会编造；
  3. 落地成本公式：FOB → 运费 → 保险 → CIF → 关税 → 增值税 → 落地总成本，
     需要「实时数据 + 计算」，必须由工具打通。

纯标准库实现（urllib / json / http.server），零第三方依赖，可离线退化（汇率走内置回退表）。

用法：
  python3 tradeland_mcp.py            # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 tradeland_mcp.py --http 8976 # streamable HTTP 模式（Smithery / 官方 registry 托管接入）

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, sys, datetime, time, urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'tradeland-mcp/1.0 (landed cost; contact niebingyu@qq.com)'}
CACHE = {}
CACHE_TTL = 3600  # 汇率缓存 1 小时

# =====================================================================
# 一、各国进口规则参考库（增值税率 / 免税额度 de minimis / 币种）
#   注：均为「参考值」，政策频繁调整（尤其美国 de minimis 与中国低值包裹），
#   实际以海关/货代为准。数据为通用常识级公开信息，非侵权。
# =====================================================================
# 字段：name 英文名 / cn 中文名 / cur 币种(ISO) / vat 标准增值税率(小数) /
#       vat_name 税种名 / de_minimis 免税额度(本币) / note 备注
COUNTRIES = {
 'US': {'name': 'United States', 'cn': '美国', 'cur': 'USD', 'vat': 0.0, 'vat_name': 'Sales tax (state-level)', 'de_minimis': 800, 'note': '无联邦增值税，州销售税另计；de minimis $800 政策 2025 年有变动，低值包裹对华政策需实时核实'},
 'GB': {'name': 'United Kingdom', 'cn': '英国', 'cur': 'GBP', 'vat': 0.20, 'vat_name': 'VAT', 'de_minimis': 135, 'note': '≤£135 由卖家代收 VAT（IOSS）'},
 'DE': {'name': 'Germany', 'cn': '德国', 'cur': 'EUR', 'vat': 0.19, 'vat_name': 'USt', 'de_minimis': 150, 'note': 'EU 低值货物 de minimis €150（关税）'},
 'FR': {'name': 'France', 'cn': '法国', 'cur': 'EUR', 'vat': 0.20, 'vat_name': 'TVA', 'de_minimis': 150, 'note': 'EU 低值货物 de minimis €150'},
 'NL': {'name': 'Netherlands', 'cn': '荷兰', 'cur': 'EUR', 'vat': 0.21, 'vat_name': 'BTW', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'IT': {'name': 'Italy', 'cn': '意大利', 'cur': 'EUR', 'vat': 0.22, 'vat_name': 'IVA', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'ES': {'name': 'Spain', 'cn': '西班牙', 'cur': 'EUR', 'vat': 0.21, 'vat_name': 'IVA', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'PL': {'name': 'Poland', 'cn': '波兰', 'cur': 'PLN', 'vat': 0.23, 'vat_name': 'VAT', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'SE': {'name': 'Sweden', 'cn': '瑞典', 'cur': 'SEK', 'vat': 0.25, 'vat_name': 'Moms', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'IE': {'name': 'Ireland', 'cn': '爱尔兰', 'cur': 'EUR', 'vat': 0.23, 'vat_name': 'VAT', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'AT': {'name': 'Austria', 'cn': '奥地利', 'cur': 'EUR', 'vat': 0.20, 'vat_name': 'USt', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'BE': {'name': 'Belgium', 'cn': '比利时', 'cur': 'EUR', 'vat': 0.21, 'vat_name': 'BTW', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'PT': {'name': 'Portugal', 'cn': '葡萄牙', 'cur': 'EUR', 'vat': 0.23, 'vat_name': 'IVA', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'DK': {'name': 'Denmark', 'cn': '丹麦', 'cur': 'DKK', 'vat': 0.25, 'vat_name': 'Moms', 'de_minimis': 150, 'note': 'EU de minimis €150'},
 'CA': {'name': 'Canada', 'cn': '加拿大', 'cur': 'CAD', 'vat': 0.05, 'vat_name': 'GST', 'de_minimis': 150, 'note': 'GST 5% 联邦 + 省税另计；关税 de minimis CAD150'},
 'AU': {'name': 'Australia', 'cn': '澳大利亚', 'cur': 'AUD', 'vat': 0.10, 'vat_name': 'GST', 'de_minimis': 1000, 'note': 'GST 10%，de minimis AUD1000'},
 'NZ': {'name': 'New Zealand', 'cn': '新西兰', 'cur': 'NZD', 'vat': 0.15, 'vat_name': 'GST', 'de_minimis': 1000, 'note': 'GST 15%，de minimis NZD1000'},
 'JP': {'name': 'Japan', 'cn': '日本', 'cur': 'JPY', 'vat': 0.10, 'vat_name': 'Consumption tax', 'de_minimis': 10000, 'note': '消费税 10%，de minimis JPY10000'},
 'KR': {'name': 'South Korea', 'cn': '韩国', 'cur': 'KRW', 'vat': 0.10, 'vat_name': 'VAT', 'de_minimis': 150, 'note': 'VAT 10%，de minimis USD150（约）'},
 'SG': {'name': 'Singapore', 'cn': '新加坡', 'cur': 'SGD', 'vat': 0.09, 'vat_name': 'GST', 'de_minimis': 400, 'note': 'GST 9%（2024 起），de minimis SGD400'},
 'MY': {'name': 'Malaysia', 'cn': '马来西亚', 'cur': 'MYR', 'vat': 0.10, 'vat_name': 'SST', 'de_minimis': 500, 'note': 'SST 10%（2024 复征），低值商品 LVG 税注意'},
 'TH': {'name': 'Thailand', 'cn': '泰国', 'cur': 'THB', 'vat': 0.07, 'vat_name': 'VAT', 'de_minimis': 1500, 'note': 'VAT 7%，de minimis THB1500'},
 'VN': {'name': 'Vietnam', 'cn': '越南', 'cur': 'VND', 'vat': 0.10, 'vat_name': 'VAT', 'de_minimis': 1000000, 'note': 'VAT 10%（部分商品临时 8%），de minimis 政策 2025 调整'},
 'ID': {'name': 'Indonesia', 'cn': '印度尼西亚', 'cur': 'IDR', 'vat': 0.11, 'vat_name': 'PPN', 'de_minimis': 3, 'note': 'PPN 11%，de minimis 极低（USD3 起征税）'},
 'PH': {'name': 'Philippines', 'cn': '菲律宾', 'cur': 'PHP', 'vat': 0.12, 'vat_name': 'VAT', 'de_minimis': 10000, 'note': 'VAT 12%，de minimis PHP10000'},
 'IN': {'name': 'India', 'cn': '印度', 'cur': 'INR', 'vat': 0.18, 'vat_name': 'GST', 'de_minimis': 0, 'note': 'GST 18%（标准），无免税额度'},
 'CN': {'name': 'China', 'cn': '中国', 'cur': 'CNY', 'vat': 0.13, 'vat_name': 'VAT', 'de_minimis': 50, 'note': '增值税 13% 标准（另有消费税），个人行邮税 50 元免征额'},
 'HK': {'name': 'Hong Kong, China', 'cn': '中国香港', 'cur': 'HKD', 'vat': 0.0, 'vat_name': 'None', 'de_minimis': 0, 'note': '自由港，无增值税/关税（酒烟等例外）'},
 'TW': {'name': 'Taiwan, China', 'cn': '中国台湾', 'cur': 'TWD', 'vat': 0.05, 'vat_name': 'VAT', 'de_minimis': 2000, 'note': 'VAT 5%，de minimis TWD2000'},
 'BR': {'name': 'Brazil', 'cn': '巴西', 'cur': 'BRL', 'vat': 0.17, 'vat_name': 'ICMS', 'de_minimis': 0, 'note': 'ICMS 州税 17-20% 不等，另有进口税，无 de minimis'},
 'MX': {'name': 'Mexico', 'cn': '墨西哥', 'cur': 'MXN', 'vat': 0.16, 'vat_name': 'IVA', 'de_minimis': 50, 'note': 'IVA 16%，de minimis USD50'},
 'AE': {'name': 'UAE', 'cn': '阿联酋', 'cur': 'AED', 'vat': 0.05, 'vat_name': 'VAT', 'de_minimis': 0, 'note': 'VAT 5%，进口无 de minimis'},
 'SA': {'name': 'Saudi Arabia', 'cn': '沙特', 'cur': 'SAR', 'vat': 0.15, 'vat_name': 'VAT', 'de_minimis': 1000, 'note': 'VAT 15%，de minimis SAR1000'},
 'TR': {'name': 'Turkey', 'cn': '土耳其', 'cur': 'TRY', 'vat': 0.20, 'vat_name': 'KDV', 'de_minimis': 30, 'note': 'KDV 20%，de minimis €30'},
 'CH': {'name': 'Switzerland', 'cn': '瑞士', 'cur': 'CHF', 'vat': 0.081, 'vat_name': 'VAT', 'de_minimis': 5, 'note': 'VAT 8.1%，de minimis CHF5'},
 'NO': {'name': 'Norway', 'cn': '挪威', 'cur': 'NOK', 'vat': 0.25, 'vat_name': 'VAT', 'de_minimis': 0, 'note': 'VAT 25%，无 de minimis（低值商品 VOEC 例外）'},
 'ZA': {'name': 'South Africa', 'cn': '南非', 'cur': 'ZAR', 'vat': 0.15, 'vat_name': 'VAT', 'de_minimis': 500, 'note': 'VAT 15%，de minimis ZAR500'},
 'RU': {'name': 'Russia', 'cn': '俄罗斯', 'cur': 'RUB', 'vat': 0.20, 'vat_name': 'VAT', 'de_minimis': 200, 'note': 'VAT 20%，de minimis €200（政策有变）'},
 'IL': {'name': 'Israel', 'cn': '以色列', 'cur': 'ILS', 'vat': 0.17, 'vat_name': 'VAT', 'de_minimis': 75, 'note': 'VAT 17%，de minimis USD75'},
 'EG': {'name': 'Egypt', 'cn': '埃及', 'cur': 'EGP', 'vat': 0.14, 'vat_name': 'VAT', 'de_minimis': 0, 'note': 'VAT 14%，无 de minimis'},
 'NG': {'name': 'Nigeria', 'cn': '尼日利亚', 'cur': 'NGN', 'vat': 0.075, 'vat_name': 'VAT', 'de_minimis': 0, 'note': 'VAT 7.5%，无 de minimis'},
 'KE': {'name': 'Kenya', 'cn': '肯尼亚', 'cur': 'KES', 'vat': 0.16, 'vat_name': 'VAT', 'de_minimis': 0, 'note': 'VAT 16%，无 de minimis'},
}

# 币种符号（仅用于展示）
CUR_SYM = {'USD': '$', 'EUR': '€', 'GBP': '£', 'CNY': '¥', 'HKD': 'HK$', 'JPY': '¥',
           'KRW': '₩', 'SGD': 'S$', 'AUD': 'A$', 'CAD': 'C$', 'NZD': 'NZ$', 'INR': '₹',
           'THB': '฿', 'MYR': 'RM', 'PHP': '₱', 'IDR': 'Rp', 'VND': '₫', 'TWD': 'NT$',
           'CHF': 'Fr', 'SEK': 'kr', 'NOK': 'kr', 'DKK': 'kr', 'PLN': 'zł', 'CZK': 'Kč',
           'TRY': '₺', 'AED': 'د.إ', 'SAR': '﷼', 'BRL': 'R$', 'MXN': 'Mex$', 'RUB': '₽',
           'ZAR': 'R', 'ILS': '₪', 'EGP': 'E£', 'NGN': '₦', 'KES': 'KSh'}

# 关税参考区间（按品类，US/EU/默认三档，均为「参考值」）
CATEGORY_DUTY = {
 'electronics': {'cn': '消费电子（手机/电脑/配件）', 'us': 0.0, 'eu': 0.03, 'default': 0.03},
 'apparel':     {'cn': '服装/纺织',               'us': 0.12, 'eu': 0.12, 'default': 0.12},
 'footwear':    {'cn': '鞋靴',                   'us': 0.12, 'eu': 0.12, 'default': 0.15},
 'toys':        {'cn': '玩具',                   'us': 0.0,  'eu': 0.047, 'default': 0.05},
 'furniture':   {'cn': '家具',                   'us': 0.02, 'eu': 0.02, 'default': 0.05},
 'machinery':   {'cn': '机械/工业品',             'us': 0.02, 'eu': 0.02, 'default': 0.03},
 'auto_parts':  {'cn': '汽配',                   'us': 0.025, 'eu': 0.045, 'default': 0.05},
 'beauty':      {'cn': '美妆/个护',               'us': 0.0,  'eu': 0.0,  'default': 0.05},
 'food':        {'cn': '食品',                   'us': 0.05, 'eu': 0.12, 'default': 0.10},
 'general':     {'cn': '一般商品（默认）',         'us': 0.03, 'eu': 0.05, 'default': 0.05},
}

EU_SET = {'DE','FR','NL','IT','ES','PL','SE','IE','AT','BE','PT','DK','GB','CZ','GR'}

# 汇率回退表（离线/上游失败时兜底，约值）
FALLBACK_USD = {'CNY': 7.2, 'HKD': 7.8, 'TWD': 31.0, 'JPY': 150.0, 'KRW': 1380.0, 'SGD': 1.34,
                'EUR': 0.92, 'GBP': 0.78, 'CHF': 0.88, 'SEK': 10.4, 'NOK': 10.6, 'DKK': 6.9,
                'PLN': 4.0, 'AUD': 1.52, 'NZD': 1.65, 'CAD': 1.36, 'INR': 83.0, 'THB': 36.0,
                'MYR': 4.7, 'PHP': 57.0, 'IDR': 16000.0, 'VND': 25000.0, 'AED': 3.67, 'SAR': 3.75,
                'TRY': 34.0, 'BRL': 5.4, 'MXN': 18.0, 'RUB': 92.0, 'ZAR': 18.5, 'ILS': 3.7,
                'EGP': 48.0, 'NGN': 1550.0, 'KES': 129.0, 'USD': 1.0}

# =====================================================================
# 二、实时汇率（open.er-api.com 免费无 key → frankfurter 兜底 → 内置表兜底）
# =====================================================================
def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', 'ignore')

def get_fx_rates():
    """返回 {币种: 每美元本币} 汇率表，带 source 标记。"""
    now = time.time()
    if 'fx' in CACHE and now - CACHE['fx'][0] < CACHE_TTL:
        return CACHE['fx'][1]
    rates, source = None, ''
    # 源 1：open.er-api.com（免费无 key，覆盖 ~160 币种）
    try:
        d = json.loads(fetch('https://open.er-api.com/v6/latest/USD'))
        if d.get('result') == 'success' and d.get('rates'):
            rates = d['rates']; source = 'open.er-api.com'
    except Exception:
        pass
    # 源 2：frankfurter（ECB，覆盖 ~30 币种）
    if rates is None:
        try:
            d = json.loads(fetch('https://api.frankfurter.app/latest?from=USD'))
            if d.get('rates'):
                rates = dict(d['rates']); rates['USD'] = 1.0; source = 'frankfurter(ECB)'
        except Exception:
            pass
    # 源 3：内置回退表
    if rates is None:
        rates = dict(FALLBACK_USD); source = 'fallback(static)'
    out = {'rates': rates, 'source': source, 'ts': now}
    CACHE['fx'] = (now, out)
    return out

def fx_convert(amount, from_cur, to_cur):
    """把 amount 从 from_cur 换算为 to_cur。返回 (数值, rate, source)。"""
    fx = get_fx_rates()
    rates = fx['rates']
    from_cur, to_cur = from_cur.upper(), to_cur.upper()
    if from_cur not in rates or to_cur not in rates:
        raise ValueError('不支持的币种: %s→%s（支持 %d 种）' % (from_cur, to_cur, len(rates)))
    # rates[x] = x 本币 / 1 美元
    usd = amount / rates[from_cur]
    out = usd * rates[to_cur]
    rate = rates[to_cur] / rates[from_cur]  # 1 from_cur = rate to_cur
    return out, rate, fx['source']

# =====================================================================
# 三、核心工具函数
# =====================================================================
def _region(dest_iso):
    if dest_iso == 'US':
        return 'us'
    if dest_iso in EU_SET:
        return 'eu'
    return 'default'

def tool_fx(args):
    """实时汇率换算。"""
    amount = float(args.get('amount', 1))
    frm = (args.get('from') or 'USD').upper()
    to = (args.get('to') or 'CNY').upper()
    if ',' in to:
        tos = [x.strip().upper() for x in to.split(',') if x.strip()]
    else:
        tos = [to]
    fx = get_fx_rates()
    rates = fx['rates']
    result = []
    for t in tos:
        val, rate, _ = fx_convert(amount, frm, t)
        result.append({'from': frm, 'to': t, 'amount': amount, 'converted': round(val, 4),
                       'rate': round(rate, 6), 'symbol': CUR_SYM.get(t, '')})
    return {'source': fx['source'], 'base': 'USD', 'ts': datetime.datetime.now().isoformat(),
            'results': result}

def tool_rules(args):
    """查询某国进口规则。"""
    iso = (args.get('country') or '').upper().strip()
    if not iso and args.get('name'):
        for k, v in COUNTRIES.items():
            if args['name'].lower() in v['name'].lower() or args['name'] in v['cn']:
                iso = k; break
    if iso not in COUNTRIES:
        return {'ok': False, 'error': '未知国家代码 %r（支持 %d 国，用 ISO 两位代码如 US/DE/CN/SG）' % (iso, len(COUNTRIES))}
    c = COUNTRIES[iso]
    return {'ok': True, 'country': iso, 'name': c['name'], 'cn': c['cn'], 'currency': c['cur'],
            'currency_symbol': CUR_SYM.get(c['cur'], ''), 'vat_name': c['vat_name'],
            'vat_rate': c['vat'], 'de_minimis': c['de_minimis'], 'note': c['note'],
            'disclaimer': '参考值，实际税率/免税额度以目的国海关及最新政策为准'}

def tool_landed(args):
    """落地成本计算器（核心）。"""
    exw = float(args.get('exw_price'))  # 出厂价
    cur = (args.get('currency') or 'USD').upper()   # 出厂价币种
    origin = (args.get('origin') or '').upper().strip()
    dest = (args.get('dest') or '').upper().strip()
    if dest not in COUNTRIES:
        return {'ok': False, 'error': '未知目的国 %r（ISO 两位代码，如 US/DE/SG/CN）' % dest}
    c = COUNTRIES[dest]
    dest_cur = c['cur']
    category = (args.get('category') or 'general').lower().strip()
    if category not in CATEGORY_DUTY:
        category = 'general'
    # 关税税率：优先用户指定，其次品类参考表
    if args.get('duty_rate') is not None:
        duty_rate = float(args['duty_rate'])
        duty_source = 'user_override'
    else:
        duty_rate = CATEGORY_DUTY[category][_region(dest)]
        duty_source = 'reference(%s)' % category
    qty = int(args.get('quantity') or 1)
    exw_total = exw * qty

    fx = get_fx_rates()
    # 出厂价换算到目的国货币
    exw_dest, rate_dest, _ = fx_convert(exw_total, cur, dest_cur)
    # 运费（目的国货币）
    freight_mode = args.get('freight_mode') or 'none'
    if args.get('freight') is not None:
        freight_dest = float(args['freight']) * qty
        freight_note = '用户指定运费'
    elif args.get('weight_kg') is not None:
        w = float(args['weight_kg']) * qty
        if freight_mode == 'air':
            usd_per_kg = 6.0
        elif freight_mode == 'express':
            usd_per_kg = 12.0
        else:  # sea/默认海运
            usd_per_kg = 2.0
        freight_usd = max(w * usd_per_kg, 5.0)
        freight_dest, _, _ = fx_convert(freight_usd, 'USD', dest_cur)
        freight_note = '按 %s 估算(%.2fkg×$%.1f/kg)' % (freight_mode, w, usd_per_kg)
    else:
        freight_dest = 0.0
        freight_note = '未提供运费/重量，按 FOB 计（不含运费）'

    insurance_dest = (exw_dest + freight_dest) * 0.005  # 保费 0.5%（国际惯例）
    cif_dest = exw_dest + freight_dest + insurance_dest
    duty_dest = cif_dest * duty_rate
    vat_base_dest = cif_dest + duty_dest
    vat_dest = vat_base_dest * c['vat']
    landed_dest = cif_dest + duty_dest + vat_dest

    _, rate_dest_usd, _ = fx_convert(1.0, dest_cur, 'USD')  # 1 本币 = X 美元
    landed_usd = landed_dest * rate_dest_usd

    s = CUR_SYM.get(dest_cur, dest_cur + ' ')
    return {'ok': True, 'origin': origin or '(未指定)', 'dest': dest, 'dest_country': c['cn'],
            'currency': dest_cur, 'symbol': s, 'quantity': qty,
            'exw_price': exw_total, 'exw_currency': cur,
            'fx_rate': round(rate_dest, 6), 'fx_source': fx['source'],
            'breakdown': {
                'exw_dest': round(exw_dest, 2),
                'freight': round(freight_dest, 2), 'freight_note': freight_note,
                'insurance': round(insurance_dest, 2),
                'cif': round(cif_dest, 2),
                'duty_rate': duty_rate, 'duty_source': duty_source,
                'duty': round(duty_dest, 2),
                'vat_rate': c['vat'], 'vat_name': c['vat_name'],
                'vat': round(vat_dest, 2),
                'landed': round(landed_dest, 2),
            },
            'landed_cost': round(landed_dest, 2), 'landed_cost_usd': round(landed_usd, 2),
            'de_minimis': c['de_minimis'], 'de_minimis_currency': dest_cur,
            'over_de_minimis': landed_dest > c['de_minimis'] if c['de_minimis'] > 0 else None,
            'disclaimer': '估算值（含参考关税/增值税），实际以海关及货代核算为准'}

# =====================================================================
# 四、MCP 协议定义
# =====================================================================
TOOLS = [
 {'name': 'landed_cost',
  'description': '计算商品跨境到岸总成本（落地成本）：出厂价(EXW) → 汇率换算 → 运费(可指定或按重量估算) → 保险费 → CIF → 关税(可指定或按品类参考) → 增值税/GST → 落地总成本。返回分项明细 + 美元/目的国货币双币种 + 是否超免税额度。给选品/报价/外贸 Agent 做成本测算。',
  'inputSchema': {'type': 'object', 'properties': {
      'exw_price': {'type': 'number', 'description': '出厂价/采购价（单件，不含运费）'},
      'currency': {'type': 'string', 'description': '出厂价币种（ISO 代码，默认 USD）'},
      'origin': {'type': 'string', 'description': '启运国 ISO 两位代码（如 CN，可选）'},
      'dest': {'type': 'string', 'description': '目的国 ISO 两位代码，如 US/DE/SG/CN（必填）'},
      'category': {'type': 'string', 'description': '商品品类：electronics/apparel/footwear/toys/furniture/machinery/auto_parts/beauty/food/general（默认 general）'},
      'quantity': {'type': 'integer', 'description': '数量（默认 1）'},
      'weight_kg': {'type': 'number', 'description': '单件重量kg（提供则按重量估算运费）'},
      'freight_mode': {'type': 'string', 'description': '运费方式：sea(海运)/air(空运)/express(快递)，配合 weight_kg 使用'},
      'freight': {'type': 'number', 'description': '单件运费（目的国货币，直接指定则优先于此）'},
      'duty_rate': {'type': 'number', 'description': '关税税率（小数，如 0.1=10%，指定则覆盖品类参考值）'}},
      'required': ['exw_price', 'dest']}},
 {'name': 'fx_convert',
  'description': '实时汇率换算（多币种，可逗号分隔多个目标币种）。返回换算结果 + 汇率 + 数据源。给需要多币种报价/比价的 Agent 用。',
  'inputSchema': {'type': 'object', 'properties': {
      'amount': {'type': 'number', 'description': '金额（默认 1）'},
      'from': {'type': 'string', 'description': '源币种 ISO 代码（默认 USD）'},
      'to': {'type': 'string', 'description': '目标币种 ISO 代码，多个用逗号分隔（如 CNY,EUR,GBP，默认 CNY）'}},
      'required': []}},
 {'name': 'import_rules',
  'description': '查询目的国进口规则：增值税率/GST、税种名、免税额度(de minimis)、币种与符号、政策备注。给选品/合规 Agent 判断某国税费与是否超免税额度。',
  'inputSchema': {'type': 'object', 'properties': {
      'country': {'type': 'string', 'description': 'ISO 两位国家代码，如 US/DE/SG/CN'},
      'name': {'type': 'string', 'description': '国家名（英文或中文，如 Germany/德国），与 country 二选一'}},
      'required': []}},
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
                   'serverInfo': {'name': 'tradeland-mcp', 'version': '1.0.0'}})
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
            if name == 'landed_cost':
                data = tool_landed(args)
            elif name == 'fx_convert':
                data = tool_fx(args)
            elif name == 'import_rules':
                data = tool_rules(args)
            else:
                return err(-32601, 'unknown tool: ' + name)
            return ok({'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=False, indent=1)}], 'isError': False})
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
        self.wfile.write(json.dumps({'service': 'tradeland-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

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
    print('tradeland-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8976
        main_http(port)
    else:
        main_stdio()
