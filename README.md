# xss-scanner

XSS 漏洞扫描 MCP Server，移植自 [XssFleet](https://github.com/jhli07/XssFleet) 的核心检测算法。

## 功能

- **反射型 XSS** — 注入 checker 探测反射点，XSStrike 风格上下文分析（html/attribute/script/comment），自动生成 payload
- **HTTP Header XSS** — Referer / User-Agent / X-Forwarded-For 等 Header 注入检测
- **Cookie 反射 XSS** — Cookie 值是否被反射到页面
- **DOM XSS 静态分析** — 检测 JS 中的 sink（innerHTML / eval / document.write）+ source（location.hash / location.search）
- **批量扫描** — 支持多 URL 并行扫描

## MCP 工具

| 工具 | 说明 |
|------|------|
| `xss_scan` | 全量扫描（反射 + Header + Cookie + 可选 DOM） |
| `xss_scan_reflected` | 反射型 XSS 扫描 |
| `xss_scan_headers` | HTTP Header XSS 扫描 |
| `xss_scan_dom` | DOM XSS 静态分析 |
| `xss_scan_batch` | 批量 URL 扫描 |

## 安装

```bash
pip install -r requirements.txt
```

## 作为 MCP Server 使用

在 Claude Code 的 `.claude.json` 中添加：

```json
{
  "mcpServers": {
    "xss-scanner": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\path\\to\\xss_mcp_server.py"]
    }
  }
}
```

重启 Claude Code 后即可使用 MCP 工具。

## 独立使用（不依赖 MCP）

```bash
# 基本扫描
python xss_scanner_standalone.py -u "http://target.com/search?q=test"

# 深度扫描（含 DOM XSS）
python xss_scanner_standalone.py -u "http://target.com/search?q=test" -d

# 只测 Header XSS
python xss_scanner_standalone.py -u "http://target.com" --header-scan

# 批量扫描
python xss_scanner_standalone.py -f urls.txt -w 5
```

## 作为 Burp Suite 扩展使用

将 `xss_scanner.py` 作为 Jython 扩展加载到 Burp Suite：

1. Burp Suite → Extensions → Add → Extension type: Python
2. 选择 `xss_scanner.py`
3. 自动集成到 Active Scan 和 Passive Scan

## 文件说明

| 文件 | 说明 |
|------|------|
| `xss_mcp_server.py` | MCP Server（FastMCP），提供 5 个 MCP 工具 |
| `xss_scanner_standalone.py` | 独立版扫描器，命令行直接运行 |
| `xss_scanner.py` | Burp Suite 扩展版（Jython） |

## 算法来源

核心检测算法移植自 [XssFleet](https://github.com/jhli07/XssFleet)：
- XSStrike 风格的 HTML 上下文解析器
- 基于上下文的 payload 自动生成（tag + event handler + filling + function 组合）
- 优先级排序的 payload 列表

## License

MIT
