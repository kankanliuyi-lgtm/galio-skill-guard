# 加里奥 Skill

安装 Agent Skill 之前，先扫描来源、指令、代码和权限风险。

> 先扫描，再安装。扫描未发现问题，不代表绝对安全。

![加里奥 Skill：安装 Agent Skill 前的安全扫描守卫](assets/galio-skill-guard-cover.png)

技术名称：`galio-skill-guard`

当前版本：`v0.2.0-alpha`

## v0.2 能力

- 直接扫描公开 GitHub 仓库 URL、本地 Skill 文件夹、ZIP 和单个 `SKILL.md`。
- GitHub 仓库固定到提交 SHA 后下载，避免扫描过程中版本漂移。
- 全程静态只读，不执行被扫描代码。
- 检查 Prompt Injection、危险命令、凭据读取、数据外传、持久化和代码混淆。
- 检查 ZIP 路径穿越、符号链接和未知可执行文件。
- 解析 npm、PyPI 依赖和安装生命周期脚本。
- 对比上一次扫描结果，识别新增文件、内容变化和新增风险。
- 标记未经证实的“官方/品牌授权”声明和可疑域名。
- 输出中文报告、文件路径、行号、证据及修复建议。

## 快速开始

```bash
python3 galio-skill-guard/scripts/scan_skill.py \
  --input https://github.com/owner/repository \
  --output-dir outputs/security-review
```

扫描 ZIP 时不会解压到磁盘；扫描目录时不会跟随符号链接，也不会运行其中的任何脚本。

扫描本地文件：

```bash
python3 galio-skill-guard/scripts/scan_skill.py \
  --input path/to/untrusted-skill.zip \
  --output-dir outputs/security-review
```

扫描新版本并和上次结果比较：

```bash
python3 galio-skill-guard/scripts/scan_skill.py \
  --input https://github.com/owner/repository \
  --baseline previous-review/findings.json \
  --output-dir outputs/new-review
```

## 安装到 Agent

安装到 Codex：

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills/galio-skill-guard"
cp -R galio-skill-guard/. "${CODEX_HOME:-$HOME/.codex}/skills/galio-skill-guard/"
```

安装到 Claude Code：

```bash
mkdir -p "$HOME/.claude/skills/galio-skill-guard"
cp -R galio-skill-guard/. "$HOME/.claude/skills/galio-skill-guard/"
```

安装后可以直接说：

```text
先用加里奥 Skill 扫描这个 Skill，确认风险后我再决定是否安装。
```

退出码：

- `0`：低风险或中风险
- `1`：高风险
- `2`：阻止安装
- `3`：扫描失败

## 输出

- `security-summary.md`
- `provenance-report.md`
- `permission-report.md`
- `code-risk-report.md`
- `dependency-report.md`
- `change-report.md`
- `findings.json`

脱敏报告示例：[examples/security-summary-example.md](examples/security-summary-example.md)

## 安全问题

发现扫描器漏洞或绕过方式时，请阅读 [SECURITY.md](SECURITY.md)。不要在公开 Issue 中粘贴真实 Token、私钥或用户文件。

## 当前边界

- 不证明 Skill 绝对安全。
- 不验证品牌法律归属。
- 不查询 DNS、WHOIS、npm/PyPI 包是否真实存在或恶意域名数据库。
- 不分析原生二进制的真实行为。
- GitHub API 限流时只能保留仓库、默认分支、提交 SHA 和下载哈希等基础证据。
- 不自动安装 Skill。

## 开发验证

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile galio-skill-guard/scripts/scan_skill.py
```

## License

MIT
