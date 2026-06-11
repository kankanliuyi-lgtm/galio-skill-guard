# Skill Install Guard

安装 Agent Skill 之前，先扫描来源、指令、代码和权限风险。

> 先扫描，再安装。扫描未发现问题，不代表绝对安全。

## MVP 能力

- 扫描本地 Skill 文件夹、ZIP 和单个 `SKILL.md`。
- 全程静态只读，不执行被扫描代码。
- 检查 Prompt Injection、危险命令、凭据读取、数据外传、持久化和代码混淆。
- 检查 ZIP 路径穿越、符号链接和未知可执行文件。
- 标记未经证实的“官方/品牌授权”声明和可疑域名。
- 输出中文报告、文件路径、行号、证据及修复建议。

## 快速开始

```bash
python3 skill-install-guard/scripts/scan_skill.py \
  --input path/to/untrusted-skill \
  --output-dir outputs/security-review
```

扫描 ZIP 时不会解压到磁盘；扫描目录时不会跟随符号链接，也不会运行其中的任何脚本。

## 安装到 Agent

安装到 Codex：

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills/skill-install-guard"
cp -R skill-install-guard/. "${CODEX_HOME:-$HOME/.codex}/skills/skill-install-guard/"
```

安装到 Claude Code：

```bash
mkdir -p "$HOME/.claude/skills/skill-install-guard"
cp -R skill-install-guard/. "$HOME/.claude/skills/skill-install-guard/"
```

安装后可以直接说：

```text
先用 skill-install-guard 扫描这个 Skill，确认风险后我再决定是否安装。
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
- `findings.json`

## 当前边界

- 不证明 Skill 绝对安全。
- 不验证品牌法律归属。
- 不查询 DNS、WHOIS、npm、PyPI 或恶意域名数据库。
- 不分析原生二进制的真实行为。
- 不自动安装 Skill。

## 开发验证

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile skill-install-guard/scripts/scan_skill.py
```

## License

MIT
