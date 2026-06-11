#!/usr/bin/env python3
"""Statically scan an Agent Skill without executing its code."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".html",
    ".css", ".env", ".lock",
}
MAX_TEXT_BYTES = 2_000_000
MAX_DOWNLOAD_BYTES = 30_000_000
SEVERITY_SCORE = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}
SEVERITY_CN = {
    "info": "提示", "low": "低风险", "medium": "中风险",
    "high": "高风险", "critical": "严重风险",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    pattern: str
    message: str
    recommendation: str
    flags: int = re.I


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    path: str
    line: int
    evidence: str
    message: str
    recommendation: str


@dataclass
class Dependency:
    ecosystem: str
    name: str
    specification: str
    path: str
    pinned: bool


RULES = [
    Rule("CMD001", "代码执行", "critical", r"\bcurl\b[^\n|]{0,300}\|\s*(?:ba)?sh\b",
         "下载内容被直接交给 Shell 执行。", "下载后先校验哈希并人工审查，禁止管道直执行。"),
    Rule("CMD002", "代码执行", "critical", r"\bwget\b[^\n|]{0,300}\|\s*(?:ba)?sh\b",
         "下载内容被直接交给 Shell 执行。", "下载后先校验哈希并人工审查，禁止管道直执行。"),
    Rule("CMD003", "代码执行", "high", r"\b(?:eval|exec)\s*\(",
         "发现动态代码执行。", "移除动态执行，改用明确、可审计的调用。"),
    Rule("CMD004", "代码执行", "medium", r"subprocess\.(?:run|Popen|call)\s*\(",
         "脚本可以启动受控子进程。", "逐条审查固定命令、参数来源、超时和用户确认流程。"),
    Rule("CMD005", "代码执行", "high", r"(?:os\.system\s*\(|shell\s*=\s*True)",
         "发现通过 Shell 执行命令的高风险方式。", "移除 shell=True/os.system，改用参数数组和固定命令。"),
    Rule("DEL001", "破坏性操作", "critical", r"\brm\s+(?:-[^\n ]*r[^\n ]*f|-[^\n ]*f[^\n ]*r)\b",
         "发现递归强制删除命令。", "阻止安装，除非删除范围被严格限定且得到用户确认。"),
    Rule("DEL002", "破坏性操作", "critical", r"\b(?:diskutil\s+erase|mkfs(?:\.\w+)?|format\s+[a-z]:)",
         "发现磁盘格式化或擦除命令。", "阻止安装。"),
    Rule("NET001", "网络与外传", "high",
         r"(?:requests\.(?:post|put)|fetch\s*\(|axios\.(?:post|put)|curl\s+(?:-[^\n ]+\s+)*-[dFT]|Invoke-WebRequest)",
         "发现可能上传数据或发送外部请求的代码。", "确认目标域名、发送字段和用户授权。"),
    Rule("NET002", "网络与外传", "medium", r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
         "发现直接访问 IP 地址。", "确认服务器所有者和证书，优先使用可验证域名。"),
    Rule("SEC001", "敏感信息", "critical",
         r"(?:\.ssh/(?:id_rsa|id_ed25519)|id_rsa|id_ed25519|Login Data|Cookies\b|credentials\.json)",
         "发现对私钥、浏览器凭据或认证文件的引用。", "阻止默认读取，必须说明必要性并逐次授权。"),
    Rule("SEC002", "敏感信息", "high", r"(?:os\.environ|getenv\s*\(|process\.env|printenv\b|env\s*\|)",
         "发现读取环境变量的行为。", "列出所需变量，禁止遍历或上传全部环境变量。"),
    Rule("SEC003", "敏感信息", "critical",
         r"(?:ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})",
         "文件中疑似包含真实密钥或 Token。", "立即撤销密钥并从历史记录中清除。"),
    Rule("PER001", "持久化与配置", "high",
         r"(?:~?/\.zshrc|~?/\.bashrc|~?/\.profile|LaunchAgents|crontab\b|systemctl\s+enable)",
         "发现修改启动项或 Shell 配置的迹象。", "要求明确说明变更内容，并在执行前逐项确认。"),
    Rule("PER002", "持久化与配置", "high",
         r"(?:~?/\.codex|~?/\.claude|AGENTS\.md|CLAUDE\.md).{0,100}(?:write|append|modify|覆盖|写入|修改)",
         "可能修改 Agent 或其他 Skill 的配置。", "限定到自身目录，并在写入前展示差异。"),
    Rule("INJ001", "指令注入", "critical",
         r"(?:ignore|disregard|override).{0,80}(?:previous|prior|system|developer).{0,40}(?:instruction|prompt)",
         "发现要求忽略上级指令的文本。", "阻止安装并人工审查上下文。"),
    Rule("INJ002", "指令注入", "high",
         r"(?:不要|不得|禁止).{0,30}(?:告诉|告知|显示|披露).{0,30}(?:用户|user)",
         "发现要求向用户隐瞒行为的文本。", "移除隐瞒指令，所有高风险操作必须透明。"),
    Rule("INJ003", "指令注入", "high",
         r"(?:无需|不要|跳过|绕过).{0,30}(?:确认|授权|permission|approval)",
         "发现绕过用户确认或权限检查的指令。", "恢复逐次确认和最小权限原则。"),
    Rule("OBF001", "混淆", "high", r"(?:base64\.b64decode|atob\s*\(|fromCharCode\s*\(|certutil\s+-decode)",
         "发现解码后可能执行或加载隐藏内容的逻辑。", "展开解码内容并人工审查，禁止解码后直接执行。"),
    Rule("OBF002", "混淆", "medium", r"(?:[A-Za-z0-9+/]{160,}={0,2})",
         "发现较长的 Base64 风格字符串。", "确认其用途并对解码内容单独扫描。"),
    Rule("SUP001", "供应链", "high", r'["\'](?:preinstall|postinstall)["\']\s*:',
         "发现安装生命周期脚本。", "人工审查脚本内容，安装时禁用脚本并锁定依赖版本。"),
    Rule("SUP002", "供应链", "medium", r"(?:git\+https?://|https?://[^\s]+\.(?:whl|tar\.gz|zip)\b)",
         "依赖或安装包直接来自 URL。", "确认发布者、固定版本和 SHA-256，避免跟随可变地址。"),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_text(data: bytes) -> str | None:
    if len(data) > MAX_TEXT_BYTES or b"\x00" in data[:4096]:
        return None
    for encoding in ("utf-8", "utf-8-sig", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def is_text_candidate(name: str) -> bool:
    path = PurePosixPath(name)
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in {
        "SKILL.md", "Dockerfile", "Makefile", "requirements.txt", "package-lock.json",
    }


def structural(rule_id: str, category: str, severity: str, path: str,
               evidence: str, message: str, recommendation: str) -> Finding:
    return Finding(rule_id, category, severity, path, 1, evidence, message, recommendation)


def collect_directory(root: Path) -> tuple[list[tuple[str, bytes]], list[Finding]]:
    files = []
    findings = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in {".git", "__pycache__", "node_modules"}]
        current_path = Path(current)
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    findings.append(structural(
                        "FS001", "文件系统", "high", relative, os.readlink(path),
                        "Skill 包含符号链接，目标可能越过 Skill 目录。",
                        "移除符号链接，或确认解析后的目标仍位于 Skill 根目录。",
                    ))
                    continue
                data = path.read_bytes()
            except OSError as exc:
                findings.append(structural(
                    "FS002", "文件系统", "medium", relative, str(exc),
                    "扫描器无法读取文件。", "人工确认文件权限和内容。",
                ))
                continue
            if is_text_candidate(relative):
                files.append((relative, data))
            elif mode & stat.S_IXUSR:
                findings.append(structural(
                    "FS003", "文件系统", "medium", relative, "executable file",
                    "发现未纳入文本分析的可执行文件。", "确认二进制来源、签名和哈希。",
                ))
    return files, findings


def collect_zip(path: Path) -> tuple[list[tuple[str, bytes]], list[Finding]]:
    with zipfile.ZipFile(path) as archive:
        return collect_zip_archive(archive, strip_root=False)


def collect_zip_archive(
    archive: zipfile.ZipFile,
    prefix: str | None = None,
    strip_root: bool = True,
) -> tuple[list[tuple[str, bytes]], list[Finding]]:
    files = []
    findings = []
    for info in archive.infolist():
        name = info.filename
        normalized = PurePosixPath(name)
        if normalized.is_absolute() or ".." in normalized.parts:
            findings.append(structural(
                "ZIP001", "压缩包", "critical", name, name,
                "ZIP 包含路径穿越条目。", "阻止安装，不要解压该压缩包。",
            ))
            continue
        unix_mode = info.external_attr >> 16
        if stat.S_ISLNK(unix_mode):
            findings.append(structural(
                "ZIP002", "压缩包", "high", name, "symbolic link",
                "ZIP 包含符号链接。", "确认链接目标不会越过 Skill 根目录。",
            ))
            continue
        if info.is_dir():
            continue
        relative = strip_archive_root(name) if strip_root else name
        if prefix:
            normalized_prefix = prefix.strip("/") + "/"
            if not relative.startswith(normalized_prefix):
                continue
            relative = relative[len(normalized_prefix):]
        if not relative:
            continue
        if info.file_size > MAX_TEXT_BYTES:
            if unix_mode & stat.S_IXUSR:
                findings.append(structural(
                    "ZIP003", "压缩包", "medium", relative, f"{info.file_size} bytes",
                    "ZIP 包含较大的可执行或未知文件。", "核验来源、签名和哈希。",
                ))
            continue
        if is_text_candidate(relative):
            files.append((relative, archive.read(info)))
    return files, findings


def strip_archive_root(name: str) -> str:
    parts = PurePosixPath(name).parts
    return PurePosixPath(*parts[1:]).as_posix() if len(parts) > 1 else name


def parse_github_url(value: str) -> tuple[str, str, str | None, str | None]:
    parsed = urlparse(value)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        raise ValueError("Only github.com repository URLs are supported")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repository")
    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])
    ref = None
    subpath = None
    if len(parts) >= 4 and parts[2] in {"tree", "blob"}:
        ref = parts[3]
        subpath = "/".join(parts[4:]) or None
        if parts[2] == "blob" and subpath:
            subpath = str(PurePosixPath(subpath).parent)
    return owner, repo, ref, subpath


def http_get(url: str, accept_json: bool = False) -> bytes:
    headers = {"User-Agent": "skill-install-guard/0.2"}
    if accept_json:
        headers["Accept"] = "application/vnd.github+json"
    last_error = None
    for _ in range(2):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=30) as response:
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"Remote content exceeds {MAX_DOWNLOAD_BYTES} bytes")
                data = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(data) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"Remote content exceeds {MAX_DOWNLOAD_BYTES} bytes")
            return data
        except http.client.IncompleteRead as exc:
            last_error = exc
    try:
        result = subprocess.run(
            [
                "curl", "-L", "--fail", "--silent", "--show-error",
                "--retry", "2", "--max-filesize", str(MAX_DOWNLOAD_BYTES), url,
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise ValueError(f"Incomplete remote download after retry: {last_error}") from exc
    if len(result.stdout) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"Remote content exceeds {MAX_DOWNLOAD_BYTES} bytes")
    return result.stdout


def resolve_github_head(owner: str, repo: str) -> tuple[str, str]:
    url = f"https://github.com/{owner}/{repo}.git"
    result = subprocess.run(
        ["git", "ls-remote", "--symref", url, "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    branch = "HEAD"
    sha = ""
    for line in result.stdout.splitlines():
        if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD"):
            branch = line.split("refs/heads/", 1)[1].split("\t", 1)[0]
        elif line.endswith("\tHEAD"):
            sha = line.split("\t", 1)[0]
    if not sha:
        raise ValueError("Unable to resolve GitHub repository HEAD")
    return branch, sha


def collect_github(value: str) -> tuple[
    list[tuple[str, bytes]], list[Finding], str, dict[str, object]
]:
    owner, repo, ref, subpath = parse_github_url(value)
    api_url = f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}"
    api_status = "available"
    try:
        metadata = json.loads(http_get(api_url, accept_json=True).decode("utf-8"))
        resolved_ref = ref or metadata.get("default_branch") or "main"
        commit_url = (
            f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}/"
            f"commits/{quote(str(resolved_ref), safe='')}"
        )
        commit = json.loads(http_get(commit_url, accept_json=True).decode("utf-8"))
        sha = commit.get("sha")
    except (HTTPError, URLError, json.JSONDecodeError):
        metadata = {
            "html_url": f"https://github.com/{owner}/{repo}",
            "owner": {},
        }
        api_status = "unavailable; used git ls-remote fallback"
        if ref:
            result = subprocess.run(
                ["git", "ls-remote", f"https://github.com/{owner}/{repo}.git", ref],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            sha = result.stdout.split("\t", 1)[0].strip()
            resolved_ref = ref
            if not sha:
                raise ValueError(f"Unable to resolve GitHub ref: {ref}")
        else:
            resolved_ref, sha = resolve_github_head(owner, repo)
    archive_url = f"https://codeload.github.com/{quote(owner)}/{quote(repo)}/zip/{quote(str(sha), safe='')}"
    archive_data = http_get(archive_url)
    with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
        files, findings = collect_zip_archive(archive, subpath)
    source_metadata = {
        "provider": "github",
        "metadata_api": api_status,
        "repository": f"{owner}/{repo}",
        "html_url": metadata.get("html_url"),
        "owner_type": (metadata.get("owner") or {}).get("type"),
        "default_branch": metadata.get("default_branch"),
        "requested_ref": ref,
        "resolved_sha": sha,
        "subpath": subpath,
        "created_at": metadata.get("created_at"),
        "updated_at": metadata.get("updated_at"),
        "pushed_at": metadata.get("pushed_at"),
        "archived": metadata.get("archived"),
        "fork": metadata.get("fork"),
        "visibility": metadata.get("visibility"),
        "stars": metadata.get("stargazers_count"),
        "download_sha256": sha256(archive_data),
    }
    if metadata.get("archived"):
        findings.append(structural(
            "PROV004", "来源真实性", "medium", "(repository)", "archived repository",
            "GitHub 仓库已归档，后续安全修复可能不再维护。",
            "确认是否有活跃的上游仓库或维护者说明。",
        ))
    return files, findings, "github", source_metadata


def collect_input(value: str) -> tuple[
    list[tuple[str, bytes]], list[Finding], str, dict[str, object]
]:
    if value.startswith(("https://github.com/", "http://github.com/")):
        return collect_github(value)
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"Input not found: {path}")
    if path.is_dir():
        files, findings = collect_directory(path)
        return files, findings, "directory", {}
    if path.suffix.lower() == ".zip":
        files, findings = collect_zip(path)
        return files, findings, "zip", {}
    return [(path.name, path.read_bytes())], [], "file", {}


def compact_evidence(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())[:240]


def is_rule_catalog_line(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("Rule(")
        or stripped.startswith('r"(?:')
        or stripped.startswith("r'(?:")
    )


def scan_text(path: str, text: str) -> list[Finding]:
    findings = []
    in_rule_catalog = False
    for number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^\s*RULES\s*=\s*\[", line):
            in_rule_catalog = True
            continue
        if in_rule_catalog:
            if line.startswith("]"):
                in_rule_catalog = False
            continue
        # Security tools legitimately store dangerous strings as inert signatures.
        if is_rule_catalog_line(line):
            continue
        for rule in RULES:
            if re.search(rule.pattern, line, rule.flags):
                findings.append(Finding(
                    rule.rule_id, rule.category, rule.severity, path, number,
                    compact_evidence(line), rule.message, rule.recommendation,
                ))
    return findings


def extract_urls(text: str) -> list[str]:
    return sorted(set(re.findall(r"https?://[^\s)\]>'\"]+", text)))


def provenance_findings(texts: list[tuple[str, str]]) -> tuple[list[Finding], list[str]]:
    findings = []
    urls = []
    for path, text in texts:
        urls.extend(extract_urls(text))
        if PurePosixPath(path).name.lower() not in {"skill.md", "readme.md", "readme.txt"}:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(r"(?:not|do not|unverified|无法证明|未经|不要).{0,40}(?:官方|official)", line, re.I):
                continue
            claim = re.search(
                r"(?:官方.{0,20}(?:发布|出品|提供|认证|授权|Skill|插件|工具|服务|助手)|"
                r"official.{0,40}(?:skill|plugin|tool|service|helper|integration)|品牌授权)",
                line,
                re.I,
            )
            if claim:
                findings.append(Finding(
                    "PROV001", "来源真实性", "medium", path, number,
                    compact_evidence(line),
                    "Skill 声称与官方或品牌有关，但静态文件无法证明该关系。",
                    "从品牌官网或已验证组织账号反向确认发布者和仓库。",
                ))
    domains = sorted({urlparse(url).hostname or "" for url in urls if urlparse(url).hostname})
    for domain in domains:
        if domain in {"github.com", "api.github.com", "codeload.github.com"}:
            continue
        if re.search(r"(?:cdn|api|download|official|service)[-.]", domain, re.I) and domain.count(".") >= 2:
            findings.append(structural(
                "PROV002", "来源真实性", "medium", "(URLs)", domain,
                "域名具有“官方/CDN/API”外观，但需要独立核验所有权。",
                "检查 DNS、证书和品牌官网是否链接到该域名。",
            ))
    return findings, domains


def is_pinned(specification: str) -> bool:
    spec = specification.strip()
    if not spec or spec in {"*", "latest"}:
        return False
    if re.fullmatch(r"\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?", spec):
        return True
    if re.search(r"(?:^|[^<>!~])==\s*[A-Za-z0-9]", spec):
        return True
    if re.fullmatch(r"[A-Fa-f0-9]{40,64}", spec):
        return True
    return False


def dependency_findings(texts: list[tuple[str, str]]) -> tuple[list[Dependency], list[Finding]]:
    dependencies = []
    findings = []
    for path, text in texts:
        name = PurePosixPath(path).name.lower()
        if name == "package.json":
            try:
                package = json.loads(text)
            except json.JSONDecodeError:
                findings.append(structural(
                    "SUP003", "供应链", "medium", path, "invalid JSON",
                    "无法解析 package.json。", "修复清单格式并人工检查安装脚本。",
                ))
                continue
            scripts = package.get("scripts") or {}
            for script_name in ("preinstall", "install", "postinstall", "prepare"):
                if script_name in scripts:
                    findings.append(Finding(
                        "SUP001", "供应链", "high", path, 1,
                        f"{script_name}: {scripts[script_name]}",
                        "发现安装生命周期脚本。",
                        "人工审查脚本，首次安装时考虑使用 --ignore-scripts。",
                    ))
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for dep_name, spec in (package.get(section) or {}).items():
                    spec_text = str(spec)
                    pinned = is_pinned(spec_text)
                    dependencies.append(Dependency("npm", dep_name, spec_text, path, pinned))
                    if not pinned:
                        findings.append(Finding(
                            "DEP001", "供应链", "medium", path, 1,
                            f"{dep_name}: {spec_text}",
                            "npm 依赖未固定到精确版本或提交。",
                            "使用 lockfile，并核对解析后的完整版本与完整性哈希。",
                        ))
        elif name in {"requirements.txt", "requirements-dev.txt"}:
            for number, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line or line.startswith(("#", "-", "--")):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)\s*(.*)", line)
                if not match:
                    continue
                dep_name, spec = match.groups()
                pinned = bool(re.match(r"\s*==\s*[^*]+$", spec))
                dependencies.append(Dependency("pypi", dep_name, spec.strip() or "*", path, pinned))
                if not pinned:
                    findings.append(Finding(
                        "DEP002", "供应链", "medium", path, number, line,
                        "Python 依赖未固定到精确版本。",
                        "固定版本并使用带哈希的 requirements lock 文件。",
                    ))
        elif name == "pyproject.toml":
            for number, raw in enumerate(text.splitlines(), start=1):
                match = re.search(r'["\']([A-Za-z0-9_.-]+)([^"\']*)["\']', raw)
                if match and any(token in raw for token in ("dependencies", "requires", " = ")):
                    dep_name, spec = match.groups()
                    dependencies.append(
                        Dependency("pypi/pyproject", dep_name, spec.strip() or "*", path, is_pinned(spec))
                    )
    return dependencies, findings


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen = set()
    result = []
    for item in findings:
        key = (item.rule_id, item.path, item.line, item.evidence)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda item: (-SEVERITY_SCORE[item.severity], item.path, item.line))


def risk_result(findings: list[Finding]) -> tuple[str, str, int]:
    rule_scores: dict[str, int] = {}
    for item in findings:
        rule_scores[item.rule_id] = max(
            rule_scores.get(item.rule_id, 0),
            SEVERITY_SCORE[item.severity],
        )
    score = sum(rule_scores.values())
    if any(item.severity == "critical" for item in findings) or score >= 25:
        return "阻止安装", "发现严重风险或高风险组合，建议不要安装。", score
    if any(item.severity == "high" for item in findings) or score >= 12:
        return "高风险", "暂缓安装，必须逐项人工复核。", score
    if any(item.severity == "medium" for item in findings) or score >= 4:
        return "中风险", "存在需要解释的权限或行为，确认后再安装。", score
    return "低风险", "未发现明显高危行为，但不代表绝对安全。", score


def markdown_table(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["未发现该类风险。", ""]
    lines = [
        "| 等级 | 规则 | 文件:行号 | 证据 | 风险说明 |",
        "|---|---|---|---|---|",
    ]
    for item in findings:
        evidence = item.evidence.replace("|", "\\|").replace("`", "'")
        lines.append(
            f"| {SEVERITY_CN[item.severity]} | `{item.rule_id}` | "
            f"`{item.path}:{item.line}` | `{evidence}` | {item.message} |"
        )
    lines.append("")
    return lines


def finding_identity(item: Finding | dict[str, object]) -> str:
    if isinstance(item, Finding):
        return f"{item.rule_id}|{item.path}|{item.evidence}"
    return f"{item.get('rule_id')}|{item.get('path')}|{item.get('evidence')}"


def load_baseline(path: str | None) -> dict[str, object] | None:
    if not path:
        return None
    baseline_path = Path(path).expanduser()
    with baseline_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or "files" not in data or "findings" not in data:
        raise ValueError("Baseline must be a findings.json generated by this scanner")
    return data


def write_change_report(
    output: Path,
    baseline: dict[str, object] | None,
    file_hashes: dict[str, str],
    findings: list[Finding],
) -> dict[str, object]:
    if baseline is None:
        result = {"baseline_used": False}
        lines = [
            "# 版本变化报告", "",
            "本次没有提供基线报告。后续可使用：",
            "",
            "```bash",
            "--baseline path/to/previous/findings.json",
            "```",
            "",
        ]
    else:
        old_files = baseline.get("files") or {}
        old_findings = baseline.get("findings") or []
        if not isinstance(old_files, dict) or not isinstance(old_findings, list):
            raise ValueError("Invalid baseline structure")
        added = sorted(set(file_hashes) - set(old_files))
        removed = sorted(set(old_files) - set(file_hashes))
        changed = sorted(
            path for path in set(file_hashes) & set(old_files)
            if file_hashes[path] != old_files[path]
        )
        old_ids = {finding_identity(item) for item in old_findings if isinstance(item, dict)}
        new_ids = {finding_identity(item) for item in findings}
        introduced = [item for item in findings if finding_identity(item) not in old_ids]
        resolved = sorted(old_ids - new_ids)
        result = {
            "baseline_used": True,
            "added_files": added,
            "removed_files": removed,
            "changed_files": changed,
            "introduced_findings": [asdict(item) for item in introduced],
            "resolved_finding_ids": resolved,
        }
        lines = [
            "# 版本变化报告", "",
            f"- 新增文件：{len(added)}",
            f"- 删除文件：{len(removed)}",
            f"- 内容变化：{len(changed)}",
            f"- 新增风险：{len(introduced)}",
            f"- 已消失风险：{len(resolved)}",
            "",
            "## 新增或变化文件", "",
        ]
        lines += [f"- 新增：`{path}`" for path in added]
        lines += [f"- 变化：`{path}`" for path in changed]
        lines += [f"- 删除：`{path}`" for path in removed]
        if not added and not changed and not removed:
            lines.append("- 文件哈希没有变化。")
        lines += ["", "## 新增风险", ""]
        lines += markdown_table(introduced)
    (output / "change-report.md").write_text("\n".join(lines), encoding="utf-8")
    return result


def write_dependency_report(
    output: Path,
    dependencies: list[Dependency],
    findings: list[Finding],
) -> None:
    supply_findings = [item for item in findings if item.category == "供应链"]
    lines = [
        "# 依赖与供应链报告", "",
        f"- 识别依赖：{len(dependencies)}",
        f"- 未固定依赖：{sum(not item.pinned for item in dependencies)}",
        "", "## 依赖清单", "",
        "| 生态 | 名称 | 版本/来源 | 已固定 | 文件 |",
        "|---|---|---|---|---|",
    ]
    if dependencies:
        for item in dependencies:
            spec = item.specification.replace("|", "\\|")
            lines.append(
                f"| {item.ecosystem} | `{item.name}` | `{spec}` | "
                f"{'是' if item.pinned else '否'} | `{item.path}` |"
            )
    else:
        lines.append("| - | 未识别到依赖清单 | - | - | - |")
    lines += ["", "## 供应链风险", ""]
    lines += markdown_table(supply_findings)
    (output / "dependency-report.md").write_text("\n".join(lines), encoding="utf-8")


def write_reports(output: Path, source: str, source_type: str,
                  file_hashes: dict[str, str], findings: list[Finding],
                  domains: list[str], dependencies: list[Dependency],
                  source_metadata: dict[str, object],
                  baseline: dict[str, object] | None) -> None:
    output.mkdir(parents=True, exist_ok=True)
    level, recommendation, score = risk_result(findings)
    counts = {severity: 0 for severity in SEVERITY_SCORE}
    for item in findings:
        counts[item.severity] += 1

    summary = [
        "# Skill 安装前安全报告", "",
        f"- 扫描对象：`{source}`",
        f"- 输入类型：`{source_type}`",
        f"- 综合结论：**{level}**",
        f"- 建议：{recommendation}",
        f"- 风险分：{score}（仅用于本工具内部排序，不代表安全认证）",
        f"- 扫描文件数：{len(file_hashes)}",
        f"- 严重/高/中/低：{counts['critical']}/{counts['high']}/{counts['medium']}/{counts['low']}",
        "",
        "> 本工具只做静态检查，不执行被扫描代码。未发现问题不等于绝对安全。",
        "", "## 主要发现", "",
    ]
    summary += markdown_table(findings[:20])
    summary += [
        "## 安装决策", "",
        f"- 当前建议：**{recommendation}**",
        "- 安装前确认发布者身份、来源仓库、所需权限和所有外部域名。",
        "- 对任何高风险发现，必须阅读原文件上下文，不要只依赖关键词命中。",
        "",
    ]
    (output / "security-summary.md").write_text("\n".join(summary), encoding="utf-8")

    provenance = [item for item in findings if item.category == "来源真实性"]
    lines = ["# 来源真实性报告", "", "## 来源元数据", ""]
    if source_metadata:
        lines += [
            f"- {key}：`{value}`"
            for key, value in source_metadata.items()
            if value is not None
        ]
    else:
        lines.append("- 本地输入，没有远程仓库元数据。")
    lines += ["", "## 外部域名", ""]
    lines += [f"- `{domain}`" for domain in domains] or ["- 未发现外部域名。"]
    lines += ["", "## 来源风险", ""] + markdown_table(provenance)
    lines += [
        "## 人工核验建议", "",
        "- 从品牌官网反向寻找仓库，不要只相信 Skill 自己提供的链接。",
        "- 核对发布者组织、仓库历史、Release、签名和固定提交 SHA。",
        "- 名称、Logo、Star 数和“官方”字样都不能单独证明真实性。",
        "",
    ]
    (output / "provenance-report.md").write_text("\n".join(lines), encoding="utf-8")

    permission_categories = {"敏感信息", "网络与外传", "持久化与配置", "文件系统", "破坏性操作"}
    permission_findings = [item for item in findings if item.category in permission_categories]
    lines = ["# 权限与数据访问报告", "", "## 发现", ""]
    lines += markdown_table(permission_findings)
    lines += [
        "## 最小权限原则", "",
        "- 未经确认，不读取凭据、浏览器数据、聊天记录和用户主目录。",
        "- 未经确认，不写入 Agent 配置、Shell 配置、启动项或其他 Skill。",
        "- 未经确认，不向外部域名上传文件、环境变量或日志。",
        "",
    ]
    (output / "permission-report.md").write_text("\n".join(lines), encoding="utf-8")

    code_findings = [item for item in findings if item.category != "来源真实性"]
    lines = ["# 代码与指令风险报告", "", "## 发现", ""]
    lines += markdown_table(code_findings)
    lines += ["## 文件哈希", ""]
    lines += [f"- `{digest}`  `{path}`" for path, digest in sorted(file_hashes.items())]
    lines.append("")
    (output / "code-risk-report.md").write_text("\n".join(lines), encoding="utf-8")

    write_dependency_report(output, dependencies, findings)
    changes = write_change_report(output, baseline, file_hashes, findings)
    payload = {
        "source": str(source), "source_type": source_type,
        "risk_level": level, "recommendation": recommendation, "risk_score": score,
        "files": file_hashes, "domains": domains,
        "source_metadata": source_metadata,
        "dependencies": [asdict(item) for item in dependencies],
        "changes": changes,
        "findings": [asdict(item) for item in findings],
    }
    (output / "findings.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )


def run(args: argparse.Namespace) -> int:
    source = args.input
    output = Path(args.output_dir).expanduser()
    raw_files, structural_findings, source_type, source_metadata = collect_input(source)
    baseline = load_baseline(args.baseline)
    texts = []
    hashes = {}
    findings = list(structural_findings)
    for path, data in raw_files:
        hashes[path] = sha256(data)
        text = decode_text(data)
        if text is None:
            findings.append(structural(
                "FS004", "文件系统", "medium", path, f"{len(data)} bytes",
                "文件不是可识别文本或超过扫描大小限制。",
                "使用专门工具核验文件类型、签名和来源。",
            ))
            continue
        texts.append((path, text))
        findings.extend(scan_text(path, text))
    provenance, domains = provenance_findings(texts)
    dependencies, dependency_risks = dependency_findings(texts)
    findings = deduplicate(findings + provenance + dependency_risks)
    write_reports(
        output, source, source_type, hashes, findings, domains,
        dependencies, source_metadata, baseline,
    )
    level, recommendation, _ = risk_result(findings)
    print(f"{level}: {recommendation}")
    print(output)
    return 2 if level == "阻止安装" else 1 if level == "高风险" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", required=True,
        help="GitHub URL, Skill directory, ZIP, or individual file",
    )
    parser.add_argument("--output-dir", required=True, help="Directory for scan reports")
    parser.add_argument("--baseline", help="Previous findings.json for update comparison")
    return parser


if __name__ == "__main__":
    try:
        raise SystemExit(run(build_parser().parse_args()))
    except (
        OSError, ValueError, zipfile.BadZipFile, HTTPError, URLError,
        json.JSONDecodeError, subprocess.SubprocessError, http.client.HTTPException,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(3)
