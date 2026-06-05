#!/usr/bin/env python3
"""
OpenSpec Commit-Stage 门禁
====================================
触发时机: git commit (pre-commit hook)
设计原则: 只跑秒级、零误报的轻量检查
====================================
检查项:
  [硬] 1. 密钥硬编码扫描
  [硬] 2. 调试残留 (debugger/console.log/System.out)
  [硬] 3. 大文件检查
  [硬] 4. 合并冲突标记残留
  [硬] 5. OpenSpec 规约校验
  [软] 6. TODO/FIXME 提示
"""

import re
import sys
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

# Windows 中文终端默认 GBK,无法编码 emoji / box-drawing;强制 UTF-8 输出
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


# ════════════════════════════════════════════════
# 颜色输出
# ════════════════════════════════════════════════
class Color:
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'


@dataclass
class CheckResult:
    check_id: str
    passed: bool
    message: str
    enforcement: str = "hard"          # hard | soft
    details: List[str] = field(default_factory=list)


class CommitGate:
    def __init__(self):
        self.results: List[CheckResult] = []
        # 只检查【本次暂存】的文件，而非全仓库（这是 commit 门禁的关键）
        self.staged_files = self._get_staged_files()

    # ════════════════════════════════════════════
    # 工具方法
    # ════════════════════════════════════════════
    def _run_cmd(self, cmd: List[str]) -> tuple[int, str]:
        """执行命令"""
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            return r.returncode, r.stdout + r.stderr
        except FileNotFoundError:
            return 127, f"命令不存在: {cmd[0]}"

    def _get_staged_files(self) -> List[Path]:
        """获取本次暂存（git add）的文件，只检查这些 ⭐"""
        code, out = self._run_cmd(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
        )
        if code != 0:
            return []
        files = []
        for line in out.splitlines():
            p = Path(line.strip())
            if p.is_file():
                files.append(p)
        return files

    def _get_staged_content(self, file: Path) -> str:
        """获取文件暂存区的内容（而非工作区，避免误判未 add 的修改）"""
        # Windows 下 str(Path) 是反斜杠,git index 只认正斜杠 → 必须 as_posix()
        code, out = self._run_cmd(["git", "show", f":{file.as_posix()}"])
        return out if code == 0 else ""

    def _is_text_file(self, file: Path) -> bool:
        """判断是否为文本文件（按扩展名）"""
        text_ext = {
            '.java', '.py', '.js', '.ts', '.go', '.rb', '.php',
            '.c', '.cpp', '.h', '.cs', '.kt', '.scala', '.rs',
            '.xml', '.yaml', '.yml', '.json', '.properties',
            '.sql', '.sh', '.md', '.txt', '.html', '.css',
        }
        return file.suffix.lower() in text_ext

    # ════════════════════════════════════════════
    # 门禁 1: 密钥硬编码扫描 (硬)
    # ════════════════════════════════════════════
    def check_secrets(self) -> CheckResult:
        patterns = {
            "密码": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']',
            "密钥": r'(?i)(secret|api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']',
            "Token": r'(?i)(token|access[_-]?token)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
            "私钥": r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            "AWS密钥": r'AKIA[0-9A-Z]{16}',
        }
        # 白名单：测试/示例文件中的占位符
        whitelist = re.compile(r'(?i)(example|test|placeholder|xxx|\*\*\*|your[_-])')

        details = []
        for file in self.staged_files:
            if not self._is_text_file(file):
                continue
            content = self._get_staged_content(file)
            for i, line in enumerate(content.splitlines(), 1):
                if whitelist.search(line):
                    continue
                for name, pat in patterns.items():
                    if re.search(pat, line):
                        details.append(f"{file}:{i} [{name}] {line.strip()[:80]}")

        return CheckResult(
            check_id="no-hardcoded-secret",
            passed=len(details) == 0,
            message="密钥硬编码扫描",
            enforcement="hard",
            details=details[:10],
        )

    # ════════════════════════════════════════════
    # 门禁 2: 调试残留 (硬)
    # ════════════════════════════════════════════
    def check_debug_residue(self) -> CheckResult:
        rules = {
            ".java": r'System\.out\.print|printStackTrace\(\)',
            ".py": r'\bpdb\.set_trace\(\)|\bbreakpoint\(\)',
            ".js": r'\bdebugger\b|console\.(log|debug)',
            ".ts": r'\bdebugger\b|console\.(log|debug)',
            ".go": r'fmt\.Println.*//\s*debug',
        }
        details = []
        for file in self.staged_files:
            pat = rules.get(file.suffix.lower())
            if not pat:
                continue
            content = self._get_staged_content(file)
            for i, line in enumerate(content.splitlines(), 1):
                # 忽略注释行
                stripped = line.strip()
                if stripped.startswith(("//", "#", "*")):
                    continue
                if re.search(pat, line):
                    details.append(f"{file}:{i} {stripped[:80]}")

        return CheckResult(
            check_id="no-debug-residue",
            passed=len(details) == 0,
            message="调试残留检查",
            enforcement="hard",
            details=details[:10],
        )

    # ════════════════════════════════════════════
    # 门禁 3: 大文件检查 (硬)
    # ════════════════════════════════════════════
    def check_large_files(self, max_kb: int = 1024) -> CheckResult:
        details = []
        for file in self.staged_files:
            try:
                size_kb = file.stat().st_size / 1024
                if size_kb > max_kb:
                    details.append(f"{file}: {size_kb:.0f} KB (上限 {max_kb} KB)")
            except OSError:
                pass

        return CheckResult(
            check_id="no-large-file",
            passed=len(details) == 0,
            message=f"大文件检查 (上限 {max_kb}KB)",
            enforcement="hard",
            details=details,
        )

    # ════════════════════════════════════════════
    # 门禁 4: 合并冲突标记残留 (硬)
    # ════════════════════════════════════════════
    def check_merge_conflict(self) -> CheckResult:
        markers = (r'^<{7}', r'^={7}$', r'^>{7}')
        details = []
        for file in self.staged_files:
            if not self._is_text_file(file):
                continue
            content = self._get_staged_content(file)
            for i, line in enumerate(content.splitlines(), 1):
                for m in markers:
                    if re.match(m, line):
                        details.append(f"{file}:{i} 残留冲突标记")
                        break

        return CheckResult(
            check_id="no-merge-conflict",
            passed=len(details) == 0,
            message="合并冲突标记检查",
            enforcement="hard",
            details=details[:10],
        )

    # ════════════════════════════════════════════
    # 门禁 5: OpenSpec 规约校验 (硬)
    # ════════════════════════════════════════════
    def check_openspec_validate(self) -> CheckResult:
        # 只在改动了 openspec/ 文件时才跑，省时间
        touched_spec = any(
            str(f).startswith("openspec/") for f in self.staged_files
        )
        if not touched_spec:
            return CheckResult(
                check_id="openspec-validate",
                passed=True,
                message="OpenSpec 校验 (未改动 openspec/，跳过)",
                enforcement="hard",
            )

        code, out = self._run_cmd(
            ["npx", "@fission-ai/openspec@latest", "validate", "--strict"]
        )
        return CheckResult(
            check_id="openspec-validate",
            passed=code == 0,
            message="OpenSpec 规约校验",
            enforcement="hard",
            details=[out.strip()[:500]] if code != 0 else [],
        )

    # ════════════════════════════════════════════
    # 门禁 6: TODO/FIXME 提示 (软)
    # ════════════════════════════════════════════
    def check_todo(self) -> CheckResult:
        details = []
        for file in self.staged_files:
            if not self._is_text_file(file):
                continue
            content = self._get_staged_content(file)
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(r'\b(TODO|FIXME|XXX)\b', line):
                    details.append(f"{file}:{i} {line.strip()[:80]}")

        return CheckResult(
            check_id="todo-check",
            passed=len(details) == 0,
            message=f"TODO/FIXME 提示 (发现 {len(details)} 处)",
            enforcement="soft",
            details=details[:5],
        )

    # ════════════════════════════════════════════
    # 主流程
    # ════════════════════════════════════════════
    def run(self) -> bool:
        print(f"{Color.BLUE}╔════════════════════════════════════════╗{Color.NC}")
        print(f"{Color.BLUE}║   OpenSpec Commit 门禁检查              ║{Color.NC}")
        print(f"{Color.BLUE}╚════════════════════════════════════════╝{Color.NC}")

        if not self.staged_files:
            print(f"{Color.YELLOW}⚠️  没有暂存的文件，跳过检查{Color.NC}")
            return True

        print(f"📋 本次提交检查 {len(self.staged_files)} 个文件\n")

        checks = [
            self.check_secrets,
            self.check_debug_residue,
            self.check_large_files,
            self.check_merge_conflict,
            self.check_openspec_validate,
            self.check_todo,
        ]

        for fn in checks:
            result = fn()
            self.results.append(result)
            self._print_result(result)

        return self._summarize()

    def _print_result(self, r: CheckResult):
        if r.passed:
            icon, color = "✅", Color.GREEN
        elif r.enforcement == "hard":
            icon, color = "❌", Color.RED
        else:
            icon, color = "⚠️ ", Color.YELLOW
        print(f"{color}{icon} [{r.enforcement.upper()}] {r.message}{Color.NC}")
        for d in r.details:
            print(f"   └─ {d}")

    def _summarize(self) -> bool:
        hard_failed = [r for r in self.results
                       if not r.passed and r.enforcement == "hard"]
        soft_failed = [r for r in self.results
                       if not r.passed and r.enforcement == "soft"]

        print("\n" + "═" * 44)
        if soft_failed:
            print(f"{Color.YELLOW}⚠️  软门禁警告: {len(soft_failed)} 条 (不阻断){Color.NC}")

        if hard_failed:
            print(f"{Color.RED}❌ 硬门禁失败: {len(hard_failed)} 条，提交被拒绝{Color.NC}")
            print(f"{Color.YELLOW}💡 修复后重新 git add & commit；"
                  f"如需紧急跳过: git commit --no-verify{Color.NC}")
            return False

        print(f"{Color.GREEN}✅ 所有硬门禁通过，允许提交{Color.NC}")
        return True


if __name__ == "__main__":
    gate = CommitGate()
    sys.exit(0 if gate.run() else 1)