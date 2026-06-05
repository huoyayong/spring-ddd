#!/usr/bin/env python3
"""
Java + AI 专属 pre-commit 门禁 (软硬分离增强版)
"""

import sys
import re
import yaml
import subprocess
from pathlib import Path

# 强制 stdout/stderr 使用 UTF-8，避免 Windows GBK 控制台无法输出 emoji
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ANSI 颜色定义
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'

MD_CONFIG_PATH = Path("openspec/validators/quality-gates.md")

def load_rules_from_md():
    """解析 Markdown 文件中的 YAML Frontmatter"""
    if not MD_CONFIG_PATH.exists():
        print(f"{YELLOW}⚠️ 警告: 找不到规约文件 {MD_CONFIG_PATH}{RESET}")
        return None

    content = MD_CONFIG_PATH.read_text(encoding='utf-8')
    match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    if match:
        try:
            return yaml.safe_load(match.group(1))
        except Exception as e:
            print(f"{RED}❌ Frontmatter 解析失败: {e}{RESET}")
    return None

def get_staged_files():
    """获取 git 暂存区的文件列表 (Added, Copied, Modified)"""
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
        capture_output=True, text=True
    )
    return [Path(f) for f in result.stdout.splitlines() if f.strip()]

def scan_java_code(staged_files, hard_gates, soft_gates):
    """扫描 Java 文件，分类收集硬门禁和软门禁命中项"""
    java_files = [f for f in staged_files if f.suffix == '.java']

    errors = []
    warnings = []

    for file_path in java_files:
        try:
            lines = file_path.read_text(encoding='utf-8').splitlines()
        except UnicodeDecodeError:
            continue # 跳过非 UTF-8 文本或二进制误判

        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            # 过滤掉注释行
            is_comment = line_stripped.startswith('//') or line_stripped.startswith('*')

            # 检查硬门禁 (Blockers)
            for rule in hard_gates:
                if is_comment and 'TODO' not in rule['pattern'] and 'FIXME' not in rule['pattern']:
                    continue
                if re.search(rule['pattern'], line):
                    errors.append(f"{file_path}:{line_num} \n    └─ {RED}{rule['msg']}{RESET} \n    └─ 代码: {line_stripped}")

            # 检查软门禁 (Warnings)
            for rule in soft_gates:
                if is_comment:
                    continue
                if re.search(rule['pattern'], line):
                    warnings.append(f"{file_path}:{line_num} \n    └─ {YELLOW}{rule['msg']}{RESET} \n    └─ 代码: {line_stripped}")

    return errors, warnings

def check_dependency_changes(staged_files, watch_files):
    """防 AI 幻觉依赖软警告"""
    for f in staged_files:
        if f.name in watch_files:
            print(f"{BLUE}💡 [依赖提醒] 你修改了依赖配置文件: {f.name}{RESET}")
            print(f"{BLUE}   注意: 若使用 AI 生成的依赖，请务必前往 Maven Central 核实版本号真实性！{RESET}\n")

def check_spec_linkage(staged_files):
    """检查是否修改了代码但没修改规约"""
    has_java_changes = any(f.suffix == '.java' and 'src/main' in str(f) for f in staged_files)
    has_spec_changes = any('openspec/' in str(f) for f in staged_files)

    if has_java_changes and not has_spec_changes:
        print(f"{BLUE}💡 [规范提醒] 本次提交包含业务代码变更，但未修改 openspec/ 相关规约。{RESET}")
        print(f"{BLUE}   (建议保持规约与代码同步演进){RESET}\n")

def main():
    print(f"{GREEN}🚀 开始 OpenSpec Pre-commit 检查...{RESET}")
    staged_files = get_staged_files()
    if not staged_files:
        return 0

    config = load_rules_from_md()
    if not config or 'config' not in config:
        print(f"{RED}❌ 无法加载门禁配置。{RESET}")
        return 1

    gate_config = config['config']
    hard_gates = gate_config.get('hard_gates', [])
    soft_gates = gate_config.get('soft_gates', [])
    watch_files = gate_config.get('watch_files', [])

    # 执行规则扫描
    errors, warnings = scan_java_code(staged_files, hard_gates, soft_gates)

    # 1. 打印结构级软提醒
    check_dependency_changes(staged_files, watch_files)
    check_spec_linkage(staged_files)

    # 2. 打印代码级软门禁 (仅警告)
    if warnings:
        print(f"{YELLOW}⚠️ 发现 {len(warnings)} 处代码规范问题 (Soft Warnings - 不阻断):{RESET}")
        for warn in warnings:
            print(f"  {warn}")
        print("") # 空行分隔

    # 3. 处理代码级硬门禁 (阻断)
    if errors:
        print(f"{RED}❌ 发现 {len(errors)} 处严重违规 (Hard Gates - 拒绝 Commit):{RESET}")
        for err in errors:
            print(f"  {err}")
        print(f"\n{RED}🚫 拦截成功。请修复上述红色的严重违规后重新提交！{RESET}")
        print(f"{YELLOW}(如遇紧急故障急需跳过，可临时使用 git commit --no-verify){RESET}")
        return 1

    print(f"{GREEN}✅ 门禁检查通过！{RESET}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
