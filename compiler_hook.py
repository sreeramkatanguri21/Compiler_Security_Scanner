import ast
import builtins
import os
import re
import sys
import traceback

# ==================== OPTIONAL WEEK 6 IMPORTS ====================
try:
    from scanner.ir_analyzer import IRAnalyzer
    HAS_IR_ANALYSIS = True
except Exception as e:
    HAS_IR_ANALYSIS = False
    print(f"⚠️  IR analyzer not available: {e}")
    print("⚠️  Using regex-only mode")


# ==================== GLOBALS / ORIGINALS ====================
_ORIGINAL_COMPILE = builtins.compile
_ORIGINAL_EXEC = builtins.exec
_ORIGINAL_EVAL = builtins.eval
_ORIGINAL_IMPORT = builtins.__import__

# Re-entrancy guard (prevents double scanning when exec triggers compile internally)
_IN_SCAN = False


# ==================== EXCEPTION ====================
class SecurityViolation(Exception):
    """Raised when CRITICAL security violations are detected."""
    pass


# ==================== SCANNING CORE ====================
def scan_for_secrets(source, filename="<string>"):
    """
    Main scanner: runs regex scanning always, and IR analysis if available.
    Returns list[dict] with keys: line, rule, severity, message, code
    """
    # Skip compiled code objects
    if hasattr(source, "co_code"):
        return []
    if not isinstance(source, str):
        return []

    issues = []
    issues.extend(_regex_scan(source))

    if HAS_IR_ANALYSIS:
        try:
            issues.extend(_ir_analysis_scan(source, filename))
        except Exception as e:
            print(f"⚠️  IR analysis warning: {e}")

    # Deduplicate findings (same line + rule + code)
    deduped = []
    seen = set()
    for it in issues:
        key = (it.get("line"), it.get("rule"), it.get("code"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)

    return deduped


def _regex_scan(source: str):
    """
    Week 5 regex-based checks. Fast and line-based.
    """
    issues = []
    lines = source.split("\n")

    for i, line in enumerate(lines, 1):
        line_lower = line.lower().strip()

        if not line_lower or line_lower.startswith("#"):
            continue

        # HS001: hardcoded password
        if any(k in line_lower for k in ("password", "passwd", "pwd")):
            if "=" in line and ("'" in line or '"' in line):
                m = re.search(r'["\']([^"\']+)["\']', line)
                if m and len(m.group(1)) > 5:
                    issues.append({
                        "line": i,
                        "rule": "HS001",
                        "severity": "HIGH",
                        "message": "Hardcoded password",
                        "code": line.strip()[:120],
                    })

        # HS002: API/secret key
        if any(k in line_lower for k in ("api_key", "api-key", "secret_key", "access_key")):
            if "=" in line and ("'" in line or '"' in line):
                m = re.search(r'["\']([^"\']+)["\']', line)
                if m and len(m.group(1)) > 8:
                    issues.append({
                        "line": i,
                        "rule": "HS002",
                        "severity": "CRITICAL",
                        "message": "API/Secret key in code",
                        "code": line.strip()[:120],
                    })

        # HS003: AWS credential (broad heuristic)
        if "aws_" in line_lower or "akia" in line_lower:
            if "=" in line:
                issues.append({
                    "line": i,
                    "rule": "HS003",
                    "severity": "CRITICAL",
                    "message": "Possible AWS credential",
                    "code": line.strip()[:120],
                })

        # WC001: weak crypto
        if "md5(" in line_lower or "sha1(" in line_lower:
            issues.append({
                "line": i,
                "rule": "WC001",
                "severity": "HIGH",
                "message": "Weak cryptographic algorithm",
                "code": line.strip()[:120],
            })

        # IR001: insecure random
        if ("random.random()" in line or "math.random()" in line or "random.randint(" in line):
            # minimal check: if the whole source doesn't import secrets, warn
            if "import secrets" not in source.lower():
                issues.append({
                    "line": i,
                    "rule": "IR001",
                    "severity": "MEDIUM",
                    "message": "Insecure random number generator",
                    "code": line.strip()[:120],
                })

    return issues


def _ir_analysis_scan(source: str, filename: str):
    """
    Week 6 IR-based analysis: builds IR, runs analysis passes,
    and extracts symbol-table-based suspicious identifiers.
    """
    if not HAS_IR_ANALYSIS:
        return []

    issues = []
    analyzer = IRAnalyzer()
    tree = ast.parse(source, filename=filename)

    analyzer.build_ir_from_ast(tree)

    # If these methods exist in your IRAnalyzer, call them safely
    for meth in ("perform_constant_propagation", "analyze_crypto_patterns", "analyze_random_generation"):
        fn = getattr(analyzer, meth, None)
        if callable(fn):
            fn()

    # Symbol-table checks (safe against None)
    symtab = getattr(analyzer, "symbol_table", None)
    if symtab and hasattr(symtab, "get_all_symbols"):
        issues.extend(_check_symbol_table(symtab))

    return issues


def _check_symbol_table(symbol_table):
    """
    Safe symbol checks. Fixes: NoneType has no attribute 'lower'
    """
    issues = []
    try:
        symbols = symbol_table.get_all_symbols()
    except Exception:
        return issues

    for sym in symbols:
        name = getattr(sym, "name", "") or ""
        name_l = str(name).lower()

        if any(k in name_l for k in ("password", "secret", "key", "token", "credential", "aws", "api")):
            issues.append({
                "line": getattr(sym, "line_no", 0) or 0,
                "rule": "ST001",
                "severity": "MEDIUM",
                "message": f"Suspicious identifier: {name}",
                "code": "",
            })

    return issues


# ==================== REPORTING ====================
def _print_report(issues, label):
    print("\n" + "=" * 70)
    print(f"🔎 SECURITY SCAN: {label}")
    print("=" * 70)

    if not issues:
        print("✅ No issues detected")
        return

    critical = [x for x in issues if x.get("severity") == "CRITICAL"]
    high = [x for x in issues if x.get("severity") == "HIGH"]
    medium = [x for x in issues if x.get("severity") == "MEDIUM"]

    if critical:
        print("\n🔴 CRITICAL ISSUES (Blocking compilation):")
        for it in critical:
            print(f"  Line {it['line']}: [{it['rule']}] {it['message']}")
            if it.get("code"):
                print(f"       Code: {it['code']}")

    if high:
        print("\n🟠 HIGH SEVERITY ISSUES:")
        for it in high:
            print(f"  Line {it['line']}: [{it['rule']}] {it['message']}")
            if it.get("code"):
                print(f"       Code: {it['code']}")

    if medium:
        print("\n🟡 MEDIUM SEVERITY ISSUES (Warnings):")
        for it in medium:
            print(f"  Line {it['line']}: [{it['rule']}] {it['message']}")
            if it.get("code"):
                print(f"       Code: {it['code']}")


def _should_block(issues):
    return any(x.get("severity") == "CRITICAL" for x in issues)


# ==================== HOOKED FUNCTIONS ====================
def secure_compile(source, filename, mode, flags=0, dont_inherit=False, optimize=-1, **kwargs):
    global _IN_SCAN
    if _IN_SCAN:
        return _ORIGINAL_COMPILE(source, filename, mode, flags, dont_inherit, optimize, **kwargs)

    try:
        _IN_SCAN = True
        issues = scan_for_secrets(source, filename)
        _print_report(issues, filename)

        if _should_block(issues):
            raise SecurityViolation("Critical security violations detected")

        return _ORIGINAL_COMPILE(source, filename, mode, flags, dont_inherit, optimize, **kwargs)
    finally:
        _IN_SCAN = False


def secure_exec(source, globals=None, locals=None):
    global _IN_SCAN
    if _IN_SCAN:
        return _ORIGINAL_EXEC(source, globals, locals)

    try:
        _IN_SCAN = True
        issues = scan_for_secrets(source, "<exec>")
        _print_report(issues, "<exec>")

        if _should_block(issues):
            raise SecurityViolation("Critical security violations detected")

        return _ORIGINAL_EXEC(source, globals, locals)
    finally:
        _IN_SCAN = False


def secure_eval(source, globals=None, locals=None):
    global _IN_SCAN
    if _IN_SCAN:
        return _ORIGINAL_EVAL(source, globals, locals)

    try:
        _IN_SCAN = True
        issues = scan_for_secrets(source, "<eval>")
        _print_report(issues, "<eval>")

        if _should_block(issues):
            raise SecurityViolation("Critical security violations detected")

        return _ORIGINAL_EVAL(source, globals, locals)
    finally:
        _IN_SCAN = False


def secure_import(name, globals=None, locals=None, fromlist=(), level=0):
    # Imports can be noisy; we just perform normal import here.
    return _ORIGINAL_IMPORT(name, globals, locals, fromlist, level)


def install_hooks():
    builtins.compile = secure_compile
    builtins.exec = secure_exec
    builtins.eval = secure_eval
    builtins.__import__ = secure_import


# Install immediately on import (your existing behavior)
install_hooks()

if __name__ == "__main__":
    print("✅ COMPILE-TIME SECURITY SCANNER")
    print("Version: 1.0 | Mode: Active\n")
    print("Hooked functions:")
    print("  • compile()  - ALL code compilation")
    print("  • exec()     - Code execution")
    print("  • eval()     - Expression evaluation")
    print("  • import     - Module imports\n")
    print("Security checks:")
    print("  • Hardcoded secrets (passwords, API keys)")
    print("  • Weak cryptographic algorithms")
    print("  • Insecure random number generation")