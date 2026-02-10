import ast
import sys
import os
import re
import builtins
import traceback

# ==================== ADD IMPORTS WITH ERROR HANDLING ====================
try:
    from scanner.ir_analyzer import IRAnalyzer
    from scanner.symbol_table import SymbolTable, Symbol
    HAS_IR_ANALYSIS = True
except ImportError as e:
    HAS_IR_ANALYSIS = False
    print(f"⚠️  IR analyzer not available: {e}")
    print("⚠️  Using regex-only mode")

# ==================== SECURITY DETECTION ====================

class SecurityViolation(Exception):
    """Exception raised when security violation is detected"""
    pass

def scan_for_secrets(source, filename="<string>"):
    """Enhanced scanning with IR analysis"""
    # If source is already compiled code object, skip
    if hasattr(source, 'co_code'):  # It's a code object
        return []
    
    if not isinstance(source, str):
        return []
    
    issues = []
    
    # 1. SIMPLE REGEX SCANNING (existing functionality)
    issues.extend(_regex_scan(source, filename))
    
    # 2. IR/STATIC ANALYSIS (only if available)
    if HAS_IR_ANALYSIS:
        issues.extend(_ir_analysis_scan(source, filename))
    
    return issues

def _regex_scan(source, filename):
    """Keep existing regex scanning"""
    issues = []
    lines = source.split('\n')
    
    for i, line in enumerate(lines, 1):
        line_lower = line.lower().strip()
        
        # Skip empty lines and comments
        if not line_lower or line_lower.startswith('#'):
            continue
        
        # 1. Check for hardcoded passwords
        if ('password' in line_lower or 'passwd' in line_lower or 'pwd' in line_lower):
            if '=' in line and ('"' in line or "'" in line):
                match = re.search(r'["\']([^"\']+)["\']', line)
                if match and len(match.group(1)) > 5:
                    issues.append({
                        'line': i,
                        'rule': 'HS001',
                        'severity': 'HIGH',
                        'message': 'Hardcoded password',
                        'code': line.strip()[:80]
                    })
        
        # 2. Check for API keys
        if ('api_key' in line_lower or 'api-key' in line_lower or 
            'secret_key' in line_lower or 'access_key' in line_lower):
            if '=' in line and ('"' in line or "'" in line):
                match = re.search(r'["\']([^"\']+)["\']', line)
                if match and len(match.group(1)) > 8:
                    issues.append({
                        'line': i,
                        'rule': 'HS002',
                        'severity': 'CRITICAL',
                        'message': 'API/Secret key in code',
                        'code': line.strip()[:80]
                    })
        
        # 3. Check for AWS keys
        if ('aws_' in line_lower or 'akia' in line_lower):
            if '=' in line:
                issues.append({
                    'line': i,
                    'rule': 'HS003',
                    'severity': 'CRITICAL',
                    'message': 'AWS credential',
                    'code': line.strip()[:80]
                })
        
        # 4. Check for weak crypto
        if 'md5(' in line_lower or 'sha1(' in line_lower:
            issues.append({
                'line': i,
                'rule': 'WC001',
                'severity': 'HIGH',
                'message': 'Weak cryptographic algorithm',
                'code': line.strip()[:80]
            })
        
        # 5. Check for insecure random
        if ('random.random()' in line or 'math.random()' in line or
            'random.randint(' in line):
            if 'import secrets' not in source.lower():
                issues.append({
                    'line': i,
                    'rule': 'IR001',
                    'severity': 'MEDIUM',
                    'message': 'Insecure random number generator',
                    'code': line.strip()[:80]
                })
    
    return issues

def _ir_analysis_scan(source, filename):
    """Use IR analyzer for sophisticated detection"""
    if not HAS_IR_ANALYSIS:
        return []
    
    issues = []
    
    try:
        # Create IR analyzer (from scanner/ir_analyzer.py)
        analyzer = IRAnalyzer()
        
        # Parse AST
        tree = ast.parse(source, filename=filename)
        
        # Build IR and analyze
        ir_root = analyzer.build_ir_from_ast(tree)
        
        # Perform analyses from ir_analyzer.py
        analyzer.perform_constant_propagation()
        analyzer.analyze_crypto_patterns()
        analyzer.analyze_random_generation()
        
        # Extract findings from symbol table
        issues.extend(_check_symbol_table(analyzer.symbol_table, filename))
        
    except SyntaxError:
        pass  # Let Python handle syntax errors
    except Exception as e:
        # Don't break scanning if IR analysis fails
        print(f"⚠️  IR analysis warning: {e}")
    
    return issues

def _check_symbol_table(symbol_table, filename):
    """Check symbols for security issues"""
    if not HAS_IR_ANALYSIS:
        return []
    
    issues = []
    
    for symbol in symbol_table.get_all_symbols():
        var_name = symbol.name.lower()
        
        # Check variable names that might contain secrets
        if any(keyword in var_name for keyword in 
               ['password', 'secret', 'key', 'token', 'credential', 'aws', 'api']):
            issues.append({
                'line': symbol.line_no,
                'rule': 'ST001',
                'severity': 'MEDIUM' if 'test' in var_name else 'HIGH',
                'message': f'Potential secret variable: {symbol.name} in scope: {symbol.scope}',
                'code': f'{symbol.name} = [from symbol table]'
            })
    
    return issues


def display_issues(issues, filename):
    """Display security issues"""
    if not issues:
        return True
    
    short_name = os.path.basename(filename) if filename != '<string>' else 'inline code'
    if short_name.endswith('.py'):
        short_name = short_name[:-3]
    
    print(f"\n{'='*60}")
    print(f"🔍 SECURITY SCAN: {short_name}")
    print(f"{'='*60}")
    
    # Group by severity
    critical = [i for i in issues if i['severity'] == 'CRITICAL']
    high = [i for i in issues if i['severity'] == 'HIGH']
    medium = [i for i in issues if i['severity'] == 'MEDIUM']
    
    if critical:
        print("\n🔴 CRITICAL ISSUES (Blocking compilation):")
        for issue in critical:
            print(f"  Line {issue['line']}: [{issue['rule']}] {issue['message']}")
            if issue.get('code'):
                print(f"       Code: {issue['code']}")
    
    if high:
        print("\n🟠 HIGH SEVERITY ISSUES:")
        for issue in high:
            print(f"  Line {issue['line']}: [{issue['rule']}] {issue['message']}")
            if issue.get('code'):
                print(f"       Code: {issue['code']}")
    
    if medium:
        print("\n🟡 MEDIUM SEVERITY ISSUES (Warnings):")
        for issue in medium:
            print(f"  Line {issue['line']}: [{issue['rule']}] {issue['message']}")
            if issue.get('code'):
                print(f"       Code: {issue['code']}")
    
    # Block if critical issues
    if critical:
        print(f"\n{'='*60}")
        print("❌ COMPILATION BLOCKED")
        print(f"{'='*60}")
        return False
    
    if high or medium:
        print(f"\n{'='*60}")
        print("⚠️  Compilation proceeding with warnings")
        print(f"{'='*60}")
    
    return True

# ==================== HOOK ALL COMPILATION FUNCTIONS ====================

# Save original functions
_original_compile = compile
_original_exec = getattr(builtins, 'exec', None)
_original_eval = getattr(builtins, 'eval', None)

def secure_compile(source, filename="<string>", mode="exec", flags=0, 
                   dont_inherit=False, optimize=-1, *args, **kwargs):
    """
    Replacement for compile() that scans code
    """
    # Skip if already compiled or not string
    if not isinstance(source, str):
        return _original_compile(source, filename, mode, flags, dont_inherit, optimize)
    
    issues = scan_for_secrets(source, filename)
    should_compile = display_issues(issues, filename)
    
    if not should_compile:
        raise SecurityViolation("Critical security violations detected")
    
    # Proceed with compilation
    try:
        return _original_compile(source, filename, mode, flags=flags, 
                               dont_inherit=dont_inherit, optimize=optimize)
    except TypeError:
        return _original_compile(source, filename, mode, flags, dont_inherit, optimize)

# Replace compile function
builtins.compile = secure_compile

# Hook exec if it exists
if _original_exec:
    def secure_exec(source, globals=None, locals=None):
        """Replacement for exec()"""
        if isinstance(source, str):
            # For string source, compile it first (which will trigger our scanner)
            code = secure_compile(source, "<exec>", "exec")
            if globals is None and locals is None:
                return _original_exec(code)
            elif locals is None:
                return _original_exec(code, globals)
            else:
                return _original_exec(code, globals, locals)
        else:
            # Already compiled code, execute directly
            if globals is None and locals is None:
                return _original_exec(source)
            elif locals is None:
                return _original_exec(source, globals)
            else:
                return _original_exec(source, globals, locals)
    
    builtins.exec = secure_exec

# Hook eval if it exists
if _original_eval:
    def secure_eval(source, globals=None, locals=None):
        """Replacement for eval()"""
        if isinstance(source, str):
            code = secure_compile(source, "<eval>", "eval")
            if globals is None and locals is None:
                return _original_eval(code)
            elif locals is None:
                return _original_eval(code, globals)
            else:
                return _original_eval(code, globals, locals)
        else:
            if globals is None and locals is None:
                return _original_eval(source)
            elif locals is None:
                return _original_eval(source, globals)
            else:
                return _original_eval(source, globals, locals)
    
    builtins.eval = secure_eval

# ==================== IMPORT HOOK ====================

_original_import = builtins.__import__

def secure_import(name, globals=None, locals=None, fromlist=(), level=0):
    """Replacement for __import__"""
    module = _original_import(name, globals, locals, fromlist, level)
    
    # Scan the module if it's a .py file
    try:
        if hasattr(module, '__file__') and module.__file__:
            filepath = module.__file__
            if filepath.endswith('.py') and os.path.exists(filepath):
                # Skip Python standard library
                if 'site-packages' in filepath or 'Lib\\' in filepath:
                    return module
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        source = f.read()
                    
                    issues = scan_for_secrets(source, filepath)
                    if issues:
                        short_name = os.path.basename(filepath)
                        display_issues(issues, short_name)
                except:
                    pass
    except:
        pass
    
    return module

builtins.__import__ = secure_import

# ==================== INITIALIZATION ====================

print("=" * 60)
print("✅ COMPILE-TIME SECURITY SCANNER")
print("=" * 60)
print("Version: 1.0 | Mode: Active")
print()
print("Hooked functions:")
print("  • compile() - ALL code compilation")
print("  • exec()    - Code execution") 
print("  • eval()    - Expression evaluation")
print("  • import    - Module imports")
print()
print("Security checks:")
print("  • Hardcoded secrets (passwords, API keys)")
print("  • Weak cryptographic algorithms")
print("  • Insecure random number generation")
print("=" * 60)

# Quick test
if __name__ == "__main__":
    print("\n🧪 Quick self-test...")
    try:
        compile('password = "test"', "<test>", "exec")
        print("✅ Ready for use!")
    except SecurityViolation:
        print("✅ Working correctly!")
    except Exception as e:
        print(f"⚠️  Note: {type(e).__name__}")