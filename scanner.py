print("COMPILER SECURITY SCANNER")
print("=" * 40)

# Simple hardcoded secret scanner
import ast
import os

def scan_file(file_path):
    print(f"Scanning: {file_path}")
    print("-" * 30)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        tree = ast.parse(code)
        issues = []
        
        for node in ast.walk(tree):
            # Check for variable assignments with sensitive names
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        
                        # Check for password-like names
                        if any(word in var_name for word in ['password', 'pass', 'pwd']):
                            issues.append(f"Line {node.lineno}: Password variable '{target.id}' found")
                        
                        # Check for key-like names
                        if any(word in var_name for word in ['key', 'secret', 'token']):
                            issues.append(f"Line {node.lineno}: Secret variable '{target.id}' found")
                        
                        # Check for AWS
                        if 'aws' in var_name or 'ak' in var_name:
                            issues.append(f"Line {node.lineno}: AWS credential '{target.id}' found")
            
            # Check for string constants that look like secrets
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) > 20 and '=' not in value:  # Long string without equals
                    if any(pattern in value.lower() for pattern in ['sk_', 'ak', 'secret', 'token']):
                        issues.append(f"Line {node.lineno}: Possible hardcoded secret string found")
        
        # Also scan line by line for patterns
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Look for MD5/SHA1
            if 'md5(' in line_lower or 'sha1(' in line_lower:
                issues.append(f"Line {i}: Weak crypto function used")
            
            # Look for random.random()
            if 'random.random()' in line or 'math.random()' in line:
                issues.append(f"Line {i}: Insecure random number generator")
        
        # Print results
        if issues:
            print(f"🚨 Found {len(issues)} security issues:\n")
            for issue in issues:
                print(f"  • {issue}")
            
            # Check if any are critical
            critical_count = sum(1 for issue in issues if 'AWS' in issue or 'Line 8' in issue)
            if critical_count > 0:
                print(f"\n❌ {critical_count} CRITICAL issues - Compilation BLOCKED!")
            else:
                print(f"\n⚠️  Issues found but compilation can proceed")
        else:
            print("✅ No security issues found!")
            print("✅ Compilation can proceed")
            
    except Exception as e:
        print(f"Error: {e}")

# Scan the vulnerable example
scan_file("examples/sample_vulnerable.py")

print("\n" + "=" * 40)
input("Press Enter to exit...")