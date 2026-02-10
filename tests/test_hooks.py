"""Tests for compiler hooks"""
import pytest
import tempfile
from pathlib import Path
from scanner.compiler_hooks import CompilerHookManager, SecurityFinding

def test_hook_manager_initialization():
    """Test hook manager initialization"""
    manager = CompilerHookManager()
    assert manager.hooks_enabled is True
    assert manager.findings == []

def test_secret_detection():
    """Test detection of hardcoded secrets"""
    manager = CompilerHookManager()
    
    # Create temporary file with hardcoded secret
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('password = "MySecret123"\n')
        f.write('api_key = "sk_test_123456"\n')
        temp_file = f.name
    
    try:
        should_compile = manager.intercept_compilation(temp_file, language='python')
        findings = manager.findings
        
        # Should find at least one security finding
        assert len(findings) > 0
        
        # Check that we found the password
        password_found = any('password' in f.message.lower() for f in findings)
        assert password_found, "Should detect hardcoded password"
        
    finally:
        Path(temp_file).unlink()

def test_false_positive_avoidance():
    """Test that short strings don't trigger false positives"""
    manager = CompilerHookManager()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = "test"\n')  # Short string, likely not a secret
        f.write('key = "abc"\n')  # Too short to be real key
        temp_file = f.name
    
    try:
        should_compile = manager.intercept_compilation(temp_file, language='python')
        # Should not flag very short strings as secrets
        assert should_compile is True
    finally:
        Path(temp_file).unlink()