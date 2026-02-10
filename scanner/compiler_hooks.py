"""
Week 5: Compiler Integration Framework
Implements compiler hook mechanism for source code interception
"""

import os
import sys
import ast
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
from rich.console import Console
from rich.table import Table
from dataclasses import dataclass

console = Console()

@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""
    file_path: str
    line_number: int
    column: int
    rule_id: str
    severity: str
    message: str
    snippet: str

class CompilerHookManager:
    """
    Main compiler hook manager that intercepts compilation process
    and performs security analysis
    """
    
    def __init__(self, config_path: str = "config/security_rules.yaml"):
        """Initialize compiler hook manager with security rules"""
        self.config = self._load_config(config_path)
        self.findings: List[SecurityFinding] = []
        self.hooks_enabled = True
        
        # Supported compilers/languages
        self.supported_toolchains = {
            'python': self._analyze_python,
            'gcc': self._simulate_gcc_hook,
            'clang': self._simulate_clang_hook,
        }
        
        console.print("[bold green]Compiler Security Scanner Initialized[/bold green]")
        console.print(f"Loaded {len(self.config.get('security_rules', {}))} security rule categories")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load security rules from YAML configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            console.print(f"[yellow]Warning: Config file {config_path} not found, using defaults[/yellow]")
            return {"security_rules": {}}
    
    def intercept_compilation(self, source_file: str, 
                            language: str = 'python',
                            toolchain: str = 'native') -> bool:
        """
        Intercept compilation process and analyze source code
        
        Args:
            source_file: Path to source file
            language: Programming language
            toolchain: Compiler toolchain
        
        Returns:
            bool: True if compilation should proceed, False if blocked
        """
        if not self.hooks_enabled:
            return True
            
        console.print(f"\n[bold]Analyzing: {source_file}[/bold]")
        
        # Read source code
        try:
            with open(source_file, 'r') as f:
                source_code = f.read()
        except Exception as e:
            console.print(f"[red]Error reading {source_file}: {e}[/red]")
            return True
        
        # Analyze based on language
        analyzer = self.supported_toolchains.get(language)
        if analyzer:
            analyzer(source_file, source_code)
        else:
            console.print(f"[yellow]Unsupported language: {language}[/yellow]")
        
        # Report findings
        self._report_findings()
        
        # Check if any critical findings should block compilation
        critical_findings = [f for f in self.findings if f.severity == "CRITICAL"]
        
        if critical_findings:
            console.print(f"\n[bold red]BLOCKING COMPILATION: {len(critical_findings)} critical vulnerabilities found[/bold red]")
            return False
        
        return True
    
    def _analyze_python(self, file_path: str, source_code: str):
        """Analyze Python source code"""
        try:
            tree = ast.parse(source_code)
            self._analyze_ast(tree, file_path, source_code)
        except SyntaxError as e:
            console.print(f"[yellow]Syntax error in {file_path}: {e}[/yellow]")
    
    def _simulate_gcc_hook(self, file_path: str, source_code: str):
        """Simulate GCC compiler hook (placeholder for C/C++ analysis)"""
        console.print(f"[cyan]Simulating GCC hook for {file_path}[/cyan]")
        # In real implementation, this would use Clang/LLVM bindings
    
    def _simulate_clang_hook(self, file_path: str, source_code: str):
        """Simulate Clang compiler hook"""
        console.print(f"[cyan]Simulating Clang hook for {file_path}[/cyan]")
    
    def _analyze_ast(self, tree: ast.AST, file_path: str, source_code: str):
        """Analyze AST for security vulnerabilities"""
        lines = source_code.split('\n')
        
        for node in ast.walk(tree):
            # Detect hardcoded secrets (simple string assignments)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(keyword in var_name for keyword in ['pass', 'key', 'secret', 'token']):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                value = node.value.value
                                if len(value) > 8:  # Likely not a placeholder
                                    finding = SecurityFinding(
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        rule_id="HS001",
                                        severity="HIGH",
                                        message=f"Hardcoded secret detected in variable '{var_name}'",
                                        snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                                    )
                                    self.findings.append(finding)
    
    def _report_findings(self):
        """Display security findings in a formatted table"""
        if not self.findings:
            console.print("[green]✓ No security vulnerabilities found[/green]")
            return
        
        table = Table(title="Security Findings", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("File:Line", style="cyan")
        table.add_column("Rule", style="yellow")
        table.add_column("Message")
        
        for finding in self.findings:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "bright_red",
                "MEDIUM": "yellow",
                "LOW": "blue"
            }.get(finding.severity, "white")
            
            location = f"{Path(finding.file_path).name}:{finding.line_number}"
            
            table.add_row(
                f"[{severity_color}]{finding.severity}[/{severity_color}]",
                location,
                finding.rule_id,
                finding.message
            )
        
        console.print(table)
        console.print(f"\n[bold]Total findings: {len(self.findings)}[/bold]")
    
    def create_pre_commit_hook(self, repo_path: str) -> bool:
        """Create pre-commit hook for Git repository"""
        hook_content = '''#!/bin/bash
# Compiler Security Scanner Pre-commit Hook
python -m scanner.compiler_hooks scan-precommit "$@"
'''
        
        hooks_dir = Path(repo_path) / ".git" / "hooks"
        pre_commit_hook = hooks_dir / "pre-commit"
        
        try:
            hooks_dir.mkdir(parents=True, exist_ok=True)
            pre_commit_hook.write_text(hook_content)
            pre_commit_hook.chmod(0o755)
            console.print(f"[green]✓ Pre-commit hook installed at {pre_commit_hook}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error installing pre-commit hook: {e}[/red]")
            return False

def scan_file(file_path: str):
    """CLI function to scan a single file"""
    hook_manager = CompilerHookManager()
    should_compile = hook_manager.intercept_compilation(file_path)
    
    if should_compile:
        console.print("\n[green]✓ Compilation would proceed[/green]")
    else:
        console.print("\n[red]✗ Compilation blocked due to critical vulnerabilities[/red]")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_file(sys.argv[1])
    else:
        console.print("Usage: python compiler_hooks.py <file_to_scan>")