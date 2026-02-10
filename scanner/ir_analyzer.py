"""
Week 6: Intermediate Representation & Analysis Foundation
Program analysis using abstract syntax trees and symbol tables
"""

import ast
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from rich.console import Console
from .symbol_table import SymbolTable, Symbol

console = Console()

@dataclass
class IRNode:
    """Base class for Intermediate Representation nodes"""
    node_type: str
    line_no: int
    col_offset: int
    children: List['IRNode'] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

class IRAnalyzer:
    """
    Intermediate Representation analyzer for security vulnerability detection
    """
    
    def __init__(self):
        self.symbol_table = SymbolTable()
        self.ir_root: Optional[IRNode] = None
        self.current_scope = "global"
        
    def build_ir_from_ast(self, ast_tree: ast.AST) -> IRNode:
        """Convert AST to Intermediate Representation"""
        self.ir_root = self._visit_node(ast_tree)
        return self.ir_root
    
    def _visit_node(self, node: ast.AST) -> IRNode:
        """Recursively visit AST nodes and convert to IR"""
        
        if isinstance(node, ast.Module):
            ir_node = IRNode("Module", 0, 0)
            for child in node.body:
                ir_node.children.append(self._visit_node(child))
            return ir_node
            
        elif isinstance(node, ast.FunctionDef):
            # Enter function scope
            old_scope = self.current_scope
            self.current_scope = node.name
            
            ir_node = IRNode("FunctionDef", node.lineno, node.col_offset, 
                           attributes={"name": node.name})
            
            # Add function to symbol table
            self.symbol_table.add_symbol(
                Symbol(node.name, "function", node.lineno, self.current_scope)
            )
            
            # Process arguments
            args_node = IRNode("Arguments", node.lineno, node.col_offset)
            for arg in node.args.args:
                arg_name = arg.arg
                args_node.children.append(
                    IRNode("Arg", arg.lineno, arg.col_offset,
                          attributes={"name": arg_name})
                )
                # Add arguments to symbol table
                self.symbol_table.add_symbol(
                    Symbol(arg_name, "parameter", arg.lineno, self.current_scope)
                )
            
            ir_node.children.append(args_node)
            
            # Process function body
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            
            ir_node.children.append(body_node)
            
            # Exit function scope
            self.current_scope = old_scope
            return ir_node
            
        elif isinstance(node, ast.Assign):
            ir_node = IRNode("Assign", node.lineno, node.col_offset)
            
            # Process targets (variables being assigned to)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_node = IRNode("Variable", target.lineno, target.col_offset,
                                       attributes={"name": target.id})
                    ir_node.children.append(target_node)
                    
                    # Add variable to symbol table
                    self.symbol_table.add_symbol(
                        Symbol(target.id, "variable", target.lineno, self.current_scope)
                    )
            
            # Process value being assigned
            value_node = self._visit_node(node.value)
            ir_node.children.append(value_node)
            
            return ir_node
            
        elif isinstance(node, ast.Constant):
            ir_node = IRNode("Constant", node.lineno, node.col_offset,
                           attributes={"value": node.value, "type": type(node.value).__name__})
            return ir_node
            
        elif isinstance(node, ast.Call):
            ir_node = IRNode("Call", node.lineno, node.col_offset)
            
            # Process function being called
            func_node = self._visit_node(node.func)
            ir_node.children.append(func_node)
            
            # Process arguments
            args_node = IRNode("CallArgs", node.lineno, node.col_offset)
            for arg in node.args:
                args_node.children.append(self._visit_node(arg))
            ir_node.children.append(args_node)
            
            return ir_node
            
        elif isinstance(node, ast.Name):
            return IRNode("Name", node.lineno, node.col_offset,
                         attributes={"id": node.id})
        
        elif isinstance(node, ast.Attribute):
            ir_node = IRNode("Attribute", node.lineno, node.col_offset)
            ir_node.children.append(self._visit_node(node.value))
            ir_node.attributes["attr"] = node.attr
            return ir_node
        
        # Default case for unhandled nodes
        return IRNode(type(node).__name__, 
                     getattr(node, 'lineno', 0),
                     getattr(node, 'col_offset', 0))
    
    def perform_constant_propagation(self):
        """Perform constant propagation analysis"""
        console.print("[cyan]Performing constant propagation analysis...[/cyan]")
        
        # This is a simplified implementation
        # In full implementation, would track constant values through assignments
        
        constants = self.symbol_table.get_symbols_by_type("variable")
        for symbol in constants:
            # Check if variable might contain hardcoded values
            if any(keyword in symbol.name.lower() for keyword in 
                  ['password', 'secret', 'key', 'token']):
                console.print(f"[yellow]  Potential secret variable: {symbol.name} in {symbol.scope}[/yellow]")
    
    def analyze_crypto_patterns(self):
        """Analyze cryptographic patterns in the code"""
        console.print("[cyan]Analyzing cryptographic patterns...[/cyan]")
        
        # Look for weak crypto algorithms
        weak_crypto_patterns = ['md5', 'sha1', 'des', 'rc4', 'base64']
        
        # Search in symbol table
        for symbol in self.symbol_table.get_all_symbols():
            for pattern in weak_crypto_patterns:
                if pattern in symbol.name.lower():
                    console.print(f"[red]  Warning: Found weak crypto reference: {symbol.name}[/red]")
    
    def analyze_random_generation(self):
        """Analyze random number generation patterns"""
        console.print("[cyan]Analyzing random number generation...[/cyan]")
        
        weak_rng_patterns = ['random', 'randint', 'Math.random', 'rand()']
        secure_rng_patterns = ['secrets.', 'Crypto.Random', 'os.urandom']
        
        # This would be integrated with AST analysis in real implementation
        console.print("[yellow]  RNG analysis requires deeper AST traversal (implemented in detectors)[/yellow]")
    
    def print_ir_tree(self, node: Optional[IRNode] = None, indent: int = 0):
        """Print IR tree structure for debugging"""
        if node is None:
            node = self.ir_root
            
        if node is None:
            return
            
        indent_str = "  " * indent
        attrs = " ".join(f"{k}={v}" for k, v in node.attributes.items())
        console.print(f"{indent_str}{node.node_type} ({node.line_no}:{node.col_offset}) {attrs}")
        
        for child in node.children:
            self.print_ir_tree(child, indent + 1)

def analyze_source_file(file_path: str):
    """Analyze a source file using IR analysis"""
    try:
        with open(file_path, 'r') as f:
            source_code = f.read()
        
        console.print(f"\n[bold]IR Analysis of: {file_path}[/bold]")
        
        # Parse to AST
        tree = ast.parse(source_code)
        
        # Build IR and analyze
        analyzer = IRAnalyzer()
        ir_root = analyzer.build_ir_from_ast(tree)
        
        # Perform analyses
        analyzer.perform_constant_propagation()
        analyzer.analyze_crypto_patterns()
        analyzer.analyze_random_generation()
        
        # Print symbol table
        console.print("\n[bold]Symbol Table:[/bold]")
        analyzer.symbol_table.print_table()
        
        # Optionally print IR tree (verbose)
        # console.print("\n[bold]IR Tree:[/bold]")
        # analyzer.print_ir_tree()
        
    except SyntaxError as e:
        console.print(f"[red]Syntax error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error analyzing file: {e}[/red]")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_source_file(sys.argv[1])
    else:
        console.print("Usage: python ir_analyzer.py <file_to_analyze>")