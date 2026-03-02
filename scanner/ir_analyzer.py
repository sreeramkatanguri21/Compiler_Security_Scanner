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
        self.constants: Dict[str, Any] = {}
        self.crypto_findings: List[Dict] = []
        self.random_findings: List[Dict] = []
        
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
                    
                    # Track constant values
                    if isinstance(node.value, ast.Constant):
                        self.constants[target.id] = node.value.value
                    
                    # Add variable to symbol table
                    value_str = None
                    if isinstance(node.value, ast.Constant):
                        value_str = str(node.value.value)
                    
                    self.symbol_table.add_symbol(
                        Symbol(target.id, "variable", target.lineno, 
                              self.current_scope, value=value_str)
                    )
            
            # Process value being assigned
            value_node = self._visit_node(node.value)
            ir_node.children.append(value_node)
            
            return ir_node
            
        elif isinstance(node, ast.Constant):
            ir_node = IRNode("Constant", node.lineno, node.col_offset,
                           attributes={"value": node.value, "type": type(node.value).__name__})
            return ir_node
        
        elif isinstance(node, ast.Name):
            ir_node = IRNode("Name", node.lineno, node.col_offset,
                           attributes={"id": node.id})
            return ir_node
        
        elif isinstance(node, ast.Call):
            ir_node = IRNode("Call", node.lineno, node.col_offset)
            
            # Check function name
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
            
            ir_node.attributes["func_name"] = func_name
            
            # Visit function node
            ir_node.children.append(self._visit_node(node.func))
            
            # Visit arguments
            for arg in node.args:
                ir_node.children.append(self._visit_node(arg))
            
            return ir_node
        
        elif isinstance(node, ast.Attribute):
            ir_node = IRNode("Attribute", node.lineno, node.col_offset,
                           attributes={"attr": node.attr})
            if hasattr(node, 'value'):
                ir_node.children.append(self._visit_node(node.value))
            return ir_node
        
        elif isinstance(node, ast.Import):
            ir_node = IRNode("Import", node.lineno, node.col_offset)
            for alias in node.names:
                import_node = IRNode("ImportName", node.lineno, node.col_offset,
                                   attributes={"name": alias.name, 
                                             "asname": alias.asname})
                ir_node.children.append(import_node)
            return ir_node
        
        elif isinstance(node, ast.ImportFrom):
            ir_node = IRNode("ImportFrom", node.lineno, node.col_offset,
                           attributes={"module": node.module})
            for alias in node.names:
                import_node = IRNode("ImportName", node.lineno, node.col_offset,
                                   attributes={"name": alias.name,
                                             "asname": alias.asname})
                ir_node.children.append(import_node)
            return ir_node
        
        elif isinstance(node, ast.Expr):
            ir_node = IRNode("Expr", node.lineno, node.col_offset)
            ir_node.children.append(self._visit_node(node.value))
            return ir_node
        
        elif isinstance(node, ast.If):
            ir_node = IRNode("If", node.lineno, node.col_offset)
            # Test condition
            test_node = IRNode("Test", node.lineno, node.col_offset)
            test_node.children.append(self._visit_node(node.test))
            ir_node.children.append(test_node)
            
            # Body
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)
            
            # Orelse
            if node.orelse:
                orelse_node = IRNode("Orelse", node.lineno, node.col_offset)
                for child in node.orelse:
                    orelse_node.children.append(self._visit_node(child))
                ir_node.children.append(orelse_node)
            
            return ir_node
        
        elif isinstance(node, ast.For):
            ir_node = IRNode("For", node.lineno, node.col_offset)
            # Target
            ir_node.children.append(self._visit_node(node.target))
            # Iter
            ir_node.children.append(self._visit_node(node.iter))
            # Body
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)
            return ir_node
        
        elif isinstance(node, ast.While):
            ir_node = IRNode("While", node.lineno, node.col_offset)
            # Test
            ir_node.children.append(self._visit_node(node.test))
            # Body
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)
            return ir_node
        
        elif isinstance(node, ast.Return):
            ir_node = IRNode("Return", node.lineno, node.col_offset)
            if node.value:
                ir_node.children.append(self._visit_node(node.value))
            return ir_node
        
        else:
            # Generic fallback for unhandled node types
            ir_node = IRNode(node.__class__.__name__, 
                           getattr(node, 'lineno', 0),
                           getattr(node, 'col_offset', 0))
            return ir_node
    
    def perform_constant_propagation(self):
        """
        Perform constant propagation analysis
        Track constant values through the program flow
        """
        if not self.ir_root:
            return
        
        # Walk through IR and track constant assignments
        self._propagate_constants(self.ir_root)
    
    def _propagate_constants(self, node: IRNode):
        """Recursively propagate constants through IR"""
        if node.node_type == "Assign":
            # Check if we're assigning a constant
            for child in node.children:
                if child.node_type == "Variable":
                    var_name = child.attributes.get("name")
                    # Find the constant value
                    for value_child in node.children:
                        if value_child.node_type == "Constant":
                            const_value = value_child.attributes.get("value")
                            self.constants[var_name] = const_value
        
        # Recursively process children
        for child in node.children:
            self._propagate_constants(child)
    
    def analyze_crypto_patterns(self):
        """
        Analyze cryptographic algorithm usage
        Detect weak or outdated algorithms
        """
        if not self.ir_root:
            return
        
        weak_algorithms = ['md5', 'sha1', 'des', 'rc4', 'md4']
        
        self._check_crypto_calls(self.ir_root, weak_algorithms)
    
    def _check_crypto_calls(self, node: IRNode, weak_algorithms: List[str]):
        """Check for weak crypto function calls"""
        if node.node_type == "Call":
            func_name = node.attributes.get("func_name", "")
            func_name_lower = func_name.lower()
            
            for weak in weak_algorithms:
                if weak in func_name_lower:
                    self.crypto_findings.append({
                        'line': node.line_no,
                        'function': func_name,
                        'algorithm': weak,
                        'severity': 'HIGH',
                        'message': f'Weak cryptographic algorithm detected: {weak}'
                    })
        
        # Check imports
        if node.node_type == "ImportFrom":
            module = node.attributes.get("module", "")
            if module in ["hashlib", "Crypto", "cryptography"]:
                for child in node.children:
                    if child.node_type == "ImportName":
                        name = child.attributes.get("name", "").lower()
                        for weak in weak_algorithms:
                            if weak in name:
                                self.crypto_findings.append({
                                    'line': node.line_no,
                                    'function': name,
                                    'algorithm': weak,
                                    'severity': 'HIGH',
                                    'message': f'Weak cryptographic algorithm imported: {weak}'
                                })
        
        # Recursively check children
        for child in node.children:
            self._check_crypto_calls(child, weak_algorithms)
    
    def analyze_random_generation(self):
        """
        Analyze random number generation
        Detect insecure random number generators
        """
        if not self.ir_root:
            return
        
        insecure_random_funcs = [
            'random.random',
            'random.randint',
            'random.choice',
            'random.randrange',
            'math.random'
        ]
        
        self._check_random_calls(self.ir_root, insecure_random_funcs)
    
    def _check_random_calls(self, node: IRNode, insecure_funcs: List[str]):
        """Check for insecure random function calls"""
        if node.node_type == "Call":
            func_name = node.attributes.get("func_name", "")
            
            for insecure in insecure_funcs:
                if insecure in func_name:
                    self.random_findings.append({
                        'line': node.line_no,
                        'function': func_name,
                        'severity': 'MEDIUM',
                        'message': f'Insecure random number generator: {func_name}. Use secrets module instead.'
                    })
        
        # Recursively check children
        for child in node.children:
            self._check_random_calls(child, insecure_funcs)
    
    def get_findings(self) -> Dict[str, List[Dict]]:
        """Get all security findings from analysis"""
        return {
            'crypto': self.crypto_findings,
            'random': self.random_findings,
            'constants': self.constants
        }
    
    def print_ir(self, node: Optional[IRNode] = None, indent: int = 0):
        """Print IR tree for debugging"""
        if node is None:
            node = self.ir_root
        
        if node is None:
            console.print("[dim]No IR to display[/dim]")
            return
        
        prefix = "  " * indent
        attrs_str = ", ".join(f"{k}={v}" for k, v in node.attributes.items())
        console.print(f"{prefix}[cyan]{node.node_type}[/cyan] ({node.line_no}:{node.col_offset}) {attrs_str}")
        
        for child in node.children:
            self.print_ir(child, indent + 1)
    
    def analyze_all(self):
        """Perform all available analyses"""
        self.perform_constant_propagation()
        self.analyze_crypto_patterns()
        self.analyze_random_generation()
        return self.get_findings()