"""
Week 6: Intermediate Representation & Analysis Foundation
Program analysis using abstract syntax trees and symbol tables
"""

import ast
from typing import Dict, List, Optional, Any
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
    children: List["IRNode"] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


class IRAnalyzer:
    """
    Intermediate Representation analyzer for security vulnerability detection
    """

    def __init__(self):
        self.symbol_table = SymbolTable()
        self.ir_root: Optional[IRNode] = None
        self.current_scope = "global"

        # Extra analysis state
        self.constants: Dict[str, Any] = {}
        self.crypto_findings: List[Dict[str, Any]] = []
        self.random_findings: List[Dict[str, Any]] = []

    # IR BUILDING 
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

        if isinstance(node, ast.FunctionDef):
            old_scope = self.current_scope
            self.current_scope = node.name

            ir_node = IRNode(
                "FunctionDef",
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                attributes={"name": node.name},
            )

            # Add function to symbol table (safe: always str)
            self.symbol_table.add_symbol(Symbol(str(node.name), "function", node.lineno, self.current_scope))

            # Args
            args_node = IRNode("Arguments", node.lineno, node.col_offset)
            for arg in node.args.args:
                arg_name = getattr(arg, "arg", "")
                args_node.children.append(
                    IRNode("Arg", getattr(arg, "lineno", node.lineno), getattr(arg, "col_offset", 0), attributes={"name": arg_name})
                )
                self.symbol_table.add_symbol(Symbol(str(arg_name), "parameter", getattr(arg, "lineno", node.lineno), self.current_scope))
            ir_node.children.append(args_node)

            # Body
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)

            self.current_scope = old_scope
            return ir_node

        if isinstance(node, ast.Assign):
            ir_node = IRNode("Assign", node.lineno, node.col_offset)

            # Targets
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tname = str(target.id)
                    ir_node.children.append(
                        IRNode("Variable", target.lineno, target.col_offset, attributes={"name": tname})
                    )

                    # Track constant values
                    value_str: Optional[str] = None
                    if isinstance(node.value, ast.Constant):
                        self.constants[tname] = node.value.value
                        value_str = str(node.value.value)

                    self.symbol_table.add_symbol(
                        Symbol(tname, "variable", target.lineno, self.current_scope, value=value_str)
                    )

            # Value
            ir_node.children.append(self._visit_node(node.value))
            return ir_node

        if isinstance(node, ast.Constant):
            return IRNode(
                "Constant",
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                attributes={"value": node.value, "type": type(node.value).__name__},
            )

        if isinstance(node, ast.Name):
            return IRNode(
                "Name",
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                attributes={"id": node.id},
            )

        if isinstance(node, ast.Attribute):
            ir_node = IRNode("Attribute", node.lineno, node.col_offset, attributes={"attr": node.attr})
            if hasattr(node, "value"):
                ir_node.children.append(self._visit_node(node.value))
            return ir_node

        if isinstance(node, ast.Call):
            ir_node = IRNode("Call", node.lineno, node.col_offset)

            # Derive a stable function name string (IMPORTANT: never None)
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = str(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                base = ""
                if isinstance(node.func.value, ast.Name):
                    base = str(node.func.value.id)
                func_name = f"{base}.{node.func.attr}" if base else str(node.func.attr)

            ir_node.attributes["func_name"] = func_name  # always string

            # Visit function expression
            ir_node.children.append(self._visit_node(node.func))

            # Visit args
            for arg in node.args:
                ir_node.children.append(self._visit_node(arg))

            return ir_node

        if isinstance(node, ast.Import):
            ir_node = IRNode("Import", node.lineno, node.col_offset)
            for alias in node.names:
                ir_node.children.append(
                    IRNode(
                        "ImportName",
                        node.lineno,
                        node.col_offset,
                        attributes={"name": alias.name, "asname": alias.asname},
                    )
                )
            return ir_node

        if isinstance(node, ast.ImportFrom):
            ir_node = IRNode("ImportFrom", node.lineno, node.col_offset, attributes={"module": node.module})
            for alias in node.names:
                ir_node.children.append(
                    IRNode(
                        "ImportName",
                        node.lineno,
                        node.col_offset,
                        attributes={"name": alias.name, "asname": alias.asname},
                    )
                )
            return ir_node

        if isinstance(node, ast.Expr):
            ir_node = IRNode("Expr", node.lineno, node.col_offset)
            ir_node.children.append(self._visit_node(node.value))
            return ir_node

        if isinstance(node, ast.If):
            ir_node = IRNode("If", node.lineno, node.col_offset)

            test_node = IRNode("Test", node.lineno, node.col_offset)
            test_node.children.append(self._visit_node(node.test))
            ir_node.children.append(test_node)

            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)

            if node.orelse:
                orelse_node = IRNode("Orelse", node.lineno, node.col_offset)
                for child in node.orelse:
                    orelse_node.children.append(self._visit_node(child))
                ir_node.children.append(orelse_node)

            return ir_node

        if isinstance(node, ast.For):
            ir_node = IRNode("For", node.lineno, node.col_offset)
            ir_node.children.append(self._visit_node(node.target))
            ir_node.children.append(self._visit_node(node.iter))
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)
            return ir_node

        if isinstance(node, ast.While):
            ir_node = IRNode("While", node.lineno, node.col_offset)
            ir_node.children.append(self._visit_node(node.test))
            body_node = IRNode("Body", node.lineno, node.col_offset)
            for child in node.body:
                body_node.children.append(self._visit_node(child))
            ir_node.children.append(body_node)
            return ir_node

        if isinstance(node, ast.Return):
            ir_node = IRNode("Return", node.lineno, node.col_offset)
            if node.value:
                ir_node.children.append(self._visit_node(node.value))
            return ir_node

        # Fallback
        return IRNode(
            node.__class__.__name__,
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
        )

    # ANALYSES 
    def perform_constant_propagation(self):
        """
        Perform constant propagation analysis (very simplified)
        """
        if not self.ir_root:
            return
        self._propagate_constants(self.ir_root)

    def _propagate_constants(self, node: IRNode):
        """Recursively propagate constants through IR"""
        if node.node_type == "Assign":
            # If assigning a constant, record it
            var_name = None
            const_value = None
            for child in node.children:
                if child.node_type == "Variable":
                    var_name = child.attributes.get("name")
                if child.node_type == "Constant":
                    const_value = child.attributes.get("value")
            if var_name is not None and const_value is not None:
                self.constants[str(var_name)] = const_value

        for child in node.children:
            self._propagate_constants(child)

    def analyze_crypto_patterns(self):
        """
        Analyze cryptographic algorithm usage and detect weak algorithms.
        """
        if not self.ir_root:
            return

        weak_algorithms = ["md5", "sha1", "des", "rc4", "md4"]
        self._check_crypto_calls(self.ir_root, weak_algorithms)

    def _check_crypto_calls(self, node: IRNode, weak_algorithms: List[str]):
        """Check for weak crypto usage from call names and imports"""
        if node.node_type == "Call":
            func_name = str(node.attributes.get("func_name") or "")
            func_name_lower = func_name.lower()

            for weak in weak_algorithms:
                if weak in func_name_lower:
                    self.crypto_findings.append({
                        "line": node.line_no,
                        "function": func_name,
                        "algorithm": weak,
                        "severity": "HIGH",
                        "message": f"Weak cryptographic algorithm detected: {weak}",
                    })

        if node.node_type == "ImportFrom":
            module = str(node.attributes.get("module") or "")
            if module in ["hashlib", "Crypto", "cryptography"]:
                for child in node.children:
                    if child.node_type == "ImportName":
                        name = str(child.attributes.get("name") or "").lower()
                        for weak in weak_algorithms:
                            if weak in name:
                                self.crypto_findings.append({
                                    "line": node.line_no,
                                    "function": name,
                                    "algorithm": weak,
                                    "severity": "HIGH",
                                    "message": f"Weak cryptographic algorithm imported: {weak}",
                                })

        for child in node.children:
            self._check_crypto_calls(child, weak_algorithms)

    def analyze_random_generation(self):
        """
        Analyze random number generation and detect insecure RNG calls.
        """
        if not self.ir_root:
            return

        insecure_random_funcs = [
            "random.random",
            "random.randint",
            "random.choice",
            "random.randrange",
            "math.random",
        ]
        self._check_random_calls(self.ir_root, insecure_random_funcs)

    def _check_random_calls(self, node: IRNode, insecure_funcs: List[str]):
        if node.node_type == "Call":
            func_name = str(node.attributes.get("func_name") or "")
            for insecure in insecure_funcs:
                if insecure in func_name:
                    self.random_findings.append({
                        "line": node.line_no,
                        "function": func_name,
                        "severity": "MEDIUM",
                        "message": f"Insecure random number generator: {func_name}. Use secrets module instead.",
                    })

        for child in node.children:
            self._check_random_calls(child, insecure_funcs)

    # OUTPUT / UTIL 
    def get_findings(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all security findings from analysis"""
        return {
            "crypto": self.crypto_findings,
            "random": self.random_findings,
            "constants": self.constants,
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