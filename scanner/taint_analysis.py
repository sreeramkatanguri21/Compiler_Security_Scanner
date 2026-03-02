import ast
from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass
class TaintFinding:
    line: int
    severity: str
    rule: str
    message: str
    code: str


SECRET_NAME_HINTS = ("password", "passwd", "pwd", "secret", "token", "api", "key", "credential", "aws")
SINK_FUNCS = {"print", "log", "logger.info", "logger.debug", "logger.warning", "requests.get", "requests.post"}


class Week8TaintAnalyzer(ast.NodeVisitor):
    """
    Minimal taint engine:
    - Marks variables as tainted if:
        * name looks secret-like OR
        * assigned from a string literal that looks like a secret OR
        * assigned from another tainted var OR
        * built by concatenating tainted values
    - Tracks taint into function parameters when called with tainted args.
    - Flags sinks when tainted values are used as arguments.
    """

    def __init__(self, source: str):
        self.source = source.splitlines()
        self.tainted: Set[str] = set()
        self.func_params_tainted: Dict[str, Set[str]] = {}  # func -> tainted param names
        self.findings: List[TaintFinding] = []

    def analyze(self) -> List[TaintFinding]:
        tree = ast.parse("\n".join(self.source))
        self.visit(tree)
        return self.findings

    # -------- helpers --------
    def _line(self, node: ast.AST) -> str:
        if hasattr(node, "lineno") and 1 <= node.lineno <= len(self.source):
            return self.source[node.lineno - 1].strip()
        return ""

    def _name_is_secret(self, name: str) -> bool:
        n = name.lower()
        return any(h in n for h in SECRET_NAME_HINTS)

    def _literal_looks_secret(self, s: str) -> bool:
        # minimal heuristic: long-ish and not just "test"
        return isinstance(s, str) and len(s) >= 10 and "test" not in s.lower()

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._literal_looks_secret(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        return False

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            # logger.info / requests.get etc.
            base = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                base.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                base.append(cur.id)
            return ".".join(reversed(base))
        return "<call>"

    # -------- visitors --------
    def visit_Assign(self, node: ast.Assign):
        tainted_value = self._expr_is_tainted(node.value)

        for t in node.targets:
            if isinstance(t, ast.Name):
                # mark tainted if value tainted OR name suspicious OR literal looks secret
                if tainted_value or self._name_is_secret(t.id):
                    self.tainted.add(t.id)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # If we previously observed tainted arguments passed to this function,
        # mark corresponding params as tainted while scanning its body.
        tainted_params = self.func_params_tainted.get(node.name, set())

        # Save/restore taint state (simple scoping)
        old = set(self.tainted)

        for arg in node.args.args:
            if arg.arg in tainted_params:
                self.tainted.add(arg.arg)

        for stmt in node.body:
            self.visit(stmt)

        self.tainted = old  # restore after function
        # do not call generic_visit because we manually visited body

    def visit_Call(self, node: ast.Call):
        call_name = self._call_name(node)

        # (A) Sink detection: if any argument is tainted -> finding
        if call_name in SINK_FUNCS and any(self._expr_is_tainted(a) for a in node.args):
            self.findings.append(
                TaintFinding(
                    line=getattr(node, "lineno", 0),
                    severity="CRITICAL",
                    rule="W8-TAINT-SINK",
                    message=f"Tainted data reaches sink: {call_name}",
                    code=self._line(node),
                )
            )

        # (B) Inter-procedural: if calling user function f(x, y) and x is tainted,
        # mark corresponding parameter in f as tainted.
        if isinstance(node.func, ast.Name):
            fname = node.func.id
            tainted_param_names = set()
            for idx, arg in enumerate(node.args):
                if self._expr_is_tainted(arg):
                    # We don't know the real parameter name here without building a full map,
                    # so we store by index in a simple encoded form: "__arg0__", "__arg1__"
                    tainted_param_names.add(f"__arg{idx}__")
            if tainted_param_names:
                self.func_params_tainted.setdefault(fname, set()).update(tainted_param_names)

        self.generic_visit(node)