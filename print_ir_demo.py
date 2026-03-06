import ast
from scanner.ir_analyzer import IRAnalyzer

code = """
def f(x):
    y = 10
    return x + y

import hashlib
h = hashlib.md5(b"data").hexdigest()
"""

analyzer = IRAnalyzer()
tree = ast.parse(code)

ir_root = analyzer.build_ir_from_ast(tree)

# Print the whole IR tree
analyzer.print_ir(ir_root)
# or simply:
# analyzer.print_ir()