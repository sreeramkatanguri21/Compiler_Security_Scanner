import ast
from scanner.ir_analyzer import IRAnalyzer

code = """
def get_password():
    return "hello"

api_token = "hello"
aws_access = "notreal"
"""

analyzer = IRAnalyzer()
tree = ast.parse(code)
analyzer.build_ir_from_ast(tree)

# Print the symbol table
analyzer.symbol_table.print_table()

# (Optional) Print stats too
analyzer.symbol_table.print_statistics()