"""
Week 6: Symbol Table Implementation
Tracks variables, functions, and constants across scopes
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

console = Console()

@dataclass
class Symbol:
    """Represents a symbol (variable, function, etc.) in the symbol table"""
    name: str
    symbol_type: str  # 'variable', 'function', 'parameter', 'constant'
    line_no: int
    scope: str
    data_type: Optional[str] = None
    value: Optional[str] = None
    is_constant: bool = False

class SymbolTable:
    """Manages symbols across different scopes"""
    
    def __init__(self):
        self.symbols: List[Symbol] = []
        self.scope_stack: List[str] = ["global"]
    
    def add_symbol(self, symbol: Symbol):
        """Add a symbol to the table"""
        # Check if symbol already exists in current scope
        existing = self.find_symbol(symbol.name, symbol.scope)
        if existing:
            # Update existing symbol
            existing.symbol_type = symbol.symbol_type
            existing.line_no = symbol.line_no
            existing.data_type = symbol.data_type
            existing.value = symbol.value
        else:
            self.symbols.append(symbol)
    
    def find_symbol(self, name: str, scope: str) -> Optional[Symbol]:
        """Find a symbol by name and scope"""
        for symbol in self.symbols:
            if symbol.name == name and symbol.scope == scope:
                return symbol
        return None
    
    def find_symbol_in_any_scope(self, name: str) -> List[Symbol]:
        """Find all symbols with given name in any scope"""
        return [s for s in self.symbols if s.name == name]
    
    def enter_scope(self, scope_name: str):
        """Enter a new scope"""
        self.scope_stack.append(scope_name)
    
    def exit_scope(self):
        """Exit current scope"""
        if len(self.scope_stack) > 1:
            self.scope_stack.pop()
    
    def get_current_scope(self) -> str:
        """Get current scope name"""
        return self.scope_stack[-1] if self.scope_stack else "global"
    
    def get_symbols_by_scope(self, scope: str) -> List[Symbol]:
        """Get all symbols in a specific scope"""
        return [s for s in self.symbols if s.scope == scope]
    
    def get_symbols_by_type(self, symbol_type: str) -> List[Symbol]:
        """Get all symbols of a specific type"""
        return [s for s in self.symbols if s.symbol_type == symbol_type]
    
    def get_all_symbols(self) -> List[Symbol]:
        """Get all symbols"""
        return self.symbols.copy()
    
    def clear(self):
        """Clear all symbols"""
        self.symbols.clear()
        self.scope_stack = ["global"]
    
    def print_table(self):
        """Print symbol table in formatted table"""
        if not self.symbols:
            console.print("  [dim]No symbols found[/dim]")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Scope", style="yellow")
        table.add_column("Line", justify="right")
        table.add_column("Data Type", style="dim")
        table.add_column("Value", style="dim")
        
        for symbol in sorted(self.symbols, key=lambda s: (s.scope, s.name)):
            table.add_row(
                symbol.name,
                symbol.symbol_type,
                symbol.scope,
                str(symbol.line_no),
                symbol.data_type or "-",
                (symbol.value[:30] + "..." if symbol.value and len(symbol.value) > 30 else symbol.value or "-")
            )
        
        console.print(table)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about symbols"""
        stats = {
            'total': len(self.symbols),
            'variables': len([s for s in self.symbols if s.symbol_type == 'variable']),
            'functions': len([s for s in self.symbols if s.symbol_type == 'function']),
            'parameters': len([s for s in self.symbols if s.symbol_type == 'parameter']),
            'constants': len([s for s in self.symbols if s.symbol_type == 'constant']),
            'scopes': len(set(s.scope for s in self.symbols))
        }
        return stats
    
    def print_statistics(self):
        """Print symbol table statistics"""
        stats = self.get_statistics()
        console.print("\n[bold]Symbol Table Statistics:[/bold]")
        console.print(f"  Total Symbols: {stats['total']}")
        console.print(f"  Variables: {stats['variables']}")
        console.print(f"  Functions: {stats['functions']}")
        console.print(f"  Parameters: {stats['parameters']}")
        console.print(f"  Constants: {stats['constants']}")
        console.print(f"  Scopes: {stats['scopes']}")