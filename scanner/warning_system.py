class WarningSystem:

    def __init__(self):
        self.warnings = []

    def add_warning(self, message, line, severity):
        warning = {
            "message": message,
            "line": line,
            "severity": severity
        }
        self.warnings.append(warning)

    def get_warnings(self):
        return self.warnings

    def print_warnings(self):
        if not self.warnings:
            print("No warnings detected.")
            return

        print("\n==== SECURITY WARNINGS ====")

        for w in self.warnings:
            print(f"[{w['severity']}] Line {w['line']} -> {w['message']}")