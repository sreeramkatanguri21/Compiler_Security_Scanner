class SecurityEnforcer:

    def __init__(self):
        self.block_compilation = False

    def enforce(self, warnings):

        for w in warnings:

            if w["severity"] == "HIGH":
                self.block_compilation = True

        return self.block_compilation