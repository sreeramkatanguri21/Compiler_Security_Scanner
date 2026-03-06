from scanner.detection_engine import DetectionEngine


def test_week9():

    ir_code = [

        {"line":1, "op":"input", "var":"user_input"},

        {"line":2, "op":"assign", "target":"cmd", "value":"user_input"},

        {"line":3, "op":"call", "func":"system", "arg":"cmd"}

    ]

    engine = DetectionEngine()

    warnings, blocked = engine.scan(ir_code)

    print("\nWarnings:")

    for w in warnings:
        print(w)

    if blocked:
        print("\nCompilation Blocked due to HIGH severity vulnerability.")
    else:
        print("\nCompilation Allowed.")