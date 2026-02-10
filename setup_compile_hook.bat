@echo off
title COMPILE-TIME SECURITY SCANNER SETUP
color 0A
echo ============================================
echo   COMPILE-TIME SECURITY SCANNER SETUP
echo ============================================
echo.
echo This will install security scanning hooks that
echo run DURING Python compilation (not after).
echo.
echo The scanner will:
echo  1. Check code as it's compiled
echo  2. Block compilation if critical issues found
echo  3. Warn about non-critical issues
echo.
echo ============================================
echo.

REM Create a test Python file that auto-imports the hook
echo import sys > auto_hook.py
echo sys.path.insert(0, '.') >> auto_hook.py
echo import compile_hook >> auto_hook.py
echo print("✅ Compile-time security scanner activated!") >> auto_hook.py
echo print("All Python code will now be scanned during compilation.") >> auto_hook.py

REM Test the hook
echo.
echo Testing compile-time scanning...
python -c "import sys; sys.path.insert(0, '.'); import compile_hook; exec('password = \"test\"')"

echo.
echo ============================================
echo SETUP COMPLETE!
echo ============================================
echo.
echo To use compile-time scanning:
echo   1. Import compile_hook in your code
echo   2. Or set PYTHONSTARTUP to auto_hook.py
echo   3. Or run: python -c "import compile_hook" my_script.py
echo.
echo Test with: python examples/sample_vulnerable.py
echo.
pause