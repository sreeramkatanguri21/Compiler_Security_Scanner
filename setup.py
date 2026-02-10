from setuptools import setup, find_packages

setup(
    name="compiler-security-scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=6.0",
        "astroid>=3.0.0",
        "tree-sitter>=0.20.0",
        "tree-sitter-languages>=1.7.0",
        "colorama>=0.4.6",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "css-scan=scanner.cli:main",
        ],
    },
    python_requires=">=3.8",
)