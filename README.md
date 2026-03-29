# Compiler Security Scanner

A Python-based compiler/execution-time security scanner that detects hardcoded secrets and insecure data flows. The project is organized as weekly milestones (Week 5 → Week 11) and includes a full pipeline with configuration, caching, filtering, reporting, and enforcement.

## Repository Structure

### Top-level
- `compiler_hook.py` — compiler/execution hook integration (scan before execution; can block on policy)
- `scanner_config.json` — main configuration file (rules, filtering, cache, enforcement)
- `requirements.txt` — Python dependencies
- `setup.py` + `compiler_security_scanner.egg-info/` — packaging metadata
- `.scanner_cache/` — disk cache directory (auto-created when caching is enabled)
- `examples/` — example code / demos
- `tests/` — weekly test suite (Week 5–Week 11)

### `scanner/` package
- `pipeline.py` — Week 10 pipeline orchestration (run detectors → normalize → filter → cache)
- `detection_engine.py` — Week 7 detection (regex, identifier heuristics, entropy)
- `taint_analysis.py` — Week 8 taint analysis (tainted data reaching sinks)
- `ir_analyzer.py` — IR-based analysis (earlier weeks / intermediate representation)
- `symbol_table.py` — symbol table extraction / identifier tracking
- `adapters.py` — normalize week-specific findings into unified `Finding`
- `types.py` — core models: `Severity`, `Finding`, `Remediation`
- `remediation.py` — default remediation suggestions per rule ID
- `reporter.py` — reporting (grouped by severity, remediation text)
- `enforcement.py` — enforcement policy (block execution when threshold met)
- `filtering.py` — false-positive reduction (whitelisting/filter rules)
- `cache.py` — disk cache (SHA-256-based cache keys)
- `config.py` — configuration dataclasses + JSON loader

## How It Works (High-Level)

1. **Load configuration** from `scanner_config.json` (or use defaults from `scanner/config.py`).
2. **Scan source** using `scanner/pipeline.py`:
   - (optional) cache lookup
   - run Week 7 detection (`scanner/detection_engine.py`)
   - run Week 8 taint analysis (`scanner/taint_analysis.py`)
   - normalize results to unified `Finding` (`scanner/adapters.py`)
   - filter findings to reduce noise (`scanner/filtering.py`)
   - (optional) save findings to disk cache (`scanner/cache.py`)
3. **Report** results with `scanner/reporter.py`.
4. **Enforce policy** with `scanner/enforcement.py` (can block execution).

## Installation

Create and activate a virtual environment:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration (`scanner_config.json`)

The scanner supports configuration-driven behavior including:
- enable/disable Week 7 and Week 8 detectors
- configure regex/entropy/identifier rules
- ignore paths (e.g., `tests/*`, `examples/*`)
- ignore specific rule IDs
- cache settings (`.scanner_cache/`)
- enforcement policy (block on CRITICAL by default)

## Run Week Tests

Run individual weekly tests like this:

```bash
python -m tests.test_week5
python -m tests.test_week6
python -m tests.test_week7
python -m tests.test_week8
python -m tests.test_week9
python -m tests.test_week10
python -m tests.test_week11_known_vulns
python -m tests.test_week11_false_positive_reduction
python -m tests.test_week11_edge_cases
python -m tests.test_week11_regression
```

Or run all tests (unittest discovery):

```bash
python -m unittest -v
```

## Week 10 Deliverables (Optimization & False Positives)
- Caching (`scanner/cache.py`) using SHA-256 keys derived from:
  - file path
  - source hash
  - configuration hash
- Filtering / whitelisting (`scanner/filtering.py`) to reduce noise from:
  - ignored paths (`tests/*`, `examples/*`)
  - known placeholders and test-like strings
- Context-aware configuration in `scanner/config.py`

## Week 11 Deliverables (Testing & Validation)

### 1) Test suite and results
Tests are included under `tests/`:
- `test_week11_known_vulns.py`
- `test_week11_false_positive_reduction.py`
- `test_week11_edge_cases.py`
- `test_week11_regression.py`

### 2) Validation report
A validation report summarizes:
- test methodology and coverage
- results (pass/fail)
- edge cases validated
- regression validation across weeks

## Notes
- The unified finding model is defined in `scanner/types.py` as `Finding`.
- Reports are grouped by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Enforcement policy can block execution depending on configured threshold.

---
