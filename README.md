# PackerScope

**PackerScope** is a production-grade Python framework for automated Windows PE packer detection, classification, and unpacking. Designed for defensive security analysts, reverse engineers, and malware analysis laboratories.

---

## Features

- **Multi-layered Detection Pipeline:**
  - **Entropy Analysis:** Measures Shannon entropy across whole files, sections, and via sliding-window heuristics.
  - **Section Analysis:** Detects anomalous section names (e.g., `UPX0`, `.vmp0`), extreme virtual-to-raw size ratios, and abnormal permissions (RWX).
  - **IAT Analysis:** Analyzes Import Address Table sparseness and suspicious loader API usage.
  - **Entry Point Analysis:** Disassembles entry point instructions using Capstone to detect stubs, jump chains, and trampolines.
  - **Structure Analysis:** Identifies structural PE header anomalies, misaligned headers, and invalid metadata.
  - **Signature Matching:** Built-in byte-pattern scanning using PEiD database signatures.
  - **YARA Scanning:** Deep static analysis utilizing community or custom YARA rules.
  - **Heuristic Aggregator:** Combines weighted multi-module signals into an ensemble packing verdict.

- **Automated Unpacking:**
  - **UPXUnpacker:** Native decompression using the UPX binary.
  - **GenericStaticUnpacker:** Framework for static decompression routines.
  - **DynamicUnpacker:** Dynamic emulation and instrumentation unpacker integration.

- **Verification Subsystem:** Automatically verifies unpacked binaries by validating PE integrity, entropy reduction, and IAT restoration.

- **Multi-Format Reporting:** Generates structured reports in JSON, CSV, Markdown, and HTML formats.

---

## Installation

### From PyPI

```bash
pip install packerscope
```

### From Source

```bash
git clone https://github.com/salmanmallah/packerscope.git
cd packerscope
pip install .
```

### Optional Dependencies

For additional disassembly, YARA, or dynamic analysis capabilities:

```bash
pip install "packerscope[all]"
```

---

## Quickstart (Python API)

PackerScope provides a simple, high-level Python API designed for rapid analysis and easy scripting.

### Basic Analysis

```python
import packerscope

# Analyze a single binary
result = packerscope.scan("path/to/sample.exe")

if result.is_packed:
    print(f"File is packed with {result.packer.upper()}")
    print(f"Confidence: {result.confidence:.2%}")
    print("Detection Reasons:")
    for reason in result.reasons:
        print(f"  - {reason}")
else:
    print("File is not packed.")
```

### Dictionary Summary

```python
import packerscope

result = packerscope.scan("path/to/sample.exe")
summary = result.summary()

print(summary)
# {
#     "file_name": "sample.exe",
#     "file_path": "C:\\samples\\sample.exe",
#     "is_packed": True,
#     "packer": "upx",
#     "confidence": 0.85,
#     "confidence_level": "high",
#     "reasons": [...],
#     "analysis_duration_seconds": 0.02
# }
```

### Automatic Unpacking

```python
import packerscope

# Analyze and unpack if a supported packer is found
result = packerscope.scan("path/to/sample.exe", unpack=True)

if result.unpack_result and result.unpack_result.success:
    print(f"Unpacked file saved to: {result.unpack_result.unpacked_path}")
```

### Batch Scanning a Directory

```python
import packerscope

# Scan all PE files in a directory concurrently
results = packerscope.batch_scan("samples_folder/", workers=8)

for res in results:
    status = "PACKED" if res.is_packed else "NOT PACKED"
    print(f"{res.file_name:<30} | {status:<10} | {res.packer:<10} | {res.confidence:.2%}")
```

---

## Command Line Interface (CLI)

PackerScope can also be executed directly from your terminal:

### Analyze a Single File

```bash
packerscope scan samples/sample.exe --format json,html --output results/
```

### Batch Analyze a Directory

```bash
packerscope batch samples/ --workers 8 --format csv
```

### Quick PE Information

```bash
packerscope info samples/sample.exe
```

---

## Architecture

1. **Orchestrator:** Coordinates pipeline lifecycle: Initialization -> Detection -> Verdict -> Unpack -> Verify -> Report.
2. **PEContext:** Central blackboard state object. Parsed PE artifacts and detector results are shared here.
3. **Plugin Manager:** Dynamically discovers and loads detectors, unpackers, reporters, and verifiers.
4. **Detectors:** Independent modules implementing `BaseDetector`, executed in priority order.
5. **Unpackers:** Modules implementing `BaseUnpacker`, invoked based on verdict classification.

---

## Project Structure

```
packer_identifier_framework/
├── packerscope/
│   ├── __init__.py            # Top-level public API (scan, detect, batch_scan)
│   ├── cli.py                 # Command-line interface
│   ├── config.py              # Central configuration (Pydantic Settings)
│   ├── constants.py           # Thresholds and heuristics constants
│   ├── context.py             # PEContext (Blackboard state)
│   ├── exceptions.py          # Custom exceptions
│   ├── orchestrator.py        # Pipeline execution logic
│   ├── plugin_manager.py      # Dynamic plugin discovery
│   ├── core/                  # Interfaces, Enums, and Pydantic Models
│   ├── detectors/             # Detection modules (Entropy, IAT, YARA, etc.)
│   ├── reporters/             # Report generators (JSON, CSV, HTML, MD)
│   ├── signatures/            # PEiD signature database & parser
│   ├── unpackers/             # Unpacker implementations
│   ├── utils/                 # Binary analysis helpers & structured logging
│   └── verification/          # Post-unpack verification logic
├── tests/                     # Unit and Integration tests
├── pyproject.toml             # Packaging metadata and dependency definitions
└── requirements.txt           # Flat dependency list
```

---

## Running Tests

Execute the automated test suite using pytest:

```bash
python -m pytest
```

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Disclaimer

**Educational and Defensive Research Purposes Only.** This framework is intended strictly for defensive security research, malware analysis, and educational use within authorized environments.
