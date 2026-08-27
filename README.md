# PackerScope

**PackerScope** is a production-quality Python framework for automatic packer detection, classification, and unpacking of Windows PE files. It is designed for defensive security research, malware analysis labs, and educational purposes.

## Features

- **Multi-layered Detection Pipeline:**
  - **Entropy Analysis:** Measures Shannon entropy across the whole file, sections, and via a sliding window.
  - **Section Analysis:** Detects anomalous section names (e.g., `UPX0`, `.vmp0`), extreme virtual-to-raw size ratios, and abnormal permissions (RWX).
  - **IAT Analysis:** Analyzes Import Address Table sparseness and suspicious API usage (e.g., `LoadLibrary`, `VirtualAlloc`).
  - **Entry Point Analysis:** Disassembles entry point instructions using Capstone to detect jump chains, NOP sleds, and push/ret trampolines.
  - **Structure Analysis:** Identifies anomalies in PE optional and file headers, missing directories, or invalid timestamps.
  - **Signature Matching:** Fast byte-pattern matching using PEiD-style `userdb.txt` databases.
  - **YARA Scanning:** Deep static analysis utilizing community or custom YARA rules.
  - **Heuristics Engine:** Aggregates weak signals across all modules to form a high-confidence final verdict.

- **Automated Unpacking (Pluggable):**
  - **UPXUnpacker:** Native fast decompression using the `upx` system binary.
  - **GenericStaticUnpacker:** Template for static algorithmic decompression (aPLib, LZMA).
  - **DynamicUnpacker:** Template for dynamic unpacking via emulation (Qiling/Unicorn) or instrumentation (Frida).

- **Verification Subsystem:** Automatically verifies the success of an unpacking attempt by checking PE validity, entropy reduction, IAT restoration, and section normalization.

- **Reporting:** Generates comprehensive analysis reports in JSON, CSV, Markdown, and HTML formats.

- **Developer-Friendly:** Written in modern Python 3.13+, completely type-hinted, and modular using Pydantic v2 data models and the Blackboard design pattern (`PEContext`).

## Requirements

- Python 3.13+
- Windows (Primary target OS, though the framework runs on Linux/macOS)
- Recommended external tools: `upx`, Capstone

## Installation

1. Clone the repository or navigate to the framework directory.
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

*(Optional)* For advanced features like disassembly and dynamic analysis, you can install optional dependency groups defined in `pyproject.toml`.

## Usage

PackerScope provides an easy-to-use Command Line Interface (CLI):

### Analyze a Single File
```bash
python -m packerscope.cli scan samples/malware.exe --format json,html --output results/
```

### Batch Analyze a Directory
```bash
python -m packerscope.cli batch samples/ --workers 8 --format csv
```

### View Quick PE Information
```bash
python -m packerscope.cli info samples/malware.exe
```

## Architecture

1. **Orchestrator:** Manages the entire pipeline (Initialization → Detection → Verdict → Unpack → Verify → Report).
2. **PEContext:** The central Blackboard state object. Parsed PE data and detector results are shared here.
3. **Plugin Manager:** Dynamically discovers and loads detectors, unpackers, and reporters from the framework and external directories.
4. **Detectors:** Implement `BaseDetector`. Executed in priority order.
5. **Unpackers:** Implement `BaseUnpacker`. Selected dynamically based on the final packer verdict.

## Project Structure

```
packer_identifier_framework/
├── packerscope/
│   ├── cli.py                 # Command-line interface
│   ├── config.py              # Central configuration (Pydantic Settings)
│   ├── constants.py           # Thresholds and heuristics constants
│   ├── context.py             # PEContext (Blackboard state)
│   ├── exceptions.py          # Custom exceptions
│   ├── orchestrator.py        # Pipeline execution logic
│   ├── plugin_manager.py      # Plugin discovery and registration
│   ├── core/                  # Interfaces, Enums, and Pydantic Models
│   ├── detectors/             # Detection modules (Entropy, IAT, YARA, etc.)
│   ├── reporters/             # Output generators (JSON, CSV, HTML, MD)
│   ├── signatures/            # PEiD signature parsing
│   ├── unpackers/             # Unpacking strategies
│   ├── utils/                 # Helpers (disasm, entropy, hasher, pe_parser)
│   └── verification/          # Unpack verification logic
├── plugins/                   # Directory for custom third-party plugins
├── tests/                     # Unit and Integration tests
├── pyproject.toml             # Project metadata and dependencies
└── requirements.txt           # Flat dependency list
```

## Running Tests

PackerScope comes with a comprehensive test suite covering core models, utility functions, detectors, config, and orchestrator integration.

```bash
pytest tests/ -v
```

## Disclaimer

**Educational and Research Purposes Only.** This framework is intended strictly for defensive security research, malware analysis, and educational use within isolated malware analysis lab environments. Do not use this tool on systems or files you do not have permission to analyze.
