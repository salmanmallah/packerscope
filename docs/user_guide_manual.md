# PackerScope User Guide Manual

Welcome to the **PackerScope** user guide! This manual will walk you through installing, configuring, and using the framework to detect, classify, and unpack Windows PE files in your malware analysis lab.

---

## 1. Installation and Setup

PackerScope requires **Python 3.13+**. It is heavily optimized for Windows but can run on Linux systems for static analysis.

### Standard Installation

Clone the repository and install the core dependencies:

```bash
git clone https://github.com/salmanmallah/packerscope.git
cd packerscope
pip install -r requirements.txt
```

### Optional Dependencies

PackerScope supports optional features that require additional libraries. You can install them via pip if needed:

- **Disassembly Heuristics:** (For deep Entry Point analysis)
  ```bash
  pip install capstone
  ```
- **YARA Scanning:** (For deep static string/pattern matching)
  ```bash
  pip install yara-python
  ```

---

## 2. Using the Command Line Interface (CLI)

PackerScope is executed via the `packerscope.cli` module. 

### Basic Syntax
```bash
python -m packerscope.cli [GLOBAL_OPTIONS] COMMAND [ARGS]
```

**Global Options:**
- `--verbose` or `-v`: Enable detailed operational logging.
- `--debug`: Enable extremely verbose debug logging (useful for troubleshooting detectors).
- `--json-log`: Output logs as structured JSON.
- `--log-file PATH`: Save the execution log to a file.

---

### Command: `scan`
Analyzes a single PE file or a directory of PE files through the full detection and unpacking pipeline.

**Usage:**
```bash
python -m packerscope.cli scan <target_path> [OPTIONS]
```

**Options:**
- `--format`, `-f`: Output formats, comma-separated (e.g., `json,csv,md,html`). Default is `json`.
- `--output`, `-o`: Output directory for generated reports.
- `--no-unpack`: Disable the automated unpacking phase.
- `--no-verify`: Disable the unpacking verification phase.

**Examples:**
```bash
# Scan a single file and generate JSON and HTML reports
python -m packerscope.cli scan C:\malware\sample.exe -f json,html -o C:\results\

# Scan a file without attempting to unpack it
python -m packerscope.cli scan C:\malware\sample.exe --no-unpack
```

---

### Command: `batch`
Optimized command for scanning entire directories containing hundreds or thousands of samples. Supports multi-processing.

**Usage:**
```bash
python -m packerscope.cli batch <directory_path> [OPTIONS]
```

**Options:**
- `--workers`, `-w`: Number of concurrent workers (default: scales to your CPU cores).
- `--format`, `-f`: Output formats (e.g., `csv`).
- `--output`, `-o`: Output directory.

**Example:**
```bash
# Analyze a folder of samples using 8 parallel workers
python -m packerscope.cli batch C:\malware\corpus\ -w 8 -f csv -o C:\results\
```

---

### Command: `info`
Provides instantaneous, high-level PE file structure information. It does **not** run the detection pipeline. Useful for quick manual triage.

**Usage:**
```bash
python -m packerscope.cli info <file_path>
```

**Example:**
```bash
python -m packerscope.cli info C:\malware\sample.exe
```


---

## 3. Extending the Framework

PackerScope is highly modular. You can extend its capabilities without modifying the Python code:

### Adding Custom YARA Rules
Drop any `.yar` or `.yara` files into the following directory. They will be automatically compiled and scanned during analysis:
`packerscope/signatures/yara_rules/custom/`

### Adding Custom PEiD Signatures
Append your custom byte patterns to the user database located at:
`packerscope/signatures/peid_userdb.txt`

Syntax:
```ini
[MyCustomPacker v1.0]
signature = 60 E8 ?? 00 00 00 5D 83 ED 06
ep_only = true
```

---

## 4. Understanding Reports

Reports are generated in the `output/reports/` directory (unless overridden by `--output`).

- **JSON (`.json`)**: Best for ingesting into SIEMs or automated databases. Contains every detail about the PE structure and detection confidence.
- **CSV (`.csv`)**: Best for batch scanning. Outputs a single flat spreadsheet row per sample.
- **Markdown / HTML (`.md`, `.html`)**: Best for human analysts. Presents a clean, styled overview of the findings, anomalies, and why the framework made its verdict.

**Verdict Confidence:**
PackerScope aggregates weak signals into a confidence score (0.0 to 1.0) mapping to:
- `NONE`: Score 0.0
- `LOW`: Score 0.0 - 0.40
- `MEDIUM`: Score 0.40 - 0.65
- `HIGH`: Score 0.65 - 0.85
- `VERY_HIGH`: Score 0.85+

---

## 5. Troubleshooting

- **Error: "NT Headers not found"**
  - *Cause*: The provided file is not a valid PE executable, or it is so heavily mutated/corrupted that it cannot be parsed by standard tools.
- **Error: "UnicodeEncodeError in CLI"**
  - *Cause*: Your Windows terminal is using a legacy codepage. Ensure you are using a modern terminal (like Windows Terminal) configured for UTF-8.
- **No Unpacking Occurs**
  - *Cause*: PackerScope only unpacks if the Verdict `is_packed` is `True` and it maps to a supported unpacker (e.g., `UPX`). If it identifies `GENERIC_PACKED`, it may skip unpacking unless a generic plugin is registered.
