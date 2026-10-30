# Cyber-Keylogger-Research

A Python-based defensive cybersecurity research project that explores detecting selected keylogger-related indicators through Windows process and executable analysis.

The project collects process information, inspects accessible executable files, checks selected imported APIs and signature information, applies detection rules, and calculates a heuristic risk score to help prioritize processes for further review.

> **Important:** Detection indicators are heuristic. A finding or risk score does not prove that a process is malicious. The published project is intended for defensive research and education; it does not record real keystrokes.

## Project Goals

- Explore Windows process and executable analysis with Python.
- Identify selected keyboard/input-related API imports.
- Apply simple rules to process and executable information.
- Combine configured indicators into an explainable risk score.
- Demonstrate detection safely with synthetic data.

## Features

- **Process scanning:** Enumerates running processes and collects available process details.
- **Executable metadata checks:** Checks whether an executable path is available and whether the file can be accessed.
- **Imported API analysis:** Inspects executable imports for selected keyboard/input-related API indicators.
- **Digital signature analysis:** Checks signature status and signer information where supported.
- **Rule-based findings:** Includes rules for keyboard/input API imports, missing executable paths, and executables located in temporary or Downloads directories.
- **Risk scoring:** Assigns points to configured indicators and produces a LOW, MEDIUM, or HIGH risk category with reasons.
- **Simulated detection demo:** Demonstrates a keyboard/input API detection rule using synthetic process and import data.
- **Tests:** Includes unit tests for detection rules and supporting analysis components.

## How It Works

The process analysis flow is:

1. Enumerate running processes.
2. Collect available process names, IDs, and executable paths.
3. Check executable accessibility and metadata.
4. Inspect executable imports.
5. Retrieve signature information where supported.
6. Apply detection rules to the available evidence.
7. Calculate a risk score and risk category.
8. Display findings and process risk information.

## Detection Rules and Indicators

The current rule set includes:

| Rule | What it checks | Important caveat |
|---|---|---|
| `KEYBOARD_INPUT_API` | Selected keyboard/input-related API imports | An API import alone does not establish malicious behavior. |
| `MISSING_EXECUTABLE` | Whether a process executable path is unavailable | Some legitimate system processes may not expose an accessible path. |
| `SUSPICIOUS_FILE_LOCATION` | Whether an executable path contains a temporary or Downloads directory | Legitimate programs can also run from these locations. |

Signature status is also considered by the risk-scoring logic.

## Risk Scoring

The current scoring logic adds points for configured indicators:

| Indicator | Points |
|---|---:|
| Keyboard/input API imports | +5 |
| Missing executable path | +5 |
| Executable in a temporary or Downloads location | +5 |
| Unsigned executable | +5 |
| Invalid or untrusted signature status | +20 |

The same rule is counted only once per process for the applicable rule.

Risk categories:

| Score | Category |
|---|---|
| 0–14 | LOW |
| 15–29 | MEDIUM |
| 30–100 | HIGH |

The score is capped at 100. These values are project-specific heuristics—not calibrated malware probabilities or a verdict about whether a process is malicious.

## Technology Stack

- Python
- `psutil` — process enumeration and information
- `pefile` — PE executable/import analysis
- `pyelftools` — ELF analysis support in the executable-analysis module
- PowerShell Authenticode checks for Windows signature analysis
- `unittest` — tests

## Repository Structure

```text
Cyber-Keylogger-Research/
├── demo.py
├── demo_detection.py
├── run_demo.py
├── requirements.txt
├── src/
│   ├── main.py
│   └── detection/
│       ├── executable_analyzer.py
│       ├── file_metadata.py
│       ├── findings.py
│       ├── indicators.py
│       ├── models.py
│       ├── process_scanner.py
│       ├── risk_scoring.py
│       ├── rule_engine.py
│       ├── rules.py
│       └── signature_analyzer.py
└── tests/
    ├── consent_demo.py
    ├── test_api_import.py
    ├── test_file_location_rule.py
    ├── test_file_metadata.py
    ├── test_keyboard_api_rule.py
    ├── test_keyboard_indicators.py
    ├── test_pe_analysis.py
    ├── test_risk_debug.py
    ├── test_risk_scoring.py
    ├── test_rules.py
    └── test_signature.py
```

## Getting Started

### Requirements

- Python 3
- Windows is recommended for the process-scanning and Windows Authenticode-signature features.
- PowerShell is used for Windows signature checks.
- Some process details may require elevated permissions.

### 1. Clone the Repository

```bash
git clone https://github.com/Lavyansh2007/Cyber-Keylogger-Research.git
cd Cyber-Keylogger-Research
```

### 2. Create and Activate a Virtual Environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation due to its execution policy, activate the environment using Command Prompt instead:

```bat
venv\Scripts\activate.bat
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

### Run the Simulated Detection Demo

```bash
python demo_detection.py
```

This demo supplies synthetic process information and a synthetic `GetAsyncKeyState` import to the keyboard/input API rule. It does not launch a keylogger or capture keystrokes.

### Run the Process Analysis Engine

```bash
python -m src.detection.rule_engine
```

This scans accessible running processes and analyzes available executable information. Output depends on the operating system, process permissions, and which executable files can be accessed.

### Run the Combined Demo

```bash
python run_demo.py
```

The combined demo runs unit tests, scans running processes, performs simulated detection, and prepares a report. It may also display a graphical report window. Because it scans the current system, review its output before sharing it.

### Run the Unit Tests

```bash
python -m unittest discover -s tests
```

## Limitations

- Imported APIs are indicators, not proof of malicious activity.
- Legitimate applications may use keyboard/input-related APIs.
- Some processes may not expose an executable path or may deny access.
- Signature analysis is platform-dependent.
- Risk scores are heuristic and depend on the configured rules and weights.
- The project is not a comprehensive antivirus or malware-detection product.
- The project does not record real keystrokes.

## Ethical Use

This project is intended for defensive cybersecurity education, research, and authorized analysis.

Use process-analysis features only on systems you own or have permission to analyze. Do not use the project to monitor other people or collect private input without their informed consent.

## Future Improvements

- Expand detection rules while reducing false positives.
- Evaluate and calibrate risk-score weights against documented test cases.
- Improve structured reporting and explainability.
- Add more safe test cases.
- Improve platform-specific handling and documentation.

## Author

**Lavyansh Tyagi**

- GitHub: [@Lavyansh2007](https://github.com/Lavyansh2007)
- Repository: [Cyber-Keylogger-Research](https://github.com/Lavyansh2007/Cyber-Keylogger-Research)
