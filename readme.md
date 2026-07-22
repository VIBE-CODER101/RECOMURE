# ReconFlow

<p align="center">
  <strong>A professional, cross-platform command-line workflow manager and system bootstrapper for authorized reconnaissance.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Alpine%20%7C%20Windows%20%7C%20iOS%20(iSH)-success.svg" alt="Platform Support">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License: MIT">
</p>

---

## ⚠️ Authorized Use Notice

**ReconFlow is a workflow organizer and file analyzer.** It does NOT perform any intrusive security testing, exploitation, or unauthorized scraping. Users are solely responsible for ensuring they have explicit authorization to assess any target domain or system. The author and maintainers disclaim any liability for misuse.

---

## 📖 Overview

ReconFlow is a mature, production-grade Python application designed to automate and organize the tedious parts of reconnaissance workflows. It functions as a dual-purpose tool:

1. **System Bootstrapper:** Automatically detects your operating system (Debian, Alpine, iSH on iOS, or Windows) and installs required dependencies (like `curl`, `git`, `sqlite`, and headless `chromium`).
2. **Reconnaissance Engine:** Takes target domains, fetches root pages, parses and categorizes URLs, downloads and analyzes JavaScript files for endpoints, captures headless browser screenshots, and generates comprehensive multi-format reports.

All data is neatly organized into a timestamped workspace directory with SQLite-backed checkpointing, allowing you to resume interrupted runs gracefully.

## ✨ Key Features

* **Cross-Platform Bootstrapper:** One command (`--bootstrap`) sets up your environment using `apt-get`, `apk`, or `winget`.
* **iSH (iPhone) Support:** Specifically detects iSH, bypasses `sudo` requirements, and skips unsupported packages (like Chromium) automatically.
* **Rich Terminal UI:** Beautiful animated banners, live progress bars, tables, and syntax-highlighted logging.
* **Automated Workspace:** Creates a strict directory structure (`recon/`, `javascript/`, `screenshots/`, `reports/`, etc.) for every run.
* **JavaScript Analysis:** Downloads `.js` files, extracts endpoint-like references, source maps, and license headers.
* **Screenshot Capture:** Uses headless Chromium to take full-page screenshots of target domains for manual inspection (where supported).
* **Resumable Checkpoints:** SQLite tracks stage completion. If you crash or `CTRL+C`, use `--resume` to pick up exactly where you left off.
* **Multi-Format Reporting:** Generates JSON, Markdown, CSV, and an interactive dark-mode HTML dashboard.
* **Threaded & Cached:** Configurable thread pools, rate limiting, and disk-based caching for maximum performance.

---

## 🚀 Installation

ReconFlow is a single standalone Python file. 

1. Ensure you have Python 3.12+ installed.
2. Download `reconflow.py`.
3. Install the required Python libraries:
   ```bash
   pip install rich
   # Optional but recommended:
   pip install requests pyyaml
   ```

### Bootstrapping Your System (Optional but recommended)

If you are on a fresh server or environment, ReconFlow can install all necessary system tools for you.

**On Linux / iSH:**
```bash
sudo python3 reconflow.py --bootstrap
# (On iSH for iPhone, sudo is not needed as you are already root)
```

**On Windows:**
*(Run PowerShell as Administrator)*
```powershell
python reconflow.py --bootstrap
```

---

## 💻 Usage

### Basic Scan
To run a standard workflow against a domain:
```bash
python3 reconflow.py --domain example.com
```

### Multiple Domains
You can pass `--domain` multiple times or use a file:
```bash
python3 reconflow.py --domain example.com --domain test.com
python3 reconflow.py --domains-file targets.txt
```

### Specifying Output Directory
By default, ReconFlow creates a `workspace/` directory. You can change this:
```bash
python3 reconflow.py --domain example.com --output ~/recon_results
```

### Resuming an Interrupted Run
If a run is interrupted, find the Run ID (e.g., `run_20231025_143000`) in your workspace directory and resume it:
```bash
python3 reconflow.py --domain example.com --resume
```

---

## ⚙️ Configuration

ReconFlow can be configured via CLI arguments, configuration files (`reconflow.yaml` or `reconflow.json`), or environment variables.

### Profiles
You can select predefined profiles using `--profile`:
* `default`: Balanced threads, downloads JS, takes screenshots.
* `fast`: High threads, skips JS download and screenshots for quick URL discovery.
* `deep`: Low threads, high timeout, rate-limited, thorough analysis.

### CLI Arguments
| Argument | Description |
| :--- | :--- |
| --domain | Target domain (can be repeated). |
| --domains-file | File containing list of domains. |
| --output | Workspace output directory. |
| --profile | Configuration profile (`default`, `fast`, `deep`). |
| --threads | Number of concurrent worker threads. |
| --timeout | HTTP request timeout in seconds. |
| --rate-limit | Max requests per second (0 = unlimited). |
| --delay | Delay between requests in seconds. |
| --proxy | HTTP/HTTPS proxy URL. |
| --user-agent | Custom User-Agent string. |
| --no-screenshots| Disable Chromium screenshot capture. |
| --no-cache | Disable HTTP/Analysis caching. |
| --bootstrap | Install required system tools and exit. |
| --self-test | Run built-in smoke tests and exit. |
| --diagnostics | Check system environment, permissions, and disk space. |

---

## 📂 Workspace Structure

Every run creates a timestamped directory inside your output folder:

```text
workspace/
└── run_20231025_143000/
    ├── logs/               # Rotating text and JSON logs
    ├── cache/              # HTTP response and JS analysis caches
    ├── database/           # SQLite database (reconflow.db)
    ├── recon/              # Categorized URL lists (all_urls.txt, js_urls.txt, etc.)
    ├── javascript/         # Downloaded and analyzed .js files
    ├── screenshots/        # Headless Chromium webpage captures
    ├── html/               # Interactive HTML dashboard report
    ├── markdown/           # Markdown summary report
    ├── json/               # Machine-readable JSON report
    └── csv/                # CSV statistics report
```

---

## 📊 Reports

ReconFlow generates comprehensive reports at the end of every run. The standout feature is the **HTML Dashboard** (`html/report.html`), which provides:
* Statistics cards (elapsed time, success rate, throughput).
* Interactive, filterable tables for discovered URLs and JS endpoints.
* A category distribution chart.
* A stage execution timeline.

---

## 🧪 Diagnostics & Self-Tests

To verify your environment is set up correctly:
```bash
python3 reconflow.py --diagnostics
```
This checks Python version, platform, write permissions, disk space, and database connectivity.

To run internal smoke tests verifying the parser, URL processor, and database logic:
```bash
python3 reconflow.py --self-test
```

---

## 📜 License

This project is licensed under the MIT License. See the `__license__` metadata within the source file for details.
