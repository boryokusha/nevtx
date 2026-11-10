# nevtx 🔍

> **The modern, lightweight Windows Event Log (`.evtx`) TUI viewer and DFIR triage tool for Linux.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-brightgreen.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)]()
[![Built with Textual](https://img.shields.io/badge/Built%20with-Textual-teal.svg)](https://textual.textualize.io/)

Designed specifically for **DFIR (Digital Forensics & Incident Response)** analysts, SOC investigators, and security researchers who daily-drive Linux and need a fast, keyboard-centric way to inspect Windows Event Logs without Wine, Windows VMs, or sluggish web engines.

---

## ⚡ Killer Features

- **⚡ Blazing Fast Rust Engine:** Powered by high-performance Rust `.evtx` bindings with low memory footprint (~40MB RAM).
- **🎯 Automated MITRE ATT&CK Triage:** Detects ransomware commands (`T1490`), credential dumping (`T1003`), obfuscated PowerShell (`T1059.001`), and log clearing (`T1070.001`).
- **🛡️ Visual Threat Ratio Bar:** Instant overview of attack distribution (`% Threats vs Clean Events`) in your log files.
- **🚨 Anti-Forensics Log Gap Detector:** Automatically identifies suspicious gaps of silence in event streams where an attacker stopped logging services or cleared events.
- **🔓 On-The-Fly Base64 Decoder:** Automatically extracts, decodes, and presents obfuscated PowerShell commands in cleartext.
- **📁 Multi-File Folder & Unified Timeline:** Open an entire directory (`nevtx ./logs/`) and switch between files or correlate events across a **Unified Merged Timeline**.
- **⌨️ Keyboard-Centric & Vim-Friendly:** Navigate with `j`/`k`, search instantly with `/`, and filter threat categories using quick keys `1`-`6`.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/boryokusha/nevtx.git
cd nevtx

# Create virtual environment and install in editable mode
python3 -m venv .venv
source .venv/bin/activate  # (or .venv/bin/activate.fish if using fish shell)
pip install -e .
```

### Usage

```bash
# 1. Inspect a single .evtx file
nevtx /path/to/Security.evtx

# 2. Inspect an entire folder of logs with unified timeline & file switcher
nevtx ~/Documents/evtx_files/

# 3. Test immediately with built-in realistic DFIR attack scenario (No EVTX file required!)
nevtx --demo
```

---

## ⌨️ Keybindings & Controls

| Key | Action |
| :--- | :--- |
| `↑` / `↓` or `k` / `j` | Navigate event rows |
| `/` | Focus instant search bar (regex, event id, command, username) |
| `Esc` | Unfocus search / return to event table |
| `1` | Show **All** Events |
| `2` | 🚨 Show **Threats / MITRE Matches Only** |
| `3` | 🔑 Show **Failed Logons (4625)** |
| `4` | 💻 Show **Process Creation (4688)** |
| `5` | ⚡ Show **PowerShell (4104)** |
| `6` | 🧹 Show **Audit Log Cleared (1102 / 104)** |
| `q` | Exit application |

---

## 🗺️ Roadmap

- [x] **v0.1.0:** Core Rust engine, Textual TUI, MITRE engine, Base64 decoder, Log Gap detector, Multi-file switcher, `--demo` mode.
- [ ] **v0.2.0:** One-click CSV / JSONL / Markdown triage report export (`e` hotkey).
- [ ] **v0.3.0:** Standalone single binary release (`PyInstaller`) & Arch Linux AUR package.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
