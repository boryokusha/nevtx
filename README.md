# nevtx 🔍

> **The modern, lightweight Windows Event Log (`.evtx`) TUI viewer and triage tool for Linux.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-brightgreen.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)]()
[![Built with Textual](https://img.shields.io/badge/Built%20with-Textual-teal.svg)](https://textual.textualize.io/)

Designed specifically for **DFIR (Digital Forensics & Incident Response)** analysts, SOC investigators, and security researchers who daily-drive Linux and need a fast, keyboard-centric way to inspect Windows Event Logs without Wine or clunky web engines.

---

## ⚡ Key Highlights

- **Lightweight & Fast:** Low RAM consumption (~40MB), powered by an ultra-fast Rust-based parsing core.
- **Split-Screen Inspector:** Live DataTable alongside a real-time syntax-highlighted JSON/XML inspector.
- **Instant Search:** Fuzzy search across Event IDs, Providers, Computers, and Process Command Lines.
- **SSH Ready:** Works seamlessly over remote SSH sessions in your native terminal (Alacritty, Kitty, WezTerm, etc.).
- **Vim-Friendly:** Navigate effortlessly using keyboard shortcuts.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nevtx.git
cd nevtx

# Install in development mode or via pip
pip install -e .
```

### Usage

```bash
nevtx /path/to/Security.evtx
```

---

## ⌨️ Keybindings

| Key | Action |
| :--- | :--- |
| `↑` / `↓` or `k` / `j` | Navigate event rows |
| `/` | Focus search bar |
| `Esc` | Unfocus search / Return to table |
| `q` | Exit application |

---

## 🗺️ Roadmap & Upcoming Features

- [x] **Phase 1:** Core Rust parser & interactive Textual TUI prototype.
- [ ] **Phase 2:** On-the-fly Base64/Hex decoder (`d` hotkey) for obfuscated PowerShell & command lines.
- [ ] **Phase 3:** Pre-built DFIR triage filters (4624, 4625, 4688, 7045, 1102).
- [ ] **Phase 4:** Multi-EVTX timeline correlation (`nevtx ./logs/`).
- [ ] **Phase 5:** Standalone single binary release (`PyInstaller`) & Arch Linux AUR package.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
