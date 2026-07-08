# Provider Manager — Claude · Codex · Gemini

**Version 3.0.0**

A unified, secure desktop tool for managing multiple API-provider configurations for the major coding agents — **Claude Code**, **Codex (OpenAI)**, and **Gemini**. Store your providers once in an encrypted vault, then generate each agent's config file (and switch the active provider) from a single GUI.

> **`manager_v3.py` is the whole app — a single self-contained file.** Keep just `manager_v3.py` and your `providers.enc`; no side-modules are required. (Earlier split-module and v1 editions have been removed.)

---

## ✨ Features

- **Three agents in one place** — manage Claude, Codex, and Gemini providers side by side.
- **Envelope encryption with a daily PIN** — the vault is encrypted with a random data key that is wrapped twice: once under a strong **recovery password**, once under a short **daily PIN**. Unlock day-to-day with the PIN; the password is your recovery. Wrong PINs lock out after 5 tries (password always works and resets the lockout).
- **Preview before write** — see a unified diff of exactly what will change on disk before any config file is touched.
- **Automatic config generation** —
  - **Claude** → `settings.json` (API key + `env` block, theme, effort).
  - **Codex** → `auth.json` + `config.toml` (model provider, wire API, reasoning effort).
  - **Gemini** → `.env` + `settings.json` (merged, preserving your existing keys).
- **Safe writes** — any file that would be overwritten is backed up to `*.bak` first.
- **Import** existing configs from `settings.json`, `auth.json`, or `config.toml` — the API key is captured and stored encrypted.
- **Redacted export** — dump a human-readable YAML of your whole setup with API keys masked to their last 4 chars (for eyeballing/diffing, not importable).
- **Automatic v1 → v2 migration** — opening an old (v1) `providers.enc` offers a one-click upgrade, backing up the original first.

---

## 🗂️ Project Structure / File Map

```
ai-router-config-manager/
│
├── manager_v3.py       ★ The app. Single self-contained file — crypto,
│                          agent-target, export, and GUI logic are all bundled
│                          in here. This is the only file you need to run.
│
├── providers.enc         Encrypted vault (your data — DO NOT SHARE / commit).
├── providers.enc.v1.bak  Local backup from the v1→v2 migration (git-ignored).
│
├── requirements.txt      Python dependencies (cryptography).
├── run.bat               Windows launcher.
├── run.sh                Linux/macOS launcher.
├── README.md             This file.
└── LICENSE
```

### How v3 is organized

`manager_v3.py` is one file with four clearly separated sections:

```
                 manager_v3.py  (single file)
   ┌─────────────┬─────────────┬─────────────┬──────────────┐
   │ 1. crypto   │ 2. targets  │ 3. export   │ 4. GUI + app │
   │ (vault)     │ (agent I/O) │ (redacted)  │  flow        │
   └─────────────┴─────────────┴─────────────┴──────────────┘
                        │
              Claude / Codex / Gemini config files on disk
```

- **Section 1 (crypto)** never touches agent files; it only encrypts/decrypts the vault (`providers.enc`).
- **Section 2 (targets)** never touches the vault; it only reads/writes the agents' own config files. Adding a 4th agent = one new `Target` entry + its generate/read strategy.
- **Section 3 (export)** is a pure, dependency-free view used by the "Export (redacted)" button.
- **Section 4 (GUI)** owns the window, the unlock/migration dialogs, provider add/edit/delete/set-active, and the "read → preview → write" agent panel.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.x** (with `tkinter`, included in standard CPython installs).
- A terminal or command prompt.

### Installation

```bash
pip install -r requirements.txt
```

### Running

**Windows:**

```cmd
python manager_v3.py
```

**Linux / macOS:**

```bash
python3 manager_v3.py
```

> `run.bat` (Windows) and `run.sh` (Linux/macOS) launch `manager_v3.py` for you.

---

## 🧭 Usage

1. **First launch** — set a strong **recovery password**, then a short **daily PIN** (≥ 4 digits). *Do not forget the password* — it's the only recovery path if the PIN gets locked.
2. **Pick an agent** — Claude, Codex, or Gemini (radio buttons at the top).
3. **Add a provider** — click **Add**, then fill in Name, API Key, Base URL, Model (Codex also has Wire API and Reasoning effort).
4. **Set active** — select a provider and click **Set Active**.
5. **Point at the config path** — the agent panel shows the default path (`~/.claude/settings.json`, `~/.codex`, `~/.gemini`); use **Browse** to change it.
6. **Preview → Write** — click **Preview changes** to see the diff, then **Write config** to apply (existing files are backed up first).
7. **Import / Export / Change PIN / Change Password** — available from the bottom bar.

---

## 🔐 Security Model

- **Cipher:** `cryptography` Fernet (AES-128-CBC + HMAC).
- **Key derivation:** PBKDF2-HMAC-SHA256, 200 000 iterations, random 16-byte salt.
- **Envelope:** a random 32-byte **DEK** encrypts the database; the DEK is wrapped separately by the password-derived key and the PIN-derived key.
- **Lockout:** 5 wrong PIN attempts disables PIN unlock until you authenticate with the password.

On-disk vault (`providers.enc`) shape:

```json
{
  "version": 2,
  "kdf": { "salt": "<b64>", "iterations": 200000 },
  "wrap_pw":  "<fernet token encrypting the DEK, key = derive(password)>",
  "wrap_pin": "<fernet token encrypting the DEK, key = derive(pin)>",
  "meta": { "pin_fails": 0, "pin_locked": false },
  "payload": "<fernet token encrypting the JSON database, key = DEK>"
}
```

---

## 🛡️ Sharing Safety

**Never share or commit these:**

- `providers.enc` — your encrypted vault.
- `providers.enc.v1.bak` and any `*.bak` files.
- Generated `settings.json`, `auth.json`, `config.toml`, `.env`.
- `__pycache__/`.

**Safe to share:** `manager_v3.py`, `requirements.txt`, `run.bat`, `run.sh`, `README.md`, `LICENSE`.

---

## 📌 Known Notes

- `requirements.txt` lists only `cryptography`; `tkinter` ships with standard Python.
- On first run against an old (v1) `providers.enc`, the app migrates it to the v2 envelope format and writes a one-time `providers.enc.v1.bak`.

---

## Version History

- **3.0.0** — Single-file edition (`manager_v3.py`). All logic inlined into one self-contained script. Adds Gemini, PIN + password envelope encryption, preview-diff before write, redacted YAML export, and automatic v1 → v2 migration. Import captures the API key from an existing config (stored encrypted). Earlier split-module (v2) and single-password (v1) editions have been removed.
