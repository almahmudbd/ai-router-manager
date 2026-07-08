#!/usr/bin/env python3
"""
Provider Manager v3 — single-file edition (Claude · Codex · Gemini).

Everything the app needs lives in THIS one file. Just keep manager_v3.py plus
your encrypted providers.enc; no pv_*.py side-modules are required anymore.

What it does (same purpose as manager.py, rebuilt):
  * Envelope encryption with a short daily PIN and a recovery password.
      - A random 32-byte DEK encrypts the database.
      - The DEK is wrapped by BOTH the password and the PIN; either unlocks.
      - Wrong PIN 5x -> PIN locks; the password always works and resets it.
  * Per-agent Read -> Preview (diff) -> Write for Claude, Codex, Gemini.
      - Writes back up any existing config file(s) first (.bak, .bak.2, ...).
      - Gemini writes ~/.gemini/.env and MERGES settings.json (keeps OAuth etc).
  * Import an existing agent config (pulls its API key too, stored encrypted).
  * Export a redacted YAML view (keys masked) for eyeballing/diffing — not
    importable, never leaks secrets.

The original manager.py and providers.enc are left untouched. On first open of a
legacy (v1) providers.enc it offers to migrate to the v2 envelope format,
backing up the original first (providers.enc.v1.bak).

Only third-party dependency: `cryptography`  (pip install cryptography)
"""

import difflib
import json
import os
import shutil
import types
from base64 import b64encode, b64decode, urlsafe_b64encode
from dataclasses import dataclass

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ===========================================================================
# Section 1 — Envelope encryption (was pv_crypto)
# ===========================================================================
PBKDF2_ITERATIONS = 200000
LEGACY_SALT = b"pr0v_m4ng3r_2024_s@lt!"
MAX_PIN_FAILS = 5


class VaultError(Exception):
    """Base class for vault problems (missing/corrupt file, etc.)."""


class WrongCredential(VaultError):
    """The supplied password or PIN did not unwrap the DEK."""


class PinLocked(VaultError):
    """The PIN is disabled (no PIN set) or locked after too many failures."""


def _derive(secret: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a urlsafe-base64 Fernet key from a secret + salt."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return urlsafe_b64encode(kdf.derive(secret.encode()))


def _wrap(dek_b64: bytes, secret: str, salt: bytes, iterations: int) -> str:
    """Encrypt the DEK under a secret-derived key; return a text token."""
    key = _derive(secret, salt, iterations)
    return Fernet(key).encrypt(dek_b64).decode()


def _unwrap(token: str, secret: str, salt: bytes, iterations: int) -> bytes:
    """Recover the DEK bytes from a wrap token; raise WrongCredential on failure."""
    key = _derive(secret, salt, iterations)
    try:
        return Fernet(key).decrypt(token.encode())
    except (InvalidToken, ValueError, TypeError):
        raise WrongCredential("Wrong password or PIN.")


def _new_dek() -> bytes:
    """A fresh random DEK, encoded as a valid Fernet key (urlsafe-b64 of 32 bytes)."""
    return urlsafe_b64encode(os.urandom(32))


def _salt_of(vault: dict) -> tuple[bytes, int]:
    kdf = vault["kdf"]
    return b64decode(kdf["salt"]), int(kdf["iterations"])


def new_vault(password: str, pin: str | None = None, db: dict | None = None) -> dict:
    """Create a fresh v2 vault with a random DEK and salt."""
    if db is None:
        db = {}
    salt = os.urandom(16)
    dek_b64 = _new_dek()
    vault: dict = {
        "version": 2,
        "kdf": {"salt": b64encode(salt).decode(), "iterations": PBKDF2_ITERATIONS},
        "wrap_pw": _wrap(dek_b64, password, salt, PBKDF2_ITERATIONS),
        "wrap_pin": None,
        "meta": {"pin_fails": 0, "pin_locked": False},
        "payload": Fernet(dek_b64).encrypt(json.dumps(db, indent=2).encode()).decode(),
    }
    if pin:
        set_pin(vault, dek_b64, pin)
    return vault


def save_vault(path: str, vault: dict) -> None:
    """Write the vault dict as JSON text (utf-8)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)


def load_vault(path: str) -> dict:
    """Read and parse a v2 vault file."""
    if not os.path.exists(path):
        raise VaultError(f"Vault not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            raise VaultError("Vault file is empty.")
        vault = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        raise VaultError(f"Cannot read vault: {e}")
    if not isinstance(vault, dict) or vault.get("version") != 2:
        raise VaultError("Not a v2 vault file.")
    vault.setdefault("meta", {"pin_fails": 0, "pin_locked": False})
    return vault


def _decrypt_payload(vault: dict, dek_b64: bytes) -> dict:
    token = vault.get("payload") or ""
    if not token:
        return {}
    try:
        return json.loads(Fernet(dek_b64).decrypt(token.encode()).decode())
    except (InvalidToken, ValueError) as e:
        raise VaultError(f"Payload decryption failed: {e}")


def unlock_with_pin(vault: dict, pin: str) -> tuple[bytes, dict]:
    """Unlock using the PIN. Mutates vault's failure counters; caller must save."""
    meta = vault["meta"]
    if meta.get("pin_locked") or not vault.get("wrap_pin"):
        raise PinLocked("PIN is disabled or locked. Use your password.")
    salt, iterations = _salt_of(vault)
    try:
        dek_b64 = _unwrap(vault["wrap_pin"], pin, salt, iterations)
    except WrongCredential:
        meta["pin_fails"] = int(meta.get("pin_fails", 0)) + 1
        if meta["pin_fails"] >= MAX_PIN_FAILS:
            meta["pin_locked"] = True
            raise PinLocked("Too many wrong PINs. PIN locked — use your password.")
        raise
    meta["pin_fails"] = 0
    meta["pin_locked"] = False
    return dek_b64, _decrypt_payload(vault, dek_b64)


def unlock_with_password(vault: dict, password: str) -> tuple[bytes, dict]:
    """Unlock using the recovery password; resets any PIN lockout."""
    salt, iterations = _salt_of(vault)
    dek_b64 = _unwrap(vault["wrap_pw"], password, salt, iterations)
    vault["meta"]["pin_fails"] = 0
    vault["meta"]["pin_locked"] = False
    return dek_b64, _decrypt_payload(vault, dek_b64)


def set_pin(vault: dict, dek: bytes, new_pin: str) -> None:
    """Re-wrap the DEK under a new PIN and clear the lockout."""
    salt, iterations = _salt_of(vault)
    vault["wrap_pin"] = _wrap(dek, new_pin, salt, iterations)
    vault["meta"]["pin_fails"] = 0
    vault["meta"]["pin_locked"] = False


def clear_pin(vault: dict) -> None:
    """Disable PIN unlock entirely."""
    vault["wrap_pin"] = None
    vault["meta"]["pin_fails"] = 0
    vault["meta"]["pin_locked"] = False


def change_password(vault: dict, dek: bytes, new_password: str) -> None:
    """Re-wrap the DEK under a new password. Keeps the existing salt (shared with PIN)."""
    salt, iterations = _salt_of(vault)
    vault["wrap_pw"] = _wrap(dek, new_password, salt, iterations)


def write_payload(vault: dict, dek: bytes, db: dict) -> None:
    """Re-encrypt the DB under the DEK and store it as the payload."""
    vault["payload"] = Fernet(dek).encrypt(json.dumps(db, indent=2).encode()).decode()


def is_pin_available(vault: dict) -> bool:
    """True when a PIN is set and not locked."""
    return bool(vault.get("wrap_pin")) and not vault["meta"].get("pin_locked")


def _v1_backup_path(path: str) -> str:
    """Return a non-clobbering backup path: path.v1.bak, .v1.bak.2, ..."""
    base = path + ".v1.bak"
    if not os.path.exists(base):
        return base
    n = 2
    while os.path.exists(f"{base}.{n}"):
        n += 1
    return f"{base}.{n}"


def migrate_v1(path: str, password: str) -> dict:
    """Decrypt an old v1 file, back it up, and return a NEW v2 vault (unsaved)."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    key = urlsafe_b64encode(
        PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                   salt=LEGACY_SALT, iterations=PBKDF2_ITERATIONS).derive(password.encode())
    )
    try:
        token = b64decode(raw.encode())
        db = json.loads(Fernet(key).decrypt(token).decode())
    except (InvalidToken, ValueError, TypeError):
        raise WrongCredential("Wrong password for legacy database.")
    backup = _v1_backup_path(path)
    with open(backup, "w", encoding="utf-8") as f:
        f.write(raw)
    return new_vault(password, pin=None, db=db)


def detect_version(path: str) -> int:
    """0 if missing/empty, 2 if a v2 vault, else 1 (assume legacy)."""
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except OSError:
        return 0
    if not raw:
        return 0
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and obj.get("version") == 2:
            return 2
    except json.JSONDecodeError:
        pass
    return 1


pv_crypto = types.SimpleNamespace(
    MAX_PIN_FAILS=MAX_PIN_FAILS,
    VaultError=VaultError, WrongCredential=WrongCredential, PinLocked=PinLocked,
    new_vault=new_vault, save_vault=save_vault, load_vault=load_vault,
    unlock_with_pin=unlock_with_pin, unlock_with_password=unlock_with_password,
    set_pin=set_pin, clear_pin=clear_pin, change_password=change_password,
    write_payload=write_payload, is_pin_available=is_pin_available,
    migrate_v1=migrate_v1, detect_version=detect_version,
)


# ===========================================================================
# Section 2 — Agent config targets: read / preview / write (was pv_targets)
# ===========================================================================
HOME = os.environ.get("USERPROFILE") or os.environ.get("HOME") or os.path.expanduser("~")


@dataclass
class Target:
    id: str
    display_name: str
    path_key: str
    default_path: str
    path_kind: str  # "file" or "dir"


_TARGETS: list[Target] = [
    Target("claude", "Claude", "claude_settings",
           os.path.join(HOME, ".claude", "settings.json"), "file"),
    Target("codex", "Codex (OpenAI)", "codex_dir",
           os.path.join(HOME, ".codex"), "dir"),
    Target("gemini", "Gemini", "gemini_settings",
           os.path.join(HOME, ".gemini"), "dir"),
]
_BY_ID = {t.id: t for t in _TARGETS}


def all_targets() -> list[Target]:
    return list(_TARGETS)


def get_target(target_id: str) -> Target:
    if target_id not in _BY_ID:
        raise KeyError(f"Unknown target: {target_id}")
    return _BY_ID[target_id]


def _mask(key: str) -> str:
    if not key:
        return ""
    return ("•" * 4 + key[-4:]) if len(key) >= 4 else "•" * len(key)


# ---- generators (pure): return {relative_filename: content_text} ----------

def _gen_claude(name: str, prov: dict) -> dict[str, str]:
    key = prov.get("apiKey", "")
    url = prov.get("baseUrl", "")
    model = prov.get("model", "")
    lines = ["{"]
    lines.append(f'  "apiKeyHelper": "echo \'\'\' + \'{key}\' + \'\'\'",')
    lines.append('  "env": {')
    lines.append(f'    "ANTHROPIC_API_KEY": "{key}",')
    lines.append(f'    "ANTHROPIC_BASE_URL": "{url}",')
    lines.append('    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"')
    if model:
        lines[-1] += ","
        lines.append(f'    "ANTHROPIC_MODEL": "{model}"')
    lines.append("  },")
    lines.append('  "permissions": { "allow": [], "deny": [], "defaultMode": "default" },')
    lines.append('  "theme": "dark",')
    lines.append('  "effortLevel": "high"')
    lines.append("}")
    return {"settings.json": "\n".join(lines)}


def _gen_codex(name: str, prov: dict) -> dict[str, str]:
    key = prov.get("apiKey", "")
    model = prov.get("model", "")
    reason = prov.get("model_reasoning_effort") or "high"
    url = prov.get("baseUrl", "")
    wire = prov.get("wire_api") or "responses"
    auth = json.dumps({"OPENAI_API_KEY": key}, indent=2)
    toml_lines = [
        f'model_provider = "{name}"',
        f'model = "{model}"',
        f'model_reasoning_effort = "{reason}"',
        "disable_response_storage = true",
        'preferred_auth_method = "apikey"',
        "",
        f"[model_providers.{name}]",
        f'name = "{name}"',
        f'base_url = "{url}"',
        f'wire_api = "{wire}"',
    ]
    return {"auth.json": auth, "config.toml": "\n".join(toml_lines)}


def _gemini_settings_merged(path_dir: str) -> dict:
    """Read existing ~/.gemini/settings.json and set API-key auth, preserving other keys."""
    settings_path = os.path.join(path_dir, "settings.json")
    data: dict = {}
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                loaded = json.loads(f.read() or "{}")
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}
    data.setdefault("security", {})
    if not isinstance(data["security"], dict):
        data["security"] = {}
    data["security"].setdefault("auth", {})
    if not isinstance(data["security"]["auth"], dict):
        data["security"]["auth"] = {}
    data["security"]["auth"]["selectedType"] = "gemini-api-key"
    return data


def _gen_gemini(name: str, prov: dict, path_dir: str = "") -> dict[str, str]:
    key = prov.get("apiKey", "")
    url = prov.get("baseUrl", "")
    model = prov.get("model", "")
    env_lines = [f"GEMINI_API_KEY={key}"]
    if url:
        env_lines.append(f"GOOGLE_GEMINI_BASE_URL={url}")
    if model:
        env_lines.append(f"GEMINI_MODEL={model}")
    settings = _gemini_settings_merged(path_dir)
    return {
        ".env": "\n".join(env_lines) + "\n",
        "settings.json": json.dumps(settings, indent=2),
    }


_STRATEGIES = {"claude": _gen_claude, "codex": _gen_codex, "gemini": _gen_gemini}


def generate(target_id: str, provider_name: str, provider: dict,
             path: str = "") -> dict[str, str]:
    """Return {relative_filename: content} that would be written. Pure (no disk writes)."""
    if target_id == "gemini":
        return _gen_gemini(provider_name, provider, path)
    return _STRATEGIES[target_id](provider_name, provider)


# ---- reading current on-disk state ----------------------------------------

def _read_claude(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.loads(f.read() or "{}")
        env = data.get("env", {}) if isinstance(data, dict) else {}
        url = env.get("ANTHROPIC_BASE_URL", "")
        key = env.get("ANTHROPIC_API_KEY", "")
        return {"provider_guess": url or None, "baseUrl": url,
                "model": env.get("ANTHROPIC_MODEL", ""),
                "apiKey": key, "apiKey_masked": _mask(key), "raw_ok": True}
    except (OSError, json.JSONDecodeError):
        return {"provider_guess": None, "baseUrl": "", "model": "",
                "apiKey": "", "apiKey_masked": "", "raw_ok": False}


def _parse_toml_value(line: str) -> str:
    return line.split("=", 1)[1].strip().strip('"') if "=" in line else ""


def _read_codex(path: str) -> dict | None:
    config_path = os.path.join(path, "config.toml")
    auth_path = os.path.join(path, "auth.json")
    if not os.path.exists(config_path) and not os.path.exists(auth_path):
        return None
    url = model = provider = ""
    try:
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                for line in f.read().splitlines():
                    s = line.strip()
                    if s.startswith("base_url ="):
                        url = _parse_toml_value(s)
                    elif s.startswith("model ="):
                        model = _parse_toml_value(s)
                    elif s.startswith("model_provider ="):
                        provider = _parse_toml_value(s)
        key = ""
        if os.path.exists(auth_path):
            with open(auth_path, "r", encoding="utf-8") as f:
                key = json.loads(f.read() or "{}").get("OPENAI_API_KEY", "")
        return {"provider_guess": provider or url or None, "baseUrl": url,
                "model": model, "apiKey": key, "apiKey_masked": _mask(key),
                "raw_ok": True}
    except (OSError, json.JSONDecodeError):
        return {"provider_guess": None, "baseUrl": "", "model": "",
                "apiKey": "", "apiKey_masked": "", "raw_ok": False}


def _read_gemini(path: str) -> dict | None:
    env_path = os.path.join(path, ".env")
    if not os.path.exists(env_path):
        return None
    url = model = key = ""
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f.read().splitlines():
                s = line.strip()
                if s.startswith("GEMINI_API_KEY="):
                    key = s.split("=", 1)[1]
                elif s.startswith("GOOGLE_GEMINI_BASE_URL="):
                    url = s.split("=", 1)[1]
                elif s.startswith("GEMINI_MODEL="):
                    model = s.split("=", 1)[1]
        return {"provider_guess": url or ("gemini-api-key" if key else None),
                "baseUrl": url, "model": model,
                "apiKey": key, "apiKey_masked": _mask(key), "raw_ok": True}
    except OSError:
        return {"provider_guess": None, "baseUrl": "", "model": "",
                "apiKey": "", "apiKey_masked": "", "raw_ok": False}


_READERS = {"claude": _read_claude, "codex": _read_codex, "gemini": _read_gemini}


def read_current(target_id: str, path: str, reveal: bool = False) -> dict | None:
    """Best-effort read of the live config. Never raises.

    The full API key is included only when reveal=True (used for import). For
    on-screen display callers leave reveal=False, so only apiKey_masked is set.
    """
    try:
        result = _READERS[target_id](path)
    except Exception:
        result = {"provider_guess": None, "baseUrl": "", "model": "",
                  "apiKey": "", "apiKey_masked": "", "raw_ok": False}
    if result is None:
        return None
    if not reveal:
        result.pop("apiKey", None)
    return result


# ---- writing (with backup) and diff preview -------------------------------

def _target_file_path(target: Target, path: str, relname: str) -> str:
    if target.path_kind == "file":
        return path
    return os.path.join(path, relname)


def _backup(dest: str) -> None:
    if not os.path.exists(dest):
        return
    bak = dest + ".bak"
    if os.path.exists(bak):
        n = 2
        while os.path.exists(f"{bak}.{n}"):
            n += 1
        bak = f"{bak}.{n}"
    shutil.copy2(dest, bak)


def write(target_id: str, provider_name: str, provider: dict, path: str) -> list[str]:
    """Generate, back up any existing files, then write. Returns abs paths written."""
    target = get_target(target_id)
    files = generate(target_id, provider_name, provider, path)
    written: list[str] = []
    if target.path_kind == "dir":
        os.makedirs(path, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    for relname, content in files.items():
        dest = _target_file_path(target, path, relname)
        _backup(dest)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)
        written.append(os.path.abspath(dest))
    return written


def diff_preview(target_id: str, path: str, provider_name: str, provider: dict) -> str:
    """Unified diff of current on-disk content vs generated content, per file."""
    target = get_target(target_id)
    files = generate(target_id, provider_name, provider, path)
    chunks: list[str] = []
    for relname, new_content in files.items():
        dest = _target_file_path(target, path, relname)
        old = ""
        if os.path.exists(dest):
            try:
                with open(dest, "r", encoding="utf-8") as f:
                    old = f.read()
            except OSError:
                old = ""
        label = os.path.basename(dest)
        diff = difflib.unified_diff(
            old.splitlines(), new_content.splitlines(),
            fromfile=f"{label} (current)", tofile=f"{label} (new)", lineterm="")
        body = "\n".join(diff)
        chunks.append(body if body else f"# {label}: no changes")
    return "\n\n".join(chunks)


pv_targets = types.SimpleNamespace(
    Target=Target, all_targets=all_targets, get_target=get_target,
    read_current=read_current, generate=generate, write=write,
    diff_preview=diff_preview,
)


# ===========================================================================
# Section 3 — Redacted YAML export (was pv_export)
# ===========================================================================
_EXPORT_HEADER = "# Redacted export — API keys are masked. For reading/diffing only, NOT for import.\n"
_SECRET_HINTS = ("apikey", "api_key", "token", "secret", "password")
_EXPORT_SECTIONS = ("claude", "codex", "gemini")


def redact_secret(value: str) -> str:
    """Mask a secret, keeping only the last 4 chars as a hint."""
    if value is None:
        return ""
    value = str(value)
    if len(value) < 4:
        return "•" * len(value)
    return "••••" + value[-4:]


def _is_secret_key(key: str) -> bool:
    k = key.lower()
    return any(hint in k for hint in _SECRET_HINTS)


def _scalar(value) -> str:
    """Render a scalar as YAML, quoting when needed."""
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    if s == "":
        return '""'
    needs_quote = (s[0] in "!&*?|>%@`\"'#[]{}," or ": " in s or s.endswith(":")
                   or s.strip() != s or s in ("true", "false", "null", "~"))
    if needs_quote:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def _emit_provider(name: str, prov: dict, active: str, indent: str) -> list[str]:
    marker = "  # <- active" if name == active else ""
    lines = [f"{indent}{_scalar(name)}:{marker}"]
    child = indent + "  "
    for key, val in prov.items():
        shown = redact_secret(val) if _is_secret_key(key) else val
        lines.append(f"{child}{key}: {_scalar(shown)}")
    return lines


def _emit_section(name: str, section: dict) -> list[str]:
    active = section.get("active", "") or ""
    providers = section.get("providers", {}) or {}
    lines = [f"{name}:"]
    lines.append(f"  active: {_scalar(active)}")
    lines.append("  providers:")
    if not providers:
        lines.append("    {}")
    for pname, prov in providers.items():
        lines.extend(_emit_provider(pname, prov if isinstance(prov, dict) else {},
                                    active, "    "))
    return lines


def to_redacted_yaml(db: dict) -> str:
    """Produce the redacted YAML text for a decrypted DB dict."""
    out: list[str] = [_EXPORT_HEADER.rstrip("\n"), ""]
    if db.get("version") is not None:
        out.append(f"version: {_scalar(db['version'])}")
        out.append("")
    for name in _EXPORT_SECTIONS:
        if name in db and isinstance(db[name], dict):
            out.extend(_emit_section(name, db[name]))
            out.append("")
    paths = db.get("paths")
    if isinstance(paths, dict) and paths:
        out.append("paths:")
        for k, v in paths.items():
            out.append(f"  {k}: {_scalar(v)}")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def export_to_file(db: dict, path: str) -> None:
    """Write the redacted YAML to a file (utf-8)."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_redacted_yaml(db))


pv_export = types.SimpleNamespace(
    redact_secret=redact_secret, to_redacted_yaml=to_redacted_yaml,
    export_to_file=export_to_file,
)


# ===========================================================================
# Section 4 — GUI (was manager_v2)
# ===========================================================================
__version__ = "3.0.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "providers.enc")
SECTIONS = ["claude", "codex", "gemini"]


def new_empty_db() -> dict:
    db = {"version": 2, "paths": {}}
    for t in pv_targets.all_targets():
        db[t.id] = {"active": "", "providers": {}}
        db["paths"][t.path_key] = t.default_path
    return db


# ---------------------------------------------------------------------------
# Auth dialog: PIN-first, with a "use password" fallback and a "set" mode.
# ---------------------------------------------------------------------------
class CredentialDialog(tk.Toplevel):
    """mode: 'pin' | 'password' | 'new_password' | 'new_pin'."""

    def __init__(self, parent, mode: str, message: str = "", allow_switch: bool = False):
        super().__init__(parent)
        self.mode = mode
        self.result = None
        self.switch = False
        self.title({"pin": "Unlock", "password": "Unlock (password)",
                    "new_password": "Set Password", "new_pin": "Set PIN"}.get(mode, "Unlock"))
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        f = ttk.Frame(self, padding=16)
        f.pack(fill="both", expand=True)

        prompt = {
            "pin": "Enter your PIN:",
            "password": "Enter your database password:",
            "new_password": "Set a strong database password (recovery):",
            "new_pin": "Set a short PIN for daily unlock:",
        }[mode]
        if message:
            ttk.Label(f, text=message, foreground="#a33").pack(anchor="w", pady=(0, 6))
        ttk.Label(f, text=prompt).pack(anchor="w", pady=(0, 8))

        self.v1 = tk.StringVar()
        e1 = ttk.Entry(f, textvariable=self.v1, show="*", width=32)
        e1.pack(fill="x", pady=(0, 10))
        e1.focus_set()
        e1.bind("<Return>", lambda _: self._ok())

        self.v2 = None
        if mode in ("new_password", "new_pin"):
            ttk.Label(f, text="Confirm:").pack(anchor="w", pady=(0, 4))
            self.v2 = tk.StringVar()
            e2 = ttk.Entry(f, textvariable=self.v2, show="*", width=32)
            e2.pack(fill="x", pady=(0, 10))
            e2.bind("<Return>", lambda _: self._ok())

        bf = ttk.Frame(f)
        bf.pack(fill="x", pady=(4, 0))
        ttk.Button(bf, text="OK", width=10, command=self._ok).pack(side="right", padx=(6, 0))
        ttk.Button(bf, text="Cancel", width=10, command=self.destroy).pack(side="right")
        if allow_switch:
            ttk.Button(bf, text="Use password instead",
                       command=self._use_password).pack(side="left")

        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _use_password(self):
        self.switch = True
        self.destroy()

    def _ok(self):
        val = self.v1.get()
        if not val:
            messagebox.showwarning("Required", "Please enter a value.", parent=self)
            return
        if self.v2 is not None and val != self.v2.get():
            messagebox.showwarning("Mismatch", "Entries do not match.", parent=self)
            return
        if self.mode == "new_pin" and (not val.isdigit() or len(val) < 4):
            messagebox.showwarning("Weak PIN", "Use at least 4 digits.", parent=self)
            return
        self.result = val
        self.destroy()


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Provider Manager v{__version__} — Claude · Codex · Gemini")
        self.minsize(860, 600)
        self.geometry("920x660")
        self._apply_theme()

        self.db_path = DEFAULT_DB_PATH
        self.vault = None
        self.dek = None
        self.data = None
        self.type_var = tk.StringVar(value="claude")
        self.selected_provider = None

        if not self._auth_flow():
            self.destroy()
            return

        self._build_ui()
        self._refresh_list()
        self._refresh_agent_panel()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _apply_theme(self):
        try:
            style = ttk.Style()
            for t in ["vista", "xpnative", "winnative", "clam", "default"]:
                if t in style.theme_names():
                    style.theme_use(t)
                    break
        except Exception:
            pass

    # ---- auth / migration -------------------------------------------------
    def _auth_flow(self) -> bool:
        version = pv_crypto.detect_version(self.db_path)
        if version == 0:
            return self._first_run()
        if version == 1:
            return self._migrate_flow()
        return self._unlock_flow()

    def _first_run(self) -> bool:
        messagebox.showinfo("Welcome",
                            "No database found. Set a strong password (recovery), "
                            "then a short PIN for daily unlock.")
        pw = self._ask(CredentialDialog(self, "new_password"))
        if pw is None:
            return False
        pin = self._ask(CredentialDialog(self, "new_pin"))
        if pin is None:
            return False
        self.data = new_empty_db()
        self.vault = pv_crypto.new_vault(pw, pin=pin, db=self.data)
        _, self.dek = self._dek_and_db_from(pw)
        pv_crypto.save_vault(self.db_path, self.vault)
        return True

    def _dek_and_db_from(self, password):
        dek, db = pv_crypto.unlock_with_password(self.vault, password)
        self.data = db
        self.dek = dek
        return db, dek

    def _migrate_flow(self) -> bool:
        if not messagebox.askyesno(
                "Upgrade database",
                "This is an older (v1) database. Upgrade it to the new PIN-enabled "
                "format?\n\nYour original file will be backed up first."):
            return False
        pw = self._ask(CredentialDialog(self, "password",
                                        message="Enter your existing password to upgrade."))
        if pw is None:
            return False
        try:
            self.vault = pv_crypto.migrate_v1(self.db_path, pw)
        except pv_crypto.WrongCredential:
            messagebox.showerror("Wrong password", "Could not decrypt the legacy database.")
            return self._migrate_flow()
        self._dek_and_db_from(pw)
        self._normalize_db()
        pin = self._ask(CredentialDialog(self, "new_pin",
                                         message="Upgrade complete. Set a daily PIN."))
        if pin:
            pv_crypto.set_pin(self.vault, self.dek, pin)
        pv_crypto.write_payload(self.vault, self.dek, self.data)
        pv_crypto.save_vault(self.db_path, self.vault)
        return True

    def _unlock_flow(self) -> bool:
        self.vault = pv_crypto.load_vault(self.db_path)
        if pv_crypto.is_pin_available(self.vault):
            while True:
                dlg = CredentialDialog(self, "pin", allow_switch=True)
                self._center(dlg)
                self.wait_window(dlg)
                if dlg.switch:
                    break
                if dlg.result is None:
                    return False
                try:
                    dek, db = pv_crypto.unlock_with_pin(self.vault, dlg.result)
                    self.dek, self.data = dek, db
                    self._normalize_db()
                    pv_crypto.save_vault(self.db_path, self.vault)  # persist reset counter
                    return True
                except pv_crypto.PinLocked:
                    pv_crypto.save_vault(self.db_path, self.vault)
                    messagebox.showwarning("PIN locked",
                                           "Too many wrong PINs. Use your password.")
                    break
                except pv_crypto.WrongCredential:
                    pv_crypto.save_vault(self.db_path, self.vault)
                    messagebox.showwarning("Wrong PIN", "Try again or use your password.")
        # password path
        while True:
            pw = self._ask(CredentialDialog(self, "password"))
            if pw is None:
                return False
            try:
                self._dek_and_db_from(pw)
                self._normalize_db()
                pv_crypto.save_vault(self.db_path, self.vault)
                return True
            except pv_crypto.WrongCredential:
                messagebox.showerror("Wrong password", "Incorrect password.")

    def _normalize_db(self):
        """Ensure all sections/paths exist (older dbs may lack gemini)."""
        self.data.setdefault("version", 2)
        self.data.setdefault("paths", {})
        for t in pv_targets.all_targets():
            self.data.setdefault(t.id, {"active": "", "providers": {}})
            self.data["paths"].setdefault(t.path_key, t.default_path)

    def _ask(self, dlg):
        self._center(dlg)
        self.wait_window(dlg)
        return dlg.result

    def _center(self, win):
        win.update_idletasks()
        try:
            x = self.winfo_x() + (self.winfo_width() - win.winfo_width()) // 2
            y = self.winfo_y() + (self.winfo_height() - win.winfo_height()) // 2
            win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except Exception:
            pass

    # ---- persistence helpers ---------------------------------------------
    def _persist(self):
        pv_crypto.write_payload(self.vault, self.dek, self.data)
        pv_crypto.save_vault(self.db_path, self.vault)

    def _save_db_and_refresh(self, preserve=None):
        self._persist()
        self._refresh_list(preserve=preserve)
        self._refresh_agent_panel()

    # ---- UI ---------------------------------------------------------------
    def _build_ui(self):
        hdr = ttk.Frame(self, padding=(12, 8, 12, 4))
        hdr.pack(fill="x")
        ttk.Label(hdr, text=f"Provider Manager v{__version__}",
                  font=("Segoe UI", 13, "bold")).pack(side="left")
        ttk.Label(hdr, text="🔒 Encrypted · PIN unlock",
                  foreground="green").pack(side="right")

        tf = ttk.LabelFrame(self, text=" Agent ", padding=(8, 4))
        tf.pack(fill="x", padx=12, pady=(0, 6))
        for t in pv_targets.all_targets():
            ttk.Radiobutton(tf, text=t.display_name, variable=self.type_var,
                            value=t.id, command=self._on_type_change).pack(side="left", padx=(0, 16))

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=12, pady=4)

        # Left: provider list
        lf = ttk.LabelFrame(main, text=" Providers ", padding=(6, 4))
        main.add(lf, weight=0)
        self.listbox = tk.Listbox(lf, width=26, font=("Consolas", 10),
                                  activestyle="none", exportselection=0)
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        lbf = ttk.Frame(lf)
        lbf.pack(fill="x", pady=(6, 0))
        ttk.Button(lbf, text="Add", width=7, command=self._add).pack(side="left", padx=(0, 3))
        ttk.Button(lbf, text="Delete", width=7, command=self._delete).pack(side="left", padx=(0, 3))
        ttk.Button(lbf, text="Set Active", command=self._set_active).pack(side="right")

        # Right: details + agent panel stacked
        right = ttk.Frame(main)
        main.add(right, weight=1)

        rf = ttk.LabelFrame(right, text=" Provider Details ", padding=(10, 8))
        rf.pack(fill="x")
        self._fields = {}
        rows = [("name", "Name:"), ("api_key", "API Key:"),
                ("base_url", "Base URL:"), ("model", "Model:")]
        for i, (k, lbl) in enumerate(rows):
            ttk.Label(rf, text=lbl).grid(row=i, column=0, sticky="e", pady=2, padx=(0, 6))
            v = tk.StringVar()
            ttk.Entry(rf, textvariable=v, width=44).grid(row=i, column=1, sticky="ew", pady=2)
            self._fields[k] = v
        self.lbl_wire = ttk.Label(rf, text="Wire API:")
        self.lbl_wire.grid(row=4, column=0, sticky="e", pady=2, padx=(0, 6))
        self._fields["wire_api"] = tk.StringVar()
        self.ent_wire = ttk.Entry(rf, textvariable=self._fields["wire_api"], width=44)
        self.ent_wire.grid(row=4, column=1, sticky="ew", pady=2)
        self.lbl_reason = ttk.Label(rf, text="Reasoning:")
        self.lbl_reason.grid(row=5, column=0, sticky="e", pady=2, padx=(0, 6))
        self._fields["reasoning"] = tk.StringVar(value="high")
        self.cmb_reason = ttk.Combobox(rf, textvariable=self._fields["reasoning"],
                                       values=["low", "medium", "high", "xhigh"],
                                       width=41, state="readonly")
        self.cmb_reason.grid(row=5, column=1, sticky="w", pady=2)
        rf.grid_columnconfigure(1, weight=1)
        bf = ttk.Frame(rf)
        bf.grid(row=6, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(bf, text="Save", width=10, command=self._save).pack(side="left")

        # Agent config panel (read -> preview -> write)
        af = ttk.LabelFrame(right, text=" Agent Config File ", padding=(10, 8))
        af.pack(fill="both", expand=True, pady=(8, 0))
        self.agent_status = tk.StringVar(value="")
        ttk.Label(af, textvariable=self.agent_status, font=("Segoe UI", 9),
                  justify="left").pack(anchor="w")
        pf = ttk.Frame(af)
        pf.pack(fill="x", pady=(4, 4))
        ttk.Label(pf, text="Path:").pack(side="left")
        self.path_var = tk.StringVar()
        ttk.Entry(pf, textvariable=self.path_var, width=52).pack(side="left", fill="x",
                                                                 expand=True, padx=(4, 4))
        ttk.Button(pf, text="Browse", command=self._browse_path).pack(side="left")
        abf = ttk.Frame(af)
        abf.pack(fill="x")
        ttk.Button(abf, text="Preview changes", command=self._preview).pack(side="left", padx=(0, 4))
        ttk.Button(abf, text="Write config", command=self._write_config).pack(side="left")

        # bottom bar
        sf = ttk.Frame(self, padding=(12, 4, 12, 8))
        sf.pack(fill="x")
        self.status = tk.StringVar(value="Ready")
        ttk.Label(sf, textvariable=self.status).pack(side="left")
        ttk.Button(sf, text="Change PIN", command=self._change_pin).pack(side="right", padx=(4, 0))
        ttk.Button(sf, text="Change Password", command=self._change_password).pack(side="right", padx=(4, 0))
        ttk.Button(sf, text="Export (redacted)", command=self._export).pack(side="right", padx=(4, 0))
        ttk.Button(sf, text="Import", command=self._import).pack(side="right", padx=(4, 0))

        self._update_field_labels()

    # ---- provider CRUD ----------------------------------------------------
    def _providers(self):
        return self.data[self.type_var.get()]

    def _on_type_change(self):
        self._update_field_labels()
        self._refresh_list()
        self._refresh_agent_panel()

    def _update_field_labels(self):
        is_codex = self.type_var.get() == "codex"
        for w in (self.lbl_wire, self.ent_wire, self.lbl_reason, self.cmb_reason):
            (w.grid() if is_codex else w.grid_remove())

    def _refresh_list(self, preserve=None):
        prev = preserve or self.selected_provider
        self.listbox.delete(0, "end")
        sec = self._providers()
        active = sec.get("active", "")
        names = sorted(sec.get("providers", {}).keys())
        sel = -1
        for i, name in enumerate(names):
            self.listbox.insert("end", f"{name}{' [ACTIVE]' if name == active else ''}")
            if name == prev:
                sel = i
        if sel >= 0:
            self.listbox.selection_set(sel)
            self.selected_provider = prev
            self._load_details(prev)
        else:
            self._clear_details()

    def _on_select(self, event):
        cur = event.widget.curselection()
        if not cur:
            return
        name = event.widget.get(cur[0]).replace(" [ACTIVE]", "")
        self.selected_provider = name
        self._load_details(name)

    def _clear_details(self):
        for v in self._fields.values():
            v.set("")
        self._fields["reasoning"].set("high")
        self.selected_provider = None

    def _load_details(self, name):
        p = self._providers().get("providers", {}).get(name)
        if not p:
            return
        self._fields["name"].set(name)
        self._fields["api_key"].set(p.get("apiKey", ""))
        self._fields["base_url"].set(p.get("baseUrl", ""))
        self._fields["model"].set(p.get("model", ""))
        self._fields["wire_api"].set(p.get("wire_api", ""))
        self._fields["reasoning"].set(p.get("model_reasoning_effort", "high"))

    def _add(self):
        name = simpledialog.askstring("Add Provider", "Provider name:", parent=self)
        if not name or not name.strip():
            return
        name = name.strip()
        sec = self._providers()
        if name in sec["providers"]:
            messagebox.showwarning("Exists", f"Provider '{name}' already exists.")
            return
        entry = {"apiKey": "", "baseUrl": "", "model": ""}
        if self.type_var.get() == "codex":
            entry["wire_api"] = "responses"
            entry["model_reasoning_effort"] = "high"
        sec["providers"][name] = entry
        self._save_db_and_refresh(preserve=name)
        self.status.set(f"Added: {name}")

    def _save(self):
        name = self._fields["name"].get().strip()
        if not name:
            messagebox.showwarning("Name required", "Enter a provider name.")
            return
        sec = self._providers()
        entry = {"apiKey": self._fields["api_key"].get().strip(),
                 "baseUrl": self._fields["base_url"].get().strip(),
                 "model": self._fields["model"].get().strip()}
        if self.type_var.get() == "codex":
            entry["wire_api"] = self._fields["wire_api"].get().strip() or "responses"
            entry["model_reasoning_effort"] = self._fields["reasoning"].get().strip() or "high"
        orig = self.selected_provider
        if orig and orig != name and orig in sec["providers"]:
            del sec["providers"][orig]
            if sec.get("active") == orig:
                sec["active"] = name
        sec["providers"][name] = entry
        self.selected_provider = name
        self._save_db_and_refresh(preserve=name)
        self.status.set(f"Saved: {name}")

    def _delete(self):
        name = self.selected_provider
        if not name:
            return
        if not messagebox.askyesno("Delete", f"Delete provider '{name}'?"):
            return
        sec = self._providers()
        sec["providers"].pop(name, None)
        if sec.get("active") == name:
            sec["active"] = ""
        self.selected_provider = None
        self._save_db_and_refresh()
        self.status.set(f"Deleted: {name}")

    def _set_active(self):
        name = self.selected_provider
        if not name:
            return
        self._providers()["active"] = name
        self._save_db_and_refresh(preserve=name)
        self.status.set(f"Active: {name}")

    # ---- agent config panel ----------------------------------------------
    def _current_target(self):
        return pv_targets.get_target(self.type_var.get())

    def _current_path(self):
        t = self._current_target()
        return self.data["paths"].get(t.path_key, t.default_path)

    def _refresh_agent_panel(self):
        t = self._current_target()
        self.path_var.set(self._current_path())
        sec = self._providers()
        active = sec.get("active", "")
        cur = pv_targets.read_current(t.id, self.path_var.get())
        if not cur or not cur.get("raw_ok"):
            on_disk = "not found / unreadable"
            sync = "○ no config file yet"
        else:
            on_disk = cur.get("provider_guess") or cur.get("baseUrl") or "unknown"
            active_url = sec.get("providers", {}).get(active, {}).get("baseUrl", "")
            in_sync = active and active_url and (active_url in (cur.get("baseUrl") or ""))
            sync = "● IN SYNC" if in_sync else "○ OUT OF SYNC"
        active_txt = active or "(none set)"
        self.agent_status.set(
            f"On disk:  {on_disk}\n"
            f"Active :  {active_txt}\n"
            f"Status :  {sync}")

    def _browse_path(self):
        t = self._current_target()
        if t.path_kind == "dir":
            p = filedialog.askdirectory(title=f"{t.display_name} directory")
        else:
            p = filedialog.asksaveasfilename(title=f"{t.display_name} file",
                                             initialfile=os.path.basename(t.default_path))
        if p:
            self.path_var.set(p)
            self.data["paths"][t.path_key] = p
            self._persist()
            self._refresh_agent_panel()

    def _active_provider_entry(self):
        sec = self._providers()
        active = sec.get("active", "")
        if not active or active not in sec.get("providers", {}):
            messagebox.showwarning("No active provider",
                                   f"Set an active {self.type_var.get()} provider first.")
            return None, None
        return active, sec["providers"][active]

    def _preview(self):
        t = self._current_target()
        active, prov = self._active_provider_entry()
        if not active:
            return
        # keep chosen path saved so preview & write agree
        self.data["paths"][t.path_key] = self.path_var.get()
        diff = pv_targets.diff_preview(t.id, self.path_var.get(), active, prov)
        self._show_text(f"Preview — {t.display_name} ({active})", diff or "# no changes")

    def _write_config(self):
        t = self._current_target()
        active, prov = self._active_provider_entry()
        if not active:
            return
        path = self.path_var.get()
        if not messagebox.askyesno(
                "Write config",
                f"Write {t.display_name} config for '{active}' to:\n{path}\n\n"
                "Existing files are backed up (.bak) first. Continue?"):
            return
        try:
            written = pv_targets.write(t.id, active, prov, path)
            self.data["paths"][t.path_key] = path
            self._persist()
            self._refresh_agent_panel()
            self.status.set(f"Wrote {t.display_name} config for {active}")
            messagebox.showinfo("Done", "Written:\n" + "\n".join(written))
        except Exception as e:
            messagebox.showerror("Write failed", str(e))

    # ---- import (settings.json / auth.json / config.toml) ----------------
    def _import(self):
        t = self.type_var.get()
        f = filedialog.askopenfilename(title=f"Import {t} config",
                                       filetypes=[("Config", "*.json *.toml"), ("All", "*.*")])
        if not f:
            return
        cur = pv_targets.read_current(t, f if t == "claude" else os.path.dirname(f),
                                      reveal=True)
        if not cur or not cur.get("raw_ok"):
            messagebox.showinfo("Unrecognized", "Could not parse that file for this agent.")
            return
        name = simpledialog.askstring("Import as", "Save imported provider as:", parent=self)
        if not name or not name.strip():
            return
        name = name.strip()
        key = cur.get("apiKey", "")
        entry = {"apiKey": key, "baseUrl": cur.get("baseUrl", ""),
                 "model": cur.get("model", "")}
        if t == "codex":
            entry["wire_api"] = "responses"
            entry["model_reasoning_effort"] = "high"
        self._providers()["providers"][name] = entry
        self._save_db_and_refresh(preserve=name)
        if key:
            messagebox.showinfo("Imported",
                                f"Imported '{name}' including its API key (stored encrypted).")
        else:
            messagebox.showinfo("Imported",
                                f"Imported '{name}'. No API key was found in that file — "
                                "enter it and Save.")

    # ---- export / credential changes -------------------------------------
    def _export(self):
        path = filedialog.asksaveasfilename(
            title="Export redacted YAML", defaultextension=".yaml",
            initialfile="providers.redacted.yaml",
            filetypes=[("YAML", "*.yaml *.yml"), ("All", "*.*")])
        if not path:
            return
        try:
            pv_export.export_to_file(self.data, path)
            self.status.set(f"Exported redacted view → {path}")
            messagebox.showinfo("Exported", f"Redacted YAML written to:\n{path}\n\n"
                                            "API keys are masked. Not importable.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _change_pin(self):
        pin = self._ask(CredentialDialog(self, "new_pin", message="Set a new daily PIN."))
        if pin is None:
            return
        pv_crypto.set_pin(self.vault, self.dek, pin)
        pv_crypto.save_vault(self.db_path, self.vault)
        self.status.set("PIN updated.")

    def _change_password(self):
        pw = self._ask(CredentialDialog(self, "new_password", message="Set a new password."))
        if pw is None:
            return
        pv_crypto.change_password(self.vault, self.dek, pw)
        pv_crypto.save_vault(self.db_path, self.vault)
        self.status.set("Password updated.")

    # ---- small text popup -------------------------------------------------
    def _show_text(self, title, text):
        top = tk.Toplevel(self)
        top.title(title)
        top.geometry("640x460")
        top.transient(self)
        box = tk.Text(top, wrap="none", font=("Consolas", 9))
        box.pack(fill="both", expand=True, padx=8, pady=8)
        box.insert("1.0", text)
        box.configure(state="disabled")
        ttk.Button(top, text="Close", command=top.destroy).pack(pady=(0, 8))


if __name__ == "__main__":
    App().mainloop()
