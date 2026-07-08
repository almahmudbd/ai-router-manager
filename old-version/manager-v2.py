#!/usr/bin/env python3
"""
Provider Manager — Codex & Claude
Unified provider config manager with encrypted database.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import json
import os
import hashlib
from base64 import b64encode, b64decode
import threading

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    messagebox.showerror("Missing Dependency",
        "cryptography library not found.\nRun: pip install cryptography")
    raise SystemExit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "providers.enc")
DEFAULT_CLAUDE_PATH = os.path.join(
    os.environ.get("USERPROFILE", ""), ".claude", "settings.json")
DEFAULT_CODEX_DIR = os.path.join(
    os.environ.get("USERPROFILE", ""), ".codex")

SALT = b"pr0v_m4ng3r_2024_s@lt!"
PBKDF2_ITERATIONS = 200000


def derive_key(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=SALT, iterations=PBKDF2_ITERATIONS)
    return b64encode(kdf.derive(password.encode())).decode()


def encrypt_data(data, password):
    key = derive_key(password)
    f = Fernet(key.encode())
    token = f.encrypt(json.dumps(data, indent=2).encode())
    return b64encode(token).decode()


def decrypt_data(encrypted, password):
    key = derive_key(password)
    f = Fernet(key.encode())
    token = b64decode(encrypted.encode())
    return json.loads(f.decrypt(token).decode())


def load_db(filepath, password):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        return None
    return decrypt_data(raw, password)


def save_db(filepath, data, password):
    raw = encrypt_data(data, password)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(raw)


def new_empty_db():
    return {
        "claude": {"active": "", "providers": {}},
        "codex":  {"active": "", "providers": {}},
        "paths": {
            "claude_settings": DEFAULT_CLAUDE_PATH,
            "codex_dir":       DEFAULT_CODEX_DIR
        }
    }


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, mode="login"):
        super().__init__(parent)
        self.parent = parent
        self.mode = mode
        self.result = None
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        f = ttk.Frame(self, padding=16)
        f.pack(fill="both", expand=True)

        if mode == "login":
            ttk.Label(f, text="Enter database password:").pack(anchor="w", pady=(0, 8))
        else:
            ttk.Label(f, text="Set new database password:").pack(anchor="w", pady=(0, 8))

        self.pw = tk.StringVar()
        e = ttk.Entry(f, textvariable=self.pw, show="*", width=30)
        e.pack(fill="x", pady=(0, 12))
        e.focus_set()
        e.bind("<Return>", lambda _: self.on_ok())

        if mode == "new":
            ttk.Label(f, text="Confirm password:").pack(anchor="w", pady=(0, 4))
            self.pw2 = tk.StringVar()
            e2 = ttk.Entry(f, textvariable=self.pw2, show="*", width=30)
            e2.pack(fill="x", pady=(0, 12))
            e2.bind("<Return>", lambda _: self.on_ok())

        bf = ttk.Frame(f)
        bf.pack(fill="x")
        ttk.Button(bf, text="OK", width=10, command=self.on_ok).pack(side="right", padx=(6, 0))
        ttk.Button(bf, text="Cancel", width=10, command=self.destroy).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def on_ok(self):
        pw = self.pw.get().strip()
        if not pw:
            messagebox.showwarning("Password required", "Password cannot be empty.", parent=self)
            return
        if self.mode == "new":
            pw2 = self.pw2.get().strip()
            if pw != pw2:
                messagebox.showwarning("Mismatch", "Passwords do not match.", parent=self)
                return
        self.result = pw
        self.destroy()


class ProviderManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Provider Manager \u2014 Codex & Claude")
        self.minsize(780, 540)
        self.geometry("820x580")

        try:
            style = ttk.Style()
            styles = style.theme_names()
            for t in ["winnative", "xpnative", "vista", "default"]:
                if t in styles:
                    style.theme_use(t)
                    break
        except Exception:
            pass

        self.db_path = DEFAULT_DB_PATH
        self.password = None
        self.data = None
        self.type_var = tk.StringVar(value="claude")
        self.selected_provider = None

        if not self._do_auth():
            self.destroy()
            return

        self._build_ui()
        self._refresh_list()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _do_auth(self):
        if os.path.exists(self.db_path):
            dlg = PasswordDialog(self, "Unlock Database")
            self.wait_window(dlg)
            if dlg.result is None:
                return False
            pw = dlg.result
            try:
                self.data = load_db(self.db_path, pw)
                if self.data is None:
                    self.data = new_empty_db()
            except Exception:
                messagebox.showerror("Error", "Wrong password or corrupted database.")
                return self._do_auth()
            self.password = pw
        else:
            dlg = PasswordDialog(self, "New Database", mode="new")
            self.wait_window(dlg)
            if dlg.result is None:
                return False
            self.password = dlg.result
            self.data = new_empty_db()
            save_db(self.db_path, self.data, self.password)
        return True

    def _build_ui(self):
        # Top title
        hdr = ttk.Frame(self, padding=(12, 8, 12, 4))
        hdr.pack(fill="x")
        ttk.Label(hdr, text="Provider Manager \u2014 Codex & Claude",
                  font=("Segoe UI", 13, "bold")).pack(side="left")

        # Type selector
        tf = ttk.LabelFrame(self, text=" Provider Type ", padding=(8, 4))
        tf.pack(fill="x", padx=12, pady=(0, 6))
        ttk.Radiobutton(tf, text="Claude", variable=self.type_var,
                        value="claude", command=self._refresh_list).pack(side="left", padx=(0, 16))
        ttk.Radiobutton(tf, text="Codex", variable=self.type_var,
                        value="codex", command=self._refresh_list).pack(side="left")

        # Main area
        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=12, pady=4)

        # Left: provider list
        lf = ttk.LabelFrame(main, text=" Providers ", padding=(6, 4), width=280)
        main.add(lf, weight=0)

        self.listbox = tk.Listbox(lf, width=28, font=("Consolas", 10),
                                  selectmode="single", borderwidth=1,
                                  relief="sunken", activestyle="none",
                                  exportselection=0)
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        lbf = ttk.Frame(lf)
        lbf.pack(fill="x", pady=(6, 0))
        ttk.Button(lbf, text="Add", width=8, command=self._add).pack(side="left", padx=(0, 4))
        ttk.Button(lbf, text="Delete", width=8, command=self._delete).pack(side="left", padx=(0, 4))
        ttk.Button(lbf, text="Import", width=8, command=self._import).pack(side="left", padx=(0, 4))
        ttk.Button(lbf, text="Set Active", width=10, command=self._set_active).pack(side="right")

        # Right: details
        rf = ttk.LabelFrame(main, text=" Provider Details ", padding=(10, 8))
        main.add(rf, weight=1)

        self._details_widgets = {}
        field_labels = [
            ("name",    "Name:"),
            ("api_key", "API Key:"),
            ("base_url","Base URL:"),
            ("model",   "Model:"),
        ]
        for i, (key, label) in enumerate(field_labels):
            ttk.Label(rf, text=label).grid(row=i, column=0, sticky="e", pady=2, padx=(0, 6))
            v = tk.StringVar()
            ttk.Entry(rf, textvariable=v, width=40).grid(row=i, column=1, sticky="ew", pady=2, padx=(0, 8))
            self._details_widgets[key] = v

        # Wire API / Extra (row 4)
        self.label_wire = ttk.Label(rf, text="Wire API:")
        self.label_wire.grid(row=4, column=0, sticky="e", pady=2, padx=(0, 6))
        self._details_widgets["wire_api"] = tk.StringVar()
        self.entry_wire = ttk.Entry(rf, textvariable=self._details_widgets["wire_api"], width=40)
        self.entry_wire.grid(row=4, column=1, sticky="ew", pady=2, padx=(0, 8))

        # Reasoning Effort (row 5, Codex only)
        self.label_reason = ttk.Label(rf, text="Reasoning:")
        self.label_reason.grid(row=5, column=0, sticky="e", pady=2, padx=(0, 6))
        self._details_widgets["reasoning"] = tk.StringVar(value="high")
        self.combo_reason = ttk.Combobox(rf, textvariable=self._details_widgets["reasoning"],
                                          values=["low", "medium", "high", "xhigh"],
                                          width=37, state="readonly")
        self.combo_reason.grid(row=5, column=1, sticky="w", pady=2, padx=(0, 8))

        rf.grid_columnconfigure(1, weight=1)
        self._update_labels()

        # Buttons row
        bf = ttk.Frame(rf)
        bf.grid(row=6, column=0, columnspan=2, pady=(12, 0), sticky="e")
        ttk.Button(bf, text="Save", width=10, command=self._save).pack(side="left", padx=(0, 6))
        ttk.Button(bf, text="Generate Config", command=self._generate).pack(side="left")

        # Paths section
        pf = ttk.LabelFrame(self, text=" Paths ", padding=(8, 4))
        pf.pack(fill="x", padx=12, pady=(8, 4))

        ttk.Label(pf, text="Claude settings.json:").grid(row=0, column=0, sticky="e", padx=(0, 4), pady=2)
        self.claude_path_var = tk.StringVar(value=self.data["paths"].get("claude_settings", DEFAULT_CLAUDE_PATH))
        e = ttk.Entry(pf, textvariable=self.claude_path_var, width=60)
        e.grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=2)
        ttk.Button(pf, text="Browse", command=lambda: self._browse_file(self.claude_path_var, "settings.json")).grid(row=0, column=2, pady=2)

        ttk.Label(pf, text="Codex directory:").grid(row=1, column=0, sticky="e", padx=(0, 4), pady=2)
        self.codex_path_var = tk.StringVar(value=self.data["paths"].get("codex_dir", DEFAULT_CODEX_DIR))
        e = ttk.Entry(pf, textvariable=self.codex_path_var, width=60)
        e.grid(row=1, column=1, sticky="ew", padx=(0, 4), pady=2)
        ttk.Button(pf, text="Browse", command=lambda: self._browse_dir(self.codex_path_var)).grid(row=1, column=2, pady=2)

        pf.grid_columnconfigure(1, weight=1)

        # Status bar
        sf = ttk.Frame(self, padding=(12, 4, 12, 8))
        sf.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(sf, textvariable=self.status_var, font=("Segoe UI", 9)).pack(side="left")
        ttk.Button(sf, text="Change Password", command=self._change_password).pack(side="right", padx=(4, 0))
        ttk.Label(sf, text="\U0001F512 Encrypted DB", foreground="green").pack(side="right", padx=(0, 12))

    def _update_labels(self):
        is_codex = self.type_var.get() == "codex"
        self.label_wire.configure(text="Wire API:" if is_codex else "Extra:")
        state = "normal" if is_codex else "hidden"
        self.label_reason.grid_remove() if not is_codex else self.label_reason.grid()
        self.combo_reason.grid_remove() if not is_codex else self.combo_reason.grid()

    def _get_providers(self):
        t = self.type_var.get()
        return self.data.get(t, {"active": "", "providers": {}})

    def _refresh_list(self, preserve=None):
        prev = preserve or self.selected_provider
        self._update_labels()
        self.listbox.delete(0, "end")
        provs = self._get_providers()
        active = provs.get("active", "")
        items = provs.get("providers", {})
        idx = 0
        sel_idx = -1
        for name in sorted(items.keys()):
            mark = " [ACTIVE]" if name == active else ""
            display = f"{name}{mark}"
            self.listbox.insert("end", display)
            if name == prev:
                sel_idx = idx
            idx += 1
        if sel_idx >= 0:
            self.listbox.selection_set(sel_idx)
            self.listbox.activate(sel_idx)
            self.selected_provider = prev
            self._load_details(prev)
        else:
            self._clear_details()
            self.selected_provider = None

    def _on_select(self, event):
        sel = event.widget.curselection()
        if not sel:
            return
        txt = event.widget.get(sel[0])
        name = txt.replace(" [ACTIVE]", "")
        self.selected_provider = name
        self._load_details(name)

    def _clear_details(self):
        for k, v in self._details_widgets.items():
            v.set("")
        self.selected_provider = None

    def _load_details(self, name):
        provs = self._get_providers()
        p = provs.get("providers", {}).get(name)
        if not p:
            return
        self._details_widgets["name"].set(name)
        self._details_widgets["api_key"].set(p.get("apiKey", ""))
        self._details_widgets["base_url"].set(p.get("baseUrl", ""))
        self._details_widgets["model"].set(p.get("model", ""))
        self._details_widgets["wire_api"].set(p.get("wire_api", p.get("extra", "")))
        self._details_widgets["reasoning"].set(p.get("model_reasoning_effort", "high"))

    def _add(self):
        name = simpledialog.askstring("Add Provider", "Provider name:", parent=self)
        if not name:
            return
        if name.strip() == "":
            return
        name = name.strip()
        t = self.type_var.get()
        if name in self.data[t]["providers"]:
            messagebox.showwarning("Exists", f"Provider '{name}' already exists.")
            return
        self.data[t]["providers"][name] = {
            "apiKey": "", "baseUrl": "", "model": ""
        }
        if t == "codex":
            self.data[t]["providers"][name]["wire_api"] = "responses"
            self.data[t]["providers"][name]["model_reasoning_effort"] = "high"
        else:
            self.data[t]["providers"][name]["extra"] = ""
        self._save_db_and_refresh(preserve=name)
        self.status_var.set(f"Added provider: {name}")

    def _import(self):
        t = self.type_var.get()
        if t == "claude":
            paths = [("Claude settings", "settings.json"), ("JSON files", "*.json"), ("All", "*.*")]
            f = filedialog.askopenfilename(title="Import Claude config", filetypes=paths,
                                           initialdir=os.path.dirname(self.claude_path_var.get()))
        else:
            paths = [("Codex auth.json", "auth.json"), ("JSON files", "*.json"), ("TOML files", "*.toml"), ("All", "*.*")]
            init = self.codex_path_var.get() if os.path.isdir(self.codex_path_var.get()) else SCRIPT_DIR
            f = filedialog.askopenfilename(title="Import Codex config", filetypes=paths, initialdir=init)
        if not f:
            return

        try:
            imported = []
            base = os.path.basename(f).lower()

            if base == "auth.json":
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                api_key = data.get("OPENAI_API_KEY", "")
                name = simpledialog.askstring("Import", "Name for this provider:", parent=self)
                if not name:
                    return
                toml_dir = os.path.dirname(f)
                toml_path = os.path.join(toml_dir, "config.toml")
                model = ""
                url = ""
                wire = "responses"
                reason = "high"
                if os.path.exists(toml_path):
                    with open(toml_path, "r", encoding="utf-8") as fh:
                        toml_text = fh.read()
                    for line in toml_text.splitlines():
                        if line.startswith("model ="):
                            model = line.split('"')[1] if '"' in line else ""
                        if line.startswith("base_url ="):
                            url = line.split('"')[1] if '"' in line else ""
                        if line.startswith("wire_api ="):
                            wire = line.split('"')[1] if '"' in line else ""
                        if line.startswith("model_reasoning_effort ="):
                            reason = line.split('"')[1] if '"' in line else "high"
                if not url:
                    url = "https://api.openai.com"
                self.data["codex"]["providers"][name] = {
                    "apiKey": api_key, "baseUrl": url, "model": model,
                    "wire_api": wire, "model_reasoning_effort": reason
                }
                if not self.data["codex"]["active"]:
                    self.data["codex"]["active"] = name
                imported = [name]

            elif base == "settings.json" or base.startswith("settings"):
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                env = data.get("env", {})
                api_key = env.get("ANTHROPIC_API_KEY", "")
                url = env.get("ANTHROPIC_BASE_URL", "")
                model = env.get("ANTHROPIC_MODEL", "")
                name = simpledialog.askstring("Import", "Name for this provider:", parent=self,
                                               initialvalue=os.path.basename(os.path.dirname(f)))
                if not name:
                    return
                self.data["claude"]["providers"][name] = {
                    "apiKey": api_key, "baseUrl": url, "model": model, "extra": ""
                }
                if not self.data["claude"]["active"]:
                    self.data["claude"]["active"] = name
                imported = [name]

            elif f.endswith(".toml"):
                with open(f, "r", encoding="utf-8") as fh:
                    toml_text = fh.read()
                model = ""
                url = ""
                wire = "responses"
                reason = "high"
                prov_name = ""
                for line in toml_text.splitlines():
                    if line.startswith("model_provider ="):
                        prov_name = line.split('"')[1] if '"' in line else ""
                    if line.startswith("model =") and not line.startswith("model_"):
                        model = line.split('"')[1] if '"' in line else ""
                    if line.startswith("base_url ="):
                        url = line.split('"')[1] if '"' in line else ""
                    if line.startswith("wire_api ="):
                        wire = line.split('"')[1] if '"' in line else ""
                    if line.startswith("model_reasoning_effort ="):
                        reason = line.split('"')[1] if '"' in line else "high"
                auth_dir = os.path.dirname(f)
                auth_path = os.path.join(auth_dir, "auth.json")
                api_key = ""
                if os.path.exists(auth_path):
                    with open(auth_path, "r", encoding="utf-8") as fh:
                        auth_data = json.load(fh)
                    api_key = auth_data.get("OPENAI_API_KEY", "")
                name = prov_name or simpledialog.askstring("Import", "Name for this provider:", parent=self)
                if not name:
                    return
                if not url:
                    url = "https://api.openai.com"
                self.data["codex"]["providers"][name] = {
                    "apiKey": api_key, "baseUrl": url, "model": model,
                    "wire_api": wire, "model_reasoning_effort": reason
                }
                if not self.data["codex"]["active"]:
                    self.data["codex"]["active"] = name
                imported = [name]

            elif base == "codex-backup" or base.startswith("codex-backup -"):
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                name = os.path.splitext(os.path.basename(f))[0].replace("codex-backup - ", "")
                self.data["codex"]["providers"][name] = {
                    "apiKey": data.get("apiKey", ""),
                    "baseUrl": data.get("base_url", ""),
                    "model": data.get("model", ""),
                    "wire_api": data.get("wire_api", "responses"),
                    "model_reasoning_effort": data.get("model_reasoning_effort", "high")
                }
                if not self.data["codex"]["active"]:
                    self.data["codex"]["active"] = name
                imported = [name]

            else:
                messagebox.showinfo("Unrecognized", "File format not recognized. Try importing a settings.json or auth.json file.")
                return

            if imported:
                self._save_db_and_refresh(preserve=imported[0])
                self.status_var.set(f"Imported: {', '.join(imported)}")
                messagebox.showinfo("Done", f"Imported provider(s):\n" + "\n".join(imported))

        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    def _delete(self):
        name = self._get_sel_name()
        if not name:
            messagebox.showwarning("No selection", "Select a provider from the list first.")
            return
        if not messagebox.askyesno("Confirm", f"Delete '{name}'?"):
            return
        t = self.type_var.get()
        if name in self.data[t]["providers"]:
            del self.data[t]["providers"][name]
            if self.data[t].get("active") == name:
                remaining = list(self.data[t]["providers"].keys())
                self.data[t]["active"] = remaining[0] if remaining else ""
        self._save_db_and_refresh()
        self.status_var.set(f"Deleted: {name}")

    def _get_sel_name(self):
        sel = self.listbox.curselection()
        if not sel:
            return None
        return self.listbox.get(sel[0]).replace(" [ACTIVE]", "")

    def _set_active(self):
        name = self._get_sel_name()
        if not name:
            messagebox.showwarning("No selection", "Select a provider from the list first.")
            return
        t = self.type_var.get()
        if name not in self.data[t]["providers"]:
            return
        self.data[t]["active"] = name
        self._save_db_and_refresh(preserve=name)
        self.status_var.set(f"Active: {name} ({t})")
        self._generate()

    def _save(self):
        new_name = self._details_widgets["name"].get().strip()
        if not new_name:
            messagebox.showwarning("Required", "Provider name cannot be empty.")
            return
        t = self.type_var.get()
        if new_name not in self.data[t]["providers"] and not self.selected_provider:
            if not messagebox.askyesno("New Provider", f"'{new_name}' is new. Create it?"):
                return

        orig = self.selected_provider
        entry = {
            "apiKey":  self._details_widgets["api_key"].get().strip(),
            "baseUrl": self._details_widgets["base_url"].get().strip(),
            "model":   self._details_widgets["model"].get().strip()
        }
        if t == "codex":
            entry["wire_api"] = self._details_widgets["wire_api"].get().strip()
            entry["model_reasoning_effort"] = self._details_widgets["reasoning"].get().strip()
        else:
            entry["extra"] = self._details_widgets["wire_api"].get().strip()

        if orig and orig != new_name:
            if new_name in self.data[t]["providers"]:
                messagebox.showwarning("Exists", f"Provider '{new_name}' already exists.")
                return
            del self.data[t]["providers"][orig]
            if self.data[t].get("active") == orig:
                self.data[t]["active"] = new_name

        self.data[t]["providers"][new_name] = entry
        self._save_db_and_refresh(preserve=new_name)
        self.status_var.set(f"Saved: {new_name}")

    def _generate(self):
        t = self.type_var.get()
        active = self.data[t].get("active", "")
        if not active or active not in self.data[t]["providers"]:
            messagebox.showwarning("No active provider",
                f"No active {t} provider set.")
            return
        prov = self.data[t]["providers"][active]

        if t == "claude":
            self._gen_claude(active, prov)
        else:
            self._gen_codex(active, prov)

    def _gen_claude(self, name, prov):
        path = self.claude_path_var.get().strip()
        if not path:
            messagebox.showwarning("Path not set", "Set Claude settings.json path first.")
            return
        try:
            key = prov.get("apiKey", "")
            url = prov.get("baseUrl", "")
            model = prov.get("model", "")
            lines = ['{']
            lines.append(f'  "apiKeyHelper": "echo \'\'\' + \'{key}\' + \'\'\'",')
            lines.append(f'  "env": {{')
            lines.append(f'    "ANTHROPIC_API_KEY": "{key}",')
            lines.append(f'    "ANTHROPIC_BASE_URL": "{url}",')
            lines.append(f'    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"')
            if model:
                lines[-1] += ","
                lines.append(f'    "ANTHROPIC_MODEL": "{model}"')
            lines.append('  },')
            lines.append('  "permissions": { "allow": [], "deny": [], "defaultMode": "default" },')
            lines.append('  "theme": "dark",')
            lines.append('  "effortLevel": "high"')
            lines.append('}')
            content = "\n".join(lines)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.status_var.set(f"Claude settings.json generated for: {name}")
            messagebox.showinfo("Done", f"Claude config written to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _gen_codex(self, name, prov):
        d = self.codex_path_var.get().strip()
        if not d:
            messagebox.showwarning("Path not set", "Set Codex directory path first.")
            return
        try:
            os.makedirs(d, exist_ok=True)
            auth_path = os.path.join(d, "auth.json")
            config_path = os.path.join(d, "config.toml")

            key = prov.get("apiKey", "")
            model = prov.get("model", "")
            reason = prov.get("model_reasoning_effort", "high")
            url = prov.get("baseUrl", "")
            wire = prov.get("wire_api", "responses")

            # auth.json
            auth = json.dumps({"OPENAI_API_KEY": key}, indent=2)
            with open(auth_path, "w", encoding="utf-8") as f:
                f.write(auth)

            # config.toml
            toml_lines = [
                f'model_provider = "{name}"',
                f'model = "{model}"',
                f'model_reasoning_effort = "{reason}"',
                'disable_response_storage = true',
                'preferred_auth_method = "apikey"',
                "",
                f'[model_providers.{name}]',
                f'name = "{name}"',
                f'base_url = "{url}"',
                f'wire_api = "{wire}"',
            ]
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("\n".join(toml_lines))

            self.status_var.set(f"Codex config generated for: {name}")
            messagebox.showinfo("Done",
                f"Codex config written to:\n{auth_path}\n{config_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _browse_file(self, var, filename=None):
        init = var.get()
        init_dir = os.path.dirname(init) if init and os.path.exists(os.path.dirname(init)) else SCRIPT_DIR
        f = filedialog.asksaveasfilename(
            initialdir=init_dir,
            title="Select settings.json path",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=filename or "settings.json")
        if f:
            var.set(f)

    def _browse_dir(self, var):
        init = var.get()
        init_dir = init if init and os.path.exists(init) else SCRIPT_DIR
        d = filedialog.askdirectory(initialdir=init_dir, title="Select Codex directory")
        if d:
            var.set(d)

    def _save_db_and_refresh(self, preserve=None):
        self.data["paths"]["claude_settings"] = self.claude_path_var.get().strip()
        self.data["paths"]["codex_dir"] = self.codex_path_var.get().strip()
        save_db(self.db_path, self.data, self.password)
        self._refresh_list(preserve=preserve)

    def _change_password(self):
        dlg = PasswordDialog(self, "Change Password", mode="new")
        self.wait_window(dlg)
        if dlg.result:
            self.password = dlg.result
            save_db(self.db_path, self.data, self.password)
            self.status_var.set("Password changed.")

    def on_close(self):
        self.data["paths"]["claude_settings"] = self.claude_path_var.get().strip()
        self.data["paths"]["codex_dir"] = self.codex_path_var.get().strip()
        save_db(self.db_path, self.data, self.password)
        self.destroy()


if __name__ == "__main__":
    app = ProviderManager()
    app.mainloop()
