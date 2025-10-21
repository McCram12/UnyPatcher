#!/usr/bin/env python3
# unypatcher_gui.py
# Save as unypatcher_gui.py and run: python unypatcher_gui.py
#
# Requirements: Python 3.7+ (uses standard library only)
#
# Description:
#   GUI for creating and applying .unypatch files for Unity games (generic file-level patcher).
#   .unypatch = ZIP with manifest.json and files/<relative paths...>

import os
import sys
import json
import zipfile
import hashlib
import shutil
import time
import threading
import queue
import traceback
from tkinter import (
    Tk, Frame, Label, Entry, Button, Text, END, DISABLED, NORMAL, StringVar, BooleanVar, IntVar, filedialog, messagebox
)
from tkinter import ttk

# ---------------------------
# Core logic (create / apply)
# ---------------------------

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def collect_files(root):
    files = {}
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            files[rel] = full
    return files

def build_manifest_and_changed(orig_root, mod_root):
    """
    Returns manifest dict and list of changed file relative paths (that must be included under files/)
    """
    orig = collect_files(orig_root)
    mod = collect_files(mod_root)

    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": "unypatcher-gui",
        "entries": []
    }

    all_keys = sorted(set(orig.keys()) | set(mod.keys()))
    changed_keys = []

    for k in all_keys:
        in_orig = k in orig
        in_mod = k in mod
        if in_orig and in_mod:
            h_orig = sha256_file(orig[k])
            h_mod = sha256_file(mod[k])
            if h_orig != h_mod:
                manifest["entries"].append({
                    "path": k,
                    "action": "replace",
                    "original_hash": h_orig,
                    "patched_hash": h_mod,
                })
                changed_keys.append(k)
        elif in_mod and not in_orig:
            h_mod = sha256_file(mod[k])
            manifest["entries"].append({
                "path": k,
                "action": "add",
                "original_hash": None,
                "patched_hash": h_mod,
            })
            changed_keys.append(k)
        elif in_orig and not in_mod:
            h_orig = sha256_file(orig[k])
            manifest["entries"].append({
                "path": k,
                "action": "delete",
                "original_hash": h_orig,
                "patched_hash": None,
            })

    return manifest, changed_keys, orig, mod

def create_unypatch(orig_root, mod_root, out_path, progress_cb=None, log_cb=None):
    if log_cb: log_cb(f"Starting patch creation:\n  Original: {orig_root}\n  Modified: {mod_root}\n  Output: {out_path}")
    manifest, changed_keys, orig_map, mod_map = build_manifest_and_changed(orig_root, mod_root)

    if not manifest["entries"]:
        if log_cb: log_cb("No changes found. Patch not created.")
        return False, "No changes found."

    try:
        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            total = len(changed_keys)
            for i, rel in enumerate(changed_keys, start=1):
                src = mod_map[rel]
                arcname = "files/" + rel
                if log_cb: log_cb(f"Writing {rel} -> {arcname}")
                z.write(src, arcname)
                if progress_cb:
                    progress_cb(int(i * 100 / total))
        if log_cb: log_cb(f"Patch created: {out_path}")
        return True, None
    except Exception as e:
        if log_cb: log_cb(f"ERROR creating patch: {e}")
        return False, str(e)

def apply_unypatch(target_root, patch_path, progress_cb=None, log_cb=None, force=False):
    if log_cb: log_cb(f"Starting patch application:\n  Target: {target_root}\n  Patch: {patch_path}\n  Force: {force}")
    timestamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    backup_root = os.path.join(target_root, f"backup_unypatch_{timestamp}")
    os.makedirs(backup_root, exist_ok=True)

    try:
        with zipfile.ZipFile(patch_path, "r") as z:
            if "manifest.json" not in z.namelist():
                return False, "Invalid patch file: manifest.json missing"
            manifest = json.loads(z.read("manifest.json").decode("utf-8"))
            entries = manifest.get("entries", [])
            if log_cb: log_cb(f"Manifest contains {len(entries)} entries.")

            # validation
            to_process = [e for e in entries]
            total = len(to_process) if to_process else 1
            validated_count = 0
            for e in to_process:
                rel = e["path"]
                action = e["action"]
                orig_hash = e.get("original_hash")
                target_file = os.path.join(target_root, rel)
                if action in ("replace", "delete"):
                    if not os.path.exists(target_file):
                        msg = f"Expected original file missing: {rel}"
                        if log_cb: log_cb("ERROR: " + msg)
                        return False, msg
                    if orig_hash and not force:
                        actual = sha256_file(target_file)
                        if actual != orig_hash:
                            msg = f"SHA256 mismatch for {rel}: expected {orig_hash}, found {actual}"
                            if log_cb: log_cb("ERROR: " + msg)
                            return False, msg
                validated_count += 1
                if progress_cb:
                    progress_cb(int(validated_count * 50 / total))
            # apply
            applied = 0
            for e in to_process:
                rel = e["path"]
                action = e["action"]
                target_file = os.path.join(target_root, rel)
                backup_file = os.path.join(backup_root, rel)
                if os.path.exists(target_file):
                    os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                    shutil.copy2(target_file, backup_file)
                if action == "delete":
                    if os.path.exists(target_file):
                        os.remove(target_file)
                        if log_cb: log_cb(f"deleted: {rel}")
                elif action in ("replace", "add"):
                    member_name = "files/" + rel
                    if member_name not in z.namelist():
                        msg = f"Patch file does not contain expected file: {member_name}"
                        if log_cb: log_cb("ERROR: " + msg)
                        return False, msg
                    out_dir = os.path.dirname(target_file)
                    if out_dir:
                        os.makedirs(out_dir, exist_ok=True)
                    with z.open(member_name) as src, open(target_file, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    if log_cb: log_cb(f"{action}: {rel}")
                applied += 1
                if progress_cb:
                    progress_cb(50 + int(applied * 50 / total))
            if log_cb: log_cb(f"Patch applied. Backup in folder: {backup_root}")
            return True, None
    except Exception as e:
        if log_cb:
            log_cb("ERROR applying patch:")
            log_cb(traceback.format_exc())
        return False, str(e)

# ---------------------------
# GUI
# ---------------------------

class UnypatcherGUI:
    def __init__(self, root):
        self.root = root
        root.title("Unypatcher GUI - .unypatch (Unity)")
        root.geometry("820x520")

        self.mainframe = Frame(root)
        self.mainframe.pack(fill="both", expand=True, padx=8, pady=8)

        self.notebook = ttk.Notebook(self.mainframe)
        self.notebook.pack(fill="both", expand=True)

        self.log_queue = queue.Queue()
        self._setup_logging_area()

        self.create_tab = Frame(self.notebook)
        self._build_create_tab(self.create_tab)
        self.notebook.add(self.create_tab, text="Create Patch")

        self.apply_tab = Frame(self.notebook)
        self._build_apply_tab(self.apply_tab)
        self.notebook.add(self.apply_tab, text="Apply Patch")

        self._update_ui_loop()

    # ---------------------
    # Logging & progress UI
    # ---------------------
    def _setup_logging_area(self):
        bottom = Frame(self.mainframe)
        bottom.pack(fill="x", pady=(6, 0))

        Label(bottom, text="Log:").pack(anchor="w")
        self.log_text = Text(bottom, height=10, state=DISABLED, wrap="word")
        self.log_text.pack(fill="both", expand=True)

        status_frame = Frame(bottom)
        status_frame.pack(fill="x", pady=(4, 0))
        self.progress_var = IntVar(value=0)
        self.progress = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", expand=True, side="left", padx=(0, 8))
        self.clear_button = Button(status_frame, text="Clear Log", command=self.clear_log)
        self.clear_button.pack(side="right")

    def log(self, msg):
        self.log_queue.put(msg)

    def clear_log(self):
        self.log_text.configure(state=NORMAL)
        self.log_text.delete(1.0, END)
        self.log_text.configure(state=DISABLED)

    def _update_ui_loop(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.configure(state=NORMAL)
                self.log_text.insert(END, msg + "\n")
                self.log_text.see(END)
                self.log_text.configure(state=DISABLED)
        except queue.Empty:
            pass
        self.root.after(150, self._update_ui_loop)

    # ---------------------
    # Create tab
    # ---------------------
    def _build_create_tab(self, parent):
        pad = {"padx": 6, "pady": 6}
        frame = Frame(parent)
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        Label(frame, text="Original Folder:").grid(row=0, column=0, sticky="w", **pad)
        self.orig_entry = Entry(frame, width=70)
        self.orig_entry.grid(row=0, column=1, sticky="w", **pad)
        Button(frame, text="Select", command=self._choose_orig).grid(row=0, column=2, **pad)

        Label(frame, text="Modified Folder:").grid(row=1, column=0, sticky="w", **pad)
        self.mod_entry = Entry(frame, width=70)
        self.mod_entry.grid(row=1, column=1, sticky="w", **pad)
        Button(frame, text="Select", command=self._choose_mod).grid(row=1, column=2, **pad)

        Label(frame, text="Output .unypatch:").grid(row=2, column=0, sticky="w", **pad)
        self.out_entry = Entry(frame, width=70)
        self.out_entry.grid(row=2, column=1, sticky="w", **pad)
        Button(frame, text="Save As...", command=self._choose_output).grid(row=2, column=2, **pad)

        self.show_preview_button = Button(frame, text="Show Preview", command=self._preview_changes)
        self.show_preview_button.grid(row=3, column=1, sticky="w", **pad)
        self.create_button = Button(frame, text="Create Patch", command=self._start_create)
        self.create_button.grid(row=3, column=2, sticky="e", **pad)

        Label(frame, text="Changes (Preview):").grid(row=4, column=0, sticky="w", **pad)
        self.preview_tree = ttk.Treeview(frame, columns=("action", "path"), show="headings", height=10)
        self.preview_tree.heading("action", text="Action")
        self.preview_tree.heading("path", text="Path")
        self.preview_tree.column("action", width=100, anchor="center")
        self.preview_tree.column("path", width=600, anchor="w")
        self.preview_tree.grid(row=5, column=0, columnspan=3, sticky="nsew", **pad)

        frame.grid_rowconfigure(5, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def _choose_orig(self):
        path = filedialog.askdirectory(title="Select Original Folder")
        if path:
            self.orig_entry.delete(0, END)
            self.orig_entry.insert(0, path)

    def _choose_mod(self):
        path = filedialog.askdirectory(title="Select Modified Folder")
        if path:
            self.mod_entry.delete(0, END)
            self.mod_entry.insert(0, path)

    def _choose_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".unypatch",
                                            filetypes=[("Unypatch", "*.unypatch"), ("ZIP", "*.zip"), ("All files", "*.*")],
                                            title="Save Output .unypatch As")
        if path:
            self.out_entry.delete(0, END)
            self.out_entry.insert(0, path)

    def _preview_changes(self):
        orig = self.orig_entry.get().strip()
        mod = self.mod_entry.get().strip()
        self.preview_tree.delete(*self.preview_tree.get_children())
        if not orig or not mod:
            messagebox.showwarning("Missing Input", "Please select both Original and Modified folders.")
            return
        try:
            manifest, changed_keys, _, _ = build_manifest_and_changed(orig, mod)
            for e in manifest["entries"]:
                self.preview_tree.insert("", END, values=(e["action"], e["path"]))
            self.log(f"Preview: {len(manifest['entries'])} changes detected.")
        except Exception as e:
            messagebox.showerror("Preview Error", str(e))
            self.log("Error in preview: " + str(e))

    def _start_create(self):
        orig = self.orig_entry.get().strip()
        mod = self.mod_entry.get().strip()
        out = self.out_entry.get().strip()
        if not orig or not mod or not out:
            messagebox.showwarning("Missing Input", "Please specify Original folder, Modified folder, and Output file.")
            return
        self.create_button.config(state=DISABLED)
        self.show_preview_button.config(state=DISABLED)
        t = threading.Thread(target=self._worker_create, args=(orig, mod, out), daemon=True)
        t.start()

    def _worker_create(self, orig, mod, out):
        def progress_cb(p):
            self.progress_var.set(p)

        def log_cb(msg):
            self.log(msg)

        success, err = create_unypatch(orig, mod, out, progress_cb=progress_cb, log_cb=log_cb)
        if not success:
            messagebox.showerror("Creation Error", f"{err}")
        else:
            messagebox.showinfo("Created", f"Patch successfully created:\n{out}")
        self.create_button.config(state=NORMAL)
        self.show_preview_button.config(state=NORMAL)
        self.progress_var.set(0)

    # ---------------------
    # Apply tab
    # ---------------------
    def _build_apply_tab(self, parent):
        pad = {"padx": 6, "pady": 6}
        frame = Frame(parent)
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        Label(frame, text="Game Folder (Target):").grid(row=0, column=0, sticky="w", **pad)
        self.target_entry = Entry(frame, width=70)
        self.target_entry.grid(row=0, column=1, sticky="w", **pad)
        Button(frame, text="Select", command=self._choose_target).grid(row=0, column=2, **pad)

        Label(frame, text=".unypatch File:").grid(row=1, column=0, sticky="w", **pad)
        self.patch_entry = Entry(frame, width=70)
        self.patch_entry.grid(row=1, column=1, sticky="w", **pad)
        Button(frame, text="Open", command=self._choose_patchfile).grid(row=1, column=2, **pad)

        self.force_var = BooleanVar(value=False)
        self.force_check = ttk.Checkbutton(frame, text="Ignore SHA check (force)", variable=self.force_var)
        self.force_check.grid(row=2, column=1, sticky="w", **pad)

        self.preview_apply_button = Button(frame, text="Show Manifest", command=self._show_manifest)
        self.preview_apply_button.grid(row=3, column=1, sticky="w", **pad)
        self.apply_button = Button(frame, text="Apply Patch", command=self._start_apply)
        self.apply_button.grid(row=3, column=2, sticky="e", **pad)

        Label(frame, text="Manifest Contents:").grid(row=4, column=0, sticky="w", **pad)
        self.manifest_tree = ttk.Treeview(frame, columns=("action", "path"), show="headings", height=10)
        self.manifest_tree.heading("action", text="Action")
        self.manifest_tree.heading("path", text="Path")
        self.manifest_tree.column("action", width=100, anchor="center")
        self.manifest_tree.column("path", width=600, anchor="w")
        self.manifest_tree.grid(row=5, column=0, columnspan=3, sticky="nsew", **pad)

        frame.grid_rowconfigure(5, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def _choose_target(self):
        path = filedialog.askdirectory(title="Select Target Game Folder")
        if path:
            self.target_entry.delete(0, END)
            self.target_entry.insert(0, path)

    def _choose_patchfile(self):
        path = filedialog.askopenfilename(title="Select Patch File",
                                          filetypes=[("Unypatch", "*.unypatch"), ("ZIP", "*.zip"), ("All files", "*.*")])
        if path:
            self.patch_entry.delete(0, END)
            self.patch_entry.insert(0, path)

    def _show_manifest(self):
        patch = self.patch_entry.get().strip()
        self.manifest_tree.delete(*self.manifest_tree.get_children())
        if not patch:
            messagebox.showwarning("No Patch File", "Please select a .unypatch file.")
            return
        try:
            with zipfile.ZipFile(patch, "r") as z:
                if "manifest.json" not in z.namelist():
                    messagebox.showerror("Invalid", "Patch file does not contain manifest.json")
                    return
                manifest = json.loads(z.read("manifest.json").decode("utf-8"))
                for e in manifest.get("entries", []):
                    self.manifest_tree.insert("", END, values=(e["action"], e["path"]))
                self.log(f"Manifest loaded: {len(manifest.get('entries', []))} entries.")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            self.log("Error loading manifest: " + str(e))

    def _start_apply(self):
        target = self.target_entry.get().strip()
        patch = self.patch_entry.get().strip()
        force = bool(self.force_var.get())
        if not target or not patch:
            messagebox.showwarning("Missing Input", "Please specify Target folder and Patch file.")
            return
        self.apply_button.config(state=DISABLED)
        self.preview_apply_button.config(state=DISABLED)
        t = threading.Thread(target=self._worker_apply, args=(target, patch, force), daemon=True)
        t.start()

    def _worker_apply(self, target, patch, force):
        def progress_cb(p):
            self.progress_var.set(p)

        def log_cb(msg):
            self.log(msg)

        success, err = apply_unypatch(target, patch, progress_cb=progress_cb, log_cb=log_cb, force=force)
        if not success:
            messagebox.showerror("Apply Error", f"{err}")
        else:
            messagebox.showinfo("Success", "Patch applied successfully.")
        self.apply_button.config(state=NORMAL)
        self.preview_apply_button.config(state=NORMAL)
        self.progress_var.set(0)

# ---------------------------
# Entrypoint
# ---------------------------
def main():
    root = Tk()
    app = UnypatcherGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
