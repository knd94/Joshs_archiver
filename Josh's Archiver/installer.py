# installer_hidden_repo_launch_fix.py
# Installer GUI with hidden repo updater (no visible repo link)
# Modified to detect/launch extracted exe named "Joshs_Archiver.exe" (or any exe found)
# Save and run: python installer_hidden_repo_launch_fix.py

import sys, os, shutil, subprocess, time, tempfile, json, traceback, re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import winreg

# Qt
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout,
    QRadioButton, QGroupBox, QLineEdit, QTextEdit, QCheckBox, QMessageBox, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# network lib (optional)
try:
    import requests
except Exception:
    requests = None

# ------------------- CONFIG -------------------
# Hidden repo used by updater (not shown to user)
_HIDDEN_GITHUB_REPO = "knd94/Joshs_archiver"   # owner/repo (kept in code; not shown to user)

# Preferred executable filename inside releases (detector)
PREFERRED_EXE_NAME = "Joshs_Archiver.exe"  # exact name to prefer; case-insensitive

# ------------------- helpers -------------------
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_cmd(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return -1, "", str(e)

def run_powershell(ps_script):
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
    return run_cmd(cmd)

def ps_escape(s: str) -> str:
    return s.replace("'", "''")

def create_shortcut(target, shortcut_path, args="", icon=None):
    tgt = ps_escape(str(Path(target).resolve()))
    sh = ps_escape(str(Path(shortcut_path).resolve()))
    args_esc = ps_escape(str(args or ""))
    working = ps_escape(str(Path(target).resolve().parent))
    ic_block = ""
    if icon:
        icon_esc = ps_escape(str(Path(icon).resolve()))
        ic_block = f"$Shortcut.IconLocation = '{icon_esc}'\n"
    ps = (
        "$W = New-Object -ComObject WScript.Shell\n"
        f"$Shortcut = $W.CreateShortcut('{sh}')\n"
        f"$Shortcut.TargetPath = '{tgt}'\n"
        f"$Shortcut.Arguments = '{args_esc}'\n"
        f"$Shortcut.WorkingDirectory = '{working}'\n"
        f"{ic_block}"
        "$Shortcut.Save()\n"
    )
    return run_powershell(ps)

def set_registry_value(root, path, name, value, vtype=winreg.REG_SZ):
    try:
        key = winreg.CreateKeyEx(root, path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, name, 0, vtype, value)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

_url_re = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
def redact_urls(s: str) -> str:
    if not s:
        return s
    return _url_re.sub("[LINK REDACTED]", str(s))

# ------------------- Install result -------------------
@dataclass
class InstallTaskResult:
    ok: bool
    messages: list
    installed_path: Optional[str] = None

# ------------------- Installer thread -------------------
class InstallerThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(object)  # will emit InstallTaskResult

    def __init__(self, src_exe: Optional[str], dest_dir: str, create_shortcuts: bool,
                 register_jarc: bool, add_path: bool, use_admin: bool):
        super().__init__()
        self.src_exe = src_exe
        self.dest_dir = dest_dir
        self.create_shortcuts = create_shortcuts
        self.register_jarc = register_jarc
        self.add_path = add_path
        self.use_admin = use_admin

    def emit_log(self, s):
        self.log.emit(redact_urls(str(s)))
        print(redact_urls(str(s)), flush=True)

    def _find_installed_exe(self, dest: Path) -> Optional[Path]:
        # Prefer the explicit preferred name (case-insensitive), else pick the first .exe found (search recursively).
        try:
            for p in dest.rglob("*"):
                if p.is_file() and p.suffix.lower() == ".exe" and p.name.lower() == PREFERRED_EXE_NAME.lower():
                    return p
            # fallback: any exe
            exes = list(dest.rglob("*.exe"))
            return exes[0] if exes else None
        except Exception:
            return None

    def _finalize_install(self, dest: Path):
        msgs = []
        target_exe = None
        try:
            # Look recursively for preferred exe name or any exe
            target_exe = self._find_installed_exe(dest)
            if self.create_shortcuts and target_exe:
                try:
                    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
                    start_menu = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Joshs Archiver"
                    start_menu.mkdir(parents=True, exist_ok=True)
                    lnk = start_menu / "Joshs Archiver.lnk"
                    rc, out, err = create_shortcut(str(target_exe), str(lnk), args="", icon=str(target_exe))
                    if rc == 0:
                        self.emit_log("Created Start Menu shortcut")
                    else:
                        self.emit_log("Start menu shortcut error")
                    desktop = Path(os.environ.get("USERPROFILE", Path.home())) / "Desktop"
                    desk_lnk = desktop / "Joshs Archiver.lnk"
                    rc2, out2, err2 = create_shortcut(str(target_exe), str(desk_lnk), args="", icon=str(target_exe))
                    if rc2 == 0:
                        self.emit_log("Created Desktop shortcut")
                    else:
                        self.emit_log("Desktop shortcut error")
                except Exception:
                    self.emit_log("Shortcut creation failed")
            elif self.create_shortcuts and not target_exe:
                self.emit_log("No EXE found to make shortcuts for.")

            if self.register_jarc:
                try:
                    progid = "JoshsArchiver.jarc"
                    exe_cmd = f'"{str(target_exe)}" "%1"' if target_exe else f'"{str(dest / "unknown_app.exe")}" "%1"'
                    set_registry_value(winreg.HKEY_CURRENT_USER, r"Software\Classes\.jarc", "", progid)
                    set_registry_value(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{progid}\shell\open\command", "", exe_cmd)
                    set_registry_value(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{progid}", "", "Josh's Archiver JARC")
                    self.emit_log("Registered .jarc (HKCU)")
                except Exception:
                    self.emit_log("Register .jarc failed")

            uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\JoshsArchiver"
            try:
                set_registry_value(winreg.HKEY_CURRENT_USER, uninstall_key, "DisplayName", "Josh's Archiver")
                uninst_cmd = f'"{str(target_exe)}" --uninstall' if target_exe else f'"{str(dest / "unknown_app.exe")}" --uninstall'
                set_registry_value(winreg.HKEY_CURRENT_USER, uninstall_key, "UninstallString", uninst_cmd)
                set_registry_value(winreg.HKEY_CURRENT_USER, uninstall_key, "DisplayVersion", "1.0")
                set_registry_value(winreg.HKEY_CURRENT_USER, uninstall_key, "Publisher", "You")
                set_registry_value(winreg.HKEY_CURRENT_USER, uninstall_key, "InstallLocation", str(dest))
                self.emit_log("Wrote Uninstall entry (HKCU)")
            except Exception:
                self.emit_log("Uninstall registry failed")

            if self.add_path:
                try:
                    env_key = r"Environment"
                    current = ""
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, env_key, 0, winreg.KEY_READ) as k:
                            current = winreg.QueryValueEx(k, "Path")[0]
                    except Exception:
                        current = os.environ.get("PATH", "")
                    new = str(dest) + ";" + current
                    set_registry_value(winreg.HKEY_CURRENT_USER, env_key, "Path", new)
                    import ctypes
                    HWND_BROADCAST = 0xffff
                    WM_SETTINGCHANGE = 0x1A
                    SMTO_ABORTIFHUNG = 0x2
                    ctypes.windll.user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, 5000, None)
                    self.emit_log("Added install folder to user PATH (HKCU)")
                except Exception:
                    self.emit_log("Add PATH failed")

            return True, msgs, (str(target_exe) if target_exe else None)
        except Exception as e:
            self.emit_log("Finalize error")
            return False, [str(e)], None

    def run(self):
        msgs = []
        installed_path = None
        try:
            self.emit_log(f"Installing to {self.dest_dir}")
            self.progress.emit(5)
            dest = Path(self.dest_dir)
            dest.mkdir(parents=True, exist_ok=True)
            self.progress.emit(15)
            time.sleep(0.05)

            # If a local EXE provided, copy it; otherwise assume files already placed or produced by updater
            if self.src_exe:
                src = Path(self.src_exe)
                if not src.exists():
                    raise RuntimeError("Source EXE not found")
                dest_exe = dest / src.name
                # If file already at dest and same, skip copying; else copy
                try:
                    shutil.copy2(str(src), str(dest_exe))
                except Exception:
                    # finalization will search, so ignore copy errors
                    pass
                self.emit_log("Copied main exe into install folder (or left existing).")
                installed_path = str(dest_exe)
                self.progress.emit(45)
            else:
                self.emit_log("No local EXE provided — finalizing based on files present.")
                self.progress.emit(55)

            ok, fm, exe_path = self._finalize_install(dest)
            msgs += fm
            if exe_path:
                installed_path = exe_path
            self.progress.emit(100)
            self.finished.emit(InstallTaskResult(ok=True, messages=msgs, installed_path=installed_path))
        except Exception as e:
            tb = traceback.format_exc()
            self.emit_log("Install failed: " + str(e))
            self.finished.emit(InstallTaskResult(ok=False, messages=[str(e)], installed_path=None))

# ------------------- Updater thread (uses hidden repo) -------------------
class UpdaterThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, token: Optional[str], install_location: Optional[str], check_only: bool = False):
        super().__init__()
        self.token = token.strip() if token else None
        self.install_location = install_location
        self.check_only = check_only
        self._stopped = False

    def emit_log(self, s):
        self.log.emit(redact_urls(str(s)))
        print(redact_urls(str(s)), flush=True)

    def _gh_headers(self):
        h = {"Accept": "application/vnd.github+json", "User-Agent": "JoshInstaller/1.0"}
        if self.token:
            h["Authorization"] = f"token {self.token}"
        return h

    def _find_exe_in_dir(self, d: Path) -> Optional[Path]:
        try:
            for p in d.rglob("*"):
                if p.is_file() and p.suffix.lower() == ".exe" and p.name.lower() == PREFERRED_EXE_NAME.lower():
                    return p
            exes = list(d.rglob("*.exe"))
            return exes[0] if exes else None
        except Exception:
            return None

    def run(self):
        if requests is None:
            self.finished.emit({"ok": False, "msg": "requests required (pip install requests)."})
            return
        try:
            owner_repo = _HIDDEN_GITHUB_REPO
            if "/" not in owner_repo:
                self.finished.emit({"ok": False, "msg": "Internal repo configuration error."}); return
            owner, repo = owner_repo.split("/", 1)
            api = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
            self.emit_log(f"Querying latest release for internal repo.")
            r = requests.get(api, headers=self._gh_headers(), timeout=20)
            if r.status_code == 404:
                self.finished.emit({"ok": False, "msg": "No releases found."}); return
            if r.status_code in (401,403):
                self.finished.emit({"ok": False, "msg": "Auth error accessing releases."}); return
            data = r.json()
            tag = data.get("tag_name") or data.get("name")
            if not tag:
                self.finished.emit({"ok": False, "msg": "No release tag found."}); return
            self.emit_log(f"Latest release: {tag}")
            assets = data.get("assets", [])
            if not assets:
                self.finished.emit({"ok": False, "msg": "No release assets."}); return

            chosen = None
            for a in assets:
                n = a.get("name","").lower()
                if n.endswith(".exe"):
                    chosen = a; break
            if not chosen:
                for a in assets:
                    if a.get("name","").lower().endswith(".zip"):
                        chosen = a; break
            if not chosen:
                chosen = assets[0]

            asset_name = chosen.get("name", "<unknown>")
            size = chosen.get("size", 0)
            if self.check_only or not self.install_location:
                # return metadata only (do not download)
                self.finished.emit({"ok": True, "msg": f"Latest: {tag}. Asset: {asset_name} ({size} bytes)", "tag": tag, "asset_name": asset_name})
                return

            url = chosen.get("browser_download_url")
            tmp = Path(tempfile.mkdtemp(prefix="jinstaller_"))
            out_file = tmp / asset_name
            self.emit_log(f"Downloading {asset_name} ...")
            with requests.get(url, headers=self._gh_headers(), stream=True, timeout=120) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("content-length") or 0)
                downloaded = 0
                with open(out_file, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
                            downloaded += len(chunk)
                            if total:
                                pct = int(downloaded * 90 / total)
                                self.progress.emit(pct)
            self.emit_log("Download finished.")
            inst = Path(self.install_location)
            inst.mkdir(parents=True, exist_ok=True)
            lower = out_file.suffix.lower()
            installed_path = None
            if lower == ".zip":
                import zipfile
                self.emit_log("Extracting asset into install folder...")
                with zipfile.ZipFile(out_file, "r") as zf:
                    # Extract into install dir (flattening may occur depending on zip)
                    zf.extractall(path=str(inst))
                self.emit_log("Extraction complete.")
                # try to find the exe in extracted tree
                found = self._find_exe_in_dir(inst)
                if found:
                    installed_path = str(found)
            else:
                # other asset types: copy into install dir
                dest_path = inst / out_file.name
                shutil.copy2(str(out_file), str(dest_path))
                self.emit_log("Copied release asset into install folder.")
                # if it's an exe we copied
                if dest_path.suffix.lower() == ".exe":
                    installed_path = str(dest_path)

            # emit installed_path if found (so installer can launch)
            msg = f"Installed {asset_name} to {str(inst)}"
            res = {"ok": True, "msg": msg, "asset_name": asset_name, "tag": tag}
            if installed_path:
                res["installed_path"] = installed_path
                self.emit_log(f"Found installed exe: {installed_path}")
            else:
                self.emit_log("No exe found automatically inside the release (will finalize later).")
            self.progress.emit(100)
            self.finished.emit(res)
        except Exception as e:
            tb = traceback.format_exc()
            self.emit_log("Updater error (details redacted).")
            self.finished.emit({"ok": False, "msg": str(e)})

# ------------------- GUI -------------------
class InstallerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Josh's Archiver - Installer (Updater hidden)")
        self.resize(820, 640)
        self._build_ui()
        self.install_thread = None
        self.updater_thread = None

    def _build_ui(self):
        v = QVBoxLayout(self)
        beta = QLabel("PRIVATE BETA")
        beta.setStyleSheet("font-weight: bold; color: white; background-color: #b30000; padding:6px; font-size:16px;")
        beta.setAlignment(Qt.AlignCenter)
        v.addWidget(beta)

        h0 = QHBoxLayout()
        v.addLayout(h0)
        h0.addWidget(QLabel("Application EXE:"))
        self.exe_path = QLineEdit()
        self.exe_path.setPlaceholderText("Path to your packaged app EXE (auto-detected if present)")
        h0.addWidget(self.exe_path, 1)
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.browse_exe)
        h0.addWidget(btn_browse)

        detected = self._autodetect_exe()
        if detected:
            self.exe_path.setText(str(detected))

        gb = QGroupBox("Install options")
        gv = QVBoxLayout(gb)
        rg = QHBoxLayout()
        self.radio_user = QRadioButton("Per-user (no admin) [recommended]")
        self.radio_user.setChecked(True)
        self.radio_program = QRadioButton("Program Files (all users) [requires admin]")
        rg.addWidget(self.radio_user); rg.addWidget(self.radio_program)
        gv.addLayout(rg)

        self.chk_shortcuts = QCheckBox("Create Start Menu + Desktop shortcuts")
        self.chk_shortcuts.setChecked(True)
        gv.addWidget(self.chk_shortcuts)

        self.chk_register = QCheckBox("Register .jarc file association (user)")
        self.chk_register.setChecked(True)
        gv.addWidget(self.chk_register)

        self.chk_path = QCheckBox("Add install folder to user PATH")
        self.chk_path.setChecked(False)
        gv.addWidget(self.chk_path)

        # Launch after install option
        self.chk_launch_after = QCheckBox("Launch application after install")
        self.chk_launch_after.setChecked(True)
        gv.addWidget(self.chk_launch_after)

        self.chk_download_if_missing = QCheckBox("If EXE missing: download latest release asset from hidden repo and install")
        self.chk_download_if_missing.setChecked(True)
        gv.addWidget(self.chk_download_if_missing)

        v.addWidget(gb)

        up_row = QHBoxLayout()
        self.btn_check_updates = QPushButton("Check for updates (hidden repo)")
        self.btn_check_updates.clicked.connect(self.check_updates_now)
        up_row.addWidget(self.btn_check_updates)
        up_row.addStretch()
        v.addLayout(up_row)

        row = QHBoxLayout()
        self.btn_install = QPushButton("Install")
        self.btn_install.clicked.connect(self.start_install)
        row.addWidget(self.btn_install)
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.close)
        row.addWidget(self.btn_close)
        v.addLayout(row)

        self.progress = QProgressBar(); self.progress.setRange(0,100)
        v.addWidget(self.progress)
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setMinimumHeight(260)
        v.addWidget(self.log)

        footer = QLabel("Note: Updater will ask permission before downloading/replacing files. The internal repo is hidden for safety.")
        footer.setWordWrap(True)
        v.addWidget(footer)

    def _autodetect_exe(self) -> Optional[Path]:
        cwd = Path.cwd()
        # look for dist folder with the expected exe name first
        cand = list(cwd.glob("dist/" + PREFERRED_EXE_NAME))
        if cand:
            return cand[0]
        candidates = list(cwd.glob("dist/*.exe")) + list(cwd.glob("*.exe"))
        return candidates[0] if candidates else None

    def browse_exe(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Select application EXE", filter="Executables (*.exe);;All files (*)")
        if fn:
            self.exe_path.setText(fn)

    def append_log(self, s):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log.append(f"[{t}] {redact_urls(str(s))}")

    # ---------------- install flow ----------------
    def start_install(self):
        src = self.exe_path.text().strip()
        have_local_exe = bool(src and Path(src).exists())
        if self.radio_program.isChecked() and not is_admin():
            resp = QMessageBox.question(self, "Admin required", "Program Files install chosen but you are not admin. Continue with per-user install instead?",
                                        QMessageBox.Yes | QMessageBox.No)
            if resp != QMessageBox.Yes:
                return
            self.radio_user.setChecked(True)

        if self.radio_program.isChecked():
            program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            dest_dir = Path(program_files) / "Joshs Archiver"
        else:
            local = os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
            dest_dir = Path(local) / "Programs" / "Joshs Archiver"

        create_shortcuts = self.chk_shortcuts.isChecked()
        register_jarc = self.chk_register.isChecked()
        add_path = self.chk_path.isChecked()
        download_if_missing = self.chk_download_if_missing.isChecked()
        launch_after = self.chk_launch_after.isChecked()

        if have_local_exe:
            proceed = QMessageBox.question(self, "Confirm install", f"Install from local EXE:\n{redact_urls(src)}\n\nInstall to:\n{redact_urls(str(dest_dir))}\nProceed?",
                                           QMessageBox.Yes | QMessageBox.No)
            if proceed != QMessageBox.Yes:
                return
            self.btn_install.setEnabled(False)
            self.append_log("Starting installer (local EXE)...")
            self.install_thread = InstallerThread(src_exe=src, dest_dir=str(dest_dir),
                                                   create_shortcuts=create_shortcuts, register_jarc=register_jarc,
                                                   add_path=add_path, use_admin=self.radio_program.isChecked())
            self.install_thread.progress.connect(self.progress.setValue)
            self.install_thread.log.connect(self.append_log)
            def on_fin(res: InstallTaskResult):
                self.btn_install.setEnabled(True)
                self.append_log("Installer finished.")
                if res.ok:
                    QMessageBox.information(self, "Installed", "Installation completed. Installer will remain open.")
                    # Launch if requested and installed_path exists
                    if launch_after and res.installed_path and Path(res.installed_path).exists():
                        try:
                            os.startfile(res.installed_path)
                            self.append_log("Launched installed application.")
                        except Exception as e:
                            self.append_log("Failed to launch installed app: " + str(e))
                else:
                    QMessageBox.warning(self, "Install failed", "See installer log.")
            self.install_thread.finished.connect(on_fin)
            self.install_thread.start()
        else:
            if not download_if_missing:
                QMessageBox.warning(self, "Missing EXE", "No local EXE chosen and 'download if missing' is disabled. Choose an EXE or enable the option.")
                return
            proceed = QMessageBox.question(self, "Confirm GitHub install",
                                           f"No local EXE selected.\nThe installer will download the latest release asset from the internal repository and install it to:\n{redact_urls(str(dest_dir))}\nProceed?",
                                           QMessageBox.Yes | QMessageBox.No)
            if proceed != QMessageBox.Yes:
                return
            self.btn_install.setEnabled(False)
            self.append_log("Starting updater to download latest release and install into folder...")
            token = None
            self.updater_thread = UpdaterThread(token=token, install_location=str(dest_dir), check_only=False)
            self.updater_thread.progress.connect(self.progress.setValue)
            self.updater_thread.log.connect(self.append_log)
            def on_update_done(info):
                msg = redact_urls(str(info.get("msg", "")))
                self.append_log("Updater finished: " + msg)
                if info.get("ok"):
                    # If updater provided installed_path, use it to finalize & potentially launch.
                    installed_exe = info.get("installed_path")
                    # Run finalization (shortcuts/registry) via InstallerThread but pass src_exe=None (finalizer searches for exe recursively)
                    fin_thread = InstallerThread(src_exe=None, dest_dir=str(dest_dir),
                                                 create_shortcuts=create_shortcuts, register_jarc=register_jarc,
                                                 add_path=add_path, use_admin=self.radio_program.isChecked())
                    fin_thread.progress.connect(self.progress.setValue)
                    fin_thread.log.connect(self.append_log)
                    def on_fin(res: InstallTaskResult):
                        self.btn_install.setEnabled(True)
                        self.append_log("Finalization finished.")
                        # prefer installed_exe from updater if present, else res.installed_path
                        exe_to_launch = installed_exe or res.installed_path
                        if res.ok:
                            QMessageBox.information(self, "Installed", "Installation from GitHub release completed. Installer remains open.")
                            if launch_after and exe_to_launch and Path(exe_to_launch).exists():
                                try:
                                    os.startfile(exe_to_launch)
                                    self.append_log("Launched installed application: " + str(exe_to_launch))
                                except Exception as e:
                                    self.append_log("Failed to launch installed app: " + str(e))
                        else:
                            QMessageBox.warning(self, "Finalize failed", "See log for details.")
                    fin_thread.finished.connect(on_fin)
                    fin_thread.start()
                else:
                    self.append_log("Updater reported failure: " + msg)
                    self.btn_install.setEnabled(True)
                    QMessageBox.warning(self, "Update failed", msg)
            self.updater_thread.finished.connect(on_update_done)
            self.updater_thread.start()

    # ---------------- check updates (uses hidden repo) ----------------
    def check_updates_now(self):
        if requests is None:
            QMessageBox.warning(self, "Missing dependency", "This feature requires the 'requests' package. Run: pip install requests")
            return
        self.append_log("Checking for updates (hidden repo)...")
        self.updater_thread = UpdaterThread(token=None, install_location=None, check_only=True)
        self.updater_thread.progress.connect(self.progress.setValue)
        self.updater_thread.log.connect(self.append_log)
        def on_up_done(info):
            ok = info.get("ok", False)
            msg = redact_urls(str(info.get("msg", "")))
            QMessageBox.information(self, "Update check", msg)
            self.append_log("Updater check finished: " + msg)
        self.updater_thread.finished.connect(on_up_done)
        self.updater_thread.start()

# ------------------- main -------------------
def main():
    app = QApplication(sys.argv)
    win = InstallerGUI()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
