import os, sys, json, time, shutil, tempfile, subprocess, traceback, threading, re, struct, zlib, hashlib
from pathlib import Path
from io import BytesIO

# --- QT binding selection ---
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, QThread, pyqtSignal as Signal, QSize
    from PyQt5.QtGui import QPixmap, QIcon
    from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QListWidgetItem, QFileIconProvider
    QT = "PyQt5"
except Exception:
    from PySide6 import QtCore, QtGui, QtWidgets
    from PySide6.QtCore import Qt, QThread, Signal, QSize
    from PySide6.QtGui import QPixmap, QIcon
    from PySide6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QListWidgetItem, QFileIconProvider
    QT = "PySide6"

# Optional libs
try:
    import py7zr; HAS_PY7ZR = True
except Exception:
    HAS_PY7ZR = False
try:
    import rarfile; HAS_RARFILE = True
except Exception:
    HAS_RARFILE = False
try:
    import pyzipper; HAS_PYZIPPER = True
except Exception:
    HAS_PYZIPPER = False
try:
    from PIL import Image
    HAS_PIL = True
except Exception:
    HAS_PIL = False

ON_WINDOWS = sys.platform.startswith("win")
if ON_WINDOWS:
    try:
        import winreg
    except Exception:
        winreg = None

# --- config ---
def cfg_path():
    if ON_WINDOWS:
        return Path(os.getenv("APPDATA") or Path.home()) / "miniarch_cfg.json"
    return Path.home() / ".miniarch_cfg.json"
CFG_FILE = cfg_path()
def load_cfg():
    try:
        if CFG_FILE.exists():
            return json.loads(CFG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}
CFG = load_cfg()

# thumbnail cache
def thumb_cache_dir():
    if ON_WINDOWS:
        base = Path(os.getenv("APPDATA") or Path.home())
    else:
        base = Path.home()
    d = base / "miniarch_thumbs"
    d.mkdir(parents=True, exist_ok=True)
    return d
THUMB_CACHE = thumb_cache_dir()

# small embedded icon (tiny placeholder PNG base64)
APP_ICON_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKUlEQVR4nO3NMQEAAAjDMO5fNFh4gqYAAAAAAAAAAAAAAAAAAAAAAABcC6kYAAEUgq1QAAAAAElFTkSuQmCC"
)

# --- helper utilities ---
def safe_run(cmd, timeout=900, cwd=None):
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout, cwd=cwd, creationflags=creationflags)
        return proc.returncode, proc.stdout.decode(errors="ignore"), proc.stderr.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -2, "", str(e)

def save_cfg():
    try:
        CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CFG_FILE.write_text(json.dumps(CFG, indent=2), encoding="utf-8")
    except Exception:
        pass

# --- jarc format helpers (minimal) ---
JARC_MAGIC = b"JARC"
JARC_FOOTER = b"JARCEOF"
def create_jarc(out_path, inputs, compress=True):
    files = []
    for p in inputs:
        pth = Path(p)
        if not pth.exists(): continue
        if pth.is_dir():
            parent = pth.parent
            for root, _, names in os.walk(pth):
                for n in names:
                    full = Path(root)/n
                    arc = full.relative_to(parent)
                    files.append((str(full), str(arc).replace("\\","/")))
        else:
            files.append((str(pth), pth.name))
    with open(out_path, "wb") as f:
        f.write(JARC_MAGIC); f.write(b'\x01')
        entries=[]
        for full, arc in files:
            off = f.tell()
            with open(full, "rb") as rf:
                data = rf.read()
            if compress:
                stored = zlib.compress(data); compressed = True
            else:
                stored = data; compressed = False
            f.write(stored)
            entries.append({"name":arc, "offset":off, "size":len(stored), "compressed":compressed})
        manifest = json.dumps(entries, ensure_ascii=False).encode("utf-8")
        f.write(manifest)
        f.write(struct.pack("<Q", len(manifest)))
        f.write(JARC_FOOTER)

def read_jarc_manifest(path):
    with open(path, "rb") as f:
        if f.read(4) != JARC_MAGIC:
            raise RuntimeError("Not a JARC")
        f.read(1)
        f.seek(0, os.SEEK_END)
        fs = f.tell()
        f.seek(fs - (len(JARC_FOOTER) + 8))
        manifest_len = struct.unpack("<Q", f.read(8))[0]
        footer = f.read(len(JARC_FOOTER))
        if footer != JARC_FOOTER:
            raise RuntimeError("Missing footer")
        start = fs - (len(JARC_FOOTER) + 8) - manifest_len
        f.seek(start)
        entries = json.loads(f.read(manifest_len).decode("utf-8"))
        return entries

def extract_jarc_member_bytes(path, entry_name):
    entries = read_jarc_manifest(path)
    for e in entries:
        if e["name"] == entry_name:
            with open(path, "rb") as f:
                f.seek(e["offset"])
                b = f.read(e["size"])
                return zlib.decompress(b) if e.get("compressed") else b
    raise KeyError("entry not found")

# --- Thumb worker (QThread) ---
class ThumbWorker(QtCore.QObject):
    thumb_ready = Signal(str, str)   # member, cache_path
    finished = Signal()
    log = Signal(str)

    def __init__(self, archive_path, archive_fmt, members, password=None):
        super().__init__()
        self.archive_path = archive_path
        self.archive_fmt = archive_fmt
        self.members = list(members)
        self.password = password
        self._alive = True

    def stop(self):
        self._alive = False

    def run(self):
        try:
            for name in self.members:
                if not self._alive: break
                # name may be absolute path (for dir) or member path (for archive)
                ext = Path(name).suffix.lower()
                if ext not in (".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"):
                    continue
                # fingerprint key: archive_path|name|archive_mtime (works for dir too)
                try:
                    archive_mtime = ""
                    try:
                        archive_mtime = str(Path(self.archive_path).stat().st_mtime)
                    except Exception:
                        archive_mtime = ""
                    key = hashlib.sha1((str(self.archive_path) + '|' + str(name) + '|' + archive_mtime).encode()).hexdigest()
                    cache_file = THUMB_CACHE / (key + ".png")
                except Exception:
                    continue

                if cache_file.exists():
                    self.thumb_ready.emit(name, str(cache_file)); continue
                data = None
                try:
                    if self.archive_fmt == "zip":
                        import zipfile
                        with zipfile.ZipFile(self.archive_path, "r") as zf:
                            candidate = None
                            for nm in zf.namelist():
                                if nm == name or Path(nm).name == Path(name).name:
                                    candidate = nm; break
                            if candidate:
                                try:
                                    data = zf.read(candidate)
                                except RuntimeError:
                                    data = None
                    elif self.archive_fmt == "7z" and HAS_PY7ZR:
                        tmpdir = Path(tempfile.mkdtemp(prefix="thumb_"))
                        try:
                            with py7zr.SevenZipFile(self.archive_path, 'r', password=(self.password if self.password else None)) as a:
                                try:
                                    a.extract(targets=[name], path=str(tmpdir))
                                except Exception:
                                    a.extractall(path=str(tmpdir))
                                cand = tmpdir / Path(name)
                                if cand.exists(): data = cand.read_bytes()
                                else:
                                    for p in tmpdir.rglob("*"):
                                        if p.is_file() and p.name == Path(name).name:
                                            data = p.read_bytes(); break
                        finally:
                            shutil.rmtree(str(tmpdir), ignore_errors=True)
                    elif self.archive_fmt == "rar" and HAS_RARFILE:
                        try:
                            with rarfile.RarFile(self.archive_path) as rf:
                                target = None
                                for nm in rf.namelist():
                                    if nm == name or Path(nm).name == Path(name).name:
                                        target = nm; break
                                if target:
                                    with rf.open(target) as fh:
                                        data = fh.read()
                        except Exception:
                            data = None
                    elif self.archive_fmt == "jarc":
                        try:
                            data = extract_jarc_member_bytes(self.archive_path, name)
                        except Exception:
                            data = None
                    elif self.archive_fmt == "dir":
                        # name is expected to be either absolute path or relative to archive_path
                        # try absolute first:
                        p = Path(name)
                        if not p.exists():
                            p = Path(self.archive_path) / name
                        if p.exists():
                            try:
                                data = p.read_bytes()
                            except Exception:
                                data = None
                except Exception as e:
                    self.log.emit(f"thumb extract error {name}: {e}")
                    data = None
                if not data: continue
                try:
                    THUMB_CACHE.mkdir(parents=True, exist_ok=True)
                    if HAS_PIL:
                        img = Image.open(BytesIO(data)).convert("RGBA")
                        img.thumbnail((128,128), Image.LANCZOS)
                        img.save(str(cache_file), format="PNG")
                    else:
                        cache_file.write_bytes(data)
                    self.thumb_ready.emit(name, str(cache_file))
                except Exception as e:
                    self.log.emit("thumb save error "+str(e))
                QtCore.QThread.msleep(20)
        except Exception as e:
            self.log.emit("thumbworker crashed: "+str(e)+"\n"+traceback.format_exc())
        finally:
            self.finished.emit()

# --- Par2 Manager ---
class Par2Signals(QtCore.QObject):
    log = Signal(str)
    progress = Signal(int,int)
    finished = Signal(object)

class Par2Manager:
    """
    Manages par2 create & repair. 
    run_create(groups, redundancy, default_out_dir=None) where groups is list of (files_list, base_name, out_dir)
    run_repair_many(par2_files, move_repaired_to=None, extract_repaired=True)
    """

    def __init__(self, par2_exe=None, timeout=900):
        self.par2_exe = par2_exe or CFG.get("par2_exe") or shutil.which("par2") or shutil.which("par2.exe")
        self.timeout = timeout
        self.signals = Par2Signals()
        self._thread = None
        self._stop = False

    def is_ok(self):
        return bool(self.par2_exe and Path(self.par2_exe).exists())

    def _log(self, s):
        try:
            self.signals.log.emit(s)
        except Exception:
            pass

    def _try_run(self, cmd, cwd):
        rc, out, err = safe_run(cmd, timeout=self.timeout, cwd=cwd)
        return rc, out, err

    def _create_single(self, files, redundancy, base_name=None, out_dir=None):
        res = {"files": files, "created": [], "rc": None, "out": "", "err": "", "error": None}
        try:
            # Filter out any .par2 files from the candidate set
            files = [f for f in files if not str(f).lower().endswith(".par2")]
            files = [f for f in files if Path(f).exists()]
            if not files:
                res["error"] = "No non-par2 files to protect"
                return res
            workdir = Path(out_dir) if out_dir else Path(files[0]).parent
            workdir.mkdir(parents=True, exist_ok=True)
            if base_name:
                par2_path = Path(out_dir if out_dir else workdir) / (base_name + ".par2")
            else:
                par2_path = Path(workdir) / (Path(files[0]).stem + ".par2")
            # Build command: par2 create -r{redundancy} par2_path file1 file2 ...
            cmd = [self.par2_exe, "create", f"-r{redundancy}", str(par2_path)] + files
            self._log(f"par2: Running: {' '.join(cmd)} (cwd={workdir})")
            rc, out, err = self._try_run(cmd, cwd=str(workdir))
            res["rc"] = rc; res["out"] = out; res["err"] = err
            # pick up created par2s with same stem
            stem = par2_path.stem
            created = []
            for f in workdir.iterdir():
                if f.is_file() and f.suffix.lower() == ".par2" and f.stem.startswith(stem):
                    created.append(str(f))
            res["created"] = created
            if rc != 0 and not created:
                res["error"] = f"par2 returned rc={rc}"
            return res
        except Exception as e:
            res["error"] = str(e)
            self._log("par2 create error: "+str(e))
            return res

    def run_create(self, groups, redundancy=10, default_out_dir=None):
        if self._thread and self._thread.is_alive():
            self._log("par2: already running create")
            return
        def worker():
            total = len(groups)
            summary=[]
            for idx, grp in enumerate(groups, start=1):
                if self._stop: break
                files, base_name, out_dir = grp
                out_dir = out_dir or default_out_dir
                # Expand folders to file-lists (but exclude .par2)
                expanded=[]
                for f in files:
                    p = Path(f)
                    if not p.exists(): continue
                    if p.is_dir():
                        for root, _, names in os.walk(str(p)):
                            for n in names:
                                fn = Path(root) / n
                                if not fn.name.lower().endswith(".par2"):
                                    expanded.append(str(fn))
                    else:
                        if not p.name.lower().endswith(".par2"):
                            expanded.append(str(p))
                files = expanded
                self.signals.progress.emit(idx, total)
                self._log(f"par2: Creating par2 for group {idx}/{total} files={len(files)} base={base_name} out_dir={out_dir}")
                r = self._create_single(files, redundancy, base_name=base_name, out_dir=out_dir)
                summary.append(r)
            self.signals.finished.emit(summary)
        self._thread = threading.Thread(target=worker, daemon=True); self._thread.start()

    def _pick_main_par2(self, par2_files):
        # choose first file that does not contain '+' or 'vol' in name (heuristic)
        for f in par2_files:
            name = Path(f).name.lower()
            if "+" not in name and "vol" not in name:
                return f
        # else return the longest/first
        return par2_files[0] if par2_files else None

    def _try_extract_file(self, file_path: str, dest_folder: str):
        """Attempt to extract archives (zip,7z,rar,jarc) to dest_folder.
           Returns list of extracted paths (may be empty)."""
        extracted = []
        p = Path(file_path)
        ext = p.suffix.lower()
        dest = Path(dest_folder)
        dest.mkdir(parents=True, exist_ok=True)
        try:
            if ext == ".zip":
                import zipfile
                try:
                    with zipfile.ZipFile(str(p), "r") as zf:
                        zf.extractall(path=str(dest))
                        extracted = [str(Path(dest)/nm) for nm in zf.namelist()]
                except RuntimeError:
                    self._log("zip extraction failed (maybe password).")
            elif ext == ".7z" and HAS_PY7ZR:
                try:
                    with py7zr.SevenZipFile(str(p), 'r') as a:
                        a.extractall(path=str(dest))
                        for nm in a.getnames():
                            extracted.append(str(Path(dest)/nm))
                except Exception as e:
                    self._log("7z extract failed: "+str(e))
            elif ext == ".rar" and HAS_RARFILE:
                try:
                    with rarfile.RarFile(str(p)) as rf:
                        rf.extractall(path=str(dest))
                        for nm in rf.namelist():
                            extracted.append(str(Path(dest)/nm))
                except Exception as e:
                    self._log("rar extract failed: "+str(e))
            elif ext == ".jarc":
                try:
                    entries = read_jarc_manifest(str(p))
                    for e in entries:
                        data = extract_jarc_member_bytes(str(p), e["name"])
                        outp = dest / Path(e["name"])
                        outp.parent.mkdir(parents=True, exist_ok=True)
                        outp.write_bytes(data)
                        extracted.append(str(outp))
                except Exception as e:
                    self._log("jarc extract failed: "+str(e))
        except Exception as e:
            self._log("extract attempt error: "+str(e))
        return extracted

    def _repair_single(self, main_par2, move_repaired_to=None, extract_repaired=True):
        res = {"par2": main_par2, "rc": None, "out":"", "err":"", "moved":[], "extracted":[], "error": None}
        try:
            p = Path(main_par2)
            if not p.exists():
                res["error"] = "par2 missing"; return res
            workdir = Path(p.parent)
            # snapshot existing file mtimes (excluding .par2 files)
            before = {}
            for f in workdir.iterdir():
                if f.is_file() and f.suffix.lower() != ".par2":
                    try: before[str(f)] = f.stat().st_mtime
                    except Exception: before[str(f)] = 0
            cmd = [self.par2_exe, "repair", str(p)]
            self._log("par2: Running repair: " + " ".join(cmd) + f" (cwd={workdir})")
            rc, out, err = self._try_run(cmd, cwd=str(workdir))
            res["rc"] = rc; res["out"] = out; res["err"] = err
            # small wait; re-scan to find files with newer mtime
            time.sleep(0.2)
            moved = []
            changed_files = []
            for f in workdir.iterdir():
                if f.is_file() and f.suffix.lower() != ".par2":
                    old = before.get(str(f), 0)
                    try:
                        if f.stat().st_mtime > old + 0.0001:
                            changed_files.append(str(f))
                    except Exception:
                        pass
            # if move_repaired_to provided, move changed files
            if move_repaired_to and changed_files:
                dest = Path(move_repaired_to); dest.mkdir(parents=True, exist_ok=True)
                for cf in changed_files:
                    try:
                        src = Path(cf)
                        dst = dest / src.name
                        if dst.exists():
                            dst = dest / (src.stem + f"_{int(time.time())}" + src.suffix)
                        shutil.move(str(src), str(dst))
                        moved.append(str(dst))
                    except Exception:
                        try:
                            shutil.copy2(str(src), str(dest / Path(src).name))
                            moved.append(str(dest / Path(src).name))
                        except Exception as e:
                            self._log("Failed to move repaired file: " + str(e))
            else:
                # no move requested — keep changed files in place (but report them)
                moved = []
            res["moved"] = moved

            # Extraction step: for each changed file, if it's an archive, extract it
            extracted_all = []
            for cf in (moved if moved else changed_files):
                # if we moved, extract from moved location; else from original location
                src_path = Path(cf)
                # choose extraction target: if moved->extract into same dest folder with subfolder; else into same folder
                if move_repaired_to:
                    extract_into = Path(move_repaired_to) / (src_path.stem + "_extracted")
                else:
                    extract_into = src_path.parent / (src_path.stem + "_extracted")
                # check extension
                ext = src_path.suffix.lower()
                if ext in (".zip", ".7z", ".rar", ".jarc"):
                    self._log(f"par2: extracting repaired archive {src_path} -> {extract_into}")
                    extracted = self._try_extract_file(str(src_path), str(extract_into))
                    extracted_all += extracted
            res["extracted"] = extracted_all

            return res
        except Exception as e:
            res["error"] = str(e)
            self._log("par2 repair error: "+str(e)+"\n"+traceback.format_exc())
            return res

    def run_repair_many(self, par2_files, move_repaired_to=None, extract_repaired=True):
        if self._thread and self._thread.is_alive():
            self._log("par2: repair already running")
            return
        # Group by directory and base (simple heuristic)
        grouped = {}
        for p in par2_files:
            pp = Path(p)
            key = str(pp.parent)
            grouped.setdefault(key, []).append(str(pp))
        def worker():
            total = len(grouped)
            summary=[]
            for idx, (dirpath, files) in enumerate(grouped.items(), start=1):
                if self._stop: break
                self.signals.progress.emit(idx, total)
                main = self._pick_main_par2(files)
                if not main:
                    self._log("par2: no main par2 found for group in " + dirpath)
                    continue
                self._log(f"par2: Repairing {main} in {dirpath}")
                r = self._repair_single(main, move_repaired_to=move_repaired_to, extract_repaired=extract_repaired)
                r["group"] = files
                summary.append(r)
            self.signals.finished.emit(summary)
        self._thread = threading.Thread(target=worker, daemon=True); self._thread.start()

    def stop(self):
        self._stop = True

# --- GUI Window ---
class MiniArchWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Josh's Archiver")
        self.resize(1100,780)
        self._install_icon()
        self._build_ui()
        self.current_archive = None
        self.current_format = None
        self.pwd_cache = {}
        self.archive_stack = []
        self.temp_dirs = []
        self.thumb_thread = None
        self.thumb_worker = None
        self.par2mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
        self._log(f"Init: QT={QT}, py7zr={HAS_PY7ZR}, pyzipper={HAS_PYZIPPER}, rarfile={HAS_RARFILE}, pillow={HAS_PIL}")
        self.statusBar().showMessage(f"par2: {self.par2mgr.par2_exe or 'not found'}")

        # If the process was launched with args (e.g., via "Open with"), schedule extraction after shown.
        self._pending_cli_paths = []
        if len(sys.argv) > 1:
            # keep only existing file paths
            for a in sys.argv[1:]:
                if os.path.exists(a):
                    self._pending_cli_paths.append(os.path.abspath(a))

    def _install_icon(self):
        try:
            import base64
            data = base64.b64decode(APP_ICON_BASE64)
            pm = QPixmap(); pm.loadFromData(data)
            if not pm.isNull(): self.setWindowIcon(QIcon(pm))
        except Exception:
            pass

    def _build_ui(self):
        w = QtWidgets.QWidget(); self.setCentralWidget(w)
        v = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout(); v.addLayout(top)
        self.btn_open = QtWidgets.QPushButton("Open Archive..."); self.btn_open.clicked.connect(self.open_archive); top.addWidget(self.btn_open)
        self.btn_extract_archive = QtWidgets.QPushButton("Extract Archive..."); self.btn_extract_archive.clicked.connect(self.extract_archive); top.addWidget(self.btn_extract_archive)
        self.btn_back = QtWidgets.QPushButton("Back"); self.btn_back.clicked.connect(self.go_back); self.btn_back.setEnabled(False); top.addWidget(self.btn_back)
        top.addStretch()
        self.btn_clear_thumbs = QtWidgets.QPushButton("Clear thumbnail cache"); self.btn_clear_thumbs.clicked.connect(self.clear_thumb_cache); top.addWidget(self.btn_clear_thumbs)
        self.btn_loc = QtWidgets.QPushButton("Locate par2"); self.btn_loc.clicked.connect(self.locate_par2); top.addWidget(self.btn_loc)
        self.btn_search = QtWidgets.QPushButton("Search par2"); self.btn_search.clicked.connect(self.search_par2); top.addWidget(self.btn_search)
        self.btn_install = QtWidgets.QPushButton("Install par2 via Chocolatey"); self.btn_install.clicked.connect(self.install_par2_choco); top.addWidget(self.btn_install)

        split = QtWidgets.QSplitter(); v.addWidget(split, 1)
        left = QtWidgets.QWidget(); left_l = QtWidgets.QVBoxLayout(left); split.addWidget(left)
        right = QtWidgets.QWidget(); right_l = QtWidgets.QVBoxLayout(right); split.addWidget(right)

        # make initial equal sizes
        split.setSizes([600,600])

        left_l.addWidget(QtWidgets.QLabel("Archive contents:"))
        self.list_contents = QtWidgets.QListWidget(); self.list_contents.setIconSize(QSize(96,96))
        self.list_contents.setMinimumWidth(420)
        left_l.addWidget(self.list_contents, 1)
        self.list_contents.itemDoubleClicked.connect(self.item_double)

        # context menu for list_contents
        self.list_contents.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_contents.customContextMenuRequested.connect(self._on_list_context_menu)

        left_l.addWidget(QtWidgets.QLabel("Log:"))
        self.log_text = QtWidgets.QTextEdit(); self.log_text.setReadOnly(True); left_l.addWidget(self.log_text, 1)

        right_l.addWidget(QtWidgets.QLabel("Create / Stage"))
        self.combo_fmt = QtWidgets.QComboBox(); self.combo_fmt.addItems(["zip","7z","jarc","rar"]); right_l.addWidget(self.combo_fmt)
        self.input_pwd = QtWidgets.QLineEdit(); self.input_pwd.setEchoMode(QtWidgets.QLineEdit.Password); self.input_pwd.setPlaceholderText("Password (blank = none)"); right_l.addWidget(self.input_pwd)
        h = QtWidgets.QHBoxLayout(); right_l.addLayout(h)
        self.chk_par2_auto = QtWidgets.QCheckBox("Also create .par2 after archive"); h.addWidget(self.chk_par2_auto)
        h.addWidget(QtWidgets.QLabel("Redundancy %"))
        self.spin_red = QtWidgets.QSpinBox(); self.spin_red.setRange(1,500); self.spin_red.setValue(10); h.addWidget(self.spin_red)

        self.btn_add_files = QtWidgets.QPushButton("Add Files"); self.btn_add_files.clicked.connect(self.stage_add_files); right_l.addWidget(self.btn_add_files)
        self.btn_add_folder = QtWidgets.QPushButton("Add Folder"); self.btn_add_folder.clicked.connect(self.stage_add_folder); right_l.addWidget(self.btn_add_folder)
        self.list_stage = QtWidgets.QListWidget(); self.list_stage.setMinimumWidth(320); right_l.addWidget(self.list_stage, 1)
        row = QtWidgets.QHBoxLayout(); right_l.addLayout(row)
        self.btn_create = QtWidgets.QPushButton("Create Archive"); self.btn_create.clicked.connect(self.create_archive); row.addWidget(self.btn_create)
        # removed Create RAR button as requested

        right_l.addWidget(QtWidgets.QLabel("Par2 Targets (files/folders):"))
        self.list_par2_targets = QtWidgets.QListWidget(); right_l.addWidget(self.list_par2_targets, 1)
        pr = QtWidgets.QHBoxLayout(); right_l.addLayout(pr)
        self.btn_par2_files = QtWidgets.QPushButton("Add Files"); self.btn_par2_files.clicked.connect(self.par2_add_files); pr.addWidget(self.btn_par2_files)
        self.btn_par2_folder = QtWidgets.QPushButton("Add Folder"); self.btn_par2_folder.clicked.connect(self.par2_add_folder); pr.addWidget(self.btn_par2_folder)
        p2 = QtWidgets.QHBoxLayout(); right_l.addLayout(p2)
        self.radio_one = QtWidgets.QRadioButton("One .par2 per file/folder"); self.radio_one.setChecked(True); p2.addWidget(self.radio_one)
        self.radio_all = QtWidgets.QRadioButton("One .par2 for all"); p2.addWidget(self.radio_all)
        ract = QtWidgets.QHBoxLayout(); right_l.addLayout(ract)
        self.btn_par2_create_selected = QtWidgets.QPushButton("Create .par2 for Selected"); self.btn_par2_create_selected.clicked.connect(self.par2_create_selected); ract.addWidget(self.btn_par2_create_selected)
        self.btn_par2_create_all = QtWidgets.QPushButton("Create .par2 for All"); self.btn_par2_create_all.clicked.connect(self.par2_create_all); ract.addWidget(self.btn_par2_create_all)

        right_l.addWidget(QtWidgets.QLabel("Loaded .par2 files (repair):"))
        self.list_loaded_par2 = QtWidgets.QListWidget(); right_l.addWidget(self.list_loaded_par2, 1)
        rrow = QtWidgets.QHBoxLayout(); right_l.addLayout(rrow)
        self.btn_load_par2 = QtWidgets.QPushButton("Load .par2 Files"); self.btn_load_par2.clicked.connect(self.load_par2); rrow.addWidget(self.btn_load_par2)
        self.btn_repair_selected = QtWidgets.QPushButton("Repair & Move Selected"); self.btn_repair_selected.clicked.connect(self.repair_selected); rrow.addWidget(self.btn_repair_selected)
        self.btn_repair_all = QtWidgets.QPushButton("Repair & Move All"); self.btn_repair_all.clicked.connect(self.repair_all); rrow.addWidget(self.btn_repair_all)
        self.btn_repair_selected.setEnabled(False); self.btn_repair_all.setEnabled(False)

        # new checkbox: extract repaired archives automatically
        self.chk_extract_after = QtWidgets.QCheckBox("Extract repaired archives"); self.chk_extract_after.setChecked(True)
        right_l.addWidget(self.chk_extract_after)

        self.progress = QtWidgets.QProgressBar(); v.addWidget(self.progress)

    # --- logging ---
    def _log(self, s):
        try:
            t = time.strftime("%Y-%m-%d %H:%M:%S")
            ln = f"{t} {s}"
            self.log_text.append(ln)
        except Exception:
            pass
        print(s, flush=True)

    # --- archive load / list ---
    def open_archive(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open archive", filter="Archives (*.zip *.7z *.rar *.jarc);;All files (*)")
        if not fn: return
        ext = Path(fn).suffix.lower().lstrip('.')
        if ext not in ("zip","7z","rar","jarc"):
            QMessageBox.warning(self, "Unsupported", "Supported: zip,7z,rar,jarc"); return
        if self.current_archive:
            self.archive_stack.append((self.current_archive, self.current_format))
            self.btn_back.setEnabled(True)
        self.load_archive(fn, ext)

    def go_back(self):
        if not self.archive_stack: return
        path, fmt = self.archive_stack.pop()
        if not self.archive_stack:
            self.btn_back.setEnabled(False)
        # if fmt == 'dir' use load_directory, else load_archive
        if fmt == "dir":
            self.load_directory(path)
        else:
            self.load_archive(path, fmt)

    def load_archive(self, path, fmt):
        # fmt expected: zip,7z,rar,jarc
        self.current_archive = path; self.current_format = fmt
        self._log(f"Loading archive: {path}")
        self.list_contents.clear()
        members=[]
        pwd = self.pwd_cache.get(path)
        try:
            if fmt == "zip":
                import zipfile
                with zipfile.ZipFile(path, 'r') as zf:
                    need_pwd=False
                    for zi in zf.infolist():
                        if getattr(zi, "flag_bits", 0) & 0x1:
                            need_pwd=True; break
                    if need_pwd and not pwd:
                        p = self._ask_password("ZIP seems encrypted; enter password to list")
                        if not p: QMessageBox.information(self, "Password", "Won't list"); return
                        self.pwd_cache[path]=p; pwd=p
                    members = zf.namelist()
            elif fmt == "7z":
                if not HAS_PY7ZR: raise RuntimeError("py7zr required")
                try:
                    with py7zr.SevenZipFile(path, 'r', password=(pwd if pwd else None)) as a:
                        members = a.getnames()
                except Exception:
                    p = self._ask_password("7z requires password")
                    if not p: QMessageBox.information(self, "Password", "Won't list"); return
                    self.pwd_cache[path]=p; pwd=p
                    with py7zr.SevenZipFile(path, 'r', password=p) as a:
                        members = a.getnames()
            elif fmt == "rar":
                if not HAS_RARFILE: raise RuntimeError("rarfile required")
                try:
                    with rarfile.RarFile(path) as rf:
                        members = rf.namelist()
                except rarfile.NeedPassword:
                    p = self._ask_password("RAR needs password")
                    if not p: QMessageBox.information(self, "Password", "Won't list"); return
                    self.pwd_cache[path]=p; pwd=p
                    with rarfile.RarFile(path) as rf:
                        members = rf.namelist()
                except Exception:
                    p = self._ask_password("RAR may require password")
                    if not p: QMessageBox.information(self, "Password", "Won't list"); return
                    self.pwd_cache[path]=p; pwd=p
                    with rarfile.RarFile(path) as rf:
                        members = rf.namelist()
            elif fmt == "jarc":
                entries = read_jarc_manifest(path)
                members = [e["name"] for e in entries]
        except Exception as e:
            self._log("list error: " + str(e) + "\n" + traceback.format_exc())
            QMessageBox.critical(self, "List error", str(e)); return

        image_members=[]
        for m in members:
            it = QListWidgetItem(m)
            if m.endswith('/') or m.endswith('\\'):
                it.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_DirIcon))
            else:
                ext = Path(m).suffix.lower()
                if ext in (".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"):
                    it.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_FileIcon))
                    image_members.append(m)
                else:
                    try:
                        provider = QFileIconProvider()
                        dummy = Path(THUMB_CACHE) / ("dummy" + (ext or ".txt"))
                        if not dummy.exists():
                            dummy.write_bytes(b"")
                        qfi = QtCore.QFileInfo(str(dummy))
                        icon = provider.icon(qfi)
                        it.setIcon(icon)
                    except Exception:
                        it.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_FileIcon))
            self.list_contents.addItem(it)
        if image_members:
            self._start_thumb_worker(image_members)

    def load_directory(self, folder_path):
        """Show a filesystem folder in the list_contents (used to showcase extracted folder)."""
        folder = Path(folder_path)
        if not folder.exists() or not folder.is_dir():
            self._log("load_directory: invalid folder: "+str(folder_path))
            return
        self.current_archive = str(folder)
        self.current_format = "dir"
        self._log(f"Loading directory: {folder_path}")
        self.list_contents.clear()
        members = []
        try:
            for p in sorted(folder.iterdir()):
                # show top-level only (like folder view). If you want recursive, adjust.
                display_name = p.name + ("/" if p.is_dir() else "")
                it = QListWidgetItem(display_name)
                if p.is_dir():
                    it.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_DirIcon))
                else:
                    ext = p.suffix.lower()
                    if ext in (".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"):
                        it.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_FileIcon))
                        members.append(str(p))  # pass absolute paths for thumbs
                    else:
                        try:
                            provider = QFileIconProvider()
                            qfi = QtCore.QFileInfo(str(p))
                            icon = provider.icon(qfi)
                            it.setIcon(icon)
                        except Exception:
                            it.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_FileIcon))
                self.list_contents.addItem(it)
        except Exception as e:
            self._log("load_directory error: "+str(e))

        # start thumbnails for image files (members contains full paths)
        if members:
            self._start_thumb_worker(members)

    def _ask_password(self, prompt):
        text, ok = QtWidgets.QInputDialog.getText(self, "Password", prompt, QtWidgets.QLineEdit.Password)
        if ok and text:
            return text
        return None

    # thumbnail worker management
    def _start_thumb_worker(self, names):
        try:
            if self.thumb_worker and self.thumb_thread:
                self.thumb_worker.stop(); self.thumb_thread.quit(); self.thumb_thread.wait(200)
        except Exception:
            pass
        # for directory mode we pass archive_path as the folder and format 'dir'
        self.thumb_worker = ThumbWorker(self.current_archive, self.current_format, names, password=self.pwd_cache.get(self.current_archive))
        self.thumb_thread = QThread()
        self.thumb_worker.moveToThread(self.thumb_thread)
        self.thumb_thread.started.connect(self.thumb_worker.run)
        self.thumb_worker.thumb_ready.connect(self._on_thumb_ready)
        self.thumb_worker.log.connect(lambda s: self._log("thumb: "+s))
        self.thumb_worker.finished.connect(self._on_thumb_finished)
        self.thumb_thread.start()

    def _on_thumb_ready(self, member, cache_path):
        # For dir, member may be an absolute path; the list item text is name or name + /
        for i in range(self.list_contents.count()):
            it = self.list_contents.item(i)
            # match by name
            if Path(member).name == Path(it.text()).name:
                try:
                    pm = QPixmap(cache_path)
                    if not pm.isNull():
                        it.setIcon(QIcon(pm.scaled(96,96, Qt.KeepAspectRatio, Qt.SmoothTransformation)))
                except Exception:
                    pass

    def _on_thumb_finished(self):
        self._log("Thumbnail worker finished")
        try:
            if self.thumb_thread:
                self.thumb_thread.quit(); self.thumb_thread.wait(200)
        except Exception:
            pass

    def clear_thumb_cache(self):
        removed=0
        for f in THUMB_CACHE.iterdir():
            if f.is_file() and f.suffix.lower()==".png":
                try: f.unlink(); removed+=1
                except Exception: pass
        self._log(f"Cleared {removed} thumbnails")

    # --- open/extract nested members ---
    def item_double(self, item):
        member = item.text()
        # strip trailing slash if folder
        member = member.rstrip("/\\")
        if self.current_format == "dir":
            # open file/folder in system
            p = Path(self.current_archive) / member
            if p.exists():
                if p.is_dir():
                    # drill into directory within our UI
                    self.archive_stack.append((self.current_archive, self.current_format))
                    self.btn_back.setEnabled(True)
                    self.load_directory(str(p))
                else:
                    self._open_with_system(p)
            else:
                QMessageBox.warning(self, "Open", "File not found")
            return

        ext = Path(member).suffix.lower().lstrip('.')
        if ext in ("zip","7z","rar","jarc"):
            tmpd = Path(tempfile.mkdtemp(prefix="miniarch_nested_")); self.temp_dirs.append(tmpd)
            got = self._extract_member_to_temp(member, tmpd)
            if got:
                # if we successfully extracted a nested archive file, load it as archive
                if self.current_archive:
                    self.archive_stack.append((self.current_archive, self.current_format))
                    self.btn_back.setEnabled(True)
                self.load_archive(str(got), ext)
            else:
                QMessageBox.warning(self, "Open nested", "Could not extract nested archive")
        else:
            tmpd = Path(tempfile.mkdtemp(prefix="miniarch_open_")); self.temp_dirs.append(tmpd)
            got = self._extract_member_to_temp(member, tmpd)
            if got and got.exists():
                self._open_with_system(got)
            else:
                # try to find by name in tempdir
                found=None
                for p in tmpd.rglob("*"):
                    if p.is_file() and p.name == Path(member).name:
                        found=p; break
                if found: self._open_with_system(found)
                else: QMessageBox.warning(self, "Open", "Could not extract/open member")

    def _open_with_system(self, p: Path):
        try:
            if ON_WINDOWS:
                os.startfile(str(p))
            else:
                subprocess.run(["xdg-open", str(p)], check=False)
        except Exception as e:
            self._log("open error: "+str(e))

    def _extract_member_to_temp(self, member, tmpdir: Path):
        """Extract a single member (by name) from current archive into tmpdir and return Path to extracted item."""
        if not self.current_archive: return None
        fmt = self.current_format; path = self.current_archive; pwd = self.pwd_cache.get(path)
        try:
            if fmt=="zip":
                import zipfile
                with zipfile.ZipFile(path, "r") as zf:
                    cand=None
                    for nm in zf.namelist():
                        if nm==member or Path(nm).name == Path(member).name:
                            cand=nm; break
                    if not cand: return None
                    try:
                        if pwd:
                            zf.extract(cand, path=str(tmpdir), pwd=pwd.encode())
                        else:
                            zf.extract(cand, path=str(tmpdir))
                        return tmpdir / cand
                    except RuntimeError:
                        p = self._ask_password("ZIP needs password")
                        if not p: return None
                        self.pwd_cache[path]=p; zf.extract(cand, path=str(tmpdir), pwd=p.encode()); return tmpdir / cand
            elif fmt=="7z":
                if not HAS_PY7ZR: raise RuntimeError("py7zr required")
                try:
                    with py7zr.SevenZipFile(path, 'r', password=(pwd if pwd else None)) as a:
                        names = a.getnames(); target=None
                        for n in names:
                            if n==member or Path(n).name==Path(member).name:
                                target=n; break
                        if not target: return None
                        a.extract(targets=[target], path=str(tmpdir)); return tmpdir / target
                except Exception:
                    p = self._ask_password("7z needs password")
                    if not p: return None
                    self.pwd_cache[path]=p
                    with py7zr.SevenZipFile(path, 'r', password=p) as a:
                        names=a.getnames(); target=None
                        for n in names:
                            if n==member or Path(n).name==Path(member).name: target=n; break
                        if not target: return None
                        a.extract(targets=[target], path=str(tmpdir)); return tmpdir / target
            elif fmt=="rar":
                if not HAS_RARFILE: raise RuntimeError("rarfile required")
                with rarfile.RarFile(path) as rf:
                    target=None
                    for n in rf.namelist():
                        if n==member or Path(n).name==Path(member).name:
                            target=n; break
                    if not target: return None
                    try:
                        rf.extract(target, path=str(tmpdir), pwd=(pwd if pwd else None))
                    except rarfile.BadRarFile:
                        p = self._ask_password("RAR needs password")
                        if not p: return None
                        self.pwd_cache[path]=p; rf.extract(target, path=str(tmpdir), pwd=p)
                    except Exception:
                        p = self._ask_password("RAR may require password")
                        if not p: return None
                        self.pwd_cache[path]=p; rf.extract(target, path=str(tmpdir), pwd=p)
                    return tmpdir / target
            elif fmt=="jarc":
                data = extract_jarc_member_bytes(path, member); outp = tmpdir / Path(member).name; outp.parent.mkdir(parents=True, exist_ok=True); outp.write_bytes(data); return outp
        except Exception as e:
            self._log("extract member error: "+str(e)+"\n"+traceback.format_exc())
            return None

    # --- NEW: extract current archive to chosen folder (supports dest parameter) ---
    def extract_archive(self, dest=None):
        """
        If dest is None, asks user; otherwise extracts to dest directly.
        Works in both archive modes (zip,7z,rar,jarc) and 'dir' (no-op).
        """
        if not self.current_archive or not self.current_format:
            QMessageBox.information(self, "No archive", "Open an archive first.")
            return
        fmt = self.current_format; path = self.current_archive; pwd = self.pwd_cache.get(path)
        # if dest is None ask user
        if dest is None:
            dest = QFileDialog.getExistingDirectory(self, "Select folder to extract into")
            if not dest: return
        self._log(f"Extracting {path} -> {dest}")
        try:
            if fmt == "dir":
                # nothing to extract, maybe copy items to dest?
                try:
                    for p in Path(path).iterdir():
                        target = Path(dest) / p.name
                        if p.is_dir():
                            shutil.copytree(str(p), str(target), dirs_exist_ok=True)
                        else:
                            shutil.copy2(str(p), str(target))
                except Exception as e:
                    self._log("dir extract error: "+str(e)); QMessageBox.critical(self, "Extract error", str(e)); return
            elif fmt == "zip":
                import zipfile
                try:
                    with zipfile.ZipFile(path, "r") as zf:
                        if any(getattr(zi,"flag_bits",0)&0x1 for zi in zf.infolist()) and not pwd:
                            p = self._ask_password("ZIP seems encrypted; enter password to extract")
                            if not p: QMessageBox.information(self, "Password", "Won't extract"); return
                            self.pwd_cache[path] = p; pwd = p
                        if pwd:
                            zf.extractall(path=dest, pwd=pwd.encode())
                        else:
                            zf.extractall(path=dest)
                except Exception as e:
                    self._log("ZIP extract error: "+str(e))
                    QMessageBox.critical(self, "Extract error", str(e)); return
            elif fmt == "7z":
                if not HAS_PY7ZR:
                    QMessageBox.critical(self, "Missing py7zr", "py7zr required for 7z extraction."); return
                try:
                    with py7zr.SevenZipFile(path, 'r', password=(pwd if pwd else None)) as a:
                        a.extractall(path=dest)
                except Exception:
                    p = self._ask_password("7z needs password")
                    if not p: QMessageBox.information(self, "Password", "Won't extract"); return
                    self.pwd_cache[path] = p
                    with py7zr.SevenZipFile(path, 'r', password=p) as a:
                        a.extractall(path=dest)
            elif fmt == "rar":
                if not HAS_RARFILE:
                    QMessageBox.critical(self, "Missing rarfile", "rarfile required for rar extraction."); return
                try:
                    with rarfile.RarFile(path) as rf:
                        try:
                            rf.extractall(path=dest, pwd=(pwd if pwd else None))
                        except rarfile.NeedPassword:
                            p = self._ask_password("RAR needs password")
                            if not p: QMessageBox.information(self, "Password", "Won't extract"); return
                            self.pwd_cache[path] = p; rf.extractall(path=dest, pwd=p)
                except Exception as e:
                    self._log("RAR extract error: "+str(e))
                    QMessageBox.critical(self, "Extract error", str(e)); return
            elif fmt == "jarc":
                try:
                    entries = read_jarc_manifest(path)
                    for e in entries:
                        data = extract_jarc_member_bytes(path, e["name"])
                        outp = Path(dest) / Path(e["name"])
                        outp.parent.mkdir(parents=True, exist_ok=True)
                        outp.write_bytes(data)
                except Exception as e:
                    self._log("JARC extract error: "+str(e))
                    QMessageBox.critical(self, "Extract error", str(e)); return
            QMessageBox.information(self, "Extracted", f"Archive extracted to: {dest}")
            self._log("Extraction finished")
            # After extraction, showcase extracted folder in UI
            self.load_directory(dest)
        except Exception as e:
            self._log("extract_archive error: "+str(e)+"\n"+traceback.format_exc())
            QMessageBox.critical(self, "Extract error", str(e))

    # helper for programmatic extraction of an arbitrary file path (used by CLI)
    def extract_file_path(self, path, dest=None):
        """If dest is None, extract 'here' to the archive's parent folder. After extraction, showcase the extracted folder."""
        p = Path(path)
        if not p.exists():
            self._log("extract_file_path: not found: "+str(path)); return
        ext = p.suffix.lower()
        if ext not in (".zip",".7z",".rar",".jarc"):
            self._log("extract_file_path: unsupported type: "+ext); return
        if dest is None:
            dest = str(p.parent)
        self.load_archive(str(p), ext)
        self.extract_archive(dest=dest)

    # --- stage/create ---
    def stage_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select files")
        for f in files: self.list_stage.addItem(f)

    def stage_add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select folder")
        if d: self.list_stage.addItem(d)

    def create_archive(self):
        if self.list_stage.count() == 0:
            QMessageBox.information(self, "No files", "Stage files/folders first"); return
        fmt = self.combo_fmt.currentText()
        out, _ = QFileDialog.getSaveFileName(self, "Save archive as", filter=f"{fmt.upper()} (*.{fmt})")
        if not out: return
        if not out.lower().endswith("." + fmt): out += "." + fmt
        items = [self.list_stage.item(i).text() for i in range(self.list_stage.count())]
        pwd = self.input_pwd.text().strip()
        try:
            if fmt=="zip":
                import zipfile
                if pwd and not HAS_PYZIPPER:
                    QMessageBox.critical(self, "Missing pyzipper", "pyzipper required for passworded zip."); return
                if pwd:
                    with pyzipper.AESZipFile(out, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                        zf.setpassword(pwd.encode())
                        for p in items:
                            pth = Path(p)
                            if pth.is_dir():
                                parent = pth.parent
                                for root, _, names in os.walk(pth):
                                    for n in names:
                                        full = Path(root)/n; arc = str(full.relative_to(parent)).replace("\\","/")
                                        zf.write(str(full), arcname=arc)
                            else:
                                zf.write(str(pth), arcname=pth.name)
                else:
                    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                        for p in items:
                            pth = Path(p)
                            if pth.is_dir():
                                parent = pth.parent
                                for root, _, names in os.walk(pth):
                                    for n in names:
                                        full = Path(root)/n; arc = str(full.relative_to(parent)).replace("\\","/")
                                        zf.write(str(full), arcname=arc)
                            else:
                                zf.write(str(pth), arcname=pth.name)
            elif fmt=="7z":
                if not HAS_PY7ZR:
                    QMessageBox.critical(self, "Missing py7zr", "py7zr required"); return
                if pwd:
                    with py7zr.SevenZipFile(out, 'w', password=pwd) as a:
                        for p in items:
                            pth = Path(p)
                            if pth.is_dir(): a.writeall(str(pth), arcname=pth.name)
                            else: a.write(str(pth), arcname=pth.name)
                else:
                    with py7zr.SevenZipFile(out, 'w') as a:
                        for p in items:
                            pth = Path(p)
                            if pth.is_dir(): a.writeall(str(pth), arcname=pth.name)
                            else: a.write(str(pth), arcname=pth.name)
            elif fmt=="jarc":
                create_jarc(out, items, compress=True)
            elif fmt=="rar":
                rarexe = shutil.which("rar") or shutil.which("rar.exe")
                if not rarexe:
                    QMessageBox.critical(self, "No rar", "rar.exe not found"); return
                cmd = [rarexe, "a", "-ep1", out] + items
                if pwd: cmd.insert(2, f"-hp{pwd}")
                rc, outb, errb = safe_run(cmd, timeout=600)
                if rc != 0:
                    QMessageBox.warning(self, "RAR create", f"rar returned rc={rc}")
            self._log("Created " + out)
            QMessageBox.information(self, "Created", f"Archive created: {out}")
            # If auto par2 requested, create for the created archive
            if self.chk_par2_auto.isChecked():
                mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
                if not mgr.is_ok():
                    QMessageBox.information(self, "par2 missing", "par2 not configured.")
                else:
                    # groups: single group with created archive only
                    groups = [([out], Path(out).stem, str(Path(out).parent))]
                    mgr.signals.log.connect(lambda s: self._log("par2: "+s))
                    mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
                    mgr.signals.finished.connect(lambda summary: (self._log("par2 create finished"), self.progress.setValue(0)))
                    mgr.run_create(groups, redundancy=int(self.spin_red.value()), default_out_dir=None)
        except Exception as e:
            self._log("Create error: " + str(e) + "\n" + traceback.format_exc())
            QMessageBox.critical(self, "Create error", str(e))

    # --- par2 UI functions (unchanged) ---
    def par2_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Add files to par2 targets")
        for f in files: self.list_par2_targets.addItem(f)
        self._log(f"Added {len(files)} file targets")

    def par2_add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Add folder to par2 targets")
        if folder:
            self.list_par2_targets.addItem(folder)
            self._log("Added folder target: "+folder)

    def par2_create_selected(self):
        sel = [self.list_par2_targets.item(i).text() for i in range(self.list_par2_targets.count()) if self.list_par2_targets.item(i).isSelected()]
        if not sel:
            QMessageBox.information(self, "No selection", "Select targets"); return
        self._par2_create_from_targets(sel)

    def par2_create_all(self):
        all_targets = [self.list_par2_targets.item(i).text() for i in range(self.list_par2_targets.count())]
        if not all_targets:
            QMessageBox.information(self, "No targets", "Add targets first"); return
        self._par2_create_from_targets(all_targets)

    def _expand_folder(self, folder):
        out=[]
        for root, _, names in os.walk(folder):
            for n in names:
                out.append(os.path.join(root,n))
        return out

    def _par2_create_from_targets(self, targets):
        redundancy = int(self.spin_red.value())
        mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
        if not mgr.is_ok():
            QMessageBox.information(self, "par2 missing", "par2 not configured. Use Locate/Search/Install"); return
        groups=[]
        if self.radio_one.isChecked():
            for t in targets:
                if os.path.isdir(t):
                    files = self._expand_folder(t)
                    # filter out .par2 files
                    files = [f for f in files if not f.lower().endswith(".par2")]
                    if files:
                        groups.append((files, Path(t).name, t))
                else:
                    if not Path(t).name.lower().endswith(".par2"):
                        groups.append(([t], None, None))
        else:
            # single combined par2 for all targets
            files=[]
            for t in targets:
                if os.path.isdir(t): files += [f for f in self._expand_folder(t) if not f.lower().endswith(".par2")]
                else:
                    if not Path(t).name.lower().endswith(".par2"):
                        files.append(t)
            if not files:
                QMessageBox.information(self, "No files", "No non-.par2 files found in targets"); return
            out_dir = QFileDialog.getExistingDirectory(self, "Where to write the combined .par2 file")
            if not out_dir:
                QMessageBox.information(self, "Output required", "Choose an output directory"); return
            base_name, ok = QtWidgets.QInputDialog.getText(self, "Base name", "Enter base name for .par2 (no extension):", QtWidgets.QLineEdit.Normal, "archive_par2")
            if not ok or not base_name:
                QMessageBox.information(self, "Base required", "Provide base name"); return
            groups.append((files, base_name, out_dir))
        mgr.signals.log.connect(lambda s: self._log("par2: "+s))
        mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
        mgr.signals.finished.connect(lambda summary: (self._log("par2 create finished"), self.progress.setValue(0)))
        mgr.run_create(groups, redundancy, default_out_dir=None)

    def load_par2(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Load .par2 files", filter="par2 files (*.par2);;All files (*)")
        if not files: return
        self.list_loaded_par2.clear()
        for f in files: self.list_loaded_par2.addItem(f)
        self._log("Loaded %d .par2 files" % len(files))
        self.btn_repair_selected.setEnabled(True); self.btn_repair_all.setEnabled(True)

    def repair_selected(self):
        items = [self.list_loaded_par2.item(i).text() for i in range(self.list_loaded_par2.count()) if self.list_loaded_par2.item(i).isSelected()]
        if not items:
            resp = QMessageBox.question(self, "No selection", "No .par2 selected. Load .par2 files now?", QMessageBox.Yes | QMessageBox.No)
            if resp == QMessageBox.Yes:
                self.load_par2(); items = [self.list_loaded_par2.item(i).text() for i in range(self.list_loaded_par2.count()) if self.list_loaded_par2.item(i).isSelected()]
            if not items: return
        dest = QFileDialog.getExistingDirectory(self, "Move repaired files to folder (optional)")
        extract_flag = self.chk_extract_after.isChecked()
        mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
        if not mgr.is_ok():
            QMessageBox.information(self, "par2 missing", "par2 not configured."); return
        mgr.signals.log.connect(lambda s: self._log("par2: "+s))
        mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
        def on_finished(summary):
            self._log("par2 repair finished"); self.progress.setValue(0)
            moved=[]; extracted=[]
            for group in summary:
                moved += group.get("moved", []) or []
                extracted += group.get("extracted", []) or []
            lines=[]
            if moved:
                lines.append("Moved repaired files:\n" + "\n".join(moved))
            if extracted:
                lines.append("Extracted repaired archives:\n" + "\n".join(extracted))
            if lines:
                QMessageBox.information(self, "Repair done", "\n\n".join(lines))
            else:
                QMessageBox.information(self, "Repair done", "Repair finished (see log).")
        mgr.signals.finished.connect(on_finished)
        mgr.run_repair_many(items, move_repaired_to=dest if dest else None, extract_repaired=extract_flag)

    def repair_all(self):
        all_items = [self.list_loaded_par2.item(i).text() for i in range(self.list_loaded_par2.count())]
        if not all_items:
            resp = QMessageBox.question(self, "No .par2 loaded", "No .par2 loaded. Scan a folder for .par2 files?", QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if resp == QMessageBox.Yes:
                folder = QFileDialog.getExistingDirectory(self, "Select folder to scan for .par2 files")
                if not folder: return
                found=[]
                for root, _, files in os.walk(folder):
                    for fn in files:
                        if fn.lower().endswith(".par2"): found.append(os.path.join(root, fn))
                if not found:
                    QMessageBox.information(self, "No .par2", "No .par2 files found"); return
                self.list_loaded_par2.clear()
                for f in found: self.list_loaded_par2.addItem(f)
                self._log(f"Auto-loaded {len(found)} .par2 files from {folder}")
            elif resp == QMessageBox.No:
                self.load_par2()
                all_items = [self.list_loaded_par2.item(i).text() for i in range(self.list_loaded_par2.count())]
                if not all_items: return
            else:
                return
        dest = QFileDialog.getExistingDirectory(self, "Move repaired files to folder (optional)")
        extract_flag = self.chk_extract_after.isChecked()
        mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
        if not mgr.is_ok():
            QMessageBox.information(self, "par2 missing", "par2 not configured."); return
        mgr.signals.log.connect(lambda s: self._log("par2: "+s))
        mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
        mgr.signals.finished.connect(lambda summary: (self._log("par2 repair finished"), self.progress.setValue(0)))
        mgr.run_repair_many([self.list_loaded_par2.item(i).text() for i in range(self.list_loaded_par2.count())], move_repaired_to=dest if dest else None, extract_repaired=extract_flag)

    # --- search / locate / install par2 helpers ---
    def locate_par2(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Locate par2 executable", filter="Executables (*.exe);;All files (*)")
        if not fn: return
        try:
            rc,out,err = safe_run([fn,"--version"], timeout=3)
            if rc==0 or out or err:
                CFG["par2_exe"]=fn; save_cfg(); self.par2mgr.par2_exe=fn; self.statusBar().showMessage("par2: "+fn); QMessageBox.information(self, "par2", "par2 configured"); return
        except Exception:
            pass
        QMessageBox.warning(self, "par2", "Selected file doesn't appear to be par2")

    def _search_common_par2(self):
        cand=[]
        if ON_WINDOWS:
            pf = os.getenv("PROGRAMFILES", r"C:\Program Files"); pf86 = os.getenv("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            cand += [os.path.join(pf,"par2","par2.exe"), os.path.join(pf86,"par2","par2.exe"), r"C:\ProgramData\chocolatey\lib\par2cmdline\tools\par2.exe", r"C:\ProgramData\chocolatey\bin\par2.exe"]
            for p in os.environ.get("PATH","").split(os.pathsep):
                cand.append(os.path.join(p,"par2.exe"))
        else:
            for p in os.environ.get("PATH","").split(os.pathsep):
                cand.append(os.path.join(p,"par2"))
        for c in cand:
            if not c: continue
            if Path(c).exists():
                rc,out,err = safe_run([c,"--version"], timeout=3)
                if rc==0 or out or err: return c
        return None

    def search_par2(self):
        found = self._search_common_par2()
        if found:
            CFG["par2_exe"]=found; save_cfg(); self.par2mgr.par2_exe=found; self.statusBar().showMessage("par2: "+found); QMessageBox.information(self, "Found", f"par2 found: {found}")
        else:
            QMessageBox.information(self, "Not found", "No par2 found in common locations")

    def install_par2_choco(self):
        if not ON_WINDOWS or not shutil.which("choco"):
            QMessageBox.information(self, "Chocolatey missing", "Chocolatey not in PATH."); return
        resp = QMessageBox.question(self, "Install par2 via Chocolatey", "Install par2cmdline via Chocolatey? This requires admin.", QMessageBox.Yes | QMessageBox.No)
        if resp != QMessageBox.Yes: return
        cmd = ["choco","install","par2cmdline","-y","--no-progress"]
        self._log("Running: " + " ".join(cmd))
        rc,out,err = safe_run(cmd, timeout=600)
        if rc==0:
            found = self._search_common_par2()
            if found:
                CFG["par2_exe"]=found; save_cfg(); self.par2mgr.par2_exe=found; self.statusBar().showMessage("par2: "+found); QMessageBox.information(self, "Installed", "par2 installed and configured.")
            else:
                QMessageBox.information(self, "Installed", "Installed but not found automatically. Use Locate par2.")
        else:
            self._log("choco install rc=%s out=%s err=%s" % (rc, out[:200], err[:200]))
            QMessageBox.information(self, "Install failed", f"Install returned rc={rc}. See log")

    # --- context menu for list_contents ---
    def _on_list_context_menu(self, pos):
        item = self.list_contents.itemAt(pos)
        if not item:
            return
        menu = QtWidgets.QMenu(self)
        act_open = menu.addAction("Open")
        act_extract_here = menu.addAction("Extract Here")
        act_extract_to = menu.addAction("Extract To...")
        act_reveal = menu.addAction("Reveal in Explorer")
        act_copy = menu.addAction("Copy Path")
        act_remove = menu.addAction("Remove from list")
        action = menu.exec_(self.list_contents.mapToGlobal(pos))
        text = item.text().rstrip("/\\")
        if action == act_open:
            self.item_double(item)
        elif action == act_extract_here:
            # extract member into archive parent or directory itself
            if self.current_format == "dir":
                # for dir, "extract here" -> no-op; maybe copy item to same folder (skip)
                QMessageBox.information(self, "Extract", "Item is in a folder view, already here.")
            else:
                # dest = parent folder of archive
                dest = str(Path(self.current_archive).parent)
                self._extract_member_to_dest(text, dest)
        elif action == act_extract_to:
            dest = QFileDialog.getExistingDirectory(self, "Select folder to extract into")
            if dest:
                if self.current_format == "dir":
                    # copy file/folder to dest
                    src = Path(self.current_archive) / text
                    try:
                        if src.is_dir():
                            shutil.copytree(str(src), str(Path(dest) / src.name), dirs_exist_ok=True)
                        else:
                            shutil.copy2(str(src), str(Path(dest) / src.name))
                        QMessageBox.information(self, "Copied", f"Copied to {dest}")
                    except Exception as e:
                        QMessageBox.critical(self, "Copy failed", str(e))
                else:
                    self._extract_member_to_dest(text, dest)
        elif action == act_reveal:
            if self.current_format == "dir":
                p = Path(self.current_archive) / text
            else:
                p = Path(self.current_archive)
            try:
                if p.exists():
                    if ON_WINDOWS:
                        subprocess.run(["explorer", "/select,", str(p)], check=False)
                    else:
                        # open containing folder
                        subprocess.run(["xdg-open", str(p.parent)], check=False)
                else:
                    QMessageBox.information(self, "Reveal", "Path not found.")
            except Exception as e:
                self._log("reveal error: "+str(e))
        elif action == act_copy:
            if self.current_format == "dir":
                full = str(Path(self.current_archive) / text)
            else:
                full = f"{self.current_archive}:{text}"
            QtWidgets.QApplication.clipboard().setText(full)
            QMessageBox.information(self, "Copied", full)
        elif action == act_remove:
            self.list_contents.takeItem(self.list_contents.row(item))

    def _extract_member_to_dest(self, member, dest):
        """Extract single member into dest folder."""
        tmpd = Path(tempfile.mkdtemp(prefix="miniarch_extract_")); self.temp_dirs.append(tmpd)
        got = self._extract_member_to_temp(member, tmpd)
        if not got:
            QMessageBox.warning(self, "Extract", "Could not extract member")
            return
        # move extracted item (or its contents if folder) into dest
        try:
            src = Path(got)
            if src.is_dir():
                target = Path(dest) / src.name
                shutil.copytree(str(src), str(target), dirs_exist_ok=True)
            else:
                shutil.copy2(str(src), str(Path(dest)/src.name))
            QMessageBox.information(self, "Extracted", f"Extracted to: {dest}")
            # show dest in UI
            self.load_directory(dest)
        except Exception as e:
            QMessageBox.critical(self, "Extract copy failed", str(e))

    # --- misc helpers ---
    def _clear_list_contents(self):
        self.list_contents.clear()

    def closeEvent(self, ev):
        try:
            if self.thumb_worker and self.thumb_thread:
                self.thumb_worker.stop(); self.thumb_thread.quit(); self.thumb_thread.wait(200)
        except Exception:
            pass
        for d in self.temp_dirs:
            try: shutil.rmtree(str(d), ignore_errors=True)
            except Exception: pass
        ev.accept()

    # --- CLI processing: called after the window is shown ---
    def process_pending_cli(self):
        """If the process was launched with file arguments, extract them here (extract to same folder)"""
        if not self._pending_cli_paths:
            return
        # We'll handle first argument (common case: Open with single file). If multiple, process all.
        for p in self._pending_cli_paths:
            try:
                ext = Path(p).suffix.lower()
                if ext in (".zip",".7z",".rar",".jarc"):
                    # extract to same folder (parent)
                    dest = str(Path(p).parent)
                    self._log(f"CLI: extracting {p} to {dest}")
                    # load and extract programmatically
                    self.load_archive(p, ext)
                    # Use extract_archive with dest param (it will showcase after)
                    self.extract_archive(dest=dest)
                else:
                    # not archive: show file in directory
                    self.load_directory(str(Path(p).parent))
            except Exception as e:
                self._log("CLI extract error: "+str(e))
        # clear pending list
        self._pending_cli_paths = []

# --- main ---
def main():
    app = QApplication(sys.argv)
    w = MiniArchWindow()
    w.showMaximized()

    # After the event loop starts, process any CLI args (we delay slightly to ensure UI up)
    QtCore.QTimer.singleShot(200, w.process_pending_cli)

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
