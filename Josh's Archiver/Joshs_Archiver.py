import sys, os, shutil, tempfile, json, struct, zlib, hashlib, time, traceback, threading, subprocess
from pathlib import Path
from io import BytesIO

# Try PyQt5 then PySide6
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, QThread, pyqtSignal as Signal, QSize
    from PyQt5.QtGui import QPixmap, QIcon
    from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QListWidgetItem, QFileIconProvider
    QT_BINDING = "PyQt5"
except Exception:
    from PySide6 import QtCore, QtGui, QtWidgets
    from PySide6.QtCore import Qt, QThread, Signal, QSize
    from PySide6.QtGui import QPixmap, QIcon
    from PySide6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QListWidgetItem, QFileIconProvider
    QT_BINDING = "PySide6"

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

# Config / cache paths
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

def thumb_cache_dir():
    if ON_WINDOWS:
        base = Path(os.getenv("APPDATA") or Path.home())
    else:
        base = Path.home()
    d = base / "miniarch_thumbs"
    d.mkdir(parents=True, exist_ok=True)
    return d
THUMB_CACHE = thumb_cache_dir()

# Embedded app icon (small PNG base64) - replace with your preferred image if you want
APP_ICON_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKUlEQVR4nO3NMQEAAAjDMO5fN"
    "Fh4gqYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABcC6kYAAEUgq1QAAAAAElFTkSuQmCC"
)

# JARC simple format (header + compressed files + JSON manifest + footer)
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
        entries = []
        for full, arc in files:
            off = f.tell()
            with open(full, "rb") as rf:
                data = rf.read()
            if compress:
                stored = zlib.compress(data); compressed = True
            else:
                stored = data; compressed = False
            f.write(stored)
            entries.append({"name": arc, "offset": off, "size": len(stored), "compressed": compressed})
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
            raise RuntimeError("Missing JARC footer")
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

# Subprocess helper (no console windows on Windows)
def safe_run(cmd, timeout=600, cwd=None):
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               check=False, timeout=timeout, cwd=cwd, creationflags=creationflags)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, b"", b"timeout"
    except Exception as e:
        return -2, b"", str(e).encode()

# Thumbs: worker uses QThread
class ThumbWorker(QtCore.QObject):
    thumb_ready = Signal(str, str)  # member_name, cache_path
    finished = Signal()
    log = Signal(str)

    def __init__(self, archive_path, archive_fmt, names, password=None):
        super().__init__()
        self.archive_path = archive_path
        self.archive_fmt = archive_fmt
        self.names = list(names)
        self.password = password
        self._alive = True

    def stop(self):
        self._alive = False

    def run(self):
        try:
            for name in self.names:
                if not self._alive: break
                ext = Path(name).suffix.lower()
                if ext not in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"):
                    continue
                key = hashlib.sha1((self.archive_path + '|' + name + str(Path(self.archive_path).stat().st_mtime)).encode()).hexdigest()
                cache_file = THUMB_CACHE / (key + ".png")
                if cache_file.exists():
                    self.thumb_ready.emit(name, str(cache_file))
                    continue
                data = None
                try:
                    if self.archive_fmt == "zip":
                        import zipfile
                        with zipfile.ZipFile(self.archive_path, "r") as zf:
                            candidates = zf.namelist()
                            cand = None
                            for nm in candidates:
                                if nm == name or Path(nm).name == Path(name).name:
                                    cand = nm; break
                            if cand:
                                try:
                                    data = zf.read(cand)
                                except RuntimeError:
                                    # encrypted zip, skip thumbnails (will prompt when opening)
                                    data = None
                    elif self.archive_fmt == "7z" and HAS_PY7ZR:
                        tmpd = Path(tempfile.mkdtemp(prefix="thumb_"))
                        try:
                            with py7zr.SevenZipFile(self.archive_path, 'r', password=(self.password if self.password else None)) as a:
                                try:
                                    a.extract(targets=[name], path=str(tmpd))
                                except Exception:
                                    a.extractall(path=str(tmpd))
                                cand = tmpd / Path(name)
                                if cand.exists(): data = cand.read_bytes()
                                else:
                                    for p in tmpd.rglob("*"):
                                        if p.is_file() and p.name == Path(name).name:
                                            data = p.read_bytes(); break
                        finally:
                            shutil.rmtree(str(tmpd), ignore_errors=True)
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
                except Exception as e:
                    self.log.emit(f"thumb extract error {name}: {e}")
                    data = None
                if not data:
                    continue
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
                    self.log.emit(f"thumb save error {name}: {e}")
                QtCore.QThread.msleep(30)
        except Exception as e:
            self.log.emit("thumbworker crash: " + str(e) + "\n" + traceback.format_exc())
        finally:
            self.finished.emit()

# Par2 manager
class Par2Signals(QtCore.QObject):
    log = Signal(str)
    progress = Signal(int, int)
    finished = Signal(object)

class Par2Manager:
    """
    Provides create and repair for par2 using an external par2 executable.
    run_create(groups, redundancy, default_out_dir=None)
       groups: list of tuples (files_list, base_name, out_dir)  (out_dir overrides default_out_dir)
    run_repair_many(par2_files, move_repaired_to=None)
    """
    def __init__(self, par2_exe=None, timeout=600):
        self.par2_exe = par2_exe or CFG.get("par2_exe") or shutil.which("par2") or shutil.which("par2.exe")
        self.timeout = timeout
        self.signals = Par2Signals()
        self._thread = None
        self._stop = False

    def is_ok(self):
        return bool(self.par2_exe and Path(self.par2_exe).exists())

    def _log(self, s):
        try: self.signals.log.emit(s)
        except Exception: pass

    def _append_logfile(self, text):
        try:
            path = Path(os.getenv("APPDATA") or Path.home()) / "miniarch_par2.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(path.read_text(encoding="utf-8", errors="ignore") + "\n" + text, encoding="utf-8", errors="ignore")
        except Exception:
            pass

    def _try_par2_cmds(self, cmd_base, cwd):
        # run and return rc,out,err (decoded)
        rc, outb, errb = safe_run(cmd_base, timeout=self.timeout, cwd=cwd)
        out = outb.decode(errors="ignore") if isinstance(outb, (bytes,bytearray)) else str(outb)
        err = errb.decode(errors="ignore") if isinstance(errb, (bytes,bytearray)) else str(errb)
        return rc, out, err

    def _create_single(self, files, redundancy, base_name=None, out_dir=None):
        res = {"files": files, "created": [], "rc": None, "out": "", "err": "", "error": None}
        try:
            if not files:
                res["error"]="no files"; return res
            first = Path(files[0])
            workdir = Path(out_dir) if out_dir else first.parent
            if base_name:
                base_path = workdir / (base_name + ".par2")
            else:
                base_path = workdir / (first.stem + ".par2")
            # build command (par2 create)
            cmd = [self.par2_exe, "create", f"-r{redundancy}", str(base_path)] + files
            self._log("par2: Running: " + " ".join(cmd) + f" (cwd={workdir})")
            rc, out, err = self._try_par2_cmds(cmd, cwd=str(workdir))
            res["rc"]=rc; res["out"]=out; res["err"]=err
            # detect created par2s by stem
            stem = base_path.stem
            created=[]
            for p in workdir.iterdir():
                if p.is_file() and p.suffix.lower()==".par2" and p.stem.startswith(stem):
                    created.append(str(p))
            res["created"]=created
            if rc!=0 and not created:
                res["error"]=f"par2 returned rc={rc}"
            return res
        except Exception as e:
            res["error"]=str(e); self._log("par2 create exception: " + str(e)); self._append_logfile(traceback.format_exc()); return res

    def run_create(self, groups, redundancy=10, default_out_dir=None):
        if self._thread and self._thread.is_alive():
            self._log("par2: already running"); return
        def work():
            total=len(groups); summary=[]
            for idx, grp in enumerate(groups, start=1):
                if self._stop: break
                files, base_name, out_dir = grp
                out_dir = out_dir or default_out_dir
                self.signals.progress.emit(idx, total)
                self._log(f"par2: Creating par2 for group {idx}/{total} files={len(files)} base={base_name} out_dir={out_dir}")
                r = self._create_single(files, redundancy, base_name=base_name, out_dir=out_dir)
                summary.append(r)
            self.signals.finished.emit(summary)
        self._thread = threading.Thread(target=work, daemon=True); self._thread.start()

    def _canonical_base(self, filename):
        name = Path(filename).stem
        name = re.sub(r'\.vol\d+\+\d+(?:_\d+)?$', '', name, flags=re.IGNORECASE)
        name = re.sub(r'_\d+$','', name)
        return name

    def _repair_single(self, par2file, move_repaired_to=None):
        res = {"par2": par2file, "rc": None, "out":"", "err":"", "moved":[], "error": None}
        try:
            pp = Path(par2file)
            if not pp.exists():
                res["error"]="par2 file missing"; return res
            workdir = str(pp.parent)
            self._log(f"par2: Repairing {par2file}")
            cmd = [self.par2_exe, "repair", par2file]
            rc, out, err = self._try_par2_cmds(cmd, cwd=workdir)
            res["rc"]=rc; res["out"]=out; res["err"]=err
            # detect files that changed after repair (use mtime)
            before = {}
            for f in Path(workdir).iterdir():
                if f.is_file() and f.suffix.lower() != ".par2":
                    before[str(f)] = f.stat().st_mtime
            # allow par2 to finish then re-check
            time.sleep(0.3)
            after_changed=[]
            for f in Path(workdir).iterdir():
                if f.is_file() and f.suffix.lower() != ".par2":
                    old = before.get(str(f), 0)
                    try:
                        mtime = f.stat().st_mtime
                        if mtime > old + 0.0001:
                            after_changed.append(f)
                    except Exception:
                        pass
            moved=[]
            if move_repaired_to and after_changed:
                dest = Path(move_repaired_to); dest.mkdir(parents=True, exist_ok=True)
                for f in after_changed:
                    try:
                        dst = dest / f.name
                        if dst.exists():
                            dst = dest / (f.stem + f"_{int(time.time())}" + f.suffix)
                        shutil.move(str(f), str(dst)); moved.append(str(dst))
                    except Exception:
                        try:
                            shutil.copy2(str(f), str(dest / f.name)); moved.append(str(dest / f.name))
                        except Exception as e:
                            self._log("Failed to move repaired file: "+str(e))
            res["moved"]=moved
            return res
        except Exception as e:
            res["error"]=str(e); self._log("par2 repair exception: "+str(e)); self._append_logfile(traceback.format_exc()); return res

    def run_repair_many(self, par2_files, move_repaired_to=None):
        if self._thread and self._thread.is_alive():
            self._log("par2: repair already running"); return
        # group par2s by base in same folder (simple heuristic)
        groups = {}
        for p in par2_files:
            pp = Path(p); base = pp.stem
            key = (str(pp.parent), base)
            groups.setdefault(key, []).append(str(pp))
        reps = []
        for (dirpath, base), files in groups.items():
            reps.append((files[0], files))
        def work():
            total = len(reps)
            summary=[]
            for idx, (rep, files) in enumerate(reps, start=1):
                if self._stop: break
                self.signals.progress.emit(idx, total)
                r = self._repair_single(rep, move_repaired_to=move_repaired_to)
                r["group_members"]=files
                summary.append(r)
            self.signals.finished.emit(summary)
        self._thread = threading.Thread(target=work, daemon=True); self._thread.start()

    def stop(self):
        self._stop = True

# GUI
import re

class MiniArchWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MiniArch")
        self.resize(1200,800)
        self._install_icon()
        self._setup_ui()
        self.current_archive = None
        self.current_format = None
        self.pwd_cache = {}
        self.archive_stack = []
        self.temp_dirs = []
        self.thumb_thread = None
        self.thumb_worker = None
        self.par2mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))

        self._log(f"Init: QT={QT_BINDING}, py7zr={HAS_PY7ZR}, pyzipper={HAS_PYZIPPER}, rarfile={HAS_RARFILE}, pillow={HAS_PIL}")
        self.statusBar().showMessage(f"par2: {CFG.get('par2_exe') or self.par2mgr.par2_exe or 'not found'}")

    def _install_icon(self):
        try:
            data = BytesIO(__import__('base64').b64decode(APP_ICON_BASE64))
            pm = QPixmap(); pm.loadFromData(data.read())
            if not pm.isNull():
                self.setWindowIcon(QIcon(pm))
        except Exception:
            pass

    def _setup_ui(self):
        w = QtWidgets.QWidget(); self.setCentralWidget(w)
        v = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout(); v.addLayout(top)
        self.btn_open = QtWidgets.QPushButton("Open Archive..."); self.btn_open.clicked.connect(self.open_archive); top.addWidget(self.btn_open)
        self.btn_back = QtWidgets.QPushButton("Back"); self.btn_back.clicked.connect(self.go_back); self.btn_back.setEnabled(False); top.addWidget(self.btn_back)
        top.addStretch()
        self.btn_clear_thumbs = QtWidgets.QPushButton("Clear thumbnail cache"); self.btn_clear_thumbs.clicked.connect(self.clear_thumb_cache); top.addWidget(self.btn_clear_thumbs)
        self.btn_associate = QtWidgets.QPushButton("Associate .jarc with this script"); self.btn_associate.clicked.connect(self.associate_jarc); top.addWidget(self.btn_associate)
        self.btn_locate_par2 = QtWidgets.QPushButton("Locate par2"); self.btn_locate_par2.clicked.connect(self.locate_par2); top.addWidget(self.btn_locate_par2)
        self.btn_search_par2 = QtWidgets.QPushButton("Search par2"); self.btn_search_par2.clicked.connect(self.search_par2); top.addWidget(self.btn_search_par2)
        self.btn_install_par2 = QtWidgets.QPushButton("Install par2 via Chocolatey"); self.btn_install_par2.clicked.connect(self.install_par2_choco); top.addWidget(self.btn_install_par2)

        split = QtWidgets.QSplitter(); v.addWidget(split, 1)
        left = QtWidgets.QWidget(); left_l = QtWidgets.QVBoxLayout(left); split.addWidget(left)
        right = QtWidgets.QWidget(); right_l = QtWidgets.QVBoxLayout(right); split.addWidget(right)

        left_l.addWidget(QtWidgets.QLabel("Archive contents:"))
        self.list_contents = QtWidgets.QListWidget(); self.list_contents.setIconSize(QSize(96,96))
        left_l.addWidget(self.list_contents, 1)
        self.list_contents.itemDoubleClicked.connect(self.item_double)

        left_l.addWidget(QtWidgets.QLabel("Log:"))
        self.log_text = QtWidgets.QTextEdit(); self.log_text.setReadOnly(True); left_l.addWidget(self.log_text, 1)

        right_l.addWidget(QtWidgets.QLabel("Create / Stage"))
        self.combo_fmt = QtWidgets.QComboBox(); self.combo_fmt.addItems(["zip","7z","jarc","rar"]); right_l.addWidget(self.combo_fmt)
        self.input_pwd = QtWidgets.QLineEdit(); self.input_pwd.setEchoMode(QtWidgets.QLineEdit.Password); self.input_pwd.setPlaceholderText("Password (blank=none)"); right_l.addWidget(self.input_pwd)
        h = QtWidgets.QHBoxLayout(); right_l.addLayout(h)
        self.chk_par2_auto = QtWidgets.QCheckBox("Also create .par2 after archive"); h.addWidget(self.chk_par2_auto)
        h.addWidget(QtWidgets.QLabel("Redundancy %"))
        self.spin_red = QtWidgets.QSpinBox(); self.spin_red.setRange(1,500); self.spin_red.setValue(10); h.addWidget(self.spin_red)

        self.btn_add_files = QtWidgets.QPushButton("Add Files"); self.btn_add_files.clicked.connect(self.stage_add_files); right_l.addWidget(self.btn_add_files)
        self.btn_add_folder = QtWidgets.QPushButton("Add Folder"); self.btn_add_folder.clicked.connect(self.stage_add_folder); right_l.addWidget(self.btn_add_folder)
        self.list_stage = QtWidgets.QListWidget(); right_l.addWidget(self.list_stage, 1)
        row = QtWidgets.QHBoxLayout(); right_l.addLayout(row)
        self.btn_create = QtWidgets.QPushButton("Create Archive"); self.btn_create.clicked.connect(self.create_archive); row.addWidget(self.btn_create)
        self.btn_create_rar = QtWidgets.QPushButton("Create RAR (rar.exe)"); self.btn_create_rar.clicked.connect(self.create_rar); row.addWidget(self.btn_create_rar)
        if not shutil.which("rar") and not shutil.which("rar.exe"):
            self.btn_create_rar.setEnabled(False)

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
        # disabled until files loaded
        self.btn_repair_selected.setEnabled(False); self.btn_repair_all.setEnabled(False)

        self.progress = QtWidgets.QProgressBar(); v.addWidget(self.progress)

    # ---------- logging ----------
    def _log(self, s):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        ln = f"{t} {s}"
        try:
            self.log_text.append(ln)
        except Exception:
            pass
        print(ln, flush=True)

    # ---------- archive open/list ----------
    def open_archive(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open archive", filter="Archives (*.zip *.7z *.rar *.jarc);;All files (*)")
        if not fn: return
        ext = Path(fn).suffix.lower().lstrip('.')
        if ext not in ("zip","7z","rar","jarc"):
            QMessageBox.warning(self, "Unsupported", "Supported: zip, 7z, rar, jarc"); return
        if self.current_archive:
            self.archive_stack.append((self.current_archive, self.current_format))
            self.btn_back.setEnabled(True)
        self.load_archive(fn, ext)

    def go_back(self):
        if not self.archive_stack: return
        path, fmt = self.archive_stack.pop()
        if not self.archive_stack:
            self.btn_back.setEnabled(False)
        self.load_archive(path, fmt)

    def load_archive(self, path, fmt):
        self.current_archive = path; self.current_format = fmt
        self._log(f"Loading archive: {path}")
        self.list_contents.clear()
        members=[]
        pwd = self.pwd_cache.get(path)
        try:
            if fmt == "zip":
                import zipfile
                with zipfile.ZipFile(path, 'r') as zf:
                    # detect encryption bits
                    needs_pwd = False
                    for zi in zf.infolist():
                        if getattr(zi, "flag_bits", 0) & 0x1:
                            needs_pwd=True; break
                    if needs_pwd and not pwd:
                        p = self.ask_password(f"ZIP {Path(path).name} appears encrypted. Enter password:")
                        if not p: QMessageBox.information(self, "Password", "Won't list without password"); return
                        self.pwd_cache[path]=p; pwd=p
                    members = zf.namelist()
            elif fmt == "7z":
                if not HAS_PY7ZR: raise RuntimeError("py7zr required")
                try:
                    with py7zr.SevenZipFile(path, 'r', password=(pwd if pwd else None)) as a:
                        members = a.getnames()
                except Exception:
                    p = self.ask_password(f"7z {Path(path).name} needs a password")
                    if not p: QMessageBox.information(self, "Password", "Won't list without password"); return
                    self.pwd_cache[path]=p; pwd=p
                    with py7zr.SevenZipFile(path, 'r', password=p) as a:
                        members = a.getnames()
            elif fmt == "rar":
                if not HAS_RARFILE: raise RuntimeError("rarfile required")
                try:
                    with rarfile.RarFile(path) as rf:
                        members = rf.namelist()
                except rarfile.NeedPassword:
                    p = self.ask_password(f"RAR {Path(path).name} needs a password")
                    if not p: QMessageBox.information(self, "Password", "Won't list without password"); return
                    self.pwd_cache[path]=p; pwd=p
                    with rarfile.RarFile(path) as rf:
                        members = rf.namelist()
                except Exception:
                    p = self.ask_password(f"RAR {Path(path).name} may require a password")
                    if not p: QMessageBox.information(self, "Password", "Won't list without password"); return
                    self.pwd_cache[path]=p; pwd=p
                    with rarfile.RarFile(path) as rf:
                        members = rf.namelist()
            elif fmt == "jarc":
                try:
                    entries = read_jarc_manifest(path)
                    members = [e["name"] for e in entries]
                except Exception as e:
                    QMessageBox.critical(self, "JARC", f"Bad JARC: {e}"); return
        except Exception as e:
            self._log("list error: " + str(e) + "\n" + traceback.format_exc())
            QMessageBox.critical(self, "List error", str(e)); return

        image_members=[]
        for m in members:
            item = QListWidgetItem(m)
            if m.endswith('/') or m.endswith('\\'):
                item.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_DirIcon))
            else:
                ext = Path(m).suffix.lower()
                if ext in (".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"):
                    item.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_FileIcon))
                    image_members.append(m)
                else:
                    # system icon probe
                    try:
                        provider = QFileIconProvider()
                        dummy = Path(THUMB_CACHE) / ("dummy" + (ext or ".txt"))
                        if not dummy.exists():
                            dummy.write_bytes(b"")
                        qfi = QtCore.QFileInfo(str(dummy))
                        icon = provider.icon(qfi)
                        item.setIcon(icon)
                    except Exception:
                        item.setIcon(QApplication.style().standardIcon(QtWidgets.QStyle.SP_FileIcon))
            self.list_contents.addItem(item)
        if image_members:
            self._start_thumb_worker(image_members)

    def ask_password(self, prompt):
        text, ok = QtWidgets.QInputDialog.getText(self, "Password", prompt, QtWidgets.QLineEdit.Password)
        if ok and text: return text
        return None

    # ---------- thumbnails ----------
    def _start_thumb_worker(self, names):
        try:
            if self.thumb_worker and self.thumb_thread:
                self.thumb_worker.stop()
                self.thumb_thread.quit(); self.thumb_thread.wait(200)
        except Exception:
            pass
        self.thumb_worker = ThumbWorker(self.current_archive, self.current_format, names, password=self.pwd_cache.get(self.current_archive))
        self.thumb_thread = QThread()
        self.thumb_worker.moveToThread(self.thumb_thread)
        self.thumb_thread.started.connect(self.thumb_worker.run)
        self.thumb_worker.thumb_ready.connect(self._on_thumb_ready)
        self.thumb_worker.log.connect(lambda s: self._log("thumb: " + s))
        self.thumb_worker.finished.connect(self._on_thumb_finished)
        self.thumb_thread.start()

    def _on_thumb_ready(self, member, cache_path):
        for i in range(self.list_contents.count()):
            it = self.list_contents.item(i)
            if it.text()==member:
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

    # ---------- open / extract members (nested) ----------
    def item_double(self, item):
        member = item.text()
        ext = Path(member).suffix.lower().lstrip('.')
        if ext in ("zip","7z","rar","jarc"):
            tmpd = Path(tempfile.mkdtemp(prefix="miniarch_nested_")); self.temp_dirs.append(tmpd)
            got = self._extract_member_to_temp(member, tmpd)
            if got:
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
                # try search for file by name in temp dir
                found=None
                for p in tmpd.rglob("*"):
                    if p.is_file() and p.name==Path(member).name:
                        found=p; break
                if found:
                    self._open_with_system(found)
                else:
                    QMessageBox.warning(self, "Open", "Could not extract/open member")

    def _open_with_system(self, p: Path):
        try:
            if ON_WINDOWS:
                os.startfile(str(p))
            else:
                subprocess.run(["xdg-open", str(p)], check=False)
        except Exception as e:
            self._log("open error: "+str(e))
            QMessageBox.warning(self, "Open", f"Failed to open: {e}")

    def _extract_member_to_temp(self, member, tmpdir: Path):
        if not self.current_archive:
            return None
        fmt = self.current_format; path = self.current_archive; pwd = self.pwd_cache.get(path)
        try:
            if fmt=="zip":
                import zipfile
                with zipfile.ZipFile(path,"r") as zf:
                    names = zf.namelist()
                    cand=None
                    for nm in names:
                        if nm==member or Path(nm).name==Path(member).name:
                            cand=nm; break
                    if not cand: return None
                    try:
                        if pwd:
                            zf.extract(cand, path=str(tmpdir), pwd=pwd.encode())
                        else:
                            zf.extract(cand, path=str(tmpdir))
                        return tmpdir / cand
                    except RuntimeError:
                        p = self.ask_password("ZIP needs password:")
                        if not p: return None
                        self.pwd_cache[path]=p
                        zf.extract(cand, path=str(tmpdir), pwd=p.encode())
                        return tmpdir / cand
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
                    p = self.ask_password("7z needs password:")
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
                    names=rf.namelist(); target=None
                    for n in names:
                        if n==member or Path(n).name==Path(member).name: target=n; break
                    if not target: return None
                    try:
                        rf.extract(target, path=str(tmpdir), pwd=(pwd if pwd else None))
                    except rarfile.BadRarFile:
                        p = self.ask_password("RAR needs password:")
                        if not p: return None
                        self.pwd_cache[path]=p; rf.extract(target, path=str(tmpdir), pwd=p)
                    except Exception:
                        p = self.ask_password("RAR may require password:")
                        if not p: return None
                        self.pwd_cache[path]=p; rf.extract(target, path=str(tmpdir), pwd=p)
                    return tmpdir / target
            elif fmt=="jarc":
                data = extract_jarc_member_bytes(path, member); outp = tmpdir / Path(member).name; outp.parent.mkdir(parents=True, exist_ok=True); outp.write_bytes(data); return outp
        except Exception as e:
            self._log("extract member error: "+str(e)+"\n"+traceback.format_exc())
            return None

    # ---------- stage/create ----------
    def stage_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select files")
        for f in files:
            self.list_stage.addItem(f)

    def stage_add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select folder")
        if d: self.list_stage.addItem(d)

    def create_archive(self):
        if self.list_stage.count()==0:
            QMessageBox.information(self, "No files", "Stage files/folders first"); return
        fmt = self.combo_fmt.currentText()
        out, _ = QFileDialog.getSaveFileName(self, "Save archive as", filter=f"{fmt.upper()} (*.{fmt})")
        if not out: return
        if not out.lower().endswith("." + fmt): out += "." + fmt
        items=[self.list_stage.item(i).text() for i in range(self.list_stage.count())]
        pwd = self.input_pwd.text().strip()
        try:
            if fmt=="zip":
                import zipfile
                if pwd and not HAS_PYZIPPER:
                    QMessageBox.critical(self, "Missing pyzipper", "pyzipper is required for passworded zip (pip install pyzipper)"); return
                if pwd:
                    with pyzipper.AESZipFile(out, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                        zf.setpassword(pwd.encode())
                        for p in items:
                            pth = Path(p)
                            if pth.is_dir():
                                parent = pth.parent
                                for root, _, names in os.walk(p):
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
                                for root, _, names in os.walk(p):
                                    for n in names:
                                        full=Path(root)/n; arc = str(full.relative_to(parent)).replace("\\","/")
                                        zf.write(str(full), arcname=arc)
                            else:
                                zf.write(str(pth), arcname=pth.name)
            elif fmt=="7z":
                if not HAS_PY7ZR: QMessageBox.critical(self, "Missing py7zr", "py7zr required"); return
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
                if rc!=0:
                    QMessageBox.warning(self, "RAR create", f"rar returned rc={rc}")
            self._log("Created " + out)
            QMessageBox.information(self, "Created", f"Archive created: {out}")
            if self.chk_par2_auto.isChecked():
                par2_red = int(self.spin_red.value()); mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
                if not mgr.is_ok():
                    QMessageBox.information(self, "par2 missing", "par2 not configured. Use Locate/Search/Install")
                else:
                    groups = [([out], None, None)]
                    mgr.signals.log.connect(lambda s: self._log("par2: "+s))
                    mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
                    mgr.signals.finished.connect(lambda summary: (self._log("par2 create finished"), self.progress.setValue(0)))
                    mgr.run_create(groups, par2_red, default_out_dir=None)
        except Exception as e:
            self._log("Create error: "+str(e)+"\n"+traceback.format_exc())
            QMessageBox.critical(self, "Create error", str(e))

    def create_rar(self):
        rarexe = shutil.which("rar") or shutil.which("rar.exe")
        if not rarexe:
            QMessageBox.critical(self, "No rar", "rar.exe not found"); return
        items=[self.list_stage.item(i).text() for i in range(self.list_stage.count())]
        if not items:
            QMessageBox.information(self, "No files", "stage files"); return
        out, _ = QFileDialog.getSaveFileName(self, "Save RAR as", filter="RAR (*.rar)")
        if not out: return
        if not out.lower().endswith(".rar"): out += ".rar"
        pwd = self.input_pwd.text().strip()
        cmd = [rarexe, "a", "-ep1"]
        if pwd: cmd.append(f"-hp{pwd}")
        cmd.append(out); cmd += items
        rc, outb, errb = safe_run(cmd, timeout=600)
        if rc==0:
            self._log("RAR created: "+out)
            QMessageBox.information(self, "RAR created", out)
        else:
            QMessageBox.warning(self, "RAR create", f"rc={rc}")

    # ---------- par2 UI ----------
    def par2_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Add files to par2 targets")
        for f in files: self.list_par2_targets.addItem(f)
        self._log(f"Added {len(files)} file targets")

    def par2_add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Add folder to par2 targets (won't expand on add)")
        if folder: self.list_par2_targets.addItem(folder); self._log("Added folder target: "+folder)

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
                    if files: groups.append((files, Path(t).name, t))
                else:
                    groups.append(([t], None, None))
        else:
            files=[]
            for t in targets:
                if os.path.isdir(t): files += self._expand_folder(t)
                else: files.append(t)
            out_dir = QFileDialog.getExistingDirectory(self, "Where to write the .par2 file (directory)")
            if not out_dir: QMessageBox.information(self, "Output required", "Choose an output directory"); return
            base_name, ok = QtWidgets.QInputDialog.getText(self, "Base name", "Enter base name for .par2 (no extension):", QtWidgets.QLineEdit.Normal, "archive_par2")
            if not ok: base_name=None
            groups.append((files, base_name or None, out_dir))
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
        mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
        if not mgr.is_ok():
            QMessageBox.information(self, "par2 missing", "par2 not configured."); return
        mgr.signals.log.connect(lambda s: self._log("par2: "+s))
        mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
        def on_finished(summary):
            self._log("par2 repair finished"); self.progress.setValue(0)
            moved=[]
            for group in summary:
                moved += group.get("moved", []) or []
            if moved:
                QMessageBox.information(self, "Repair done", "Moved repaired files:\n" + "\n".join(moved))
            else:
                QMessageBox.information(self, "Repair done", "Repair finished (see log).")
        mgr.signals.finished.connect(on_finished)
        mgr.run_repair_many(items, move_repaired_to=dest if dest else None)

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
                        if fn.lower().endswith(".par2"):
                            found.append(os.path.join(root, fn))
                if not found:
                    QMessageBox.information(self, "No .par2", f"No .par2 files found under {folder}")
                    return
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
        mgr = Par2Manager(par2_exe=CFG.get("par2_exe"))
        if not mgr.is_ok():
            QMessageBox.information(self, "par2 missing", "par2 not configured."); return
        mgr.signals.log.connect(lambda s: self._log("par2: "+s))
        mgr.signals.progress.connect(lambda c,t: self.progress.setValue(int((c/t)*100) if t else 0))
        mgr.signals.finished.connect(lambda summary: (self._log("par2 repair finished"), self.progress.setValue(0)))
        mgr.run_repair_many([self.list_loaded_par2.item(i).text() for i in range(self.list_loaded_par2.count())], move_repaired_to=dest if dest else None)

    # ---------- par2 locate / search / install ----------
    def locate_par2(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Locate par2 executable", filter="Executables (*.exe);;All files (*)")
        if not fn: return
        try:
            rc, out, err = safe_run([fn, "--version"], timeout=3)
            if rc==0 or out or err:
                CFG["par2_exe"]=fn; save_cfg(); self.par2mgr.par2_exe=fn; self.statusBar().showMessage("par2: "+fn); QMessageBox.information(self, "par2", "par2 configured"); return
        except Exception:
            pass
        QMessageBox.warning(self, "par2", "Selected file doesn't appear to be par2")

    def search_par2(self):
        found = self._search_common_par2_locations()
        if found:
            CFG["par2_exe"]=found; save_cfg(); self.par2mgr.par2_exe=found; self.statusBar().showMessage("par2: "+found); QMessageBox.information(self, "Found", f"par2 found: {found}")
        else:
            QMessageBox.information(self, "Not found", "No par2 found in common locations")

    def _search_common_par2_locations(self):
        cand=[]
        if ON_WINDOWS:
            pf = os.getenv("PROGRAMFILES", r"C:\Program Files"); pf86 = os.getenv("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            cand += [os.path.join(pf,"par2","par2.exe"), os.path.join(pf86,"par2","par2.exe"),
                     os.path.join(pf,"par2cmdline","par2.exe"), os.path.join(pf86,"par2cmdline","par2.exe"),
                     r"C:\ProgramData\chocolatey\lib\par2cmdline\tools\par2.exe"]
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

    def install_par2_choco(self):
        if not ON_WINDOWS or not shutil.which("choco"):
            QMessageBox.information(self, "Chocolatey missing", "Chocolatey not in PATH."); return
        resp = QMessageBox.question(self, "Install par2 via Chocolatey", "Install par2cmdline via Chocolatey? This requires admin.", QMessageBox.Yes | QMessageBox.No)
        if resp!=QMessageBox.Yes: return
        cmd = ["choco","install","par2cmdline","-y","--no-progress"]
        self._log("Running: " + " ".join(cmd))
        rc,out,err = safe_run(cmd, timeout=600)
        if rc==0:
            found = self._search_common_par2_locations()
            if found:
                CFG["par2_exe"]=found; save_cfg(); self.par2mgr.par2_exe=found; self.statusBar().showMessage("par2: "+found); QMessageBox.information(self, "Installed", "par2 installed and configured.")
            else:
                QMessageBox.information(self, "Installed", "Installed but not found automatically. Use Locate par2.")
        else:
            self._log("choco install rc=%s out=%s err=%s" % (rc, out[:200], err[:200]))
            QMessageBox.information(self, "Install failed", f"Install returned rc={rc}. See log")

    # ---------- association helper ----------
    def associate_jarc(self):
        if not ON_WINDOWS or winreg is None:
            QMessageBox.information(self, "Not supported", "Association helper only works on Windows.")
            return
        script_default = os.path.abspath(sys.argv[0])
        script_path, _ = QFileDialog.getOpenFileName(self, "Select script or exe to associate .jarc with", script_default)
        if not script_path: return
        python_exec = sys.executable
        cmd = f'"{python_exec}" "{script_path}" "%1"'
        try:
            base = r"Software\\Classes"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base, 0, winreg.KEY_WRITE) as hk:
                with winreg.CreateKey(hk, ".jarc") as k:
                    winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "MiniArch.jarc")
                with winreg.CreateKey(hk, "MiniArch.jarc") as prog:
                    winreg.SetValueEx(prog, "", 0, winreg.REG_SZ, "MiniArch JARC File")
                    with winreg.CreateKey(prog, "DefaultIcon") as di:
                        winreg.SetValueEx(di, "", 0, winreg.REG_SZ, "")
                    with winreg.CreateKey(prog, r"shell\\open\\command") as cmdk:
                        winreg.SetValueEx(cmdk, "", 0, winreg.REG_SZ, cmd)
            QMessageBox.information(self, "Associated", ".jarc associated. You may need to use Open With to select default.")
            self._log(".jarc associated to "+cmd)
        except Exception as e:
            self._log("Association failed: "+str(e)); QMessageBox.critical(self, "Assoc failed", str(e))

    # ---------- cleanup ----------
    def closeEvent(self, evt):
        try:
            if self.thumb_worker and self.thumb_thread:
                self.thumb_worker.stop(); self.thumb_thread.quit(); self.thumb_thread.wait(200)
        except Exception:
            pass
        for d in self.temp_dirs:
            try: shutil.rmtree(str(d), ignore_errors=True)
            except Exception: pass
        evt.accept()

# save cfg helper
def save_cfg():
    try:
        CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CFG_FILE.write_text(json.dumps(CFG, indent=2), encoding="utf-8")
    except Exception:
        pass

# run
def main():
    app = QApplication(sys.argv)
    w = MiniArchWindow()
    w.showMaximized()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
