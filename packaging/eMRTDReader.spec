# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-file spec for the eMRTD Reader GUI.

Build (from the project root):
    pyinstaller --noconfirm --clean packaging/eMRTDReader.spec

Output: a single executable  dist/eMRTDReader(.exe)
"""
import os

from PyInstaller.utils.hooks import collect_all, collect_submodules

# PyInstaller exposes SPECPATH = directory containing this spec file.
project_root = os.path.abspath(os.path.join(SPECPATH, os.pardir))
os.chdir(project_root)

datas, binaries, hiddenimports = [], [], []

# CustomTkinter ships theme / font assets - bundle everything. Pillow's
# ImageTk needs its C extension and the `_tkinter_finder` helper too.
for pkg in ("customtkinter", "PIL"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# pyscard (python wrapper over PC/SC). Its subpackage is `smartcard`.
d, b, h = collect_all("smartcard")
datas += d
binaries += b
hiddenimports += h
hiddenimports += ["smartcard.scard", "smartcard.pcsc", "smartcard.util"]

# pycryptodome - pull in every module that the protocol code imports.
hiddenimports += collect_submodules("Crypto")
hiddenimports += [
    "Crypto.Cipher.AES",
    "Crypto.Cipher.DES",
    "Crypto.Hash.CMAC",
    "Crypto.Hash.SHA1",
    "Crypto.Hash.SHA256",
    "Crypto.Hash.SHA384",
    "Crypto.Hash.SHA512",
    "Crypto.PublicKey.ECC",
    "Crypto.PublicKey.RSA",
    "Crypto.Signature.DSS",
    "Crypto.Signature.pkcs1_15",
    "PIL.Image",
    "PIL.ImageTk",
    "PIL._imagingtk",
    "PIL._tkinter_finder",
]

a = Analysis(
    [os.path.join(project_root, "epassport_gui.py")],
    pathex=[project_root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter.test"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="eMRTDReader",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # GUI app -> no console window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # optional: icon="packaging/app.ico"
)
