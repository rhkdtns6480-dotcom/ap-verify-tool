# -*- coding: utf-8 -*-
"""
build.py - AP Verify Tool PyInstaller Build Script

Usage:
    python build.py              # default (onefile + windowed)
    python build.py --debug      # keep console window
    python build.py --onedir     # folder output (faster, for debugging)
    python build.py --no-upx     # disable UPX compression
"""
import os
import subprocess
import sys
import pkgutil

# Windows cp949 터미널 인코딩 문제 방지
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


def get_scapy_hidden_imports():
    imports = []
    try:
        import scapy.layers
        import scapy.contrib
        for m in pkgutil.iter_modules(scapy.layers.__path__):
            imports.append(f"scapy.layers.{m.name}")
        for m in pkgutil.iter_modules(scapy.contrib.__path__):
            imports.append(f"scapy.contrib.{m.name}")
        print(f"[INFO] Scapy hidden imports: {len(imports)} modules")
    except ImportError:
        print("[WARN] scapy not installed - skipping hidden imports")
    return imports


def main():
    base   = os.path.dirname(os.path.abspath(__file__))
    debug  = "--debug"  in sys.argv
    onedir = "--onedir" in sys.argv
    no_upx = "--no-upx" in sys.argv

    print("=" * 60)
    print("  AP Verify Tool - PyInstaller Build")
    print(f"  debug={debug} / onedir={onedir} / no-upx={no_upx}")
    print("=" * 60)

    # --- Resource files ---
    add_data = [
        f"scenarios{os.pathsep}scenarios",
        f"assets{os.pathsep}assets",
    ]

    # Korean font for PDF
    for font_path in [r"C:\Windows\Fonts\malgun.ttf",
                      r"C:\Windows\Fonts\malgunbd.ttf"]:
        if os.path.exists(font_path):
            add_data.append(f"{font_path}{os.pathsep}.")
            print(f"[INFO] Font included: {os.path.basename(font_path)}")
        else:
            print(f"[WARN] Font not found: {font_path}")

    # Npcap installer - auto bundle if present in project folder
    npcap_installer = None
    for fname in os.listdir(base):
        if fname.lower().startswith("npcap") and fname.lower().endswith(".exe"):
            npcap_installer = os.path.join(base, fname)
            break

    if npcap_installer:
        add_data.append(f"{npcap_installer}{os.pathsep}.")
        print(f"[INFO] Npcap installer bundled: {os.path.basename(npcap_installer)}")
    else:
        print("[WARN] npcap-*.exe not found - must be distributed separately")
        print("       Download: https://npcap.com/#download")

    # --- Hidden imports ---
    hidden = [
        # Internal modules
        "plugins.dummy_plugins",
        "plugins.base_plugin",
        "virtual_mac_manager",
        "npcap_check",
        # tkinter
        "tkinter", "tkinter.ttk", "tkinter.messagebox",
        "tkinter.filedialog", "tkinter.simpledialog",
        # packages
        "openpyxl", "openpyxl.styles", "openpyxl.utils",
        "reportlab", "reportlab.lib", "reportlab.lib.colors",
        "reportlab.lib.pagesizes", "reportlab.lib.styles",
        "reportlab.lib.units", "reportlab.pdfbase",
        "reportlab.pdfbase.ttfonts", "reportlab.platypus",
        "psutil",
        # Windows registry (for Npcap check)
        "winreg",
        # Scapy core
        "scapy", "scapy.all",
        "scapy.arch", "scapy.arch.windows", "scapy.arch.windows.native",
        "scapy.config", "scapy.data", "scapy.error",
        "scapy.interfaces", "scapy.packet", "scapy.sendrecv",
        "scapy.utils", "scapy.volatile", "scapy.fields",
        "scapy.plist", "scapy.supersocket", "scapy.ansmachine",
    ]
    hidden.extend(get_scapy_hidden_imports())

    # Scapy data files (OUI DB etc.)
    try:
        import scapy
        scapy_dir = os.path.dirname(scapy.__file__)
        for fname in ["oui.txt", "manuf"]:
            fpath = os.path.join(scapy_dir, "data", fname)
            if os.path.exists(fpath):
                add_data.append(f"{fpath}{os.pathsep}scapy/data")
                print(f"[INFO] Scapy data included: {fname}")
    except ImportError:
        pass

    # --- PyInstaller command ---
    icon_path     = os.path.join(base, "assets", "icon.ico")
    manifest_path = os.path.join(base, "app.manifest")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "main_app.py",
        "--name", "AP_Verify_Tool",
        "--windowed" if not debug else "--console",
        "--onefile"  if not onedir else "--onedir",
        "--clean",
        "--noconfirm",
    ]

    if os.path.exists(icon_path):
        cmd += ["--icon", icon_path]
    else:
        print("[WARN] assets/icon.ico not found - using default icon")

    if os.path.exists(manifest_path):
        cmd += ["--manifest", manifest_path]
    else:
        print("[WARN] app.manifest not found - admin rights not configured")

    if no_upx:
        cmd += ["--noupx"]

    for d in add_data:
        cmd += ["--add-data", d]
    for h in hidden:
        cmd += ["--hidden-import", h]

    print(f"\n[CMD] PyInstaller with {len(cmd)} arguments")
    print("[BUILD] Starting... (may take 3-10 minutes)\n")

    result = subprocess.run(cmd, cwd=base)

    if result.returncode == 0:
        out_exe = os.path.join(base, "dist",
                               "AP_Verify_Tool.exe" if not onedir
                               else "AP_Verify_Tool")

        print(f"\n{'='*60}")
        print("  BUILD SUCCESS!")
        print(f"  Output: {out_exe}")
        print(f"{'='*60}")
        print()
        print("  [Distribution package]")
        print("  dist/")
        print("  +-- AP_Verify_Tool.exe")
        if npcap_installer:
            print(f"  +-- {os.path.basename(npcap_installer)}  (bundled)")
        else:
            print("  +-- npcap-1.80.exe  <-- ADD THIS MANUALLY")
            print("      Download: https://npcap.com/#download")
        print()
        print("  [How to run on target PC]")
        print("  1. Right-click exe -> Run as Administrator")
        print("  2. If Npcap not installed, auto-install dialog appears")
        print("  3. After install, app restarts automatically")
        print(f"{'='*60}")
    else:
        print(f"\n[FAIL] Build failed (exit code: {result.returncode})")
        sys.exit(1)


if __name__ == "__main__":
    main()
