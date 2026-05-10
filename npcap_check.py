"""
npcap_check.py — Npcap 설치 확인 및 자동 설치 모듈

동작 흐름:
  1. Npcap 설치 여부 레지스트리/드라이버로 확인
  2. Scapy import 가능 여부 확인
  3. 미설치 시:
     a. 옆에 npcap-*.exe 있으면 silent 자동 설치
     b. 없으면 다운로드 안내 다이얼로그 표시
  4. 결과 반환 → 앱이 실제/시뮬 모드 결정
"""
import os
import sys
import subprocess
import threading
from typing import Callable, Optional


# ──────────────────────────────────────────────
# Npcap 설치 확인
# ──────────────────────────────────────────────

NPCAP_REG_PATHS = [
    r"SOFTWARE\Npcap",
    r"SOFTWARE\WOW6432Node\Npcap",
]
NPCAP_SERVICE   = "npcap"
NPCAP_DRIVER    = r"C:\Windows\System32\Npcap\npcap.sys"
NPCAP_DLL       = r"C:\Windows\System32\Npcap\wpcap.dll"
NPCAP_DOWNLOAD  = "https://npcap.com/#download"
NPCAP_VERSION   = "1.80"   # 권장 버전


def is_npcap_installed() -> bool:
    """Npcap 설치 여부 확인 (레지스트리 + 드라이버 파일)"""
    if sys.platform != "win32":
        return True   # Linux/Mac은 libpcap 사용 → 별도 체크 불필요

    # 방법 1: 드라이버 파일 존재 확인
    if os.path.exists(NPCAP_DRIVER) or os.path.exists(NPCAP_DLL):
        return True

    # 방법 2: 레지스트리 확인
    try:
        import winreg
        for path in NPCAP_REG_PATHS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                continue
    except ImportError:
        pass

    # 방법 3: 서비스 확인
    try:
        result = subprocess.run(
            ["sc", "query", NPCAP_SERVICE],
            capture_output=True, text=True, timeout=5
        )
        if "RUNNING" in result.stdout or "STOPPED" in result.stdout:
            return True
    except Exception:
        pass

    return False


def is_scapy_functional() -> bool:
    """Scapy가 실제로 패킷 송수신 가능한지 확인"""
    try:
        from scapy.all import conf
        # Windows에서 Npcap 없으면 conf.L2socket이 None
        if sys.platform == "win32":
            return is_npcap_installed()
        return True
    except ImportError:
        return False


def find_npcap_installer() -> Optional[str]:
    """
    실행 파일 옆에 npcap-*.exe 찾기
    PyInstaller: sys._MEIPASS 기준
    일반 실행: 스크립트 디렉터리 기준
    """
    search_dirs = []

    # PyInstaller 번들 내부
    if getattr(sys, "frozen", False):
        search_dirs.append(os.path.dirname(sys.executable))
        # _MEIPASS는 임시 압축해제 폴더 (onefile)
        if hasattr(sys, "_MEIPASS"):
            search_dirs.append(sys._MEIPASS)
    else:
        search_dirs.append(os.path.dirname(os.path.abspath(__file__)))

    for d in search_dirs:
        for fname in os.listdir(d):
            if fname.lower().startswith("npcap") and fname.lower().endswith(".exe"):
                return os.path.join(d, fname)
    return None


# ──────────────────────────────────────────────
# 자동 설치
# ──────────────────────────────────────────────

def install_npcap_silent(installer_path: str,
                         on_progress: Optional[Callable[[str], None]] = None
                         ) -> bool:
    """
    Npcap silent 설치
    /S = silent, /winpcap_mode=yes = WinPcap 호환 모드 활성화
    반환: True=성공, False=실패
    """
    if on_progress:
        on_progress("Npcap 설치 중... (1~2분 소요)")

    try:
        result = subprocess.run(
            [installer_path, "/S", "/winpcap_mode=yes"],
            timeout=180,
            capture_output=True,
        )
        success = result.returncode == 0

        if on_progress:
            if success:
                on_progress("Npcap 설치 완료!")
            else:
                on_progress(f"설치 실패 (code: {result.returncode})")

        return success

    except subprocess.TimeoutExpired:
        if on_progress:
            on_progress("설치 타임아웃 — 수동으로 확인하세요")
        return False
    except Exception as e:
        if on_progress:
            on_progress(f"설치 오류: {e}")
        return False


# ──────────────────────────────────────────────
# GUI 다이얼로그 (tkinter)
# ──────────────────────────────────────────────

def show_npcap_dialog(parent=None) -> str:
    """
    Npcap 미설치 시 다이얼로그 표시
    반환: "install" | "download" | "skip" | "installed"
    """
    import tkinter as tk
    from tkinter import ttk

    # 색상 (앱 다크 테마와 동일)
    BG      = "#1E1E1E"
    BG2     = "#252526"
    PANEL   = "#2D2D2D"
    BORDER  = "#3C3C3C"
    TEXT    = "#D4D4D4"
    TEXT2   = "#9D9D9D"
    BLUE    = "#2196F3"
    AMBER   = "#FFA000"
    GREEN   = "#4CAF50"
    RED     = "#F44336"

    result = {"action": "skip"}

    dlg = tk.Tk() if parent is None else tk.Toplevel(parent)
    dlg.title("Npcap 드라이버 필요")
    dlg.geometry("480x360")
    dlg.resizable(False, False)
    dlg.configure(bg=BG)
    if parent:
        dlg.grab_set()
        dlg.transient(parent)

    # 아이콘 영역
    top = tk.Frame(dlg, bg=BG2,
                   highlightbackground=BORDER, highlightthickness=1)
    top.pack(fill="x")

    tk.Label(top, text="⚠", bg=BG2, fg=AMBER,
             font=("Segoe UI", 28)).pack(side="left", padx=16, pady=12)

    hdr_txt = tk.Frame(top, bg=BG2)
    hdr_txt.pack(side="left", pady=12)
    tk.Label(hdr_txt, text="Npcap 드라이버가 설치되지 않았습니다",
             bg=BG2, fg=TEXT,
             font=("Segoe UI", 12, "bold")).pack(anchor="w")
    tk.Label(hdr_txt,
             text="실제 패킷 송수신(가상 MAC DHCP, 연결 확인)에 필요합니다",
             bg=BG2, fg=TEXT2,
             font=("Segoe UI", 9)).pack(anchor="w")

    # 설명
    body = tk.Frame(dlg, bg=BG)
    body.pack(fill="both", expand=True, padx=20, pady=12)

    installer = find_npcap_installer()

    if installer:
        fname = os.path.basename(installer)
        tk.Label(body,
                 text=f"설치 파일 발견: {fname}\n\n"
                      "자동 설치 시 WinPcap 호환 모드가 활성화됩니다.\n"
                      "설치 완료 후 앱이 자동으로 재시작됩니다.",
                 bg=BG, fg=TEXT,
                 font=("Segoe UI", 10),
                 justify="left").pack(anchor="w")
    else:
        tk.Label(body,
                 text=f"설치 파일(npcap-*.exe)을 찾을 수 없습니다.\n\n"
                      f"아래 다운로드 버튼으로 Npcap {NPCAP_VERSION}을 받아\n"
                      f"설치 후 앱을 다시 실행하세요.\n\n"
                      f"또는 '건너뛰기'를 누르면 시뮬레이션 모드로 실행됩니다.",
                 bg=BG, fg=TEXT,
                 font=("Segoe UI", 10),
                 justify="left").pack(anchor="w")

    # 진행 바 (자동 설치 시)
    prog_frame = tk.Frame(dlg, bg=BG)
    prog_frame.pack(fill="x", padx=20)
    prog_lbl = tk.Label(prog_frame, text="", bg=BG, fg=TEXT2,
                        font=("Segoe UI", 9))
    prog_lbl.pack(anchor="w")
    prog_bar = ttk.Progressbar(prog_frame, mode="indeterminate")

    # 버튼
    btn_frame = tk.Frame(dlg, bg=BG2,
                         highlightbackground=BORDER, highlightthickness=1)
    btn_frame.pack(fill="x", side="bottom")

    def _auto_install():
        result["action"] = "install"
        for btn in btns:
            btn.config(state="disabled")
        prog_bar.pack(fill="x", pady=4)
        prog_bar.start(10)

        def _do():
            def _prog(msg):
                dlg.after(0, lambda: prog_lbl.config(text=msg))

            ok = install_npcap_silent(installer, on_progress=_prog)
            def _done():
                prog_bar.stop()
                if ok:
                    result["action"] = "installed"
                    dlg.destroy()
                else:
                    result["action"] = "skip"
                    prog_lbl.config(text="설치 실패 — 시뮬레이션 모드로 계속",
                                    fg=RED)
                    for btn in btns:
                        btn.config(state="normal")
                    prog_bar.pack_forget()
            dlg.after(0, _done)

        threading.Thread(target=_do, daemon=True).start()

    def _download():
        import webbrowser
        webbrowser.open(NPCAP_DOWNLOAD)
        result["action"] = "download"

    def _skip():
        result["action"] = "skip"
        dlg.destroy()

    btns = []
    if installer:
        b = tk.Button(btn_frame, text="자동 설치",
                      bg=GREEN, fg="white",
                      font=("Segoe UI", 10, "bold"),
                      relief="flat", cursor="hand2",
                      padx=16, pady=8,
                      command=_auto_install)
        b.pack(side="left", padx=10, pady=8)
        btns.append(b)

    b2 = tk.Button(btn_frame, text="다운로드 페이지 열기",
                   bg=BLUE, fg="white",
                   font=("Segoe UI", 10),
                   relief="flat", cursor="hand2",
                   padx=12, pady=8,
                   command=_download)
    b2.pack(side="left", padx=4, pady=8)
    btns.append(b2)

    tk.Button(btn_frame, text="건너뛰기 (시뮬레이션 모드)",
              bg=PANEL, fg=TEXT2,
              font=("Segoe UI", 9),
              relief="flat", cursor="hand2",
              padx=10, pady=8,
              command=_skip).pack(side="right", padx=10, pady=8)

    dlg.protocol("WM_DELETE_WINDOW", _skip)

    if parent is None:
        dlg.mainloop()
    else:
        dlg.wait_window()

    return result["action"]


# ──────────────────────────────────────────────
# 메인 체크 함수 (앱 시작 시 호출)
# ──────────────────────────────────────────────

class EnvCheckResult:
    def __init__(self):
        self.scapy_ok:    bool = False   # scapy import 성공
        self.npcap_ok:    bool = False   # npcap 설치됨
        self.packet_ok:   bool = False   # 실제 패킷 가능
        self.mode:        str  = "sim"   # "real" | "sim"
        self.npcap_action:str  = ""      # 사용자 액션


def check_environment(parent=None, silent: bool = False) -> EnvCheckResult:
    """
    앱 시작 시 환경 체크 메인 함수
    silent=True → 다이얼로그 없이 결과만 반환
    """
    r = EnvCheckResult()

    # 1. Scapy 확인
    try:
        import scapy  # noqa
        r.scapy_ok = True
    except ImportError:
        r.scapy_ok = False

    # 2. Npcap 확인
    r.npcap_ok = is_npcap_installed()

    # 3. 종합 판정
    r.packet_ok = r.scapy_ok and r.npcap_ok
    r.mode      = "real" if r.packet_ok else "sim"

    if r.packet_ok or silent:
        return r

    # 4. 미설치 시 다이얼로그
    if sys.platform == "win32" and not r.npcap_ok:
        action = show_npcap_dialog(parent)
        r.npcap_action = action
        if action == "installed":
            # 재확인
            r.npcap_ok  = is_npcap_installed()
            r.packet_ok = r.scapy_ok and r.npcap_ok
            r.mode      = "real" if r.packet_ok else "sim"

    return r


# ──────────────────────────────────────────────
# 개발/디버그용 직접 실행
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Npcap 설치됨: {is_npcap_installed()}")
    print(f"Scapy 동작:   {is_scapy_functional()}")
    print(f"설치 파일:    {find_npcap_installer()}")
    r = check_environment(silent=True)
    print(f"모드:         {r.mode}")
