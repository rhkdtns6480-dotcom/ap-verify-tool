"""
main_app.py — AP Auto Verification Tool
메인 진입점 및 전체 GUI (Tkinter Notebook 6탭)

실행: python main_app.py
빌드: pyinstaller main_app.py --name AP_Verify_Tool --onefile --windowed ...
"""
import json
import os
import queue
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from tkinter import (BooleanVar, END, IntVar, StringVar, Text, Tk, Toplevel,
                     filedialog, messagebox, simpledialog, ttk)
import tkinter as tk

# ── 내부 모듈 ──────────────────────────────────
from logger import log
from scenario_engine import (RepeatConfig, Scenario, ScenarioEngine,
                              ScenarioStep, list_scenarios, save_scenario)
from plugins.dummy_plugins import PLUGIN_REGISTRY
# virtual_mac_manager는 Scapy 감지 목적으로만 참조 (직접 사용 없음)
from npcap_check import check_environment, EnvCheckResult
import report_writer

APP_NAME    = "AP Auto Verification Tool"
APP_VERSION = "v0.0.1"

# ──────────────────────────────────────────────
# 색상 팔레트 (목업 디자인 반영)
# ──────────────────────────────────────────────
CLR = {
    # ── 다크 배경 계열 ──
    "bg":         "#1E1E1E",   # 메인 배경 (VS Code 다크 수준)
    "bg2":        "#252526",   # 사이드바/패널 배경
    "panel":      "#2D2D2D",   # 카드/입력 배경
    "border":     "#3C3C3C",   # 기본 구분선
    "border2":    "#505050",   # 강조 구분선
    # ── 텍스트 ──
    "text":       "#D4D4D4",   # 기본 텍스트
    "text2":      "#9D9D9D",   # 보조 텍스트
    "text3":      "#6B6B6B",   # 힌트 텍스트
    # ── 액센트 (밝기 높여 다크 배경에서 잘 보이도록) ──
    "blue_bg":    "#1A3A5C",
    "blue_fg":    "#4FC3F7",
    "blue_mid":   "#2196F3",
    "green_bg":   "#1A3A1A",
    "green_fg":   "#81C784",
    "green_mid":  "#4CAF50",
    "amber_bg":   "#3A2E00",
    "amber_fg":   "#FFD54F",
    "amber_mid":  "#FFA000",
    "red_bg":     "#3A1A1A",
    "red_fg":     "#EF9A9A",
    "red_mid":    "#F44336",
    "gray_bg":    "#333333",
    "gray_fg":    "#AAAAAA",
    "purple_bg":  "#2A1A4A",
    "purple_fg":  "#CE93D8",
}

STEP_TYPE_COLORS = {
    "Send":   (CLR["blue_bg"],   CLR["blue_fg"]),
    "Wait":   (CLR["purple_bg"], CLR["purple_fg"]),
    "Check":  (CLR["amber_bg"],  CLR["amber_fg"]),
    "Delay":  (CLR["gray_bg"],   CLR["gray_fg"]),
    "Assert": (CLR["green_bg"],  CLR["green_fg"]),
}

LOG_COLORS = {
    "DEBUG": CLR["gray_fg"],
    "INFO":  CLR["blue_fg"],
    "WARN":  CLR["amber_fg"],
    "ERROR": CLR["red_fg"],
}
LOG_BG = {
    "DEBUG": CLR["panel"],
    "INFO":  CLR["panel"],
    "WARN":  "#FFFCF5",
    "ERROR": "#FFF8F8",
}

# ──────────────────────────────────────────────
# 유틸
# ──────────────────────────────────────────────

def _font(size=11, bold=False, mono=False):
    family = "Consolas" if mono else "Segoe UI"
    weight = "bold" if bold else "normal"
    return (family, size, weight)


def _get_interfaces() -> list[dict]:
    """PC 인터페이스 목록 조회 (psutil)"""
    try:
        import psutil
        ifaces = []
        addrs  = psutil.net_if_addrs()
        stats  = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ip = "—"
            for a in addr_list:
                if a.family == 2:   # AF_INET
                    ip = a.address
                    break
            is_up = stats.get(name, None)
            ifaces.append({
                "name": name,
                "ip":   ip,
                "up":   is_up.isup if is_up else False,
            })
        return ifaces
    except Exception:
        return [
            {"name": "Ethernet 0", "ip": "192.168.1.10", "up": True},
            {"name": "Ethernet 1", "ip": "192.168.2.20", "up": True},
            {"name": "Wi-Fi 0",    "ip": "—",            "up": False},
        ]


# ──────────────────────────────────────────────
# 설정 저장/불러오기
# ──────────────────────────────────────────────

CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CFG = {
    "report_dir":      "",
    "log_dir":         "",
    "auto_detect_sec": 5,
    "pkt_timeout_ms":  3000,
    "device_name":     "",
    "firmware":        "",
    "tester":          "",
}


def load_config() -> dict:
    if os.path.exists(CFG_PATH):
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                return {**DEFAULT_CFG, **json.load(f)}
        except Exception:
            pass
    return dict(DEFAULT_CFG)


def save_config(cfg: dict):
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def _resolve_scapy_iface(iface_name: str) -> str:
    """
    psutil 인터페이스 이름 → Scapy 인터페이스 객체/이름 변환
    Windows: psutil은 "Wi-Fi", "이더넷" 등 표시 이름 반환
             Scapy는 내부적으로 GUID 기반 이름 사용
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        # 표시 이름(name) 또는 설명(description)으로 매칭
        for iface in ifaces:
            name_match = (
                iface.get("name", "").lower()        == iface_name.lower() or
                iface.get("description", "").lower() == iface_name.lower() or
                iface.get("win_index", "")           == iface_name
            )
            if name_match:
                # Scapy는 description을 iface 인자로 받음
                return iface.get("description") or iface.get("name") or iface_name
    except Exception:
        pass

    # Linux / Mac or fallback: 이름 그대로 사용
    return iface_name


def _is_admin() -> bool:
    """현재 프로세스가 관리자 권한인지 확인"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _apply_ip_to_iface(iface_name: str, mode: str,
                       ip: str, mask: str, gw: str,
                       dns1: str, dns2: str) -> dict:
    """
    Windows netsh로 실제 인터페이스 IP 적용
    관리자 권한 필요
    반환: {"ok": bool, "error": str}
    """
    import subprocess, sys

    if sys.platform != "win32":
        return {"ok": False, "error": "Windows 전용 기능입니다."}

    # 관리자 권한 사전 확인
    if not _is_admin():
        return {
            "ok": False,
            "error": "관리자 권한 필요 — 터미널을 '관리자 권한으로 실행' 후 재시도"
        }

    # netsh 출력 한글(cp949) 인코딩 명시
    run_kw = dict(
        timeout=20,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="cp949",
        errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    def _run(cmd: list) -> tuple[int, str]:
        try:
            r = subprocess.run(cmd, **run_kw)
            out = (r.stdout or "") + (r.stderr or "")
            log.info(
                f"netsh: {' '.join(cmd[3:6])} → rc={r.returncode} / {out.strip()[:80]}",
                source="NETSH")
            return r.returncode, out.strip()
        except subprocess.TimeoutExpired:
            return -1, "Timeout"
        except Exception as e:
            return -1, str(e)

    try:
        if mode == "dynamic":
            rc, out = _run([
                "netsh", "interface", "ip", "set", "address",
                "name=" + iface_name, "source=dhcp"
            ])
            if rc != 0:
                return {"ok": False, "error": out or f"DHCP 설정 실패 (rc={rc})"}
            _run(["netsh", "interface", "ip", "set", "dns",
                  "name=" + iface_name, "source=dhcp"])
            return {"ok": True, "error": ""}

        else:  # static
            if not ip or not mask:
                return {"ok": False, "error": "IP/서브넷 마스크를 입력하세요."}

            cmd_ip = [
                "netsh", "interface", "ip", "set", "address",
                "name=" + iface_name,
                "source=static",
                "addr=" + ip,
                "mask=" + mask,
            ]
            if gw:
                cmd_ip += ["gateway=" + gw, "gwmetric=1"]

            rc, out = _run(cmd_ip)
            if rc != 0:
                if rc == 5 or "권한" in out or "access" in out.lower() or "elev" in out.lower():
                    msg = "관리자 권한 필요 — 앱을 관리자로 재실행하세요"
                elif "찾을 수 없" in out or "not found" in out.lower():
                    msg = f"인터페이스를 찾을 수 없습니다: {iface_name}"
                elif "올바르지" in out or "invalid" in out.lower():
                    msg = "IP/서브넷 형식 오류"
                else:
                    msg = f"설정 실패 (rc={rc}) — Syslog NETSH 확인"
                return {"ok": False, "error": msg}

            if dns1:
                _run(["netsh", "interface", "ip", "set", "dns",
                      "name=" + iface_name, "source=static",
                      "addr=" + dns1, "register=primary"])
            if dns2:
                _run(["netsh", "interface", "ip", "add", "dns",
                      "name=" + iface_name, "addr=" + dns2, "index=2"])

            return {"ok": True, "error": ""}

    except Exception as e:
        return {"ok": False, "error": str(e)}


def _is_public_ip(ip: str) -> bool:
    """
    IP가 공인 IP인지 판별
    사설/특수 대역이 아니면 공인 IP로 판단
    """
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_multicast or
            addr.is_reserved or
            addr.is_unspecified
        )
    except Exception:
        return False


def _lookup_vendor(mac: str) -> str:
    """
    MAC OUI(앞 3옥텟)로 제조사 조회
    Scapy의 manuf DB 활용 → 없으면 빈 문자열
    """
    try:
        from scapy.data import ETHER_TYPES
        from scapy.layers.l2 import Ether
        # Scapy 내장 ManufDB
        from scapy.libs.manuf import ManufDB
        db = ManufDB()
        result = db.lookup(mac)
        if result:
            return result[1] or result[0] or ""
    except Exception:
        pass
    # OUI 앞 6자리만 대문자로 표시 (fallback)
    try:
        return mac.upper()[:8]
    except Exception:
        return ""


# ══════════════════════════════════════════════
# 탭 1 — 토폴로지 뷰
# ══════════════════════════════════════════════

class TopologyTab(tk.Frame):
    PKT_COLORS = {"ok": CLR["green_mid"], "warn": CLR["amber_mid"], "err": CLR["red_mid"]}

    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self._ifaces:  list[dict] = []
        self._roles:   dict[str, str] = {}    # name → master|slave|none
        self._ip_mode: dict[str, str] = {}    # name → static|dynamic|server
        self._custom_ip: dict[str, str] = {}
        self._running  = False
        self._pkt_job  = None
        self._cnt = {"ok": 0, "warn": 0, "err": 0}
        self._pkt_items: list = []
        self._conn_status: dict[str, str] = {}
        self._ap_info: dict = {"detected": False}
        self._ip_settings: dict[str, dict] = {}
        self._ap_list: list[dict] = []
        self._ap_card_widgets: dict[str, dict] = {}
        # 노드 자유 위치 {node_id: (cx, cy)} — 드래그로 변경
        self._node_pos: dict[str, tuple] = {}
        # 드래그 상태
        self._drag_node: str | None = None     # 드래그 중인 노드 id
        self._drag_offset: tuple = (0, 0)      # 클릭 오프셋
        self._connect_src: str | None = None   # 연결 드래그 시작 노드
        self._connect_line = None              # 임시 연결선 canvas item
        self._build()
        self._refresh_interfaces()

    # ── 레이아웃 ──────────────────────────────

    def _build(self):
        # 2-panel: [좌측 서브탭 패널 260px] | [토폴로지 캔버스+로그]
        left = tk.Frame(self, bg=CLR["bg2"], width=260, relief="flat",
                        highlightbackground=CLR["border"], highlightthickness=1)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._build_left(left)

        right = tk.Frame(self, bg=CLR["bg"])
        right.pack(side="left", fill="both", expand=True)
        self._build_right(right)

    def _build_left(self, parent):
        # ── 서브탭 헤더: 인터페이스 | AP 관리 | 플러그인 ─
        subtab_bar = tk.Frame(parent, bg=CLR["bg2"])
        subtab_bar.pack(fill="x")

        self._left_panel_iface  = tk.Frame(parent, bg=CLR["bg2"])
        self._left_panel_ap     = tk.Frame(parent, bg=CLR["bg2"])
        self._left_panel_plugin = tk.Frame(parent, bg=CLR["bg2"])

        def _style_btn(btn, active):
            if active:
                btn.config(bg=CLR["panel"], fg=CLR["blue_fg"],
                           font=_font(10, bold=True))
            else:
                btn.config(bg=CLR["bg2"], fg=CLR["text2"],
                           font=_font(10, bold=False))

        self._btn_subtab_iface  = tk.Label(subtab_bar, text="인터페이스",
                                           bg=CLR["panel"], fg=CLR["blue_fg"],
                                           font=_font(10, bold=True),
                                           cursor="hand2", padx=8, pady=7)
        self._btn_subtab_ap     = tk.Label(subtab_bar, text="AP 관리",
                                           bg=CLR["bg2"], fg=CLR["text2"],
                                           font=_font(10, bold=False),
                                           cursor="hand2", padx=8, pady=7)
        self._btn_subtab_plugin = tk.Label(subtab_bar, text="플러그인",
                                           bg=CLR["bg2"], fg=CLR["text2"],
                                           font=_font(10, bold=False),
                                           cursor="hand2", padx=8, pady=7)
        self._btn_subtab_iface.pack(side="left")
        self._btn_subtab_ap.pack(side="left")
        self._btn_subtab_plugin.pack(side="left")

        # 새로고침 버튼 (인터페이스 탭에서만 유효)
        self._btn_refresh = tk.Button(subtab_bar, text="새로고침",
                                      font=_font(9), bg=CLR["bg2"],
                                      fg=CLR["text2"], relief="flat", cursor="hand2",
                                      command=self._refresh_interfaces)
        self._btn_refresh.pack(side="right", padx=6)

        # 구분선
        tk.Frame(parent, bg=CLR["border"], height=1).pack(fill="x")

        def _show_iface():
            self._left_panel_ap.pack_forget()
            self._left_panel_plugin.pack_forget()
            self._left_panel_iface.pack(fill="both", expand=True)
            _style_btn(self._btn_subtab_iface,  True)
            _style_btn(self._btn_subtab_ap,     False)
            _style_btn(self._btn_subtab_plugin, False)
            self._btn_refresh.pack(side="right", padx=6)

        def _show_ap():
            self._left_panel_iface.pack_forget()
            self._left_panel_plugin.pack_forget()
            self._left_panel_ap.pack(fill="both", expand=True)
            _style_btn(self._btn_subtab_iface,  False)
            _style_btn(self._btn_subtab_ap,     True)
            _style_btn(self._btn_subtab_plugin, False)
            self._btn_refresh.pack_forget()

        def _show_plugin():
            self._left_panel_iface.pack_forget()
            self._left_panel_ap.pack_forget()
            self._left_panel_plugin.pack(fill="both", expand=True)
            _style_btn(self._btn_subtab_iface,  False)
            _style_btn(self._btn_subtab_ap,     False)
            _style_btn(self._btn_subtab_plugin, True)
            self._btn_refresh.pack_forget()

        self._btn_subtab_iface.bind("<Button-1>",  lambda e: _show_iface())
        self._btn_subtab_ap.bind("<Button-1>",     lambda e: _show_ap())
        self._btn_subtab_plugin.bind("<Button-1>", lambda e: _show_plugin())

        for btn, show_fn in [(self._btn_subtab_iface,  _show_iface),
                              (self._btn_subtab_ap,     _show_ap),
                              (self._btn_subtab_plugin, _show_plugin)]:
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=CLR["border"])
                     if b.cget("bg") == CLR["bg2"] else None)
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=CLR["bg2"])
                     if b.cget("bg") == CLR["border"] else None)

        # ── 각 패널 내용 빌드 ─────────────────────
        self._build_iface_panel(self._left_panel_iface)
        self._build_ap_panel(self._left_panel_ap)
        self._build_plugin_panel(self._left_panel_plugin)

        # 기본: 인터페이스 표시
        self._left_panel_iface.pack(fill="both", expand=True)

    def _build_ap_panel(self, parent):
        """AP 관리 서브패널 — AP 추가/편집/연결 확인"""
        # 헤더 + 추가 버튼
        hdr = tk.Frame(parent, bg=CLR["bg2"])
        hdr.pack(fill="x", padx=8, pady=(8,4))
        tk.Label(hdr, text="DUT AP 목록", bg=CLR["bg2"],
                 font=_font(10, bold=True), fg=CLR["text"]).pack(side="left")
        tk.Button(hdr, text="＋ AP 추가", bg=CLR["amber_bg"], fg=CLR["amber_fg"],
                  font=_font(9), relief="flat", cursor="hand2",
                  command=self._add_ap).pack(side="right")

        tk.Frame(parent, bg=CLR["border"], height=1).pack(fill="x", padx=6)

        # 스크롤 영역
        sc = tk.Frame(parent, bg=CLR["bg2"])
        sc.pack(fill="both", expand=True, padx=4, pady=4)
        ap_sb = ttk.Scrollbar(sc, orient="vertical")
        ap_sb.pack(side="right", fill="y")
        self._ap_canvas = tk.Canvas(sc, bg=CLR["bg2"],
                                    highlightthickness=0,
                                    yscrollcommand=ap_sb.set)
        self._ap_canvas.pack(side="left", fill="both", expand=True)
        ap_sb.config(command=self._ap_canvas.yview)
        self._ap_inner = tk.Frame(self._ap_canvas, bg=CLR["bg2"])
        self._ap_win   = self._ap_canvas.create_window(
            (0,0), window=self._ap_inner, anchor="nw")

        def _cfg(e): self._ap_canvas.configure(
            scrollregion=self._ap_canvas.bbox("all"))
        def _cfw(e): self._ap_canvas.itemconfig(self._ap_win, width=e.width)
        def _mw(e):  self._ap_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        self._ap_inner.bind("<Configure>", _cfg)
        self._ap_canvas.bind("<Configure>", _cfw)
        self._ap_canvas.bind("<MouseWheel>", _mw)

    def _add_ap(self):
        """AP 추가"""
        idx     = len(self._ap_list) + 1
        ap_id   = f"AP#{idx}"
        ap_data = {
            "id":       ap_id,
            "wan_mac":  "",
            "lan_mac":  "",
            "mode":     "NAT",
            "master":   "",
            "slave":    "",
            "status":   "",   # ok | fail | checking | ""
            "ip_wan":   "",
            "ip_lan":   "",
            "vendor":   "",
        }
        self._ap_list.append(ap_data)
        self._conn_status[ap_id] = ""
        self._render_ap_card(ap_data)
        self._draw_topology()
        log.info(f"{ap_id} 추가됨", source="TOPOLOGY")

    def _render_ap_card(self, ap: dict):
        """AP 카드 UI 생성"""
        ap_id = ap["id"]

        card = tk.Frame(self._ap_inner, bg=CLR["panel"],
                        highlightbackground=CLR["amber_mid"],
                        highlightthickness=1)
        card.pack(fill="x", pady=4, padx=2)

        # ── 헤더 행 ───────────────────────────────
        hdr = tk.Frame(card, bg=CLR["amber_bg"])
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"📡 {ap_id}", bg=CLR["amber_bg"],
                 fg=CLR["amber_fg"], font=_font(10, bold=True)).pack(side="left", padx=8, pady=4)

        # 상태 배지
        status_lbl = tk.Label(hdr, text="", bg=CLR["amber_bg"],
                              fg=CLR["text3"], font=_font(8))
        status_lbl.pack(side="left", padx=4)

        # 삭제 버튼
        tk.Button(hdr, text="✕", bg=CLR["amber_bg"], fg=CLR["red_fg"],
                  font=_font(9), relief="flat", cursor="hand2",
                  command=lambda: self._remove_ap(ap_id)).pack(side="right", padx=6)

        # ── 필드 ──────────────────────────────────
        body = tk.Frame(card, bg=CLR["panel"])
        body.pack(fill="x", padx=8, pady=4)

        def _field(label, key, row_idx):
            row = tk.Frame(body, bg=CLR["panel"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=CLR["panel"], fg=CLR["text3"],
                     font=_font(8), width=9, anchor="w").pack(side="left")
            v = StringVar(value=ap.get(key, ""))
            e = tk.Entry(row, textvariable=v, font=_font(8, mono=True),
                         bg=CLR["bg2"], fg=CLR["text"],
                         insertbackground=CLR["text"],
                         relief="flat", highlightbackground=CLR["border"],
                         highlightthickness=1)
            e.pack(side="left", fill="x", expand=True)
            def _save(event=None, k=key, var=v):
                ap[k] = var.get().strip()
            e.bind("<FocusOut>", _save)
            e.bind("<Return>",   _save)
            return v

        wan_mac_var = _field("WAN MAC",  "wan_mac", 0)
        lan_mac_var = _field("LAN MAC",  "lan_mac", 1)
        ip_wan_var  = _field("WAN IP",   "ip_wan",  2)
        ip_lan_var  = _field("LAN IP",   "ip_lan",  3)

        # ── 모드 선택 ──────────────────────────────
        mode_row = tk.Frame(body, bg=CLR["panel"])
        mode_row.pack(fill="x", pady=2)
        tk.Label(mode_row, text="모드", bg=CLR["panel"], fg=CLR["text3"],
                 font=_font(8), width=9, anchor="w").pack(side="left")
        mode_var = StringVar(value=ap.get("mode", "NAT"))
        for m, label in [("NAT","NAT"),("Bridge","Bridge")]:
            tk.Radiobutton(mode_row, text=label, variable=mode_var, value=m,
                           bg=CLR["panel"], fg=CLR["text"],
                           selectcolor=CLR["bg2"],
                           activebackground=CLR["panel"],
                           font=_font(8), cursor="hand2",
                           command=lambda v=mode_var: ap.update({"mode": v.get()})
                           ).pack(side="left", padx=4)

        # ── 인터페이스 연결 ────────────────────────
        conn_row = tk.Frame(body, bg=CLR["panel"])
        conn_row.pack(fill="x", pady=2)
        tk.Label(conn_row, text="Master", bg=CLR["panel"], fg=CLR["text3"],
                 font=_font(8), width=9, anchor="w").pack(side="left")

        master_var = StringVar(value=ap.get("master", ""))
        slave_var  = StringVar(value=ap.get("slave",  ""))

        def _get_iface_names():
            return ["(없음)"] + [f["name"] for f in self._ifaces]

        master_cb = ttk.Combobox(conn_row, textvariable=master_var,
                                 values=_get_iface_names(),
                                 state="readonly", width=9, font=_font(8))
        master_cb.pack(side="left", padx=2)

        tk.Label(conn_row, text="Slave", bg=CLR["panel"], fg=CLR["text3"],
                 font=_font(8)).pack(side="left", padx=(6,0))
        slave_cb = ttk.Combobox(conn_row, textvariable=slave_var,
                                values=_get_iface_names(),
                                state="readonly", width=9, font=_font(8))
        slave_cb.pack(side="left", padx=2)

        def _save_conn(*_):
            ap["master"] = master_var.get() if master_var.get() != "(없음)" else ""
            ap["slave"]  = slave_var.get()  if slave_var.get()  != "(없음)" else ""
            self._draw_topology()

        master_cb.bind("<<ComboboxSelected>>", _save_conn)
        slave_cb.bind("<<ComboboxSelected>>",  _save_conn)

        # ── ARP 확인 버튼 ──────────────────────────
        btn_row = tk.Frame(body, bg=CLR["panel"])
        btn_row.pack(fill="x", pady=(4,2))
        check_btn = tk.Button(btn_row, text="🔗 연결 확인",
                              bg=CLR["bg2"], fg=CLR["text2"],
                              font=_font(8), relief="flat", cursor="hand2",
                              command=lambda: self._check_ap_connection(ap, status_lbl, check_btn))
        check_btn.pack(side="left")

        # ── 위젯 참조 저장 ────────────────────────
        self._ap_card_widgets[ap_id] = {
            "card":       card,
            "status_lbl": status_lbl,
            "master_cb":  master_cb,
            "slave_cb":   slave_cb,
            "master_var": master_var,
            "slave_var":  slave_var,
            "mode_var":   mode_var,
        }

    def _remove_ap(self, ap_id: str):
        """AP 제거"""
        self._ap_list = [a for a in self._ap_list if a["id"] != ap_id]
        self._conn_status.pop(ap_id, None)
        w = self._ap_card_widgets.pop(ap_id, None)
        if w:
            w["card"].destroy()
        # 남은 AP 번호 재정렬
        for i, ap in enumerate(self._ap_list, 1):
            ap["id"] = f"AP#{i}"
        self._draw_topology()
        log.info(f"{ap_id} 제거됨", source="TOPOLOGY")

    def _check_ap_connection(self, ap: dict, status_lbl, check_btn):
        """
        AP 연결 확인
        - WAN/LAN MAC 입력됨 → 해당 MAC ARP Check (지정 인터페이스에서)
        - MAC 없음 → 자동 감지 (ARP 스캔)
        """
        ap_id   = ap["id"]
        wan_mac = ap.get("wan_mac", "").strip()
        lan_mac = ap.get("lan_mac", "").strip()
        master  = ap.get("master", "")
        slave   = ap.get("slave",  "")

        if not master and not slave:
            messagebox.showwarning("설정 오류",
                f"{ap_id}: Master 또는 Slave 인터페이스를 연결하세요.",
                parent=self)
            return

        check_btn.config(state="disabled", text="확인 중...")
        self._conn_status[ap_id] = "checking"
        status_lbl.config(text="확인 중...", fg=CLR["amber_fg"])
        self._draw_topology()

        def _run():
            try:
                from scapy.all import ARP, Ether, srp
            except ImportError:
                self.after(0, lambda: _done("fail", "Scapy 미설치"))
                return

            result_ok  = False
            result_msg = ""
            found_wan  = ""
            found_lan  = ""

            def arp_check_mac(iface_name: str, target_mac: str) -> tuple[bool, str]:
                """특정 MAC이 인터페이스에서 ARP 응답하는지 확인 → (ok, ip)"""
                scapy_if = _resolve_scapy_iface(iface_name)
                iface_info = next((f for f in self._ifaces if f["name"]==iface_name), None)
                my_ip = self._custom_ip.get(iface_name,
                        iface_info["ip"] if iface_info else "")
                if not my_ip or my_ip in ("—",""):
                    return False, ""
                base = ".".join(my_ip.split(".")[:3]) + ".0/24"
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=base)
                    ans, _ = srp(pkt, iface=scapy_if, timeout=3, verbose=False)
                    for _, rcv in ans:
                        if rcv.hwsrc.upper() == target_mac.upper():
                            return True, rcv.psrc
                except Exception:
                    pass
                return False, ""

            def arp_scan_find(iface_name: str) -> dict[str, str]:
                """인터페이스 /24 ARP 스캔 → {IP:MAC}"""
                scapy_if = _resolve_scapy_iface(iface_name)
                iface_info = next((f for f in self._ifaces if f["name"]==iface_name), None)
                my_ip = self._custom_ip.get(iface_name,
                        iface_info["ip"] if iface_info else "")
                if not my_ip or my_ip in ("—",""):
                    return {}
                base = ".".join(my_ip.split(".")[:3]) + ".0/24"
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=base)
                    ans, _ = srp(pkt, iface=_resolve_scapy_iface(iface_name),
                                 timeout=3, verbose=False)
                    return {r[1].psrc: r[1].hwsrc for r in ans}
                except Exception:
                    return {}

            has_mac = bool(wan_mac or lan_mac)

            if has_mac:
                # ── MAC 지정 모드: ARP Check ──────────
                self.after(0, lambda: self._mini_log_add("info",
                    f"[{ap_id}] MAC 지정 ARP Check 시작"))

                if wan_mac and master:
                    ok, ip = arp_check_mac(master, wan_mac)
                    if ok:
                        found_wan = ip
                        ap["ip_wan"] = ip
                        self.after(0, lambda i=ip: self._mini_log_add("ok",
                            f"[{ap_id}] WAN MAC 확인 ✓ ({wan_mac} → {i})"))
                    else:
                        self.after(0, lambda: self._mini_log_add("err",
                            f"[{ap_id}] WAN MAC 응답 없음 ({wan_mac})"))

                if lan_mac and slave:
                    ok, ip = arp_check_mac(slave, lan_mac)
                    if ok:
                        found_lan = ip
                        ap["ip_lan"] = ip
                        self.after(0, lambda i=ip: self._mini_log_add("ok",
                            f"[{ap_id}] LAN MAC 확인 ✓ ({lan_mac} → {i})"))
                    else:
                        self.after(0, lambda: self._mini_log_add("err",
                            f"[{ap_id}] LAN MAC 응답 없음 ({lan_mac})"))

                # WAN 또는 LAN 중 하나라도 확인되면 OK
                result_ok  = bool(found_wan or found_lan)
                result_msg = (f"WAN:{found_wan or '?'} LAN:{found_lan or '?'}"
                              if result_ok else "MAC ARP 응답 없음")

            else:
                # ── 자동 감지 모드: ARP 스캔 후 미지 MAC 탐색 ──
                self.after(0, lambda: self._mini_log_add("info",
                    f"[{ap_id}] 자동 감지 모드 — ARP 스캔 시작"))

                m_arp = arp_scan_find(master) if master else {}
                s_arp = arp_scan_find(slave)  if slave  else {}

                # 자신의 MAC 제외
                try:
                    from scapy.arch import get_if_hwaddr
                    my_macs = set()
                    for n in (master, slave):
                        if n:
                            try:
                                my_macs.add(get_if_hwaddr(
                                    _resolve_scapy_iface(n)).upper())
                            except Exception:
                                pass
                    m_macs = {m for m in m_arp.values() if m.upper() not in my_macs}
                    s_macs = {m for m in s_arp.values() if m.upper() not in my_macs}
                except Exception:
                    m_macs = set(m_arp.values())
                    s_macs = set(s_arp.values())

                common = m_macs & s_macs
                if common:
                    mac = common.pop()
                    ip  = next((i for i,m in m_arp.items() if m==mac), "")
                    ap["wan_mac"] = ap["lan_mac"] = mac
                    ap["ip_wan"]  = ap["ip_lan"]  = ip
                    ap["mode"]    = "Bridge"
                    result_ok  = True
                    result_msg = f"Bridge: {mac} ({ip})"
                    self.after(0, lambda: self._mini_log_add("ok",
                        f"[{ap_id}] Bridge AP 자동 감지: {mac}"))
                elif m_macs and s_macs:
                    w_mac = m_macs.pop()
                    l_mac = s_macs.pop()
                    w_ip  = next((i for i,m in m_arp.items() if m==w_mac), "")
                    l_ip  = next((i for i,m in s_arp.items() if m==l_mac), "")
                    ap["wan_mac"] = w_mac; ap["lan_mac"] = l_mac
                    ap["ip_wan"]  = w_ip;  ap["ip_lan"]  = l_ip
                    ap["mode"]    = "NAT"
                    result_ok  = True
                    result_msg = f"NAT WAN:{w_ip} LAN:{l_ip}"
                    self.after(0, lambda: self._mini_log_add("ok",
                        f"[{ap_id}] NAT AP 자동 감지: WAN={w_mac} LAN={l_mac}"))
                else:
                    result_ok  = False
                    result_msg = "AP 미감지"
                    self.after(0, lambda: self._mini_log_add("err",
                        f"[{ap_id}] 자동 감지 실패"))

            self.after(0, lambda: _done(
                "ok" if result_ok else "fail", result_msg))

        def _done(status: str, msg: str):
            self._conn_status[ap_id] = status
            check_btn.config(state="normal", text="🔗 연결 확인")
            if status == "ok":
                status_lbl.config(text=f"✓ {msg[:20]}", fg=CLR["green_fg"])
                # 카드 위젯 업데이트 (자동감지로 MAC/IP 채워졌을 수 있음)
                self._refresh_ap_card_values(ap_id, ap)
            else:
                status_lbl.config(text=f"✗ {msg[:20]}", fg=CLR["red_fg"])
            self._draw_topology()
            log.info(f"{ap_id} 연결확인: {status} / {msg}", source="TOPOLOGY")

        threading.Thread(target=_run, daemon=True).start()

    def _refresh_ap_card_values(self, ap_id: str, ap: dict):
        """자동 감지 후 카드 필드값 갱신 — 재렌더링 없이 Entry 직접 업데이트"""
        # AP inner frame의 Entry 위젯을 순서대로 찾아서 업데이트
        try:
            card = self._ap_card_widgets[ap_id]["card"]
            # 카드를 재생성하는 것이 가장 안전
            card.destroy()
            del self._ap_card_widgets[ap_id]
            self._render_ap_card(ap)
        except Exception:
            pass

    def _build_iface_panel(self, parent):
        """인터페이스 서브패널 — 스크롤 가능한 카드 목록"""
        scroll_container = tk.Frame(parent, bg=CLR["bg2"])
        scroll_container.pack(fill="both", expand=True, padx=4, pady=4)

        iface_sb = ttk.Scrollbar(scroll_container, orient="vertical")
        iface_sb.pack(side="right", fill="y")

        self._iface_canvas = tk.Canvas(
            scroll_container, bg=CLR["bg2"],
            highlightthickness=0, yscrollcommand=iface_sb.set
        )
        self._iface_canvas.pack(side="left", fill="both", expand=True)
        iface_sb.config(command=self._iface_canvas.yview)

        self._iface_frame = tk.Frame(self._iface_canvas, bg=CLR["bg2"])
        self._iface_canvas_win = self._iface_canvas.create_window(
            (0, 0), window=self._iface_frame, anchor="nw"
        )

        def _on_frame_configure(e):
            self._iface_canvas.configure(
                scrollregion=self._iface_canvas.bbox("all"))
        def _on_canvas_configure(e):
            self._iface_canvas.itemconfig(
                self._iface_canvas_win, width=e.width)
        def _on_mousewheel(e):
            self._iface_canvas.yview_scroll(int(-1*(e.delta/120)), "units")

        self._iface_frame.bind("<Configure>",   _on_frame_configure)
        self._iface_canvas.bind("<Configure>",  _on_canvas_configure)
        self._iface_canvas.bind("<MouseWheel>", _on_mousewheel)
        self._iface_frame.bind("<MouseWheel>",  _on_mousewheel)

    def _build_plugin_panel(self, parent):
        """플러그인 서브패널 — 활성화 체크박스 + 활성화 시 파라미터 표시"""
        self._plugin_en_vars:    dict[str, BooleanVar] = {}
        self._plugin_param_body: dict[str, tk.Frame]   = {}

        icon_map = {"DHCP":"■","NAT":"⇄","IGMP":"◉","Packet S/D":"≈"}
        bg_map   = {"DHCP":CLR["blue_bg"],"NAT":CLR["green_bg"],
                    "IGMP":CLR["amber_bg"],"Packet S/D":CLR["gray_bg"]}
        fg_map   = {"DHCP":CLR["blue_fg"],"NAT":CLR["green_fg"],
                    "IGMP":CLR["amber_fg"],"Packet S/D":CLR["gray_fg"]}

        # 스크롤 래퍼
        sc = tk.Frame(parent, bg=CLR["bg2"])
        sc.pack(fill="both", expand=True, padx=4, pady=4)

        pl_sb = ttk.Scrollbar(sc, orient="vertical")
        pl_sb.pack(side="right", fill="y")

        pl_cv = tk.Canvas(sc, bg=CLR["bg2"],
                          highlightthickness=0, yscrollcommand=pl_sb.set)
        pl_cv.pack(side="left", fill="both", expand=True)
        pl_sb.config(command=pl_cv.yview)

        inner = tk.Frame(pl_cv, bg=CLR["bg2"])
        pw = pl_cv.create_window((0, 0), window=inner, anchor="nw")

        def _cfg(e): pl_cv.configure(scrollregion=pl_cv.bbox("all"))
        def _cfw(e): pl_cv.itemconfig(pw, width=e.width)
        def _mw(e):  pl_cv.yview_scroll(int(-1*(e.delta/120)), "units")
        inner.bind("<Configure>",  _cfg)
        pl_cv.bind("<Configure>",  _cfw)
        pl_cv.bind("<MouseWheel>", _mw)
        inner.bind("<MouseWheel>", _mw)

        for name, plugin in PLUGIN_REGISTRY.items():
            params = plugin.get_params()

            # ── 플러그인 헤더 행 ─────────────────────
            card = tk.Frame(inner, bg=CLR["panel"],
                            highlightbackground=CLR["border"], highlightthickness=1)
            card.pack(fill="x", pady=3, padx=2)

            icon_f = tk.Frame(card, bg=bg_map.get(name, CLR["gray_bg"]),
                              width=26, height=26)
            icon_f.pack_propagate(False)
            icon_f.pack(side="left", padx=5, pady=5)
            tk.Label(icon_f, text=icon_map.get(name, "•"),
                     bg=bg_map.get(name, CLR["gray_bg"]),
                     fg=fg_map.get(name, CLR["gray_fg"]),
                     font=_font(11, bold=True)).pack(expand=True)

            tk.Label(card, text=name, bg=CLR["panel"],
                     font=_font(10, bold=True), fg=CLR["text"]).pack(
                     side="left", padx=4)

            en_var = BooleanVar(value=False)
            self._plugin_en_vars[name] = en_var

            # ── 파라미터 바디 (기본: 숨김) ───────────
            body = tk.Frame(inner, bg=CLR["bg2"])
            self._plugin_param_body[name] = body

            if params:
                vars_: dict[str, StringVar] = {}
                for p in params:
                    row = tk.Frame(body, bg=CLR["bg2"])
                    row.pack(fill="x", padx=6, pady=1)
                    tk.Label(row, text=p.label, bg=CLR["bg2"],
                             fg=CLR["text3"], font=_font(8),
                             anchor="w", width=11).pack(side="left")
                    v = StringVar(value=str(plugin.get_param(p.key)))
                    vars_[p.key] = v
                    if p.type == "choice":
                        w = ttk.Combobox(row, textvariable=v, values=p.choices,
                                         state="readonly", width=10, font=_font(8))
                    else:
                        w = ttk.Entry(row, textvariable=v, width=12, font=_font(8))
                    w.pack(side="left", padx=2)
                    w.bind("<MouseWheel>", _mw)

                def _apply(n=name, pl=plugin, vs=vars_, ps=params):
                    for k, sv in vs.items():
                        pd = next((x for x in ps if x.key == k), None)
                        raw = sv.get()
                        try:
                            if pd and pd.type == "int":   raw = int(raw)
                            if pd and pd.type == "float": raw = float(raw)
                        except Exception:
                            pass
                        pl.set_param(k, raw)
                    log.info(f"{n} 파라미터 적용", source="PLUGIN")

                btn_row = tk.Frame(body, bg=CLR["bg2"])
                btn_row.pack(fill="x", padx=6, pady=(2, 4))
                tk.Button(btn_row, text="적용", bg=CLR["blue_bg"],
                          fg=CLR["blue_fg"], font=_font(8),
                          relief="flat", cursor="hand2",
                          command=_apply).pack(side="right")

                tk.Frame(inner, bg=CLR["border"], height=1).pack(
                    fill="x", padx=4, pady=1)

            # ── 체크박스 — 활성화 시 파라미터 표시 ──
            def _on_toggle(n=name, v=en_var, b=body, pl=plugin):
                enabled = v.get()
                pl.enabled = enabled
                if enabled and self._plugin_param_body[n].winfo_children():
                    self._plugin_param_body[n].pack(fill="x", after=
                        [c for c in inner.winfo_children()
                         if isinstance(c, tk.Frame) and
                         any(isinstance(w, tk.Frame) and
                             any(isinstance(ww, tk.Label) and
                                 ww.cget("text") == n
                                 for ww in w.winfo_children())
                             for w in c.winfo_children())][-1]
                        if False else None)
                    b.pack(fill="x")
                else:
                    b.pack_forget()
                log.info(f"플러그인 {'활성화' if enabled else '비활성화'}: {n}",
                         source="PLUGIN")

            cb = tk.Checkbutton(card, text="활성화", variable=en_var,
                                bg=CLR["panel"], fg=CLR["text2"],
                                activebackground=CLR["panel"],
                                selectcolor=CLR["bg2"],
                                font=_font(8), cursor="hand2",
                                command=lambda n=name, v=en_var, b=body, pl=plugin:
                                    self._toggle_plugin(n, v, b, pl, inner))
            cb.pack(side="right", padx=6)

    def _toggle_plugin(self, name: str, var: BooleanVar,
                       body: tk.Frame, plugin, container: tk.Frame):
        """플러그인 활성화 토글 — 파라미터 표시/숨김"""
        enabled = var.get()
        plugin.enabled = enabled
        if enabled:
            # 해당 card 바로 다음에 body 삽입
            children = list(container.winfo_children())
            card_idx = next(
                (i for i, w in enumerate(children)
                 if isinstance(w, tk.Frame) and w.winfo_class() == "Frame"
                 and any(isinstance(c, tk.Label) and c.cget("text") == name
                         for c in w.winfo_children())),
                None
            )
            body.pack(fill="x")
            if card_idx is not None and card_idx + 1 < len(children):
                body.lift(children[card_idx])
        else:
            body.pack_forget()
        log.info(f"플러그인 {'활성화' if enabled else '비활성화'}: {name}",
                 source="PLUGIN")

    def _build_mid(self, parent):
        pass   # _build_left 서브탭으로 통합

    def _build_plugin_list(self):
        pass   # _build_plugin_panel 로 통합

    def _build_right(self, parent):
        # 툴바
        tb = tk.Frame(parent, bg=CLR["panel"],
                      highlightbackground=CLR["border"], highlightthickness=1)
        tb.pack(fill="x")
        self._build_toolbar(tb)

        # 캔버스
        cv_frame = tk.Frame(parent, bg=CLR["bg"])
        cv_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.canvas = tk.Canvas(cv_frame, bg=CLR["panel"], relief="flat",
                                highlightbackground=CLR["border"], highlightthickness=1)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>",      lambda e: self._draw_topology())
        # 노드 드래그 이동
        self.canvas.bind("<ButtonPress-1>",  self._on_canvas_press)
        self.canvas.bind("<B1-Motion>",      self._on_canvas_drag)
        self.canvas.bind("<ButtonRelease-1>",self._on_canvas_release)
        # 연결 드래그 (우클릭 or Ctrl+클릭)
        self.canvas.bind("<ButtonPress-3>",  self._on_connect_press)
        self.canvas.bind("<B3-Motion>",      self._on_connect_drag)
        self.canvas.bind("<ButtonRelease-3>",self._on_connect_release)

        # 미니 로그
        log_frame = tk.Frame(parent, bg=CLR["bg2"],
                             highlightbackground=CLR["border"], highlightthickness=1)
        log_frame.pack(fill="x", padx=10, pady=(0,10))
        tk.Label(log_frame, text="이벤트 로그", bg=CLR["bg2"],
                 font=_font(9), fg=CLR["text3"]).pack(anchor="w", padx=8, pady=(4,0))
        self._mini_log = Text(log_frame, height=4, bg=CLR["bg2"], fg=CLR["text2"],
                              font=_font(9, mono=True), relief="flat",
                              state="disabled", wrap="word")
        self._mini_log.pack(fill="x", padx=6, pady=(2,6))
        self._mini_log.tag_config("ok",  foreground=CLR["green_fg"])
        self._mini_log.tag_config("err", foreground=CLR["red_fg"])
        self._mini_log.tag_config("info",foreground=CLR["blue_fg"])

    def _build_toolbar(self, parent):
        btn_cfg = dict(font=_font(10), relief="flat", cursor="hand2", padx=10, pady=4)
        self._btn_start = tk.Button(parent, text="▶ 테스트 시작",
                                    bg=CLR["blue_mid"], fg="white",
                                    command=self._start_test, **btn_cfg)
        self._btn_start.pack(side="left", padx=(8,4), pady=6)

        self._btn_stop = tk.Button(parent, text="■ 중지",
                                   bg=CLR["panel"], fg=CLR["text2"],
                                   highlightbackground=CLR["border"], highlightthickness=1,
                                   command=self._stop_test, **btn_cfg)
        self._btn_stop.pack(side="left", padx=4, pady=6)

        self._btn_conn = tk.Button(parent, text="연결상태 확인",
                                   bg=CLR["panel"], fg=CLR["text2"],
                                   highlightbackground=CLR["border"], highlightthickness=1,
                                   command=self._check_connectivity, **btn_cfg)
        self._btn_conn.pack(side="left", padx=4, pady=6)

        self._btn_ap = tk.Button(parent, text="AP 자동감지",
                                 bg=CLR["amber_bg"], fg=CLR["amber_fg"],
                                 highlightbackground=CLR["amber_mid"], highlightthickness=1,
                                 command=self._detect_ap, **btn_cfg)
        self._btn_ap.pack(side="left", padx=4, pady=6)

        tk.Button(parent, text="배치 초기화",
                  bg=CLR["panel"], fg=CLR["text3"],
                  highlightbackground=CLR["border"], highlightthickness=1,
                  command=self._reset_layout, **btn_cfg).pack(side="left", padx=4, pady=6)

        # 통계 배지
        self._lbl_ok   = tk.Label(parent, text="OK: 0",   bg=CLR["green_bg"],
                                   fg=CLR["green_fg"], font=_font(10), padx=8, pady=3)
        self._lbl_warn = tk.Label(parent, text="지연: 0", bg=CLR["amber_bg"],
                                   fg=CLR["amber_fg"], font=_font(10), padx=8, pady=3)
        self._lbl_err  = tk.Label(parent, text="실패: 0", bg=CLR["red_bg"],
                                   fg=CLR["red_fg"],  font=_font(10), padx=8, pady=3)
        for lbl in (self._lbl_err, self._lbl_warn, self._lbl_ok):
            lbl.pack(side="right", padx=4, pady=6)

    # ── 인터페이스 갱신 ────────────────────────

    def _refresh_interfaces(self):
        for w in self._iface_frame.winfo_children():
            w.destroy()
        self._ifaces = _get_interfaces()
        for iface in self._ifaces:
            if iface["name"] not in self._roles:
                self._roles[iface["name"]] = "none"
            if iface["name"] not in self._ip_mode:
                self._ip_mode[iface["name"]] = "dynamic"
            self._build_iface_card(iface)
        self._draw_topology()

    def _build_iface_card(self, iface: dict):
        name = iface["name"]
        role = self._roles.get(name, "none")
        card = tk.Frame(self._iface_frame, bg=CLR["panel"],
                        highlightbackground=CLR["blue_mid"] if role=="master" else
                                           (CLR["green_mid"] if role=="slave" else CLR["border"]),
                        highlightthickness=1)
        card.pack(fill="x", pady=3, padx=4)

        def _bind_scroll(widget):
            widget.bind("<MouseWheel>",
                        lambda e: self._iface_canvas.yview_scroll(
                            int(-1*(e.delta/120)), "units"))
            for child in widget.winfo_children():
                _bind_scroll(child)

        # 헤더
        h = tk.Frame(card, bg=CLR["panel"])
        h.pack(fill="x", padx=8, pady=(6,2))
        tk.Label(h, text=name, bg=CLR["panel"],
                 font=_font(11, bold=True), fg=CLR["text"]).pack(side="left")
        status_dot = "●" if iface["up"] else "○"
        status_col = CLR["green_fg"] if iface["up"] else CLR["text3"]
        tk.Label(h, text=status_dot, bg=CLR["panel"],
                 fg=status_col, font=_font(10)).pack(side="right")

        tk.Label(card, text=iface["ip"], bg=CLR["panel"],
                 font=_font(9, mono=True), fg=CLR["text3"]).pack(anchor="w", padx=8)

        # 역할 배지
        badge_text = {"master":"Master","slave":"Slave","none":"미지정"}
        badge_bg   = {"master":CLR["blue_bg"],"slave":CLR["green_bg"],"none":CLR["gray_bg"]}
        badge_fg   = {"master":CLR["blue_fg"],"slave":CLR["green_fg"],"none":CLR["gray_fg"]}
        tk.Label(card, text=badge_text[role],
                 bg=badge_bg[role], fg=badge_fg[role],
                 font=_font(9, bold=True), padx=6, pady=1).pack(anchor="w", padx=8, pady=2)

        # 역할 선택 버튼
        btn_row = tk.Frame(card, bg=CLR["panel"])
        btn_row.pack(fill="x", padx=6, pady=(2,4))
        for r_key, r_label in [("master","Master"),("slave","Slave"),("none","—")]:
            is_active = role == r_key
            ab = {"master": CLR["blue_bg"],"slave": CLR["green_bg"],"none": CLR["bg2"]}
            af = {"master": CLR["blue_fg"],"slave": CLR["green_fg"],"none": CLR["text3"]}
            btn = tk.Button(btn_row, text=r_label,
                            bg=ab[r_key] if is_active else CLR["bg2"],
                            fg=af[r_key] if is_active else CLR["text3"],
                            font=_font(9), relief="flat", padx=6, pady=2,
                            cursor="hand2",
                            command=lambda n=name, rk=r_key: self._set_role(n, rk))
            btn.pack(side="left", padx=2)

        # IP 설정 버튼만 유지 (가상 MAC 버튼 제거)
        btn_row2 = tk.Frame(card, bg=CLR["panel"])
        btn_row2.pack(fill="x", padx=6, pady=(0,6))
        tk.Button(btn_row2, text="IP 설정", font=_font(9), relief="flat",
                  bg=CLR["bg2"], fg=CLR["text2"], cursor="hand2",
                  command=lambda n=name: self._open_ip_dialog(n)).pack(
                  side="left", padx=2)

        # 카드 내 모든 위젯에 스크롤 전파
        self.after(50, lambda: _bind_scroll(card))

    def _set_role(self, name: str, role: str):
        self._roles[name] = role
        log.info(f"인터페이스 역할 변경: {name} → {role}", source="TOPOLOGY")
        self._refresh_interfaces()

    def _open_ip_dialog(self, name: str):
        """
        IP 설정 다이얼로그
        - 고정: IP / Subnet / Gateway / DNS1 / DNS2 → netsh 실행
        - 동적: DHCP 자동 설정 → netsh 실행
        """
        # 현재 저장된 설정 불러오기
        saved = self._ip_settings.get(name, {})
        iface_info = next((f for f in self._ifaces if f["name"] == name), None)
        cur_ip = self._custom_ip.get(name,
                 iface_info["ip"] if iface_info else "")

        dlg = Toplevel(self)
        dlg.title(f"IP 설정 — {name}")
        dlg.geometry("320x380")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg=CLR["bg"])

        # ── 헤더 ─────────────────────────────────
        hdr = tk.Frame(dlg, bg=CLR["bg2"],
                       highlightbackground=CLR["border"], highlightthickness=1)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"IP 설정 — {name}",
                 bg=CLR["bg2"], fg="white",
                 font=("Segoe UI", 11, "bold")).pack(side="left", padx=14, pady=10)

        # ── 모드 선택 ─────────────────────────────
        mode_var = StringVar(value=saved.get("mode",
                   self._ip_mode.get(name, "dynamic")))

        mode_f = tk.Frame(dlg, bg=CLR["bg"])
        mode_f.pack(fill="x", padx=14, pady=(12,6))
        tk.Label(mode_f, text="IP 모드", bg=CLR["bg"],
                 fg="white", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0,4))

        rb_row = tk.Frame(mode_f, bg=CLR["bg"])
        rb_row.pack(fill="x")
        for val, label in [("static","고정 (Static)"), ("dynamic","동적 (DHCP)")]:
            tk.Radiobutton(
                rb_row, text=label, variable=mode_var, value=val,
                bg=CLR["bg"], fg="white",
                selectcolor=CLR["bg2"],
                activebackground=CLR["bg"],
                activeforeground=CLR["blue_fg"],
                font=("Segoe UI", 10), cursor="hand2",
                command=lambda: _toggle_fields()
            ).pack(side="left", padx=10)

        tk.Frame(dlg, bg=CLR["border"], height=1).pack(fill="x", padx=14, pady=4)

        # ── 입력 필드 ─────────────────────────────
        fields_f = tk.Frame(dlg, bg=CLR["bg"])
        fields_f.pack(fill="x", padx=14)

        field_vars = {}
        field_entries = {}
        field_defs = [
            ("ip",      "IP 주소",       saved.get("ip",      cur_ip)),
            ("mask",    "서브넷 마스크",  saved.get("mask",    "255.255.255.0")),
            ("gw",      "게이트웨이",     saved.get("gw",      "")),
            ("dns1",    "DNS 1차",        saved.get("dns1",    "8.8.8.8")),
            ("dns2",    "DNS 2차",        saved.get("dns2",    "8.8.4.4")),
        ]
        for key, label, default in field_defs:
            row = tk.Frame(fields_f, bg=CLR["bg"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=CLR["bg"], fg="white",
                     font=("Segoe UI", 9), width=12, anchor="w").pack(side="left")
            v = StringVar(value=default)
            field_vars[key] = v
            e = tk.Entry(row, textvariable=v, font=("Consolas", 9),
                         bg=CLR["panel"], fg="white",
                         insertbackground="white",
                         relief="flat", highlightbackground=CLR["border"],
                         highlightthickness=1)
            e.pack(side="left", fill="x", expand=True)
            field_entries[key] = e

        def _toggle_fields():
            """고정 모드: 모든 필드 활성 / 동적 모드: 비활성"""
            is_static = mode_var.get() == "static"
            state = "normal" if is_static else "disabled"
            fg_color = "white" if is_static else CLR["text3"]
            for e in field_entries.values():
                e.config(state=state, fg=fg_color)

        _toggle_fields()

        # ── 적용 / 취소 버튼 ──────────────────────
        tk.Frame(dlg, bg=CLR["border"], height=1).pack(fill="x", padx=14, pady=8)

        btn_f = tk.Frame(dlg, bg=CLR["bg"])
        btn_f.pack(fill="x", padx=14, pady=(0,12))

        # 상태 레이블 — Segoe UI로 한글 정상 표시
        status_var = StringVar(value="")
        self._ip_dlg_status = tk.Label(btn_f, textvariable=status_var,
                                        bg=CLR["bg"], fg=CLR["amber_fg"],
                                        font=("Segoe UI", 9))
        self._ip_dlg_status.pack(fill="x", pady=(0,6))

        def _apply():
            mode = mode_var.get()
            ip   = field_vars["ip"].get().strip()
            mask = field_vars["mask"].get().strip()
            gw   = field_vars["gw"].get().strip()
            dns1 = field_vars["dns1"].get().strip()
            dns2 = field_vars["dns2"].get().strip()

            # 설정 저장
            self._ip_mode[name] = mode
            self._ip_settings[name] = {
                "mode": mode, "ip": ip, "mask": mask,
                "gw": gw, "dns1": dns1, "dns2": dns2,
            }
            if mode == "static" and ip:
                self._custom_ip[name] = ip

            # 실제 인터페이스 적용 (관리자 권한 필요)
            status_var.set("적용 중...")
            self._ip_dlg_status.config(fg=CLR["amber_fg"])
            dlg.update()

            def _do_apply():
                result = _apply_ip_to_iface(name, mode, ip, mask, gw, dns1, dns2)
                def _done():
                    if result["ok"]:
                        status_var.set("✓ 적용 완료")
                        self._ip_dlg_status.config(fg=CLR["green_fg"])
                        log.info(
                            f"{name} IP 적용: {mode} / {ip}", source="TOPOLOGY")
                        self._draw_topology()
                        self.after(800, dlg.destroy)
                    else:
                        # 오류 메시지 — 한글 깨짐 방지: ASCII 범위만 표시
                        err = result['error']
                        try:
                            err_safe = err.encode('utf-8').decode('utf-8')
                        except Exception:
                            err_safe = "적용 실패 (관리자 권한 확인)"
                        status_var.set(f"✗ {err_safe[:38]}")
                        self._ip_dlg_status.config(fg=CLR["red_fg"])
                        log.error(
                            f"{name} IP 적용 실패: {result['error']}",
                            source="TOPOLOGY")
                dlg.after(0, _done)

            threading.Thread(target=_do_apply, daemon=True).start()

        tk.Button(btn_f, text="적용", bg=CLR["blue_mid"], fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2",
                  padx=20, pady=5,
                  command=_apply).pack(side="left")
        tk.Button(btn_f, text="취소", bg=CLR["bg2"], fg="white",
                  font=("Segoe UI", 10), relief="flat", cursor="hand2",
                  padx=14, pady=5,
                  command=dlg.destroy).pack(side="left", padx=8)

    # ── 토폴로지 그래픽 ────────────────────────

    def _draw_topology(self):
        cv = self.canvas
        cv.delete("all")
        w = cv.winfo_width()
        h = cv.winfo_height()
        if w < 50 or h < 50:
            return

        masters  = [n for n, r in self._roles.items() if r == "master"]
        slaves   = [n for n, r in self._roles.items() if r == "slave"]
        ap       = self._ap_info
        has_ap   = ap.get("detected", False)
        show_internet = has_ap and ap.get("show_internet", False)
        show_ap  = has_ap and not show_internet
        user_aps = self._ap_list

        node_w, node_h = 150, 90
        ap_w,   ap_h   = 160, 100

        # ── 초기 자동 배치 (위치 미설정 노드만) ────────
        self._auto_place_nodes(masters, slaves, user_aps,
                               w, h, node_w, node_h, ap_w, ap_h,
                               show_ap, show_internet)

        self._node_coords = {}

        def _trim(text, max_px, font_size=10):
            char_w = font_size * 0.68
            max_chars = int(max_px / char_w)
            return text if len(text) <= max_chars else text[:max_chars-1] + "\u2026"

        def _conn_border(name):
            conn = self._conn_status.get(name, "")
            if conn == "ok":       return CLR["green_mid"], CLR["green_fg"], "\u2713"
            if conn == "fail":     return CLR["red_mid"],   CLR["red_fg"],   "\u2717"
            if conn == "checking": return CLR["amber_mid"], CLR["amber_fg"], "\u2026"
            return None, None, None

        def draw_node(name, cx, cy, role):
            x1, y1 = cx - node_w//2, cy - node_h//2
            x2, y2 = cx + node_w//2, cy + node_h//2
            colors_role = {
                "master": (CLR["blue_bg"],  CLR["blue_mid"],  CLR["blue_fg"]),
                "slave":  (CLR["green_bg"], CLR["green_mid"], CLR["green_fg"]),
                "none":   (CLR["gray_bg"],  CLR["border2"],   CLR["gray_fg"]),
            }
            bg, border, fg = colors_role.get(role, colors_role["none"])
            cb, cfg, cbadge = _conn_border(name)
            if cb: border = cb
            cv.create_rectangle(x1, y1, x2, y2, fill=bg,
                                outline=border, width=2, tags=("node", name))
            if cbadge:
                cv.create_text(x2-6, y1+8, text=cbadge,
                               font=_font(9, bold=True), fill=cfg,
                               anchor="e", tags=("node", name))
            icon = "\U0001f5a5" if role == "master" else "\U0001f4bb"
            cv.create_text(cx, cy-22, text=icon,
                           font=("Segoe UI Emoji", 16), tags=("node", name))
            mtw = node_w - 16
            cv.create_text(cx, cy+4, text=_trim(name, mtw, 10),
                           font=_font(10, bold=True), fill=fg,
                           tags=("node", name), width=mtw)
            iface = next((f for f in self._ifaces if f["name"] == name), None)
            ip = self._custom_ip.get(name, iface["ip"] if iface else "\u2014")
            cv.create_text(cx, cy+20, text=_trim(ip, mtw, 8),
                           font=_font(8, mono=True), fill=CLR["text3"],
                           tags=("node", name), width=mtw)
            role_txt = {"master":"Master","slave":"Slave","none":"\ubbf8\uc9c0\uc815"}[role]
            cv.create_text(cx, cy+36, text=role_txt,
                           font=_font(8, bold=True), fill=fg,
                           tags=("node", name))
            # 연결 포트 힌트 (우측/좌측 원)
            cv.create_oval(x2-6, cy-6, x2+6, cy+6,
                           fill=CLR["border2"], outline="", tags=("port", name))
            cv.create_oval(x1-6, cy-6, x1+6, cy+6,
                           fill=CLR["border2"], outline="", tags=("port", name))
            self._node_coords[name] = (cx, cy)

        def draw_ap_node(cx, cy):
            x1, y1 = cx - ap_w//2, cy - ap_h//2
            x2, y2 = cx + ap_w//2, cy + ap_h//2
            mode = ap.get("mode", "")
            if mode == "NAT":
                bg, border, fg = CLR["amber_bg"], CLR["amber_mid"], CLR["amber_fg"]
            elif mode == "Bridge":
                bg, border, fg = CLR["purple_bg"], "#7F77DD", CLR["purple_fg"]
            else:
                bg, border, fg = CLR["gray_bg"], CLR["border2"], CLR["gray_fg"]
            ap_conn = self._conn_status.get("__ap__", "")
            if ap_conn == "ok":   border = CLR["green_mid"]
            if ap_conn == "fail": border = CLR["red_mid"]
            cv.create_rectangle(x1, y1, x2, y2, fill=bg, outline=border,
                                width=2, dash=(6,3), tags=("node","__ap__"))
            cv.create_rectangle(x1, y1, x1+46, y1+16,
                                fill=border, outline="", tags=("node","__ap__"))
            cv.create_text(x1+23, y1+8, text="DUT AP",
                           font=_font(8, bold=True), fill="white",
                           anchor="center", tags=("node","__ap__"))
            cv.create_text(cx, cy-24, text="\U0001f4e1",
                           font=("Segoe UI Emoji", 18), tags=("node","__ap__"))
            mode_txt = f"{mode} Mode" if mode else "\uac10\uc9c0 \uc911..."
            cv.create_text(cx, cy+4, text=mode_txt,
                           font=_font(10, bold=True), fill=fg,
                           tags=("node","__ap__"))
            wan_ip = ap.get("ip_wan",""); wan_mac = ap.get("mac_wan","")
            lan_ip = ap.get("ip_lan",""); vendor  = ap.get("vendor","")
            row = cy+20
            for txt, col in [(f"WAN: {wan_ip}" if wan_ip else "",  CLR["amber_fg"]),
                             (wan_mac[:17] if wan_mac else "",       CLR["text3"]),
                             (f"LAN: {lan_ip}" if lan_ip and mode=="NAT" else "", CLR["green_fg"]),
                             (vendor[:16] if vendor else "",         CLR["text3"])]:
                if txt:
                    cv.create_text(cx, row, text=txt, font=_font(7,mono=True),
                                   fill=col, tags=("node","__ap__"))
                    row += 11
            self._node_coords["__ap__"] = (cx, cy)

        def draw_internet_node(cx, cy):
            r = 44
            cv.create_oval(cx-r, cy-r, cx+r, cy+r,
                           fill=CLR["blue_bg"], outline=CLR["blue_mid"],
                           width=2, dash=(4,3), tags=("node","__internet__"))
            cv.create_text(cx, cy-10, text="\U0001f310",
                           font=("Segoe UI Emoji", 20),
                           tags=("node","__internet__"))
            cv.create_text(cx, cy+16, text="Internet",
                           font=_font(9, bold=True), fill=CLR["blue_fg"],
                           tags=("node","__internet__"))
            gw_ip = ap.get("ip_wan","")
            if gw_ip:
                cv.create_text(cx, cy+30, text=f"GW: {gw_ip}",
                               font=_font(7, mono=True), fill=CLR["text3"],
                               tags=("node","__internet__"))
            self._node_coords["__internet__"] = (cx, cy)

        # ── 노드 그리기 ────────────────────────────
        for name in masters:
            cx, cy = self._node_pos.get(name, (w//4, h//2))
            draw_node(name, cx, cy, "master")

        for name in slaves:
            cx, cy = self._node_pos.get(name, (w*3//4, h//2))
            draw_node(name, cx, cy, "slave")

        if show_ap:
            cx, cy = self._node_pos.get("__ap__", (w//2, h//2))
            draw_ap_node(cx, cy)

        if show_internet:
            cx, cy = self._node_pos.get("__internet__", (w*3//4, h//2))
            draw_internet_node(cx, cy)

        for uap in user_aps:
            cx, cy = self._node_pos.get(uap["id"], (w//2, h*3//4))
            self._draw_user_ap_node(cv, uap, cx, cy, ap_w, ap_h, _trim)

        # ── 연결선 ──────────────────────────────────
        def _lc(n1, n2):
            s1 = self._conn_status.get(n1,"")
            s2 = self._conn_status.get(n2,"")
            if s1=="ok" and s2=="ok":   return CLR["green_mid"], 2
            if s1=="fail" or s2=="fail": return CLR["red_mid"],  2
            if s1=="checking" or s2=="checking": return CLR["amber_mid"], 1
            return CLR["border2"], 1

        for m in masters:
            mx, my = self._node_coords.get(m, (0,0))
            if show_internet:
                ix, iy = self._node_coords.get("__internet__",(0,0))
                lc,lw = _lc(m,"__internet__")
                cv.create_line(mx+node_w//2, my, ix-44, iy,
                               fill=lc, width=lw, tags="line")
            elif show_ap:
                ax, ay = self._node_coords.get("__ap__",(0,0))
                lc,lw = _lc(m,"__ap__")
                cv.create_line(mx+node_w//2, my, ax-ap_w//2, ay,
                               fill=lc, width=lw, tags="line")
                for s in slaves:
                    sx,sy = self._node_coords.get(s,(0,0))
                    lc2,lw2 = _lc("__ap__",s)
                    cv.create_line(ax+ap_w//2, ay, sx-node_w//2, sy,
                                   fill=lc2, width=lw2, tags="line")
            else:
                for s in slaves:
                    sx,sy = self._node_coords.get(s,(0,0))
                    lc,lw = _lc(m,s)
                    cv.create_line(mx+node_w//2, my, sx-node_w//2, sy,
                                   fill=lc, width=lw, tags="line")

        if not masters and show_ap:
            ax,ay = self._node_coords.get("__ap__",(0,0))
            for s in slaves:
                sx,sy = self._node_coords.get(s,(0,0))
                lc,lw = _lc("__ap__",s)
                cv.create_line(ax+ap_w//2, ay, sx-node_w//2, sy,
                               fill=lc, width=lw, tags="line")

        # 수동 AP 연결선
        for uap in user_aps:
            uid = uap["id"]
            if uid not in self._node_coords: continue
            ux,uy = self._node_coords[uid]
            st = self._conn_status.get(uid,"")
            lc = (CLR["green_mid"] if st=="ok" else
                  CLR["red_mid"] if st=="fail" else
                  CLR["amber_mid"] if st=="checking" else CLR["border2"])
            lw = 2 if st in ("ok","fail") else 1
            for conn_key in ("master","slave"):
                peer = uap.get(conn_key,"")
                if peer and peer in self._node_coords:
                    px,py = self._node_coords[peer]
                    if conn_key == "master":
                        cv.create_line(px+node_w//2, py, ux-ap_w//2, uy,
                                       fill=lc, width=lw, tags="line")
                    else:
                        cv.create_line(ux+ap_w//2, uy, px-node_w//2, py,
                                       fill=lc, width=lw, tags="line")

        if not masters and not slaves and not user_aps and not show_ap:
            cv.create_text(w//2, h//2,
                           text="인터페이스에서 Master / Slave를 지정하세요\n"
                                "노드를 드래그하여 위치 변경 | 우클릭 드래그로 연결",
                           font=_font(10), fill=CLR["text3"], justify="center")

        # 드래그 안내 (우하단)
        cv.create_text(w-8, h-8,
                       text="좌클릭: 이동  |  우클릭 드래그: 연결",
                       font=_font(8), fill=CLR["text3"], anchor="se")

    def _auto_place_nodes(self, masters, slaves, user_aps,
                          w, h, node_w, node_h, ap_w, ap_h,
                          show_ap, show_internet):
        """위치 미설정 노드에만 자동 배치 적용"""
        # Master — 좌측
        for i, name in enumerate(masters):
            if name not in self._node_pos:
                cy = h//2 + (i - len(masters)//2) * (node_h + 40)
                self._node_pos[name] = (node_w//2 + 20, max(node_h//2+10, cy))

        # Slave — 우측
        n_sl = max(len(slaves), 1)
        for i, name in enumerate(slaves):
            if name not in self._node_pos:
                cy = h//2 + (i - (n_sl-1)/2) * (node_h + 40)
                self._node_pos[name] = (w - node_w//2 - 20, max(node_h//2+10, cy))

        # 감지된 AP — 중앙
        if show_ap and "__ap__" not in self._node_pos:
            self._node_pos["__ap__"] = (w//2, h//2)

        # Internet — 우측
        if show_internet and "__internet__" not in self._node_pos:
            self._node_pos["__internet__"] = (w*3//4, h//2)

        # 수동 AP — 하단에 균등 배치
        n_uap = len(user_aps)
        for i, uap in enumerate(user_aps):
            if uap["id"] not in self._node_pos:
                slot_w = w / (n_uap + 1)
                cx = int(slot_w * (i + 1))
                self._node_pos[uap["id"]] = (cx, h * 3 // 4)

    def _reset_layout(self):
        """노드 위치 초기화"""
        self._node_pos.clear()
        self._draw_topology()

    # ── 드래그 이동 (좌클릭) ───────────────────

    def _get_node_at(self, x: int, y: int) -> str | None:
        """좌표에 있는 노드 id 반환"""
        node_w, node_h = 150, 90
        ap_w,   ap_h   = 160, 100
        for node_id, (cx, cy) in self._node_coords.items():
            nw = ap_w if node_id.startswith("AP#") or node_id == "__ap__" else node_w
            nh = ap_h if node_id.startswith("AP#") or node_id == "__ap__" else node_h
            if (cx - nw//2 <= x <= cx + nw//2 and
                    cy - nh//2 <= y <= cy + nh//2):
                return node_id
        return None

    def _on_canvas_press(self, event):
        node_id = self._get_node_at(event.x, event.y)
        if node_id:
            self._drag_node = node_id
            cx, cy = self._node_coords[node_id]
            self._drag_offset = (event.x - cx, event.y - cy)

    def _on_canvas_drag(self, event):
        if not self._drag_node:
            return
        ox, oy = self._drag_offset
        new_cx = event.x - ox
        new_cy = event.y - oy
        self._node_pos[self._drag_node] = (new_cx, new_cy)
        self._draw_topology()

    def _on_canvas_release(self, event):
        self._drag_node = None

    # ── 연결 드래그 (우클릭) ───────────────────

    def _on_connect_press(self, event):
        node_id = self._get_node_at(event.x, event.y)
        if node_id:
            self._connect_src = node_id
            self._connect_line = None

    def _on_connect_drag(self, event):
        if not self._connect_src:
            return
        if self._connect_line:
            self.canvas.delete(self._connect_line)
        sx, sy = self._node_coords.get(self._connect_src, (event.x, event.y))
        self._connect_line = self.canvas.create_line(
            sx, sy, event.x, event.y,
            fill=CLR["blue_fg"], width=2, dash=(6,3),
            arrow="last", tags="connect_line"
        )

    def _on_connect_release(self, event):
        if self._connect_line:
            self.canvas.delete(self._connect_line)
            self._connect_line = None

        src = self._connect_src
        self._connect_src = None
        if not src:
            return

        dst = self._get_node_at(event.x, event.y)
        if not dst or dst == src:
            return

        # 연결 처리
        self._make_connection(src, dst)

    def _make_connection(self, src: str, dst: str):
        """
        노드 간 연결 생성
        인터페이스 ↔ AP : AP의 master/slave 설정
        """
        src_is_ap  = src.startswith("AP#")
        dst_is_ap  = dst.startswith("AP#")
        src_is_iface = src in [f["name"] for f in self._ifaces]
        dst_is_iface = dst in [f["name"] for f in self._ifaces]

        ap_id = src if src_is_ap else (dst if dst_is_ap else None)
        iface = dst if dst_is_iface else (src if src_is_iface else None)

        if not ap_id or not iface:
            self._mini_log_add("info", f"연결 불가: {src} ↔ {dst}")
            return

        ap = next((a for a in self._ap_list if a["id"] == ap_id), None)
        if not ap:
            return

        # Master/Slave 자동 할당
        iface_role = self._roles.get(iface, "none")
        if iface_role == "master":
            ap["master"] = iface
            conn_type = "Master"
        elif iface_role == "slave":
            ap["slave"] = iface
            conn_type = "Slave"
        else:
            # 역할 미지정이면 Master가 없으면 Master, 있으면 Slave로
            if not ap.get("master"):
                ap["master"] = iface
                conn_type = "Master"
            else:
                ap["slave"] = iface
                conn_type = "Slave"

        # 카드 UI 업데이트
        wid = self._ap_card_widgets.get(ap_id, {})
        mv = wid.get("master_var")
        sv = wid.get("slave_var")
        if mv and ap.get("master"):
            mv.set(ap["master"])
        if sv and ap.get("slave"):
            sv.set(ap["slave"])

        self._mini_log_add("ok",
            f"{ap_id} ← {iface} ({conn_type}) 연결됨")
        log.info(f"{ap_id} 연결: {iface} as {conn_type}", source="TOPOLOGY")
        self._draw_topology()

    def _draw_user_ap_node(self, cv, uap: dict, cx: int, cy: int,
                           ap_w: int, ap_h: int, _trim):
        """수동 추가 AP 노드 그리기"""
        ap_id  = uap["id"]
        mode   = uap.get("mode", "NAT")
        status = self._conn_status.get(ap_id, "")

        if mode == "NAT":
            bg, border, fg = CLR["amber_bg"], CLR["amber_mid"], CLR["amber_fg"]
        else:
            bg, border, fg = CLR["purple_bg"], "#7F77DD", CLR["purple_fg"]

        if status == "ok":       border = CLR["green_mid"]
        elif status == "fail":   border = CLR["red_mid"]
        elif status == "checking": border = CLR["amber_mid"]

        x1, y1 = cx - ap_w//2, cy - ap_h//2
        x2, y2 = cx + ap_w//2, cy + ap_h//2

        cv.create_rectangle(x1, y1, x2, y2, fill=bg, outline=border,
                            width=2, dash=(6,3), tags="node")
        cv.create_rectangle(x1, y1, x1+58, y1+16,
                            fill=border, outline="", tags="node")
        cv.create_text(x1+29, y1+8, text=f"DUT {ap_id}",
                       font=_font(8, bold=True), fill="white",
                       anchor="center", tags="node")
        cv.create_text(cx, cy-20, text="📡",
                       font=("Segoe UI Emoji", 16), tags="node")
        cv.create_text(cx, cy+2, text=f"{ap_id} ({mode})",
                       font=_font(9, bold=True), fill=fg, tags="node")

        row = cy + 18
        for label, key, color in [
            ("WAN:", "ip_wan",  CLR["amber_fg"]),
            ("",    "wan_mac", CLR["text3"]),
            ("LAN:", "ip_lan", CLR["green_fg"]),
        ]:
            val = uap.get(key, "")
            if val and (key != "ip_lan" or mode == "NAT"):
                text = f"{label} {val}" if label else val[:17]
                cv.create_text(cx, row, text=_trim(text, ap_w-10, 8),
                               font=_font(7, mono=True), fill=color, tags="node")
                row += 11

        if status == "ok":
            cv.create_text(cx, row, text="✓ 연결됨",
                           font=_font(8, bold=True), fill=CLR["green_fg"], tags="node")
        elif status == "fail":
            cv.create_text(cx, row, text="✗ 미연결",
                           font=_font(8, bold=True), fill=CLR["red_fg"], tags="node")

        self._node_coords[ap_id] = (cx, cy)

    # ── 패킷 애니메이션 ────────────────────────

    def _start_test(self):
        masters = [n for n,r in self._roles.items() if r=="master"]
        slaves  = [n for n,r in self._roles.items() if r=="slave"]
        if not masters or not slaves:
            messagebox.showwarning("설정 오류",
                "Master와 Slave 인터페이스를 각각 1개 이상 지정하세요.", parent=self)
            return
        self._running = True
        self._mini_log_add("info", f"테스트 시작 — Master:{masters[0]} → Slave:{slaves[0]}")
        log.info(f"토폴로지 테스트 시작", source="TOPOLOGY")
        self._schedule_packet()

    def _stop_test(self):
        self._running = False
        if self._pkt_job:
            self.after_cancel(self._pkt_job)
        self._mini_log_add("info",
            f"테스트 중지. OK:{self._cnt['ok']} 지연:{self._cnt['warn']} 실패:{self._cnt['err']}")

    def _schedule_packet(self):
        if not self._running:
            return
        import random
        masters = [n for n,r in self._roles.items() if r=="master"]
        slaves  = [n for n,r in self._roles.items() if r=="slave"]
        if masters and slaves:
            r = random.random()
            kind = "ok" if r > 0.2 else ("warn" if r > 0.1 else "err")
            self._cnt[kind] += 1
            self._lbl_ok.config(  text=f"● OK: {self._cnt['ok']}")
            self._lbl_warn.config(text=f"● 지연: {self._cnt['warn']}")
            self._lbl_err.config( text=f"● 실패: {self._cnt['err']}")
            self._animate_packet(masters[0], slaves[0], kind)
            if kind != "ok":
                msg = "응답 지연 감지" if kind=="warn" else "응답 없음 (FAIL)"
                self._mini_log_add("err" if kind=="err" else "info", msg)
        self._pkt_job = self.after(1200, self._schedule_packet)

    def _animate_packet(self, src_name: str, dst_name: str, kind: str):
        coords = self._node_coords
        if src_name not in coords or dst_name not in coords:
            return
        sx, sy = coords[src_name]
        dx, dy = coords[dst_name]
        sx += 75; dx -= 75   # node_w//2 = 150//2
        color = self.PKT_COLORS[kind]
        dot = self.canvas.create_oval(-6, -6, 6, 6, fill=color, outline="", tags="pkt")
        self._move_dot(dot, sx, sy, dx, dy, 0, color)

    def _move_dot(self, dot, sx, sy, dx, dy, step, color):
        total = 20
        if step > total:
            self.canvas.delete(dot)
            return
        t = step / total
        ease = t*t*(3-2*t)
        x = sx + (dx - sx) * ease
        y = sy + (dy - sy) * ease
        self.canvas.coords(dot, x-6, y-6, x+6, y+6)
        self.after(35, lambda: self._move_dot(dot, sx, sy, dx, dy, step+1, color))

    def _add_iface(self):
        messagebox.showinfo("인터페이스 추가",
            "실제 PC에서는 psutil로 자동 감지됩니다.\n시뮬레이션 모드에서는 지원하지 않습니다.", parent=self)

    # ── AP 감지 ───────────────────────────────

    def _detect_ap(self):
        """
        AP 감지 — Master/Slave 지정 여부에 따라 3가지 동작

        [Master + Slave 동시]
          양쪽 ARP 스캔 → MAC 비교
          공통 MAC → Bridge Mode AP
          다른 MAC → NAT Mode AP

        [Master만]
          자신의 GW를 ARP로 확인
          GW IP가 공인 IP → Internet망 표시
          GW IP가 사설 IP → AP(NAT) 표시

        [Slave만]
          자신의 GW를 ARP로 확인
          GW IP가 사설 IP → AP(NAT Mode) 표시
          GW IP가 공인 IP → AP(Bridge Mode) 표시
        """
        masters = [n for n, r in self._roles.items() if r == "master"]
        slaves  = [n for n, r in self._roles.items() if r == "slave"]

        if not masters and not slaves:
            messagebox.showwarning("설정 오류",
                "인터페이스에서 Master 또는 Slave를 하나 이상 지정하세요.",
                parent=self)
            return

        self._btn_ap.config(state="disabled", text="감지 중…")
        self._ap_info = {"detected": False}
        self._conn_status["__ap__"]      = "checking"
        self._conn_status["__internet__"] = ""
        self._draw_topology()
        self._mini_log_add("info", "AP 감지 시작 — GW ARP 스캔 중...")
        log.info("AP 감지 시작", source="TOPOLOGY")

        def _run():
            try:
                from scapy.all import ARP, Ether, srp
                from scapy.arch import get_if_hwaddr
            except ImportError:
                self.after(0, lambda: self._ap_detect_done(
                    False, error="Scapy 미설치"))
                return

            # ── 공통 유틸 ─────────────────────────────

            def arp_scan(iface_scapy: str, subnet: str) -> dict[str, str]:
                """/24 서브넷 ARP 스캔 → {IP: MAC}"""
                if not subnet or subnet in ("—", ""):
                    return {}
                base = ".".join(subnet.split(".")[:3]) + ".0/24"
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=base)
                    ans, _ = srp(pkt, iface=iface_scapy,
                                 timeout=3, verbose=False)
                    return {r[1].psrc: r[1].hwsrc for r in ans}
                except Exception as e:
                    log.warn(f"ARP 스캔 오류 ({iface_scapy}): {e}",
                             source="TOPOLOGY")
                    return {}

            def arp_single(iface_scapy: str, target_ip: str) -> str:
                """단일 IP ARP 조회 → MAC 반환 (없으면 '')"""
                if not target_ip or target_ip in ("—", ""):
                    return ""
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
                    ans, _ = srp(pkt, iface=iface_scapy,
                                 timeout=3, verbose=False)
                    if ans:
                        return ans[0][1].hwsrc
                except Exception:
                    pass
                return ""

            def get_gw(iface_name: str) -> str:
                """인터페이스의 기본 게이트웨이 IP 조회"""
                try:
                    import subprocess
                    # Windows: route print로 GW 조회
                    out = subprocess.check_output(
                        ["route", "print", "0.0.0.0"],
                        timeout=5
                    ).decode(errors="ignore")
                    # 인터페이스 IP와 같은 서브넷의 GW 찾기
                    iface_info = next(
                        (f for f in self._ifaces if f["name"] == iface_name), None)
                    my_ip = self._custom_ip.get(
                        iface_name, iface_info["ip"] if iface_info else "")
                    if not my_ip or my_ip in ("—", ""):
                        return ""
                    my_prefix = ".".join(my_ip.split(".")[:3])
                    for line in out.splitlines():
                        parts = line.split()
                        # route print 형식: 0.0.0.0  0.0.0.0  GW  인터페이스IP  메트릭
                        if len(parts) >= 4 and parts[0] == "0.0.0.0":
                            gw = parts[2]
                            if gw.startswith(my_prefix):
                                return gw
                    # fallback: 같은 서브넷 내 .1 또는 .254
                    for suffix in ("1", "254"):
                        candidate = f"{my_prefix}.{suffix}"
                        if candidate != my_ip:
                            return candidate
                except Exception:
                    pass
                return ""

            ap_info: dict = {"detected": False}

            # ══════════════════════════════════════════
            # CASE 1: Master + Slave 동시 → 기존 로직
            # ══════════════════════════════════════════
            if masters and slaves:
                m_name = masters[0]
                s_name = slaves[0]
                m_iface = next((f for f in self._ifaces if f["name"]==m_name),None)
                s_iface = next((f for f in self._ifaces if f["name"]==s_name),None)
                m_ip = self._custom_ip.get(m_name,
                       m_iface["ip"] if m_iface else "")
                s_ip = self._custom_ip.get(s_name,
                       s_iface["ip"] if s_iface else "")
                scapy_m = _resolve_scapy_iface(m_name)
                scapy_s = _resolve_scapy_iface(s_name)

                self.after(0, lambda: self._mini_log_add("info",
                    f"[Master+Slave] ARP 스캔: {m_name}({m_ip}) / {s_name}({s_ip})"))

                m_arp = arp_scan(scapy_m, m_ip)
                s_arp = arp_scan(scapy_s, s_ip)

                m_macs = set(m_arp.values())
                s_macs = set(s_arp.values())

                # 자신의 MAC 제외
                for sc_if in (scapy_m, scapy_s):
                    try:
                        m_macs.discard(get_if_hwaddr(sc_if).upper())
                        s_macs.discard(get_if_hwaddr(sc_if).upper())
                    except Exception:
                        pass

                self.after(0, lambda mm=m_macs, sm=s_macs:
                    self._mini_log_add("info",
                        f"Master MAC: {mm} | Slave MAC: {sm}"))

                common = m_macs & s_macs
                if common:
                    ap_mac  = common.pop()
                    ap_ip   = next((ip for ip,mac in m_arp.items()
                                    if mac==ap_mac), "")
                    ap_info = {
                        "detected": True, "mode": "Bridge",
                        "mac_wan": ap_mac, "mac_lan": ap_mac,
                        "ip_wan": ap_ip,  "ip_lan": ap_ip,
                        "vendor": _lookup_vendor(ap_mac),
                        "show_internet": False,
                    }
                    self.after(0, lambda: self._mini_log_add("ok",
                        f"Bridge Mode AP 감지: {ap_mac} ({ap_ip})"))
                    log.info(f"AP Bridge: {ap_mac}", source="TOPOLOGY")

                elif m_macs and s_macs:
                    wan_mac = m_macs.pop()
                    lan_mac = s_macs.pop()
                    wan_ip  = next((ip for ip,mac in m_arp.items()
                                    if mac==wan_mac), "")
                    lan_ip  = next((ip for ip,mac in s_arp.items()
                                    if mac==lan_mac), "")
                    ap_info = {
                        "detected": True, "mode": "NAT",
                        "mac_wan": wan_mac, "mac_lan": lan_mac,
                        "ip_wan": wan_ip,   "ip_lan": lan_ip,
                        "vendor": _lookup_vendor(wan_mac),
                        "show_internet": False,
                    }
                    self.after(0, lambda: self._mini_log_add("ok",
                        f"NAT Mode AP 감지: WAN={wan_mac}({wan_ip}) "
                        f"LAN={lan_mac}({lan_ip})"))
                    log.info(f"AP NAT: WAN={wan_mac} LAN={lan_mac}",
                             source="TOPOLOGY")
                else:
                    self.after(0, lambda: self._mini_log_add("info",
                        "AP 미감지 (직결 연결로 판단)"))

            # ══════════════════════════════════════════
            # CASE 2: Master만 → GW ARP 확인
            # ══════════════════════════════════════════
            elif masters and not slaves:
                m_name  = masters[0]
                m_iface = next((f for f in self._ifaces if f["name"]==m_name),None)
                m_ip    = self._custom_ip.get(m_name,
                          m_iface["ip"] if m_iface else "")
                scapy_m = _resolve_scapy_iface(m_name)

                self.after(0, lambda: self._mini_log_add("info",
                    f"[Master only] GW 조회 중... ({m_name}, {m_ip})"))

                gw_ip  = get_gw(m_name)
                gw_mac = ""
                if gw_ip:
                    self.after(0, lambda g=gw_ip: self._mini_log_add("info",
                        f"GW IP={g} → ARP 확인 중..."))
                    gw_mac = arp_single(scapy_m, gw_ip)

                if gw_ip and _is_public_ip(gw_ip):
                    # GW가 공인 IP → Internet망 직결
                    ap_info = {
                        "detected": True, "mode": "Internet",
                        "mac_wan": gw_mac, "mac_lan": "",
                        "ip_wan":  gw_ip,  "ip_lan": "",
                        "vendor":  _lookup_vendor(gw_mac) if gw_mac else "",
                        "show_internet": True,
                    }
                    self.after(0, lambda g=gw_ip: self._mini_log_add("ok",
                        f"Internet망 감지: GW={g} (공인 IP)"))
                    log.info(f"Internet망: GW={gw_ip}", source="TOPOLOGY")
                else:
                    # GW가 사설 IP → AP(NAT) 존재
                    ap_info = {
                        "detected": True, "mode": "NAT",
                        "mac_wan": gw_mac, "mac_lan": "",
                        "ip_wan":  gw_ip,  "ip_lan": m_ip,
                        "vendor":  _lookup_vendor(gw_mac) if gw_mac else "",
                        "show_internet": False,
                    }
                    self.after(0, lambda g=gw_ip: self._mini_log_add("ok",
                        f"AP(NAT) 감지: GW={g} (사설 IP)"))
                    log.info(f"AP NAT (Master only): GW={gw_ip}",
                             source="TOPOLOGY")

            # ══════════════════════════════════════════
            # CASE 3: Slave만 → GW ARP 확인
            # ══════════════════════════════════════════
            elif slaves and not masters:
                s_name  = slaves[0]
                s_iface = next((f for f in self._ifaces if f["name"]==s_name),None)
                s_ip    = self._custom_ip.get(s_name,
                          s_iface["ip"] if s_iface else "")
                scapy_s = _resolve_scapy_iface(s_name)

                self.after(0, lambda: self._mini_log_add("info",
                    f"[Slave only] GW 조회 중... ({s_name}, {s_ip})"))

                gw_ip  = get_gw(s_name)
                gw_mac = ""
                if gw_ip:
                    self.after(0, lambda g=gw_ip: self._mini_log_add("info",
                        f"GW IP={g} → ARP 확인 중..."))
                    gw_mac = arp_single(scapy_s, gw_ip)

                if gw_ip and _is_public_ip(gw_ip):
                    # GW가 공인 IP → AP는 Bridge Mode (IP 그대로 통과)
                    ap_info = {
                        "detected": True, "mode": "Bridge",
                        "mac_wan": gw_mac, "mac_lan": gw_mac,
                        "ip_wan":  gw_ip,  "ip_lan": gw_ip,
                        "vendor":  _lookup_vendor(gw_mac) if gw_mac else "",
                        "show_internet": False,
                    }
                    self.after(0, lambda g=gw_ip: self._mini_log_add("ok",
                        f"AP(Bridge) 감지: GW={g} (공인 IP 통과)"))
                    log.info(f"AP Bridge (Slave only): GW={gw_ip}",
                             source="TOPOLOGY")
                else:
                    # GW가 사설 IP → AP는 NAT Mode
                    ap_info = {
                        "detected": True, "mode": "NAT",
                        "mac_wan": gw_mac, "mac_lan": "",
                        "ip_wan":  gw_ip,  "ip_lan": s_ip,
                        "vendor":  _lookup_vendor(gw_mac) if gw_mac else "",
                        "show_internet": False,
                    }
                    self.after(0, lambda g=gw_ip: self._mini_log_add("ok",
                        f"AP(NAT) 감지: GW={g} (사설 IP)"))
                    log.info(f"AP NAT (Slave only): GW={gw_ip}",
                             source="TOPOLOGY")

            self.after(0, lambda: self._ap_detect_done(
                ap_info.get("detected", False), ap_info=ap_info))

        threading.Thread(target=_run, daemon=True).start()

    def _ap_detect_done(self, detected: bool,
                        ap_info: dict = None, error: str = ""):
        """AP 감지 완료 후 GUI 업데이트 (메인 스레드)"""
        self._btn_ap.config(state="normal", text="📡 AP 감지")

        if error:
            messagebox.showerror("오류", error, parent=self)
            self._conn_status.pop("__ap__", None)
            self._draw_topology()
            return

        if detected and ap_info:
            self._ap_info = ap_info
            self._conn_status["__ap__"] = "ok"
            mode = ap_info.get("mode", "")
            self._mini_log_add("ok",
                f"토폴로지 업데이트: DUT AP ({mode} Mode) 표시됨")
        else:
            self._ap_info = {"detected": False}
            self._conn_status.pop("__ap__", None)
            self._mini_log_add("info", "AP 없음 — 직결 토폴로지 유지")

        self._draw_topology()

    # ── 연결상태 확인 (ARP → Ping) ────────────

    def _check_connectivity(self):
        """
        Slave 인터페이스에서 Master IP로 ARP → ICMP Ping 수행
        Scapy 있으면 → 지정 인터페이스로 직접 패킷 송신 (Wireshark 캡처 가능)
        Scapy 없으면 → subprocess ping (인터페이스 미지정, fallback)
        """
        masters = [n for n, r in self._roles.items() if r == "master"]
        slaves  = [n for n, r in self._roles.items() if r == "slave"]
        if not masters or not slaves:
            messagebox.showwarning("설정 오류",
                "Master / Slave 인터페이스를 먼저 지정하세요.", parent=self)
            return

        self._btn_conn.config(state="disabled", text="확인 중…")
        for name in masters + slaves:
            self._conn_status[name] = "checking"
        self._draw_topology()

        def _run():
            results: dict[str, str] = {}

            for m_name in masters:
                m_iface = next((f for f in self._ifaces if f["name"] == m_name), None)
                m_ip    = self._custom_ip.get(m_name,
                          m_iface["ip"] if m_iface else "")

                if not m_ip or m_ip in ("—", ""):
                    results[m_name] = "fail"
                    self._mini_log_add("err",
                        f"[{m_name}] IP 미설정 — 연결 확인 불가")
                    continue

                for s_name in slaves:
                    s_iface = next((f for f in self._ifaces
                                    if f["name"] == s_name), None)
                    s_ip    = self._custom_ip.get(s_name,
                              s_iface["ip"] if s_iface else "")

                    ok = False

                    # ── Scapy 모드: 인터페이스 직접 지정 ───
                    try:
                        from scapy.all import (ARP, ICMP, IP, Ether,
                                               conf, srp)
                        from scapy.arch import get_if_hwaddr

                        # Scapy 인터페이스 이름 매핑
                        # Windows: psutil name → Scapy iface name 변환 필요
                        scapy_iface = _resolve_scapy_iface(s_name)

                        # Step 1: ARP — Slave 인터페이스에서 Master MAC 조회
                        self._mini_log_add("info",
                            f"[{s_name}→{m_name}] ARP 요청 중… ({m_ip})")
                        try:
                            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                      ARP(pdst=m_ip)
                            answered, _ = srp(arp_req,
                                              iface=scapy_iface,
                                              timeout=2, verbose=False)
                            if answered:
                                mac = answered[0][1].hwsrc
                                self._mini_log_add("ok",
                                    f"[{s_name}→{m_name}] ARP OK → "
                                    f"{m_ip} = {mac}")
                            else:
                                self._mini_log_add("info",
                                    f"[{s_name}→{m_name}] ARP 응답 없음 → Ping 진행")
                        except Exception as e:
                            self._mini_log_add("info",
                                f"[{s_name}→{m_name}] ARP 오류: {e}")

                        # Step 2: ICMP Ping — L2(srp)로 Windows IP 스택 우회
                        # sr1(L3)은 Windows IP 스택이 Reply를 가로채서
                        # "Protocol unreachable" 반환 → srp(L2)로 해결
                        self._mini_log_add("info",
                            f"[{s_name}→{m_name}] ICMP Ping 송신 중… "
                            f"({s_ip} → {m_ip}, iface={scapy_iface})")

                        # Master MAC 확보 (ARP 결과 재활용 or 재요청)
                        m_mac = "ff:ff:ff:ff:ff:ff"
                        try:
                            arp_again = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                        ARP(pdst=m_ip)
                            ans, _ = srp(arp_again, iface=scapy_iface,
                                         timeout=2, verbose=False)
                            if ans:
                                m_mac = ans[0][1].hwsrc
                        except Exception:
                            pass

                        # Slave MAC 가져오기
                        s_mac = "00:00:00:00:00:00"
                        try:
                            s_mac = get_if_hwaddr(scapy_iface)
                        except Exception:
                            pass

                        ping_results = []
                        for seq in range(1, 4):
                            pkt = (
                                Ether(src=s_mac, dst=m_mac) /
                                IP(src=s_ip, dst=m_ip) /
                                ICMP(id=0xBEEF, seq=seq)
                            )
                            t_send = time.time()
                            ans, _ = srp(pkt, iface=scapy_iface,
                                         timeout=2, verbose=False)
                            if ans:
                                reply_pkt = ans[0][1]
                                # ICMP type 0 = Echo Reply
                                if reply_pkt.haslayer(ICMP) and \
                                        reply_pkt[ICMP].type == 0:
                                    rtt = (time.time() - t_send) * 1000
                                    ping_results.append(rtt)
                                    self._mini_log_add("ok",
                                        f"  seq={seq} 응답 {rtt:.1f}ms")
                                else:
                                    icmp_type = reply_pkt[ICMP].type \
                                        if reply_pkt.haslayer(ICMP) else "?"
                                    self._mini_log_add("info",
                                        f"  seq={seq} ICMP type={icmp_type} 수신")
                            else:
                                self._mini_log_add("info",
                                    f"  seq={seq} 응답 없음 (timeout)")

                        ok = len(ping_results) > 0
                        if ok:
                            avg = sum(ping_results) / len(ping_results)
                            self._mini_log_add("ok",
                                f"[{s_name}→{m_name}] Ping 성공 ✓ "
                                f"평균 {avg:.1f}ms "
                                f"({len(ping_results)}/3 응답)")
                        else:
                            self._mini_log_add("err",
                                f"[{s_name}→{m_name}] Ping 실패 ✗ "
                                f"({m_ip} 응답 없음)")

                    except ImportError:
                        # ── Fallback: subprocess ping (인터페이스 미지정) ─
                        self._mini_log_add("info",
                            f"[{s_name}→{m_name}] Scapy 없음 → "
                            f"OS ping 사용 (인터페이스 미지정)")
                        import subprocess, platform
                        try:
                            if platform.system() == "Windows":
                                ret = subprocess.call(
                                    ["ping", "-n", "3", "-w", "1000", m_ip],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=10)
                            else:
                                ret = subprocess.call(
                                    ["ping", "-c", "3", "-W", "1", m_ip],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=10)
                            ok = (ret == 0)
                        except Exception:
                            ok = False

                        if ok:
                            self._mini_log_add("ok",
                                f"[{s_name}→{m_name}] Ping 성공 ✓")
                        else:
                            self._mini_log_add("err",
                                f"[{s_name}→{m_name}] Ping 실패 ✗")

                    except Exception as e:
                        self._mini_log_add("err",
                            f"[{s_name}→{m_name}] 오류: {e}")
                        ok = False

                    results[m_name] = "ok" if ok else "fail"
                    results[s_name] = "ok" if ok else "fail"
                    if ok:
                        log.info(f"연결확인 OK: {s_name}→{m_name} ({m_ip})",
                                 source="TOPOLOGY")
                    else:
                        log.warn(f"연결확인 FAIL: {s_name}→{m_name} ({m_ip})",
                                 source="TOPOLOGY")

            self.after(0, lambda: _update(results))

        def _update(results: dict):
            self._conn_status.update(results)
            self._draw_topology()
            self._btn_conn.config(state="normal", text="🔗 연결상태 확인")
            ok_cnt   = sum(1 for v in results.values() if v == "ok")
            fail_cnt = sum(1 for v in results.values() if v == "fail")
            total    = len(set(results.keys()))
            self._mini_log_add(
                "ok" if fail_cnt == 0 else "err",
                f"연결확인 완료 — 정상 {ok_cnt//2}/{total//2} 경로"
            )

        threading.Thread(target=_run, daemon=True).start()

    # ── 미니 로그 ──────────────────────────────

    def _mini_log_add(self, tag: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._mini_log.config(state="normal")
        self._mini_log.insert(END, f"[{ts}] {msg}\n", tag)
        self._mini_log.see(END)
        self._mini_log.config(state="disabled")



# ══════════════════════════════════════════════
# 탭 2 — 시나리오
# ══════════════════════════════════════════════

class ScenarioTab(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self.engine = ScenarioEngine()
        self._scenarios: list[Scenario] = []
        self._cur_sc: Scenario | None = None
        self._elapsed_sec = 0
        self._elapsed_job = None
        self._build()
        self._load_scenarios()
        self._setup_engine_callbacks()

    # ── 레이아웃 ──────────────────────────────

    def _build(self):
        # 3-pane: 목록 | 편집기 | 실행패널
        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=CLR["bg"], sashwidth=4,
                               sashrelief="flat")
        paned.pack(fill="both", expand=True)

        left = tk.Frame(paned, bg=CLR["bg2"], width=200)
        mid  = tk.Frame(paned, bg=CLR["bg"])
        right= tk.Frame(paned, bg=CLR["bg2"], width=230)
        paned.add(left,  minsize=180)
        paned.add(mid,   minsize=340)
        paned.add(right, minsize=210)

        self._build_list_panel(left)
        self._build_editor_panel(mid)
        self._build_run_panel(right)

    # ── 목록 패널 ─────────────────────────────

    def _build_list_panel(self, parent):
        hdr = tk.Frame(parent, bg=CLR["bg2"])
        hdr.pack(fill="x", padx=8, pady=(8,4))
        tk.Label(hdr, text="시나리오", bg=CLR["bg2"],
                 font=_font(10, bold=True), fg=CLR["text"]).pack(side="left")
        tk.Button(hdr, text="＋", bg=CLR["bg2"], fg=CLR["blue_fg"],
                  font=_font(12, bold=True), relief="flat", cursor="hand2",
                  command=self._new_scenario).pack(side="right")

        self._sc_tree = ttk.Treeview(parent, selectmode="browse", show="tree")
        self._sc_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self._sc_tree.bind("<<TreeviewSelect>>", self._on_sc_select)

        btn_row = tk.Frame(parent, bg=CLR["bg2"])
        btn_row.pack(fill="x", padx=6, pady=4)
        for text, cmd in [("저장", self._save_scenario), ("삭제", self._delete_scenario)]:
            tk.Button(btn_row, text=text, bg=CLR["bg2"], fg=CLR["text2"],
                      font=_font(9), relief="flat",
                      highlightbackground=CLR["border"], highlightthickness=1,
                      cursor="hand2", command=cmd).pack(side="left", padx=2)

    def _load_scenarios(self):
        self._scenarios = list_scenarios()
        self._sc_tree.delete(*self._sc_tree.get_children())
        groups = {}
        for sc in self._scenarios:
            if sc.plugin not in groups:
                groups[sc.plugin] = self._sc_tree.insert("","end", text=sc.plugin,
                                                          open=True)
            self._sc_tree.insert(groups[sc.plugin], "end",
                                 iid=sc.id, text=sc.name)

    def _on_sc_select(self, _=None):
        sel = self._sc_tree.selection()
        if not sel:
            return
        sc_id = sel[0]
        sc = next((s for s in self._scenarios if s.id == sc_id), None)
        if sc:
            self._cur_sc = sc
            self._load_editor(sc)

    # ── 편집기 패널 ───────────────────────────

    def _build_editor_panel(self, parent):
        # 상단: 시나리오 정보
        info_frame = tk.Frame(parent, bg=CLR["panel"],
                              highlightbackground=CLR["border"], highlightthickness=1)
        info_frame.pack(fill="x", padx=8, pady=(8,4))

        f1 = tk.Frame(info_frame, bg=CLR["panel"])
        f1.pack(fill="x", padx=10, pady=6)
        tk.Label(f1, text="시나리오명", bg=CLR["panel"],
                 font=_font(9), fg=CLR["text3"]).grid(row=0, column=0, sticky="w")
        self._sc_name_var = StringVar()
        ttk.Entry(f1, textvariable=self._sc_name_var, font=_font(10),
                  width=24).grid(row=0, column=1, padx=6)
        tk.Label(f1, text="플러그인", bg=CLR["panel"],
                 font=_font(9), fg=CLR["text3"]).grid(row=0, column=2, sticky="w", padx=(10,0))
        self._sc_plugin_var = StringVar()
        ttk.Combobox(f1, textvariable=self._sc_plugin_var, width=10,
                     values=list(PLUGIN_REGISTRY.keys()),
                     state="readonly").grid(row=0, column=3, padx=6)

        tk.Label(f1, text="설명", bg=CLR["panel"],
                 font=_font(9), fg=CLR["text3"]).grid(row=1, column=0, sticky="w", pady=(4,0))
        self._sc_desc_var = StringVar()
        ttk.Entry(f1, textvariable=self._sc_desc_var, font=_font(9),
                  width=50).grid(row=1, column=1, columnspan=3, sticky="ew", padx=6, pady=(4,0))

        # 반복/Aging 설정
        self._build_repeat_section(info_frame)

        # Step 목록
        step_hdr = tk.Frame(parent, bg=CLR["bg"])
        step_hdr.pack(fill="x", padx=8, pady=(6,2))
        tk.Label(step_hdr, text="Steps", bg=CLR["bg"],
                 font=_font(10, bold=True), fg=CLR["text"]).pack(side="left")
        tk.Button(step_hdr, text="＋ Step 추가", bg=CLR["blue_bg"], fg=CLR["blue_fg"],
                  font=_font(9), relief="flat", cursor="hand2",
                  command=self._add_step).pack(side="right")

        step_frame = tk.Frame(parent, bg=CLR["bg"])
        step_frame.pack(fill="both", expand=True, padx=8)

        sb = ttk.Scrollbar(step_frame)
        sb.pack(side="right", fill="y")
        self._step_tree = ttk.Treeview(
            step_frame,
            columns=("type","name","expected","timeout","on_fail","judge"),
            show="headings",
            yscrollcommand=sb.set,
            selectmode="browse",
        )
        sb.config(command=self._step_tree.yview)

        cols = [
            ("type",    "유형",    60),
            ("name",    "항목명",  200),
            ("expected","기댓값",  110),
            ("timeout", "타임아웃",70),
            ("on_fail", "실패시",  60),
            ("judge",   "판정",    55),
        ]
        for cid, label, w in cols:
            self._step_tree.heading(cid, text=label)
            self._step_tree.column(cid, width=w, anchor="center")
        self._step_tree.pack(fill="both", expand=True)
        self._step_tree.bind("<Double-1>", self._edit_step)

        # 미니 로그
        self._sc_log = Text(parent, height=4, bg=CLR["bg2"], fg=CLR["text2"],
                            font=_font(9, mono=True), relief="flat",
                            state="disabled", wrap="word")
        self._sc_log.pack(fill="x", padx=8, pady=(4,8))
        self._sc_log.tag_config("ok",  foreground=CLR["green_fg"])
        self._sc_log.tag_config("err", foreground=CLR["red_fg"])
        self._sc_log.tag_config("info",foreground=CLR["blue_fg"])

    def _build_repeat_section(self, parent):
        rf = tk.LabelFrame(parent, text="반복 / Aging 설정",
                           bg=CLR["panel"], font=_font(9),
                           fg=CLR["text3"], relief="flat",
                           highlightbackground=CLR["border"], highlightthickness=1)
        rf.pack(fill="x", padx=10, pady=(4,6))

        self._repeat_enabled = BooleanVar(value=False)
        self._repeat_mode    = StringVar(value="count")
        self._repeat_count   = IntVar(value=10)
        self._repeat_dur_h   = IntVar(value=1)
        self._repeat_dur_m   = IntVar(value=0)
        self._repeat_interval= IntVar(value=0)

        tk.Checkbutton(rf, text="반복 테스트 활성화",
                       variable=self._repeat_enabled,
                       bg=CLR["panel"], font=_font(10),
                       command=self._toggle_repeat).pack(anchor="w", padx=6, pady=2)

        self._repeat_inner = tk.Frame(rf, bg=CLR["panel"])
        self._repeat_inner.pack(fill="x", padx=6, pady=(0,4))

        mode_f = tk.Frame(self._repeat_inner, bg=CLR["panel"])
        mode_f.pack(fill="x")
        tk.Radiobutton(mode_f, text="횟수 지정", variable=self._repeat_mode,
                       value="count", bg=CLR["panel"], font=_font(10),
                       command=self._toggle_repeat_mode).pack(side="left")
        self._sp_count = ttk.Spinbox(mode_f, textvariable=self._repeat_count,
                                     from_=1, to=9999, width=6, font=_font(10))
        self._sp_count.pack(side="left", padx=4)
        tk.Label(mode_f, text="회", bg=CLR["panel"], font=_font(10),
                 fg=CLR["text3"]).pack(side="left")

        dur_f = tk.Frame(self._repeat_inner, bg=CLR["panel"])
        dur_f.pack(fill="x", pady=2)
        tk.Radiobutton(dur_f, text="시간 지정 (Aging)",
                       variable=self._repeat_mode,
                       value="duration", bg=CLR["panel"], font=_font(10),
                       command=self._toggle_repeat_mode).pack(side="left")
        self._sp_dur_h = ttk.Spinbox(dur_f, textvariable=self._repeat_dur_h,
                                      from_=0, to=999, width=5, font=_font(10))
        self._sp_dur_h.pack(side="left", padx=4)
        tk.Label(dur_f, text="시간", bg=CLR["panel"], font=_font(10),
                 fg=CLR["text3"]).pack(side="left")
        self._sp_dur_m = ttk.Spinbox(dur_f, textvariable=self._repeat_dur_m,
                                      from_=0, to=59, width=5, font=_font(10))
        self._sp_dur_m.pack(side="left", padx=4)
        tk.Label(dur_f, text="분", bg=CLR["panel"], font=_font(10),
                 fg=CLR["text3"]).pack(side="left")

        int_f = tk.Frame(self._repeat_inner, bg=CLR["panel"])
        int_f.pack(fill="x")
        tk.Label(int_f, text="반복 간 대기:", bg=CLR["panel"],
                 font=_font(10), fg=CLR["text3"]).pack(side="left")
        ttk.Spinbox(int_f, textvariable=self._repeat_interval,
                    from_=0, to=3600, width=6, font=_font(10)).pack(side="left", padx=4)
        tk.Label(int_f, text="초", bg=CLR["panel"], font=_font(10),
                 fg=CLR["text3"]).pack(side="left")

        self._toggle_repeat()

    def _toggle_repeat(self):
        state = "normal" if self._repeat_enabled.get() else "disabled"
        for w in self._repeat_inner.winfo_children():
            for ww in w.winfo_children():
                try: ww.config(state=state)
                except Exception: pass
            try: w.config(state=state)
            except Exception: pass

    def _toggle_repeat_mode(self):
        mode = self._repeat_mode.get()
        self._sp_count.config(state="normal" if mode=="count" else "disabled")
        self._sp_dur_h.config(state="normal" if mode=="duration" else "disabled")
        self._sp_dur_m.config(state="normal" if mode=="duration" else "disabled")

    # ── 실행 패널 ─────────────────────────────

    def _build_run_panel(self, parent):
        hdr = tk.Frame(parent, bg=CLR["bg2"],
                       highlightbackground=CLR["border"], highlightthickness=1)
        hdr.pack(fill="x")
        tk.Label(hdr, text="실행 현황", bg=CLR["bg2"],
                 font=_font(10, bold=True), fg=CLR["text"]).pack(side="left", padx=10, pady=6)
        self._run_status_lbl = tk.Label(hdr, text="대기 중",
                                        bg=CLR["gray_bg"], fg=CLR["gray_fg"],
                                        font=_font(9, bold=True), padx=6, pady=2)
        self._run_status_lbl.pack(side="right", padx=8)

        # 통계
        stats = tk.Frame(parent, bg=CLR["bg2"])
        stats.pack(fill="x", padx=10, pady=6)
        self._stat_labels = {}
        for label, key, fg in [("진행","progress",CLR["text"]),
                                ("PASS","pass_c",CLR["green_fg"]),
                                ("FAIL","fail_c",CLR["red_fg"]),
                                ("회차","iter",CLR["text"]),
                                ("경과","elapsed",CLR["text"])]:
            row = tk.Frame(stats, bg=CLR["bg2"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, bg=CLR["bg2"],
                     font=_font(9), fg=CLR["text3"], width=6, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="—", bg=CLR["bg2"],
                           font=_font(10, bold=True), fg=fg)
            lbl.pack(side="right")
            self._stat_labels[key] = lbl

        # 진행 바
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(parent, variable=self._progress_var,
                                              maximum=100)
        self._progress_bar.pack(fill="x", padx=10, pady=2)

        # 버튼
        btn_f = tk.Frame(parent, bg=CLR["bg2"])
        btn_f.pack(fill="x", padx=10, pady=8)
        self._btn_run = tk.Button(btn_f, text="▶ 실행", bg=CLR["blue_mid"], fg="white",
                                  font=_font(10), relief="flat", cursor="hand2",
                                  command=self._run_scenario)
        self._btn_run.pack(side="left", padx=2, ipadx=8, ipady=3)
        self._btn_pause = tk.Button(btn_f, text="⏸ 일시정지",
                                    bg=CLR["bg2"], fg=CLR["text2"],
                                    highlightbackground=CLR["border"],highlightthickness=1,
                                    font=_font(10), relief="flat", cursor="hand2",
                                    command=self._pause_scenario)
        self._btn_pause.pack(side="left", padx=2, ipadx=6, ipady=3)
        self._btn_stop2 = tk.Button(btn_f, text="■ 중단",
                                    bg=CLR["red_bg"], fg=CLR["red_fg"],
                                    highlightbackground=CLR["red_mid"],highlightthickness=1,
                                    font=_font(10), relief="flat", cursor="hand2",
                                    command=self._stop_scenario)
        self._btn_stop2.pack(side="left", padx=2, ipadx=6, ipady=3)

        # 현재 Step 상세
        sep = tk.Frame(parent, bg=CLR["border"], height=1)
        sep.pack(fill="x", padx=8, pady=4)
        tk.Label(parent, text="현재 Step", bg=CLR["bg2"],
                 font=_font(9), fg=CLR["text3"]).pack(anchor="w", padx=10)
        self._step_detail = tk.Frame(parent, bg=CLR["bg2"])
        self._step_detail.pack(fill="x", padx=10, pady=4)
        self._step_kv = {}
        for key, label in [("name","항목"),("expected","기댓값"),
                            ("actual","실측값"),("elapsed","경과ms"),("judge","판정")]:
            row = tk.Frame(self._step_detail, bg=CLR["bg2"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, bg=CLR["bg2"],
                     font=_font(9), fg=CLR["text3"], width=7, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="—", bg=CLR["bg2"],
                           font=_font(9, mono=True), fg=CLR["text"])
            lbl.pack(side="right")
            self._step_kv[key] = lbl

        # 결과서 버튼
        sep2 = tk.Frame(parent, bg=CLR["border"], height=1)
        sep2.pack(fill="x", padx=8, pady=8)
        self._btn_report = tk.Button(parent, text="결과서 생성 (Excel + PDF)",
                                     bg=CLR["amber_bg"], fg=CLR["amber_fg"],
                                     highlightbackground=CLR["amber_mid"],highlightthickness=1,
                                     font=_font(10), relief="flat", cursor="hand2",
                                     command=self._generate_report, state="disabled")
        self._btn_report.pack(padx=10, fill="x", ipady=4)

    # ── 시나리오 로드/편집 ─────────────────────

    def _load_editor(self, sc: Scenario):
        self._sc_name_var.set(sc.name)
        self._sc_plugin_var.set(sc.plugin)
        self._sc_desc_var.set(sc.description)
        # 반복 설정
        self._repeat_enabled.set(sc.repeat.enabled)
        self._repeat_mode.set(sc.repeat.mode)
        self._repeat_count.set(sc.repeat.count)
        total_sec = sc.repeat.duration_sec
        self._repeat_dur_h.set(total_sec // 3600)
        self._repeat_dur_m.set((total_sec % 3600) // 60)
        self._repeat_interval.set(sc.repeat.interval_sec)
        self._toggle_repeat()
        # Step 목록
        self._refresh_step_tree(sc)

    def _refresh_step_tree(self, sc: Scenario):
        self._step_tree.delete(*self._step_tree.get_children())
        judge_map = {}  # step_index → judge (실행 중 표시용)
        for step in sc.steps:
            judge = judge_map.get(step.index, "—")
            self._step_tree.insert("", "end", iid=str(step.index), values=(
                step.type, step.name, step.expected or "—",
                f"{step.timeout_ms}ms", step.on_fail, judge,
            ))

    def _add_step(self):
        if not self._cur_sc:
            messagebox.showinfo("알림", "먼저 시나리오를 선택하세요.", parent=self)
            return
        idx = len(self._cur_sc.steps)
        dlg = StepEditDialog(self, idx)
        if dlg.result:
            self._cur_sc.steps.append(dlg.result)
            self._refresh_step_tree(self._cur_sc)

    def _edit_step(self, _=None):
        if not self._cur_sc:
            return
        sel = self._step_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        step = next((s for s in self._cur_sc.steps if s.index == idx), None)
        if not step:
            return
        dlg = StepEditDialog(self, idx, step)
        if dlg.result:
            self._cur_sc.steps[idx] = dlg.result
            self._refresh_step_tree(self._cur_sc)

    def _new_scenario(self):
        name = simpledialog.askstring("새 시나리오", "시나리오 이름:", parent=self)
        if not name:
            return
        sc = Scenario(id=str(uuid.uuid4())[:8], name=name, plugin="DHCP",
                      description="")
        self._scenarios.append(sc)
        save_scenario(sc)
        self._load_scenarios()

    def _save_scenario(self):
        if not self._cur_sc:
            return
        self._cur_sc.name        = self._sc_name_var.get()
        self._cur_sc.plugin      = self._sc_plugin_var.get()
        self._cur_sc.description = self._sc_desc_var.get()
        dur_sec = self._repeat_dur_h.get()*3600 + self._repeat_dur_m.get()*60
        self._cur_sc.repeat = RepeatConfig(
            enabled=self._repeat_enabled.get(),
            mode=self._repeat_mode.get(),
            count=self._repeat_count.get(),
            duration_sec=dur_sec,
            interval_sec=self._repeat_interval.get(),
        )
        save_scenario(self._cur_sc)
        self._load_scenarios()
        messagebox.showinfo("저장 완료", f"'{self._cur_sc.name}' 저장됨.", parent=self)

    def _delete_scenario(self):
        if not self._cur_sc:
            return
        if messagebox.askyesno("삭제 확인", f"'{self._cur_sc.name}'을 삭제하시겠습니까?",
                               parent=self):
            path = os.path.join("scenarios", f"{self._cur_sc.id}.json")
            if os.path.exists(path):
                os.remove(path)
            self._scenarios.remove(self._cur_sc)
            self._cur_sc = None
            self._load_scenarios()

    # ── 엔진 연동 ─────────────────────────────

    def _setup_engine_callbacks(self):
        q = queue.Queue()
        self._cb_queue = q

        def on_step_start(iter_n, step_idx, step):
            q.put(("step_start", iter_n, step_idx, step))

        def on_step_done(iter_n, step_idx, result):
            q.put(("step_done", iter_n, step_idx, result))

        def on_iter_done(iter_n, record):
            q.put(("iter_done", iter_n, record))

        def on_run_done(records):
            q.put(("run_done", records))

        def on_status(msg):
            q.put(("status", msg))

        self.engine.on_step_start    = on_step_start
        self.engine.on_step_done     = on_step_done
        self.engine.on_iter_done     = on_iter_done
        self.engine.on_run_done      = on_run_done
        self.engine.on_status_update = on_status
        self._poll_queue()

    def _poll_queue(self):
        try:
            while True:
                msg = self._cb_queue.get_nowait()
                self._handle_cb(msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_cb(self, msg):
        kind = msg[0]
        if kind == "step_start":
            _, iter_n, step_idx, step = msg
            self._run_status_lbl.config(text="실행 중", bg=CLR["blue_bg"], fg=CLR["blue_fg"])
            self._stat_labels["iter"].config(text=f"{iter_n}회차")
            self._step_kv["name"].config(text=step.name[:18])
            self._step_kv["expected"].config(text=str(step.expected or "—")[:14])
            self._step_kv["actual"].config(text="—")
            self._step_kv["judge"].config(text="실행중", fg=CLR["blue_fg"])
            # 트리 행 강조
            for iid in self._step_tree.get_children():
                self._step_tree.item(iid, tags=())
            try:
                self._step_tree.selection_set(str(step_idx))
                self._step_tree.see(str(step_idx))
            except Exception:
                pass

        elif kind == "step_done":
            _, iter_n, step_idx, result = msg
            total_steps = len(self._cur_sc.steps) if self._cur_sc else 1
            done = step_idx + 1
            pct  = done / total_steps * 100
            self._progress_var.set(pct)
            self._stat_labels["progress"].config(text=f"{done}/{total_steps}")
            judge = "PASS" if result.passed else "FAIL"
            fg    = CLR["green_fg"] if result.passed else CLR["red_fg"]
            self._step_kv["actual"].config( text=str(result.actual  or "—")[:14])
            self._step_kv["elapsed"].config(text=f"{result.elapsed_ms:.0f}ms")
            self._step_kv["judge"].config(  text=judge, fg=fg)
            # 트리 업데이트
            try:
                vals = list(self._step_tree.item(str(step_idx), "values"))
                vals[5] = judge
                self._step_tree.item(str(step_idx), values=vals,
                                     tags=("pass" if result.passed else "fail",))
            except Exception:
                pass
            # 미니 로그
            self._sc_log_add("ok" if result.passed else "err",
                             f"Step {step_idx+1:02d} {judge} — {result.step_name}")

        elif kind == "iter_done":
            _, iter_n, record = msg
            self._stat_labels["pass_c"].config(text=str(record.pass_count))
            self._stat_labels["fail_c"].config(text=str(record.fail_count))

        elif kind == "run_done":
            _, records = msg
            self._run_status_lbl.config(text="완료", bg=CLR["green_bg"], fg=CLR["green_fg"])
            self._run_records = records
            self._btn_report.config(state="normal")
            self._stop_elapsed()
            log.info(f"시나리오 실행 완료. 결과서 생성 가능.", source="SCENARIO")

        elif kind == "status":
            self._run_status_lbl.config(text=msg[1], bg=CLR["blue_bg"], fg=CLR["blue_fg"])

        self._step_tree.tag_configure("pass", foreground=CLR["green_fg"])
        self._step_tree.tag_configure("fail", foreground=CLR["red_fg"])

    def _run_scenario(self):
        if not self._cur_sc:
            messagebox.showinfo("알림", "실행할 시나리오를 선택하세요.", parent=self)
            return
        if self.engine.is_running:
            messagebox.showinfo("알림", "이미 실행 중입니다.", parent=self)
            return
        # 인터페이스 확인
        topo = self.app.topo_tab
        masters = [n for n,r in topo._roles.items() if r=="master"]
        slaves  = [n for n,r in topo._roles.items() if r=="slave"]
        if not masters or not slaves:
            messagebox.showwarning("설정 오류",
                "토폴로지 탭에서 Master/Slave 인터페이스를 지정하세요.", parent=self)
            return
        plugin = PLUGIN_REGISTRY.get(self._cur_sc.plugin)
        if not plugin:
            messagebox.showerror("플러그인 오류",
                f"'{self._cur_sc.plugin}' 플러그인을 찾을 수 없습니다.", parent=self)
            return
        # Step 태그 초기화
        for iid in self._step_tree.get_children():
            vals = list(self._step_tree.item(iid, "values"))
            vals[5] = "—"
            self._step_tree.item(iid, values=vals, tags=())
        self._progress_var.set(0)
        self._btn_report.config(state="disabled")
        self._start_elapsed()
        self.engine.start(self._cur_sc, plugin, masters[0], slaves[0])

    def _pause_scenario(self):
        if self.engine.is_running:
            if self._btn_pause.cget("text").startswith("⏸"):
                self.engine.pause()
                self._btn_pause.config(text="▶ 재개")
            else:
                self.engine.resume()
                self._btn_pause.config(text="⏸ 일시정지")

    def _stop_scenario(self):
        self.engine.stop()
        self._btn_pause.config(text="⏸ 일시정지")
        self._stop_elapsed()

    def _start_elapsed(self):
        self._elapsed_sec = 0
        self._tick_elapsed()

    def _tick_elapsed(self):
        if not self.engine.is_running:
            return
        self._elapsed_sec += 1
        m = self._elapsed_sec // 60
        s = self._elapsed_sec % 60
        self._stat_labels["elapsed"].config(text=f"{m:02d}:{s:02d}")
        self._elapsed_job = self.after(1000, self._tick_elapsed)

    def _stop_elapsed(self):
        if self._elapsed_job:
            self.after_cancel(self._elapsed_job)

    def _generate_report(self):
        if not hasattr(self, "_run_records") or not self._run_records:
            messagebox.showinfo("알림", "먼저 시나리오를 실행하세요.", parent=self)
            return
        cfg = self.app.config
        device_info = {
            "device_name": cfg.get("device_name",""),
            "firmware":    cfg.get("firmware",""),
            "tester":      cfg.get("tester",""),
        }
        save_dir = cfg.get("report_dir","") or None
        try:
            xp = report_writer.export_excel(self._cur_sc, self._run_records,
                                            device_info, save_dir)
            pp = report_writer.export_pdf(  self._cur_sc, self._run_records,
                                            device_info, save_dir)
            messagebox.showinfo("저장 완료",
                f"Excel: {xp}\n\nPDF: {pp}", parent=self)
            log.info(f"결과서 생성 완료: {xp}", source="REPORT")
        except Exception as e:
            messagebox.showerror("오류", str(e), parent=self)
            log.error(str(e), source="REPORT")

    # ── 로그 ──────────────────────────────────

    def _sc_log_add(self, tag: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._sc_log.config(state="normal")
        self._sc_log.insert(END, f"[{ts}] {msg}\n", tag)
        self._sc_log.see(END)
        self._sc_log.config(state="disabled")


# ──────────────────────────────────────────────
# Step 편집 다이얼로그
# ──────────────────────────────────────────────

class StepEditDialog(Toplevel):
    def __init__(self, parent, index: int, step: ScenarioStep | None = None):
        super().__init__(parent)
        self.title("Step 편집")
        self.geometry("360x300")
        self.resizable(False, False)
        self.grab_set()
        self.configure(bg=CLR["bg"])
        self.result: ScenarioStep | None = None
        self._index = index
        self._build(step)
        self.wait_window()

    def _build(self, step):
        pad = dict(padx=14, pady=4, anchor="w")

        tk.Label(self, text="Step 편집", bg=CLR["bg"],
                 font=_font(11, bold=True), fg=CLR["text"]).pack(**pad, pady=(12,2))

        fields = tk.Frame(self, bg=CLR["bg"])
        fields.pack(fill="x", padx=14)

        def row(label, var, opts=None):
            f = tk.Frame(fields, bg=CLR["bg"])
            f.pack(fill="x", pady=3)
            tk.Label(f, text=label, bg=CLR["bg"], font=_font(9),
                     fg=CLR["text3"], width=10, anchor="w").pack(side="left")
            if opts:
                w = ttk.Combobox(f, textvariable=var, values=opts,
                                 state="readonly", width=18, font=_font(10))
            else:
                w = ttk.Entry(f, textvariable=var, font=_font(10), width=20)
            w.pack(side="left", padx=4)
            return w

        self._type_v     = StringVar(value=step.type     if step else "Send")
        self._name_v     = StringVar(value=step.name     if step else "")
        self._exp_v      = StringVar(value=step.expected if step else "")
        self._timeout_v  = IntVar(   value=step.timeout_ms if step else 3000)
        self._on_fail_v  = StringVar(value=step.on_fail  if step else "stop")
        self._tol_v      = tk.DoubleVar(value=step.tolerance if step else 0.0)

        row("유형",     self._type_v,    ["Send","Wait","Check","Delay","Assert"])
        row("항목명",   self._name_v)
        row("기댓값",   self._exp_v)
        row("타임아웃(ms)", self._timeout_v)
        row("실패 시",  self._on_fail_v, ["stop","continue","retry"])
        row("허용오차(%)", self._tol_v)

        tk.Button(self, text="확인", bg=CLR["blue_mid"], fg="white",
                  font=_font(10), relief="flat", cursor="hand2",
                  command=self._ok).pack(pady=10, ipadx=20)

    def _ok(self):
        self.result = ScenarioStep(
            index=self._index,
            name=self._name_v.get(),
            type=self._type_v.get(),
            expected=self._exp_v.get(),
            timeout_ms=self._timeout_v.get(),
            on_fail=self._on_fail_v.get(),
            tolerance=self._tol_v.get(),
        )
        self.destroy()


# ══════════════════════════════════════════════
# 탭 3 — 결과서
# ══════════════════════════════════════════════

class ReportTab(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self._build()

    def _build(self):
        # 안내
        tk.Label(self, text="결과서 탭",
                 bg=CLR["bg"], font=_font(13, bold=True), fg=CLR["text"]).pack(pady=20)
        tk.Label(self,
                 text="시나리오 탭에서 실행 완료 후\n'결과서 생성' 버튼을 누르세요.\n\n"
                      "Excel (.xlsx) + PDF가 자동 생성됩니다.",
                 bg=CLR["bg"], font=_font(11), fg=CLR["text2"],
                 justify="center").pack()

        fr = tk.LabelFrame(self, text="보고서 헤더 정보",
                           bg=CLR["bg"], font=_font(10), fg=CLR["text3"],
                           relief="flat", highlightbackground=CLR["border"],
                           highlightthickness=1)
        fr.pack(padx=40, pady=20, fill="x")

        self._dev_var = StringVar(value=self.app.config.get("device_name",""))
        self._fw_var  = StringVar(value=self.app.config.get("firmware",""))
        self._tst_var = StringVar(value=self.app.config.get("tester",""))
        self._dir_var = StringVar(value=self.app.config.get("report_dir",""))

        for label, var in [("장비명/모델", self._dev_var),
                            ("펌웨어 버전", self._fw_var),
                            ("담당자",     self._tst_var)]:
            row = tk.Frame(fr, bg=CLR["bg"])
            row.pack(fill="x", padx=14, pady=4)
            tk.Label(row, text=label, bg=CLR["bg"],
                     font=_font(10), fg=CLR["text3"], width=12, anchor="w").pack(side="left")
            ttk.Entry(row, textvariable=var, font=_font(10), width=28).pack(side="left")

        dir_row = tk.Frame(fr, bg=CLR["bg"])
        dir_row.pack(fill="x", padx=14, pady=4)
        tk.Label(dir_row, text="저장 경로", bg=CLR["bg"],
                 font=_font(10), fg=CLR["text3"], width=12, anchor="w").pack(side="left")
        ttk.Entry(dir_row, textvariable=self._dir_var,
                  font=_font(10), width=24).pack(side="left")
        tk.Button(dir_row, text="…", bg=CLR["bg2"], fg=CLR["text"],
                  font=_font(10), relief="flat", cursor="hand2",
                  command=self._browse).pack(side="left", padx=4)

        tk.Button(self, text="설정 저장", bg=CLR["blue_bg"], fg=CLR["blue_fg"],
                  font=_font(10), relief="flat", cursor="hand2",
                  highlightbackground=CLR["blue_mid"], highlightthickness=1,
                  command=self._save_cfg).pack(pady=8, ipadx=12)

    def _browse(self):
        d = filedialog.askdirectory(title="저장 경로 선택", parent=self)
        if d:
            self._dir_var.set(d)

    def _save_cfg(self):
        self.app.config.update({
            "device_name": self._dev_var.get(),
            "firmware":    self._fw_var.get(),
            "tester":      self._tst_var.get(),
            "report_dir":  self._dir_var.get(),
        })
        save_config(self.app.config)
        messagebox.showinfo("저장", "보고서 설정이 저장되었습니다.", parent=self)


# ══════════════════════════════════════════════
# 탭 4 — Syslog
# ══════════════════════════════════════════════

class SyslogTab(tk.Frame):
    MAX_ROWS = 2000

    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self._auto_scroll = True
        self._filters = {"DEBUG": True, "INFO": True, "WARN": True, "ERROR": True}
        self._search_kw = ""
        self._all_logs: list[tuple] = []   # (ts, level, source, msg)
        self._build()
        log.add_callback(self._on_log)

    def _build(self):
        # 툴바
        tb = tk.Frame(self, bg=CLR["panel"],
                      highlightbackground=CLR["border"], highlightthickness=1)
        tb.pack(fill="x")

        for lv in ["DEBUG","INFO","WARN","ERROR"]:
            bg_map = {"DEBUG":CLR["gray_bg"],"INFO":CLR["blue_bg"],
                      "WARN":CLR["amber_bg"],"ERROR":CLR["red_bg"]}
            fg_map = {"DEBUG":CLR["gray_fg"],"INFO":CLR["blue_fg"],
                      "WARN":CLR["amber_fg"],"ERROR":CLR["red_fg"]}
            btn = tk.Button(tb, text=lv,
                            bg=bg_map[lv], fg=fg_map[lv],
                            font=_font(9, bold=True),
                            relief="flat", cursor="hand2",
                            command=lambda l=lv: self._toggle_filter(l))
            btn.pack(side="left", padx=3, pady=6, ipadx=6)

        self._search_var = StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(tb, textvariable=self._search_var,
                  font=_font(10), width=18).pack(side="left", padx=6, pady=6)
        tk.Label(tb, text="검색", bg=CLR["panel"],
                 font=_font(9), fg=CLR["text3"]).pack(side="left")

        tk.Button(tb, text="자동스크롤 ON", bg=CLR["panel"], fg=CLR["text2"],
                  font=_font(9), relief="flat", cursor="hand2",
                  command=self._toggle_auto_scroll).pack(side="right", padx=4)
        tk.Button(tb, text="클리어", bg=CLR["panel"], fg=CLR["red_fg"],
                  font=_font(9), relief="flat", cursor="hand2",
                  command=self._clear).pack(side="right", padx=4)
        tk.Button(tb, text=".log 저장", bg=CLR["panel"], fg=CLR["text2"],
                  font=_font(9), relief="flat", cursor="hand2",
                  command=self._save_log).pack(side="right", padx=4)

        # 로그 뷰 (Text 위젯)
        frame = tk.Frame(self, bg=CLR["bg"])
        frame.pack(fill="both", expand=True, padx=6, pady=4)

        hdr = tk.Frame(frame, bg=CLR["bg2"])
        hdr.pack(fill="x")
        for label, w in [("타임스탬프",110),("레벨",50),("소스",80),("메시지",400)]:
            tk.Label(hdr, text=label, bg=CLR["bg2"], fg=CLR["text3"],
                     font=_font(9), width=w//8, anchor="w").pack(side="left", padx=4)

        sb = ttk.Scrollbar(frame)
        sb.pack(side="right", fill="y")
        self._log_text = Text(frame, bg=CLR["panel"], fg=CLR["text"],
                              font=_font(9, mono=True),
                              relief="flat", wrap="none",
                              yscrollcommand=sb.set, state="disabled")
        self._log_text.pack(fill="both", expand=True)
        sb.config(command=self._log_text.yview)

        for lv in ["DEBUG","INFO","WARN","ERROR"]:
            self._log_text.tag_config(lv, foreground=LOG_COLORS[lv])

        # 상태바
        self._statusbar = tk.Frame(self, bg=CLR["bg2"],
                                   highlightbackground=CLR["border"],
                                   highlightthickness=1)
        self._statusbar.pack(fill="x")
        self._lbl_total = tk.Label(self._statusbar, text="전체: 0",
                                   bg=CLR["bg2"], font=_font(9), fg=CLR["text3"])
        self._lbl_total.pack(side="left", padx=10, pady=3)
        self._lbl_err_cnt = tk.Label(self._statusbar, text="ERROR: 0",
                                     bg=CLR["bg2"], font=_font(9), fg=CLR["red_fg"])
        self._lbl_err_cnt.pack(side="left", padx=6)
        self._lbl_warn_cnt = tk.Label(self._statusbar, text="WARN: 0",
                                      bg=CLR["bg2"], font=_font(9), fg=CLR["amber_fg"])
        self._lbl_warn_cnt.pack(side="left", padx=6)
        tk.Label(self._statusbar,
                 text=f"로그파일: {log.log_file}",
                 bg=CLR["bg2"], font=_font(9), fg=CLR["text3"]).pack(side="right", padx=10)

    def _on_log(self, ts, level, source, message):
        """logger 콜백 — 백그라운드에서 호출될 수 있음"""
        self._all_logs.append((ts, level, source, message))
        if len(self._all_logs) > self.MAX_ROWS:
            self._all_logs = self._all_logs[-self.MAX_ROWS:]
        # GUI 업데이트는 메인 스레드에서
        self.after(0, lambda: self._append_row(ts, level, source, message))

    def _append_row(self, ts, level, source, message):
        if not self._filters.get(level, True):
            return
        kw = self._search_var.get().strip()
        if kw and kw.lower() not in message.lower() and kw.lower() not in source.lower():
            return
        self._log_text.config(state="normal")
        line = f"{ts:<14}  {level:<6}  [{source:<10}]  {message}\n"
        self._log_text.insert(END, line, level)
        self._log_text.config(state="disabled")
        if self._auto_scroll:
            self._log_text.see(END)
        self._update_counts()

    def _apply_filter(self):
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", END)
        self._log_text.config(state="disabled")
        kw = self._search_var.get().strip().lower()
        for ts, level, source, message in self._all_logs:
            if not self._filters.get(level, True):
                continue
            if kw and kw not in message.lower() and kw not in source.lower():
                continue
            self._log_text.config(state="normal")
            line = f"{ts:<14}  {level:<6}  [{source:<10}]  {message}\n"
            self._log_text.insert(END, line, level)
            self._log_text.config(state="disabled")
        if self._auto_scroll:
            self._log_text.see(END)
        self._update_counts()

    def _toggle_filter(self, level: str):
        self._filters[level] = not self._filters[level]
        self._apply_filter()

    def _toggle_auto_scroll(self):
        self._auto_scroll = not self._auto_scroll

    def _clear(self):
        self._all_logs.clear()
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", END)
        self._log_text.config(state="disabled")
        self._update_counts()

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            title="로그 저장", defaultextension=".log",
            filetypes=[("Log files","*.log"),("All files","*.*")],
            initialfile=f"ap_verify_{datetime.now().strftime('%Y%m%d')}.log",
            parent=self,
        )
        if path:
            with open(path, "w", encoding="utf-8-sig") as f:
                for ts, lv, src, msg in self._all_logs:
                    f.write(f"[{ts}] [{lv}] [{src}] {msg}\n")
            messagebox.showinfo("저장 완료", path, parent=self)

    def _update_counts(self):
        total = len(self._all_logs)
        errs  = sum(1 for *_, l, __, ___ in [(x,)+x[1:] for x in self._all_logs] if False)
        errs  = sum(1 for x in self._all_logs if x[1]=="ERROR")
        warns = sum(1 for x in self._all_logs if x[1]=="WARN")
        self._lbl_total.config(text=f"전체: {total}")
        self._lbl_err_cnt.config(text=f"ERROR: {errs}")
        self._lbl_warn_cnt.config(text=f"WARN: {warns}")


# ══════════════════════════════════════════════
# 탭 5 — 플러그인 관리
# ══════════════════════════════════════════════

class PluginTab(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self._build()

    def _build(self):
        tk.Label(self, text="플러그인 관리", bg=CLR["bg"],
                 font=_font(13, bold=True), fg=CLR["text"]).pack(
                 pady=(16,8), padx=20, anchor="w")

        scroll_f = tk.Frame(self, bg=CLR["bg"])
        scroll_f.pack(fill="both", expand=True, padx=20)

        icon_map = {"DHCP":"■","NAT":"⇄","IGMP":"◉","Packet S/D":"≈"}
        bg_map = {
            "DHCP":CLR["blue_bg"],"NAT":CLR["green_bg"],
            "IGMP":CLR["amber_bg"],"Packet S/D":CLR["gray_bg"],
        }
        fg_map = {
            "DHCP":CLR["blue_fg"],"NAT":CLR["green_fg"],
            "IGMP":CLR["amber_fg"],"Packet S/D":CLR["gray_fg"],
        }

        for name, plugin in PLUGIN_REGISTRY.items():
            card = tk.Frame(scroll_f, bg=CLR["panel"],
                            highlightbackground=CLR["border"], highlightthickness=1)
            card.pack(fill="x", pady=5)

            # 아이콘
            icon_f = tk.Frame(card, bg=bg_map.get(name, CLR["gray_bg"]),
                              width=44, height=44)
            icon_f.pack_propagate(False)
            icon_f.pack(side="left", padx=10, pady=10)
            tk.Label(icon_f, text=icon_map.get(name,"•"),
                     bg=bg_map.get(name,CLR["gray_bg"]),
                     fg=fg_map.get(name,CLR["gray_fg"]),
                     font=_font(16, bold=True)).pack(expand=True)

            info_f = tk.Frame(card, bg=CLR["panel"])
            info_f.pack(side="left", fill="both", expand=True, pady=8)
            tk.Label(info_f, text=name, bg=CLR["panel"],
                     font=_font(12, bold=True), fg=CLR["text"]).pack(anchor="w")
            tk.Label(info_f, text=plugin.DESCRIPTION, bg=CLR["panel"],
                     font=_font(9), fg=CLR["text3"]).pack(anchor="w")
            tk.Label(info_f, text=f"v{plugin.VERSION}", bg=CLR["panel"],
                     font=_font(9, mono=True), fg=CLR["text3"]).pack(anchor="w")

            right_f = tk.Frame(card, bg=CLR["panel"])
            right_f.pack(side="right", padx=10, pady=10)
            tk.Button(right_f, text="파라미터 설정",
                      bg=CLR["bg2"], fg=CLR["text2"],
                      font=_font(9), relief="flat", cursor="hand2",
                      command=lambda n=name, p=plugin: self._open_params(n, p)
                      ).pack(anchor="e")
            en_var = BooleanVar(value=False)
            tk.Checkbutton(right_f, text="활성화", variable=en_var,
                           bg=CLR["panel"], font=_font(9),
                           command=lambda v=en_var, p=plugin: setattr(p,"enabled",v.get())
                           ).pack(anchor="e", pady=4)

    def _open_params(self, name: str, plugin):
        params = plugin.get_params()
        if not params:
            messagebox.showinfo("파라미터", "설정 가능한 파라미터가 없습니다.", parent=self)
            return
        dlg = Toplevel(self)
        dlg.title(f"{name} 파라미터 설정")
        dlg.geometry("320x" + str(80 + len(params)*38))
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg=CLR["bg"])
        tk.Label(dlg, text=f"{name} 설정", bg=CLR["bg"],
                 font=_font(11, bold=True), fg=CLR["text"]).pack(padx=16, pady=(12,6), anchor="w")
        vars_ = {}
        for p in params:
            row = tk.Frame(dlg, bg=CLR["bg"])
            row.pack(fill="x", padx=16, pady=3)
            tk.Label(row, text=p.label, bg=CLR["bg"],
                     font=_font(10), fg=CLR["text3"], width=16, anchor="w").pack(side="left")
            v = StringVar(value=str(plugin.get_param(p.key)))
            vars_[p.key] = v
            if p.type == "choice":
                ttk.Combobox(row, textvariable=v, values=p.choices,
                             state="readonly", width=14).pack(side="left")
            else:
                ttk.Entry(row, textvariable=v, width=16).pack(side="left")

        def apply():
            for k, v in vars_.items():
                pd = next((x for x in params if x.key==k), None)
                raw = v.get()
                if pd and pd.type == "int":   raw = int(raw)
                if pd and pd.type == "float": raw = float(raw)
                plugin.set_param(k, raw)
            dlg.destroy()

        tk.Button(dlg, text="적용", bg=CLR["blue_mid"], fg="white",
                  font=_font(10), relief="flat", cursor="hand2",
                  command=apply).pack(pady=10, ipadx=20)


# ══════════════════════════════════════════════
# 탭 — 기능 검증
# ══════════════════════════════════════════════

class FuncVerifyTab(tk.Frame):
    """기능 검증 탭 — 좌측 플러그인 목록 + 우측 검증 화면 (추후 각 플러그인별 구현)"""

    # 플러그인별 아이콘/색상
    PLUGIN_META = {
        "DHCP":       ("■", CLR["blue_bg"],   CLR["blue_fg"],   CLR["blue_mid"]),
        "NAT":        ("⇄", CLR["green_bg"],  CLR["green_fg"],  CLR["green_mid"]),
        "IGMP":       ("◉", CLR["amber_bg"],  CLR["amber_fg"],  CLR["amber_mid"]),
        "Packet S/D": ("≈", CLR["gray_bg"],   CLR["gray_fg"],   CLR["border2"]),
    }

    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self._selected: str | None = None
        self._build()

    def _build(self):
        # ── 좌측 플러그인 목록 패널 ───────────────
        sidebar = tk.Frame(self, bg=CLR["bg2"], width=200,
                           highlightbackground=CLR["border"], highlightthickness=1)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="플러그인 선택", bg=CLR["bg2"],
                 font=_font(9), fg=CLR["text3"]).pack(
                 anchor="w", padx=12, pady=(12, 6))

        tk.Frame(sidebar, bg=CLR["border"], height=1).pack(fill="x", padx=8)

        self._sidebar_buttons: dict[str, tk.Frame] = {}
        plugin_scroll = tk.Frame(sidebar, bg=CLR["bg2"])
        plugin_scroll.pack(fill="both", expand=True, padx=8, pady=8)

        for name in PLUGIN_REGISTRY:
            icon, bg, fg, mid = self.PLUGIN_META.get(
                name, ("•", CLR["gray_bg"], CLR["gray_fg"], CLR["border2"]))

            btn_frame = tk.Frame(plugin_scroll, bg=CLR["bg2"],
                                 highlightbackground=CLR["border"],
                                 highlightthickness=1, cursor="hand2")
            btn_frame.pack(fill="x", pady=3)

            icon_box = tk.Frame(btn_frame, bg=bg, width=32, height=32)
            icon_box.pack_propagate(False)
            icon_box.pack(side="left", padx=6, pady=6)
            tk.Label(icon_box, text=icon, bg=bg, fg=fg,
                     font=_font(13, bold=True)).pack(expand=True)

            text_box = tk.Frame(btn_frame, bg=CLR["bg2"])
            text_box.pack(side="left", fill="both", expand=True, pady=6)
            tk.Label(text_box, text=name, bg=CLR["bg2"],
                     font=_font(11, bold=True), fg=CLR["text"]).pack(anchor="w")
            tk.Label(text_box, text="표준 검증", bg=CLR["bg2"],
                     font=_font(8), fg=CLR["text3"]).pack(anchor="w")

            # 선택 표시용 컬러바 (좌측)
            color_bar = tk.Frame(btn_frame, bg=CLR["bg2"], width=3)
            color_bar.pack(side="left", fill="y")

            self._sidebar_buttons[name] = (btn_frame, color_bar, mid)

            # 클릭 이벤트 — 모든 자식 위젯에도 바인딩
            for w in [btn_frame, icon_box, text_box, color_bar] + \
                     list(icon_box.winfo_children()) + \
                     list(text_box.winfo_children()):
                w.bind("<Button-1>", lambda e, n=name: self._select_plugin(n))

        # ── 우측 콘텐츠 패널 ─────────────────────
        self._content = tk.Frame(self, bg=CLR["bg"])
        self._content.pack(side="left", fill="both", expand=True)

        # 초기 안내 화면
        self._show_welcome()

    def _select_plugin(self, name: str):
        if self._selected == name:
            return
        self._selected = name

        # 사이드바 버튼 하이라이트 갱신
        for n, (frame, bar, mid) in self._sidebar_buttons.items():
            if n == name:
                frame.config(highlightbackground=mid)
                bar.config(bg=mid)
            else:
                frame.config(highlightbackground=CLR["border"])
                bar.config(bg=CLR["bg2"])

        # 콘텐츠 영역 갱신
        for w in self._content.winfo_children():
            w.destroy()
        self._show_plugin_verify(name)
        log.info(f"기능 검증 선택: {name}", source="VERIFY")

    def _show_welcome(self):
        f = tk.Frame(self._content, bg=CLR["bg"])
        f.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(f, text="기능 검증", bg=CLR["bg"],
                 font=_font(18, bold=True), fg=CLR["text"]).pack(pady=(0, 8))
        tk.Label(f, text="좌측 목록에서 검증할 플러그인을 선택하세요.",
                 bg=CLR["bg"], font=_font(11), fg=CLR["text3"]).pack()

    def _show_plugin_verify(self, name: str):
        """플러그인별 기능 검증 화면 — 추후 각 플러그인 전용 UI로 교체 예정"""
        plugin = PLUGIN_REGISTRY.get(name)
        icon, bg, fg, mid = self.PLUGIN_META.get(
            name, ("•", CLR["gray_bg"], CLR["gray_fg"], CLR["border2"]))

        # ── 헤더 ────────────────────────────────
        hdr = tk.Frame(self._content, bg=CLR["bg2"],
                       highlightbackground=CLR["border"], highlightthickness=1)
        hdr.pack(fill="x")

        icon_box = tk.Frame(hdr, bg=bg, width=40, height=40)
        icon_box.pack_propagate(False)
        icon_box.pack(side="left", padx=12, pady=8)
        tk.Label(icon_box, text=icon, bg=bg, fg=fg,
                 font=_font(16, bold=True)).pack(expand=True)

        hdr_txt = tk.Frame(hdr, bg=CLR["bg2"])
        hdr_txt.pack(side="left", pady=8)
        tk.Label(hdr_txt, text=f"{name} 기능 검증", bg=CLR["bg2"],
                 font=_font(13, bold=True), fg=CLR["text"]).pack(anchor="w")
        tk.Label(hdr_txt, text=plugin.DESCRIPTION if plugin else "",
                 bg=CLR["bg2"], font=_font(9), fg=CLR["text3"]).pack(anchor="w")

        ver_badge = tk.Label(hdr, text=f"v{plugin.VERSION}" if plugin else "",
                             bg=bg, fg=fg, font=_font(9, bold=True), padx=8, pady=3)
        ver_badge.pack(side="right", padx=12)

        # ── 검증 항목 테이블 ───────────────────
        body = tk.Frame(self._content, bg=CLR["bg"])
        body.pack(fill="both", expand=True, padx=16, pady=12)

        # 안내 문구 (플러그인 전용 UI 개발 전)
        placeholder = tk.Frame(body, bg=CLR["panel"],
                               highlightbackground=mid,
                               highlightthickness=1)
        placeholder.pack(fill="both", expand=True)

        inner = tk.Frame(placeholder, bg=CLR["panel"])
        inner.place(relx=0.5, rely=0.35, anchor="center")

        tk.Label(inner, text=icon, bg=CLR["panel"], fg=fg,
                 font=_font(36)).pack(pady=(0, 8))
        tk.Label(inner, text=f"{name} 표준 검증 모듈",
                 bg=CLR["panel"], font=_font(14, bold=True),
                 fg=CLR["text"]).pack()
        tk.Label(inner,
                 text="이 영역은 추후 플러그인별 표준 검증 로직으로 구현됩니다.\n"
                      "RFC 준수 검사 / 패킷 시퀀스 검증 / 성능 측정 등이 포함될 예정입니다.",
                 bg=CLR["panel"], font=_font(10), fg=CLR["text3"],
                 justify="center").pack(pady=8)

        # 검증 항목 예시 목록
        items_map = {
            "DHCP": [
                ("DISCOVER → OFFER → REQUEST → ACK 시퀀스", "RFC 2131 §4.1"),
                ("Lease Time 협상 검증",                     "RFC 2131 §4.4"),
                ("IP 주소 풀 범위 검증",                     "서버 설정"),
                ("DHCP NACK 처리 검증",                      "RFC 2131 §4.3.6"),
                ("갱신(Renew) / 재바인딩(Rebind) 검증",      "RFC 2131 §4.4.5"),
            ],
            "NAT": [
                ("포트 포워딩 규칙 생성/삭제",               "NAT RFC 3022"),
                ("세션 테이블 생성 검증",                     "내부 기준"),
                ("WAN→LAN 트래픽 변환 정확성",               "패킷 분석"),
                ("세션 타임아웃 동작",                        "설정값 기준"),
            ],
            "IGMP": [
                ("Membership Report (Join) 수신",             "RFC 3376 §4"),
                ("Leave Group 처리",                          "RFC 3376 §5"),
                ("Query 응답 타이밍 검증",                    "RFC 3376 §8.2"),
                ("멀티캐스트 트래픽 전달 검증",               "L2 스위칭"),
            ],
            "Packet S/D": [
                ("패킷 송신 성공률",                          "손실률 < 임계값"),
                ("왕복 지연(RTT) 측정",                       "ms 단위"),
                ("처리량(Throughput) 측정",                   "Mbps"),
                ("패킷 크기별 성능 검증",                     "64B ~ 1500B"),
            ],
        }
        items = items_map.get(name, [("검증 항목 준비 중", "—")])

        tbl = tk.Frame(inner, bg=CLR["panel"])
        tbl.pack(pady=(8, 0), fill="x")

        # 헤더
        for ci, (txt, w) in enumerate([("검증 항목", 280), ("기준", 140)]):
            tk.Label(tbl, text=txt, bg=CLR["bg2"], fg=CLR["text3"],
                     font=_font(9, bold=True), width=w//8, anchor="w",
                     padx=8, pady=4).grid(row=0, column=ci, sticky="ew", padx=1, pady=1)

        for ri, (item, ref) in enumerate(items, 1):
            row_bg = CLR["panel"] if ri % 2 == 0 else CLR["bg2"]
            tk.Label(tbl, text=item, bg=row_bg, fg=CLR["text"],
                     font=_font(9), anchor="w", padx=8, pady=3,
                     width=35).grid(row=ri, column=0, sticky="ew", padx=1, pady=1)
            tk.Label(tbl, text=ref, bg=row_bg, fg=CLR["text3"],
                     font=_font(8), anchor="w", padx=8, pady=3,
                     width=17).grid(row=ri, column=1, sticky="ew", padx=1, pady=1)

        tk.Label(inner,
                 text="플러그인 개발 완료 후 각 항목별 실행 버튼이 활성화됩니다.",
                 bg=CLR["panel"], font=_font(8), fg=CLR["text3"]).pack(pady=(10, 0))


# ══════════════════════════════════════════════
# 탭 6 — 환경설정
# ══════════════════════════════════════════════

class SettingsTab(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=CLR["bg"])
        self.app = app
        self._build()

    def _build(self):
        tk.Label(self, text="환경설정", bg=CLR["bg"],
                 font=_font(13, bold=True), fg=CLR["text"]).pack(
                 pady=(16,8), padx=24, anchor="w")

        fr = tk.LabelFrame(self, text="기본 경로",
                           bg=CLR["bg"], font=_font(10), fg=CLR["text3"],
                           relief="flat", highlightbackground=CLR["border"],
                           highlightthickness=1)
        fr.pack(fill="x", padx=24, pady=8)

        self._cfg_vars: dict[str, StringVar | IntVar] = {}

        def entry_row(label, key, browse=False):
            row = tk.Frame(fr, bg=CLR["bg"])
            row.pack(fill="x", padx=14, pady=5)
            tk.Label(row, text=label, bg=CLR["bg"],
                     font=_font(10), fg=CLR["text3"], width=16, anchor="w").pack(side="left")
            v = StringVar(value=self.app.config.get(key,""))
            self._cfg_vars[key] = v
            ttk.Entry(row, textvariable=v, font=_font(10), width=32).pack(side="left", padx=4)
            if browse:
                tk.Button(row, text="…", bg=CLR["bg2"], fg=CLR["text"],
                          font=_font(10), relief="flat", cursor="hand2",
                          command=lambda k=key: self._browse(k)).pack(side="left")

        entry_row("보고서 저장 경로", "report_dir", browse=True)
        entry_row("로그 파일 경로",  "log_dir",    browse=True)

        fr2 = tk.LabelFrame(self, text="타이밍 설정",
                            bg=CLR["bg"], font=_font(10), fg=CLR["text3"],
                            relief="flat", highlightbackground=CLR["border"],
                            highlightthickness=1)
        fr2.pack(fill="x", padx=24, pady=8)

        for label, key, low, high in [
            ("인터페이스 감지 주기(s)", "auto_detect_sec", 1, 60),
            ("패킷 타임아웃(ms)",       "pkt_timeout_ms",  100, 30000),
        ]:
            row = tk.Frame(fr2, bg=CLR["bg"])
            row.pack(fill="x", padx=14, pady=5)
            tk.Label(row, text=label, bg=CLR["bg"],
                     font=_font(10), fg=CLR["text3"], width=20, anchor="w").pack(side="left")
            v = IntVar(value=self.app.config.get(key, 5))
            self._cfg_vars[key] = v
            ttk.Spinbox(row, textvariable=v, from_=low, to=high,
                        width=8, font=_font(10)).pack(side="left", padx=4)

        tk.Button(self, text="설정 저장", bg=CLR["blue_mid"], fg="white",
                  font=_font(10), relief="flat", cursor="hand2",
                  command=self._save).pack(pady=12, ipadx=24)

        # 버전 정보
        sep = tk.Frame(self, bg=CLR["border"], height=1)
        sep.pack(fill="x", padx=24, pady=8)
        tk.Label(self, text=f"{APP_NAME}  {APP_VERSION}",
                 bg=CLR["bg"], font=_font(9), fg=CLR["text3"]).pack()
        tk.Label(self, text="PyInstaller 빌드 대응 · Windows 전용",
                 bg=CLR["bg"], font=_font(9), fg=CLR["text3"]).pack()

    def _browse(self, key: str):
        d = filedialog.askdirectory(title="경로 선택", parent=self)
        if d and key in self._cfg_vars:
            self._cfg_vars[key].set(d)

    def _save(self):
        for key, v in self._cfg_vars.items():
            self.app.config[key] = v.get()
        save_config(self.app.config)
        messagebox.showinfo("저장", "환경설정이 저장되었습니다.", parent=self)


# ══════════════════════════════════════════════
# 메인 앱
# ══════════════════════════════════════════════

class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  {APP_VERSION}")
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(bg=CLR["bg"])
        self.config = load_config()

        self._setup_style()
        self._build_ui()

        # ── 환경 체크 (Scapy / Npcap) ─────────────
        # withdraw로 메인창 숨긴 채로 체크 → 완료 후 deiconify
        self.withdraw()
        self.after(100, self._run_env_check)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _run_env_check(self):
        """앱 표시 전 환경 체크 수행"""
        env = check_environment(parent=self)
        self._env = env

        # 결과 로깅
        log.info(f"{APP_NAME} {APP_VERSION} 시작", source="SYSTEM")
        log.info(f"Python {sys.version.split()[0]}", source="SYSTEM")
        log.info(f"Scapy: {'OK' if env.scapy_ok else '미설치'} | "
                 f"Npcap: {'OK' if env.npcap_ok else '미설치'} | "
                 f"모드: {env.mode.upper()}",
                 source="SYSTEM")

        # 모드 배지 타이틀바에 표시
        mode_text  = "● 실제 패킷 모드" if env.mode == "real" else "● 시뮬레이션 모드"
        mode_color = CLR["green_fg"]    if env.mode == "real" else CLR["amber_fg"]
        if hasattr(self, "_mode_lbl"):
            self._mode_lbl.config(text=mode_text, fg=mode_color)

        # 시뮬 모드면 Syslog에 안내
        if env.mode == "sim":
            log.warn(
                "시뮬레이션 모드 동작 중 — 실제 패킷 없음. "
                "Scapy + Npcap 설치 후 재실행하면 실제 모드로 전환됩니다.",
                source="SYSTEM"
            )

        # 창 표시
        self.deiconify()

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # ── 입력 위젯 다크 테마 ────────────────────
        style.configure("TEntry",
                        fieldbackground=CLR["panel"],
                        foreground=CLR["text"],
                        insertcolor=CLR["text"],
                        bordercolor=CLR["border"],
                        relief="flat")
        style.configure("TCombobox",
                        fieldbackground=CLR["panel"],
                        foreground=CLR["text"],
                        selectbackground=CLR["blue_mid"],
                        arrowcolor=CLR["text2"])
        style.map("TCombobox",
                  fieldbackground=[("readonly", CLR["panel"])],
                  foreground=[("readonly", CLR["text"])])
        style.configure("TSpinbox",
                        fieldbackground=CLR["panel"],
                        foreground=CLR["text"],
                        arrowcolor=CLR["text2"],
                        bordercolor=CLR["border"])

        # ── Treeview 다크 ─────────────────────────
        style.configure("Treeview",
                        background=CLR["panel"],
                        fieldbackground=CLR["panel"],
                        foreground=CLR["text"],
                        rowheight=26,
                        font=_font(10),
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background=CLR["bg2"],
                        foreground=CLR["text2"],
                        font=_font(9, bold=True),
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", CLR["blue_mid"])],
                  foreground=[("selected", "#FFFFFF")])

        # ── 스크롤바 / 프로그레스바 ───────────────
        style.configure("TScrollbar",
                        background=CLR["border"],
                        troughcolor=CLR["bg2"],
                        arrowcolor=CLR["text3"],
                        borderwidth=0)
        style.configure("TProgressbar",
                        background=CLR["blue_mid"],
                        troughcolor=CLR["border"],
                        borderwidth=0)

    def _build_ui(self):
        # ── 타이틀바 ────────────────────────────────
        titlebar = tk.Frame(self, bg=CLR["bg2"], height=36,
                            highlightbackground=CLR["border"], highlightthickness=1)
        titlebar.pack(fill="x")
        titlebar.pack_propagate(False)

        dot_r = tk.Label(titlebar, text="●", bg=CLR["bg2"],
                         fg="#FF5F57", font=_font(11), cursor="hand2")
        dot_r.pack(side="left", padx=(10,0))
        dot_r.bind("<Button-1>", lambda e: self._on_close())
        dot_r.bind("<Enter>",    lambda e: dot_r.config(text="✕"))
        dot_r.bind("<Leave>",    lambda e: dot_r.config(text="●"))

        dot_y = tk.Label(titlebar, text="●", bg=CLR["bg2"],
                         fg="#FEBC2E", font=_font(11), cursor="hand2")
        dot_y.pack(side="left", padx=(4,0))
        dot_y.bind("<Button-1>", lambda e: self.iconify())
        dot_y.bind("<Enter>",    lambda e: dot_y.config(text="–"))
        dot_y.bind("<Leave>",    lambda e: dot_y.config(text="●"))

        dot_g = tk.Label(titlebar, text="●", bg=CLR["bg2"],
                         fg="#28C840", font=_font(11), cursor="hand2")
        dot_g.pack(side="left", padx=(4,0))
        dot_g.bind("<Button-1>", lambda e: self._toggle_maximize())
        dot_g.bind("<Enter>",    lambda e: dot_g.config(text="□"))
        dot_g.bind("<Leave>",    lambda e: dot_g.config(text="●"))

        tk.Label(titlebar, text=f"{APP_NAME}  {APP_VERSION}",
                 bg=CLR["bg2"], fg=CLR["text2"],
                 font=_font(10)).pack(expand=True)

        # 모드 배지 (환경 체크 후 업데이트됨)
        self._mode_lbl = tk.Label(titlebar,
                                  text="● 확인 중...",
                                  bg=CLR["bg2"], fg=CLR["text3"],
                                  font=_font(9))
        self._mode_lbl.pack(side="right", padx=12)

        # ── 커스텀 탭바 (크기 고정, 색만 변경) ────────
        self._tabbar = tk.Frame(self, bg=CLR["bg2"], height=38)
        self._tabbar.pack(fill="x")
        self._tabbar.pack_propagate(False)

        # 탭 컨텐츠 컨테이너
        self._tab_container = tk.Frame(self, bg=CLR["bg"])
        self._tab_container.pack(fill="both", expand=True)

        # 탭 정의: 토폴로지 → 기능 검증 → 시나리오 검증 → Syslog → 결과서 → 환경설정
        self.topo_tab     = TopologyTab(self._tab_container, self)
        self.verify_tab   = FuncVerifyTab(self._tab_container, self)
        self.sc_tab       = ScenarioTab(self._tab_container, self)
        self.syslog_tab   = SyslogTab(self._tab_container, self)
        self.report_tab   = ReportTab(self._tab_container, self)
        self.settings_tab = SettingsTab(self._tab_container, self)

        tab_defs = [
            ("토폴로지",    self.topo_tab),
            ("기능 검증",   self.verify_tab),
            ("시나리오 검증", self.sc_tab),
            ("Syslog",      self.syslog_tab),
            ("결과서",      self.report_tab),
            ("환경설정",    self.settings_tab),
        ]

        self._tab_frames  = [t for _, t in tab_defs]
        self._tab_buttons = []
        self._current_tab = 0

        for i, (label, _) in enumerate(tab_defs):
            btn = tk.Label(
                self._tabbar, text=f"  {label}  ",
                bg=CLR["panel"] if i == 0 else CLR["bg2"],
                fg=CLR["blue_fg"] if i == 0 else CLR["text2"],
                font=_font(10, bold=(i==0)),
                cursor="hand2",
                padx=4, pady=8,
            )
            btn.pack(side="left")
            btn.bind("<Button-1>", lambda e, idx=i: self._switch_tab(idx))
            btn.bind("<Enter>",    lambda e, b=btn, idx=i: b.config(
                bg=CLR["panel"] if idx==self._current_tab else CLR["border"]))
            btn.bind("<Leave>",    lambda e, b=btn, idx=i: b.config(
                bg=CLR["panel"] if idx==self._current_tab else CLR["bg2"]))
            self._tab_buttons.append(btn)

        # 하단 구분선
        tk.Frame(self._tabbar, bg=CLR["border"], width=1).pack(
            side="left", fill="y", pady=6)

        # 첫 탭 표시
        self._switch_tab(0)

    def _switch_tab(self, idx: int):
        # 이전 탭 숨기기
        for f in self._tab_frames:
            f.pack_forget()
        # 버튼 스타일 리셋
        for i, btn in enumerate(self._tab_buttons):
            if i == idx:
                btn.config(bg=CLR["panel"], fg=CLR["blue_fg"],
                           font=_font(10, bold=True))
            else:
                btn.config(bg=CLR["bg2"], fg=CLR["text2"],
                           font=_font(10, bold=False))
        # 새 탭 표시
        self._tab_frames[idx].pack(fill="both", expand=True)
        self._current_tab = idx

    def _toggle_maximize(self):
        if self.state() == "zoomed":
            self.state("normal")
        else:
            self.state("zoomed")

    def _on_close(self):
        if self.sc_tab.engine.is_running:
            if not messagebox.askyesno("종료 확인",
                "시나리오가 실행 중입니다. 종료하시겠습니까?", parent=self):
                return
            self.sc_tab.engine.stop()
        log.info("앱 종료", source="SYSTEM")
        self.destroy()


# ──────────────────────────────────────────────
# 진입점
# ──────────────────────────────────────────────

def _is_admin() -> bool:
    """현재 프로세스가 관리자 권한인지 확인"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return True   # Windows 아닌 환경은 무시


def _relaunch_as_admin():
    """UAC 요청으로 관리자 권한 재실행"""
    import ctypes, sys
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas",
            sys.executable,
            " ".join(f'"{a}"' for a in sys.argv),
            None, 1
        )
    except Exception:
        pass


if __name__ == "__main__":
    import sys

    # Windows에서 관리자 권한 필요 (netsh, Scapy RAW 소켓)
    if sys.platform == "win32" and not _is_admin():
        import tkinter as _tk
        import tkinter.messagebox as _mb
        _root = _tk.Tk()
        _root.withdraw()
        answer = _mb.askyesno(
            "관리자 권한 필요",
            "AP Verify Tool은 관리자 권한이 필요합니다.\n\n"
            "• IP 설정 (netsh)\n"
            "• 패킷 송수신 (Scapy / Npcap)\n"
            "• 연결상태 확인 (ARP / ICMP)\n\n"
            "관리자 권한으로 재실행하시겠습니까?",
        )
        _root.destroy()
        if answer:
            _relaunch_as_admin()
        sys.exit(0)

    app = App()
    app.mainloop()
