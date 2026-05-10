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
from virtual_mac_manager import (VirtualMAC, VirtualMACGroup,
                                  create_manager, generate_mac,
                                  is_valid_mac, random_mac)
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
        self._vmac_manager = create_manager()
        self._vmac_manager.on_state_change = self._on_vmac_state_change
        # AP 감지 정보: {"mac_wan": str, "mac_lan": str, "mode": "NAT"|"Bridge"|"",
        #                "ip_wan": str, "ip_lan": str, "vendor": str, "detected": bool}
        self._ap_info: dict = {"detected": False}
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
        # ── 서브탭 헤더: 인터페이스 | 플러그인 ───────
        subtab_bar = tk.Frame(parent, bg=CLR["bg2"])
        subtab_bar.pack(fill="x")

        self._left_panel_iface  = tk.Frame(parent, bg=CLR["bg2"])
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
                                           cursor="hand2", padx=10, pady=7)
        self._btn_subtab_plugin = tk.Label(subtab_bar, text="플러그인",
                                           bg=CLR["bg2"], fg=CLR["text2"],
                                           font=_font(10, bold=False),
                                           cursor="hand2", padx=10, pady=7)
        self._btn_subtab_iface.pack(side="left")
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
            self._left_panel_plugin.pack_forget()
            self._left_panel_iface.pack(fill="both", expand=True)
            _style_btn(self._btn_subtab_iface,  True)
            _style_btn(self._btn_subtab_plugin, False)
            self._btn_refresh.pack(side="right", padx=6)

        def _show_plugin():
            self._left_panel_iface.pack_forget()
            self._left_panel_plugin.pack(fill="both", expand=True)
            _style_btn(self._btn_subtab_iface,  False)
            _style_btn(self._btn_subtab_plugin, True)
            self._btn_refresh.pack_forget()

        self._btn_subtab_iface.bind("<Button-1>",  lambda e: _show_iface())
        self._btn_subtab_plugin.bind("<Button-1>", lambda e: _show_plugin())

        # hover
        for btn, show in [(self._btn_subtab_iface, _show_iface),
                          (self._btn_subtab_plugin, _show_plugin)]:
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=CLR["border"])
                     if b.cget("bg") == CLR["bg2"] else None)
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=CLR["bg2"])
                     if b.cget("bg") == CLR["border"] else None)

        # ── 인터페이스 패널 내용 ───────────────────
        self._build_iface_panel(self._left_panel_iface)

        # ── 플러그인 패널 내용 ────────────────────
        self._build_plugin_panel(self._left_panel_plugin)

        # 기본: 인터페이스 표시
        self._left_panel_iface.pack(fill="both", expand=True)

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
        self.canvas.bind("<Configure>", lambda e: self._draw_topology())

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
        self._btn_start = tk.Button(parent, text="▶  테스트 시작",
                                    bg=CLR["blue_mid"], fg="white",
                                    command=self._start_test, **btn_cfg)
        self._btn_start.pack(side="left", padx=(8,4), pady=6)

        self._btn_stop = tk.Button(parent, text="■  중지",
                                   bg=CLR["panel"], fg=CLR["text2"],
                                   highlightbackground=CLR["border"], highlightthickness=1,
                                   command=self._stop_test, **btn_cfg)
        self._btn_stop.pack(side="left", padx=4, pady=6)

        tk.Button(parent, text="＋ 인터페이스 추가",
                  bg=CLR["panel"], fg=CLR["text2"],
                  highlightbackground=CLR["border"], highlightthickness=1,
                  command=self._add_iface, **btn_cfg).pack(side="left", padx=4, pady=6)

        # 연결상태 확인 버튼 (ARP → Ping)
        self._btn_conn = tk.Button(parent, text="🔗 연결상태 확인",
                                   bg=CLR["panel"], fg=CLR["text2"],
                                   highlightbackground=CLR["border"], highlightthickness=1,
                                   command=self._check_connectivity, **btn_cfg)
        self._btn_conn.pack(side="left", padx=4, pady=6)

        # AP 감지 버튼
        self._btn_ap = tk.Button(parent, text="📡 AP 감지",
                                 bg=CLR["amber_bg"], fg=CLR["amber_fg"],
                                 highlightbackground=CLR["amber_mid"], highlightthickness=1,
                                 command=self._detect_ap, **btn_cfg)
        self._btn_ap.pack(side="left", padx=4, pady=6)

        # 통계 배지
        self._lbl_ok   = tk.Label(parent, text="● OK: 0",   bg=CLR["green_bg"],
                                   fg=CLR["green_fg"], font=_font(10), padx=8, pady=3)
        self._lbl_warn = tk.Label(parent, text="● 지연: 0", bg=CLR["amber_bg"],
                                   fg=CLR["amber_fg"], font=_font(10), padx=8, pady=3)
        self._lbl_err  = tk.Label(parent, text="● 실패: 0", bg=CLR["red_bg"],
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

        # IP 설정 버튼 + 가상 MAC 버튼
        btn_row2 = tk.Frame(card, bg=CLR["panel"])
        btn_row2.pack(fill="x", padx=6, pady=(0,6))
        tk.Button(btn_row2, text="IP 설정", font=_font(9), relief="flat",
                  bg=CLR["bg2"], fg=CLR["text2"], cursor="hand2",
                  command=lambda n=name: self._open_ip_dialog(n)).pack(
                  side="left", padx=2)
        tk.Button(btn_row2, text="가상 MAC", font=_font(9), relief="flat",
                  bg=CLR["purple_bg"], fg=CLR["purple_fg"], cursor="hand2",
                  command=lambda n=name: self._open_vmac_dialog(n)).pack(
                  side="left", padx=2)

        # 가상 MAC 카운트 배지
        group = self._vmac_manager.get_group(name)
        n_vmac = len(group.entries)
        if n_vmac > 0:
            n_bound = sum(1 for e in group.entries if e.state == "bound")
            tk.Label(btn_row2, text=f"MAC {n_bound}/{n_vmac}",
                     bg=CLR["purple_bg"], fg=CLR["purple_fg"],
                     font=_font(8, bold=True), padx=5).pack(side="right", padx=4)

        # 카드 내 모든 위젯에 스크롤 전파
        self.after(50, lambda: _bind_scroll(card))

    def _set_role(self, name: str, role: str):
        self._roles[name] = role
        log.info(f"인터페이스 역할 변경: {name} → {role}", source="TOPOLOGY")
        self._refresh_interfaces()

    def _open_ip_dialog(self, name: str):
        dlg = Toplevel(self)
        dlg.title(f"IP 설정 — {name}")
        dlg.geometry("280x200")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg=CLR["bg"])

        tk.Label(dlg, text=f"{name} IP 설정", bg=CLR["bg"],
                 font=_font(11, bold=True), fg=CLR["text"]).pack(padx=16, pady=(12,8), anchor="w")

        mode_var = StringVar(value=self._ip_mode.get(name, "dynamic"))
        mode_frame = tk.Frame(dlg, bg=CLR["bg"])
        mode_frame.pack(fill="x", padx=16)
        tk.Label(mode_frame, text="IP 모드", bg=CLR["bg"], font=_font(9),
                 fg=CLR["text3"]).pack(anchor="w")
        for m, label in [("static","고정"),("dynamic","동적"),("server","서버")]:
            tk.Radiobutton(mode_frame, text=label, variable=mode_var, value=m,
                           bg=CLR["bg"], font=_font(10)).pack(side="left", padx=6)

        tk.Label(dlg, text="IP 주소", bg=CLR["bg"], font=_font(9),
                 fg=CLR["text3"]).pack(anchor="w", padx=16, pady=(8,2))
        ip_var = StringVar(value=self._custom_ip.get(name, self._ifaces[
            next((i for i,f in enumerate(self._ifaces) if f["name"]==name), 0)]["ip"]))
        ip_entry = ttk.Entry(dlg, textvariable=ip_var, font=_font(10))
        ip_entry.pack(fill="x", padx=16)

        def apply():
            self._ip_mode[name]   = mode_var.get()
            self._custom_ip[name] = ip_var.get()
            log.info(f"{name} IP설정 적용: {mode_var.get()} / {ip_var.get()}", source="TOPOLOGY")
            dlg.destroy()
            self._draw_topology()

        tk.Button(dlg, text="적용", bg=CLR["blue_mid"], fg="white",
                  font=_font(10), relief="flat", cursor="hand2",
                  command=apply).pack(pady=12, ipadx=20)

    # ── 토폴로지 그래픽 ────────────────────────

    def _draw_topology(self):
        cv = self.canvas
        cv.delete("all")
        w = cv.winfo_width()
        h = cv.winfo_height()
        if w < 50 or h < 50:
            return

        masters = [n for n, r in self._roles.items() if r == "master"]
        slaves  = [n for n, r in self._roles.items() if r == "slave"]
        ap      = self._ap_info
        has_ap  = ap.get("detected", False)

        node_w, node_h = 150, 90
        ap_w,   ap_h   = 160, 100

        if has_ap:
            cx_m  = w // 4
            cx_ap = w // 2
            cx_s  = w * 3 // 4
        else:
            cx_m  = w // 4
            cx_ap = w // 2
            cx_s  = w * 3 // 4

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
            if cb:
                border = cb
            cv.create_rectangle(x1, y1, x2, y2, fill=bg,
                                outline=border, width=2, tags="node")
            if cbadge:
                cv.create_text(x2-6, y1+8, text=cbadge,
                               font=_font(9, bold=True), fill=cfg,
                               anchor="e", tags="node")
            icon = "\U0001f5a5" if role == "master" else "\U0001f4bb"
            cv.create_text(cx, cy-22, text=icon,
                           font=("Segoe UI Emoji", 16), tags="node")
            mtw = node_w - 16
            cv.create_text(cx, cy+4, text=_trim(name, mtw, 10),
                           font=_font(10, bold=True), fill=fg,
                           tags="node", width=mtw)
            iface = next((f for f in self._ifaces if f["name"] == name), None)
            ip = self._custom_ip.get(name, iface["ip"] if iface else "\u2014")
            cv.create_text(cx, cy+20, text=_trim(ip, mtw, 8),
                           font=_font(8, mono=True), fill=CLR["text3"],
                           tags="node", width=mtw)
            role_txt = {"master":"Master","slave":"Slave","none":"\ubbf8\uc9c0\uc815"}[role]
            cv.create_text(cx, cy+36, text=role_txt,
                           font=_font(8, bold=True), fill=fg, tags="node")
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
            cv.create_rectangle(x1, y1, x2, y2, fill=bg,
                                outline=border, width=2,
                                dash=(6, 3), tags="node")
            cv.create_rectangle(x1, y1, x1+46, y1+16,
                                fill=border, outline="", tags="node")
            cv.create_text(x1+23, y1+8, text="DUT AP",
                           font=_font(8, bold=True), fill="white",
                           anchor="center", tags="node")
            cv.create_text(cx, cy-24, text="\U0001f4e1",
                           font=("Segoe UI Emoji", 18), tags="node")
            mode_txt = f"{mode} Mode" if mode else "\uac10\uc9c0 \uc911..."
            cv.create_text(cx, cy+4, text=mode_txt,
                           font=_font(10, bold=True), fill=fg, tags="node")
            wan_mac = ap.get("mac_wan", "")
            lan_mac = ap.get("mac_lan", "")
            vendor  = ap.get("vendor",  "")
            wan_ip  = ap.get("ip_wan",  "")
            lan_ip  = ap.get("ip_lan",  "")
            row = cy + 20
            if wan_ip:
                cv.create_text(cx, row, text=f"WAN: {wan_ip}",
                               font=_font(8, mono=True),
                               fill=CLR["amber_fg"], tags="node")
                row += 12
            if wan_mac:
                cv.create_text(cx, row, text=wan_mac[:17],
                               font=_font(7, mono=True),
                               fill=CLR["text3"], tags="node")
                row += 11
            if lan_ip and mode == "NAT":
                cv.create_text(cx, row, text=f"LAN: {lan_ip}",
                               font=_font(8, mono=True),
                               fill=CLR["green_fg"], tags="node")
                row += 12
            if lan_mac and mode == "NAT":
                cv.create_text(cx, row, text=lan_mac[:17],
                               font=_font(7, mono=True),
                               fill=CLR["text3"], tags="node")
                row += 11
            if vendor:
                cv.create_text(cx, row, text=_trim(vendor, ap_w-10, 8),
                               font=_font(8), fill=CLR["text3"], tags="node")
            self._node_coords["__ap__"] = (cx, cy)

        for i, name in enumerate(masters):
            cy = h//2 + (i - len(masters)//2) * (node_h + 30)
            draw_node(name, cx_m, cy, "master")

        if has_ap:
            draw_ap_node(cx_ap, h//2)

        n_sl = max(len(slaves), 1)
        for i, name in enumerate(slaves):
            cy = h//2 + (i - (n_sl-1)/2) * (node_h + 30)
            draw_node(name, cx_s, cy, "slave")

        def _line_color(n1, n2):
            s1 = self._conn_status.get(n1, "")
            s2 = self._conn_status.get(n2, "")
            if s1 == "ok"       and s2 == "ok":       return CLR["green_mid"], 2
            if s1 == "fail"     or  s2 == "fail":     return CLR["red_mid"],   2
            if s1 == "checking" or  s2 == "checking": return CLR["amber_mid"], 1
            return CLR["border2"], 1

        for m in masters:
            mx, my = self._node_coords.get(m, (cx_m, h//2))
            if has_ap:
                ax, ay = self._node_coords.get("__ap__", (cx_ap, h//2))
                lc, lw = _line_color(m, "__ap__")
                cv.create_line(mx + node_w//2, my, ax - ap_w//2, ay,
                               fill=lc, width=lw, tags="line")
                for s in slaves:
                    sx, sy = self._node_coords.get(s, (cx_s, h//2))
                    lc2, lw2 = _line_color("__ap__", s)
                    cv.create_line(ax + ap_w//2, ay, sx - node_w//2, sy,
                                   fill=lc2, width=lw2, tags="line")
            else:
                for s in slaves:
                    sx, sy = self._node_coords.get(s, (cx_s, h//2))
                    lc, lw = _line_color(m, s)
                    cv.create_line(mx + node_w//2, my, sx - node_w//2, sy,
                                   fill=lc, width=lw, tags="line")

        if not masters and not slaves:
            cv.create_text(w//2, h//2,
                           text="\u2190 \uc778\ud130\ud398\uc774\uc2a4\uc5d0\uc11c Master / Slave\ub97c \uc9c0\uc815\ud558\uc138\uc694",
                           font=_font(11), fill=CLR["text3"])
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
        Master / Slave 인터페이스에서 ARP 스캔 후 AP 위치 및 모드 판별

        Bridge Mode: Master와 Slave 양쪽에서 동일한 MAC이 보임
                     → AP가 패킷을 그대로 투명하게 전달
        NAT Mode:    Master쪽 ARP 테이블에 AP WAN MAC만 보임
                     Slave쪽 ARP 테이블에 AP LAN MAC만 보임
                     → MAC이 달라 NAT 경계로 판단
        """
        masters = [n for n, r in self._roles.items() if r == "master"]
        slaves  = [n for n, r in self._roles.items() if r == "slave"]

        if not masters or not slaves:
            messagebox.showwarning("설정 오류",
                "Master / Slave 인터페이스를 먼저 지정하세요.", parent=self)
            return

        self._btn_ap.config(state="disabled", text="감지 중…")
        self._ap_info = {"detected": False}
        self._conn_status["__ap__"] = "checking"
        self._draw_topology()
        self._mini_log_add("info", "AP 감지 시작 — ARP 스캔 중...")
        log.info("AP 감지 시작", source="TOPOLOGY")

        def _run():
            try:
                from scapy.all import ARP, Ether, srp
            except ImportError:
                self.after(0, lambda: self._ap_detect_done(
                    False, error="Scapy 미설치"))
                return

            m_name = masters[0]
            s_name = slaves[0]
            m_iface_info = next((f for f in self._ifaces if f["name"] == m_name), None)
            s_iface_info = next((f for f in self._ifaces if f["name"] == s_name), None)
            m_ip = self._custom_ip.get(m_name,
                   m_iface_info["ip"] if m_iface_info else "")
            s_ip = self._custom_ip.get(s_name,
                   s_iface_info["ip"] if s_iface_info else "")

            scapy_m = _resolve_scapy_iface(m_name)
            scapy_s = _resolve_scapy_iface(s_name)

            def arp_scan(iface_scapy: str, subnet: str) -> dict[str, str]:
                """서브넷 ARP 스캔 → {IP: MAC} 딕셔너리 반환"""
                if not subnet or subnet in ("—", ""):
                    return {}
                # /24 범위로 스캔
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

            self.after(0, lambda: self._mini_log_add("info",
                f"Master({m_name}) ARP 스캔 중... ({m_ip})"))
            m_arp = arp_scan(scapy_m, m_ip)
            log.info(f"Master ARP 결과: {len(m_arp)}개 호스트", source="TOPOLOGY")

            self.after(0, lambda: self._mini_log_add("info",
                f"Slave({s_name}) ARP 스캔 중... ({s_ip})"))
            s_arp = arp_scan(scapy_s, s_ip)
            log.info(f"Slave ARP 결과: {len(s_arp)}개 호스트", source="TOPOLOGY")

            # ── MAC 비교 분석 ────────────────────────
            m_macs = set(m_arp.values())
            s_macs = set(s_arp.values())

            # PC 자신의 MAC 제외
            my_macs = set()
            try:
                from scapy.arch import get_if_hwaddr
                my_macs.add(get_if_hwaddr(scapy_m).upper())
                my_macs.add(get_if_hwaddr(scapy_s).upper())
            except Exception:
                pass
            m_macs -= my_macs
            s_macs -= my_macs

            self.after(0, lambda mm=m_macs, sm=s_macs: self._mini_log_add("info",
                f"Master 측 MAC: {mm} | Slave 측 MAC: {sm}"))

            common_macs = m_macs & s_macs

            ap_info: dict = {"detected": False}

            if common_macs:
                # Bridge Mode: 동일 MAC이 양쪽에서 보임
                ap_mac = common_macs.pop()
                # 해당 MAC의 IP 찾기
                ap_ip_m = next((ip for ip, mac in m_arp.items()
                                if mac == ap_mac), "")
                ap_info = {
                    "detected":  True,
                    "mode":      "Bridge",
                    "mac_wan":   ap_mac,
                    "mac_lan":   ap_mac,   # Bridge는 동일
                    "ip_wan":    ap_ip_m,
                    "ip_lan":    ap_ip_m,
                    "vendor":    _lookup_vendor(ap_mac),
                }
                self.after(0, lambda: self._mini_log_add("ok",
                    f"Bridge Mode AP 감지! MAC={ap_mac} IP={ap_ip_m}"))
                log.info(f"AP Bridge Mode 감지: {ap_mac}", source="TOPOLOGY")

            elif m_macs and s_macs:
                # NAT Mode 후보: Master쪽과 Slave쪽 MAC이 다름
                # Master쪽에서 보이는 미지 MAC → AP WAN
                # Slave쪽에서 보이는 미지 MAC → AP LAN
                wan_mac = m_macs.pop()
                lan_mac = s_macs.pop()
                wan_ip  = next((ip for ip, mac in m_arp.items()
                                if mac == wan_mac), "")
                lan_ip  = next((ip for ip, mac in s_arp.items()
                                if mac == lan_mac), "")
                ap_info = {
                    "detected":  True,
                    "mode":      "NAT",
                    "mac_wan":   wan_mac,
                    "mac_lan":   lan_mac,
                    "ip_wan":    wan_ip,
                    "ip_lan":    lan_ip,
                    "vendor":    _lookup_vendor(wan_mac),
                }
                self.after(0, lambda: self._mini_log_add("ok",
                    f"NAT Mode AP 감지! WAN={wan_mac}({wan_ip}) "
                    f"LAN={lan_mac}({lan_ip})"))
                log.info(f"AP NAT Mode 감지: WAN={wan_mac} LAN={lan_mac}",
                         source="TOPOLOGY")

            else:
                self.after(0, lambda: self._mini_log_add("info",
                    "AP 감지 실패 — Master/Slave 사이에 AP 없거나 직결 연결"))
                log.info("AP 미감지 (직결 구성으로 판단)", source="TOPOLOGY")

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

    # ── 가상 MAC 콜백 ─────────────────────────

    def _on_vmac_state_change(self, iface: str, entry: VirtualMAC):
        """가상 MAC 상태 변경 시 GUI 업데이트 (백그라운드 스레드 → 메인 스레드)"""
        level = "ok" if entry.state == "bound" else \
                "err" if entry.state == "error" else "info"
        if entry.state == "bound":
            msg = (f"[가상MAC] {entry.mac_short} → {entry.assigned_ip} "
                   f"(Lease {entry.lease_time}s)")
        elif entry.state == "error":
            msg = f"[가상MAC] {entry.mac_short} 실패: {entry.error_msg}"
        else:
            msg = f"[가상MAC] {entry.mac_short} {entry.state}"
        self.after(0, lambda: self._mini_log_add(level, msg))

    # ── 가상 MAC 다이얼로그 ────────────────────

    def _open_vmac_dialog(self, iface_name: str):
        VirtualMACDialog(self, self._vmac_manager, iface_name,
                         on_close=self._refresh_interfaces)

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
# 가상 MAC 관리 다이얼로그
# ══════════════════════════════════════════════

class VirtualMACDialog(Toplevel):
    """인터페이스별 가상 MAC 관리 팝업"""

    STATE_COLOR = {
        "idle":       CLR["text3"],
        "requesting": CLR["amber_fg"],
        "bound":      CLR["green_fg"],
        "released":   CLR["text3"],
        "error":      CLR["red_fg"],
    }
    STATE_LABEL = {
        "idle":       "대기",
        "requesting": "요청중…",
        "bound":      "할당됨",
        "released":   "해제됨",
        "error":      "오류",
    }

    def __init__(self, parent, manager, iface_name: str,
                 on_close=None):
        super().__init__(parent)
        self.title(f"가상 MAC 관리 — {iface_name}")
        self.geometry("720x520")
        self.minsize(620, 400)
        self.configure(bg=CLR["bg"])
        self.grab_set()

        self._mgr        = manager
        self._iface      = iface_name
        self._on_close   = on_close
        self._row_widgets: dict[int, dict] = {}   # index → {ip_lbl, state_lbl, …}

        # 가상 MAC 상태 변경 콜백 등록
        self._prev_cb = manager.on_state_change
        manager.on_state_change = self._on_state_change

        self._build()
        self._refresh_table()
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build(self):
        # ── 헤더 ─────────────────────────────────
        hdr = tk.Frame(self, bg=CLR["bg2"],
                       highlightbackground=CLR["border"], highlightthickness=1)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"가상 MAC — {self._iface}",
                 bg=CLR["bg2"], font=_font(12, bold=True),
                 fg=CLR["text"]).pack(side="left", padx=14, pady=10)

        # 통계 배지
        self._lbl_total = tk.Label(hdr, text="총 0개",
                                   bg=CLR["bg2"], fg=CLR["text3"], font=_font(9))
        self._lbl_total.pack(side="right", padx=8)
        self._lbl_bound = tk.Label(hdr, text="할당 0",
                                   bg=CLR["green_bg"], fg=CLR["green_fg"],
                                   font=_font(9, bold=True), padx=6)
        self._lbl_bound.pack(side="right", padx=4)

        # ── 툴바 ─────────────────────────────────
        tb = tk.Frame(self, bg=CLR["panel"],
                      highlightbackground=CLR["border"], highlightthickness=1)
        tb.pack(fill="x")
        btn_cfg = dict(font=_font(9), relief="flat", cursor="hand2",
                       padx=8, pady=4)

        tk.Button(tb, text="+ MAC 1개 추가", bg=CLR["purple_bg"],
                  fg=CLR["purple_fg"], command=self._add_one, **btn_cfg
                  ).pack(side="left", padx=6, pady=5)

        tk.Button(tb, text="일괄 생성", bg=CLR["bg2"],
                  fg=CLR["text2"], command=self._bulk_add, **btn_cfg
                  ).pack(side="left", padx=2, pady=5)

        tk.Button(tb, text="▶ 전체 DHCP 요청", bg=CLR["blue_mid"],
                  fg="white", command=self._request_all, **btn_cfg
                  ).pack(side="left", padx=6, pady=5)

        tk.Button(tb, text="■ 전체 해제", bg=CLR["red_bg"],
                  fg=CLR["red_fg"], command=self._release_all, **btn_cfg
                  ).pack(side="left", padx=2, pady=5)

        # 프리픽스 설정
        tk.Label(tb, text="OUI 프리픽스:", bg=CLR["panel"],
                 font=_font(9), fg=CLR["text3"]).pack(side="right", padx=(0,4))
        self._prefix_var = StringVar(value=
            self._mgr.get_group(self._iface).prefix)
        ttk.Entry(tb, textvariable=self._prefix_var,
                  width=11, font=_font(9)).pack(side="right", padx=4)

        # ── 테이블 헤더 ───────────────────────────
        col_defs = [
            ("#",       40),  ("MAC 주소",     160),
            ("레이블",  100), ("할당 IP",      130),
            ("서브넷",  120), ("상태",          70),
            ("동작",     80),
        ]
        hdr_row = tk.Frame(self, bg=CLR["bg2"])
        hdr_row.pack(fill="x", padx=6)
        for txt, w in col_defs:
            tk.Label(hdr_row, text=txt, bg=CLR["bg2"], fg=CLR["text3"],
                     font=_font(9, bold=True), width=w//7,
                     anchor="w").pack(side="left", padx=3, pady=4)

        tk.Frame(self, bg=CLR["border"], height=1).pack(fill="x", padx=6)

        # ── 스크롤 테이블 ─────────────────────────
        sc = tk.Frame(self, bg=CLR["bg"])
        sc.pack(fill="both", expand=True, padx=6, pady=4)

        sb = ttk.Scrollbar(sc, orient="vertical")
        sb.pack(side="right", fill="y")

        self._table_cv = tk.Canvas(sc, bg=CLR["bg"],
                                   highlightthickness=0,
                                   yscrollcommand=sb.set)
        self._table_cv.pack(side="left", fill="both", expand=True)
        sb.config(command=self._table_cv.yview)

        self._table_inner = tk.Frame(self._table_cv, bg=CLR["bg"])
        self._table_win = self._table_cv.create_window(
            (0, 0), window=self._table_inner, anchor="nw")

        def _cfg(e): self._table_cv.configure(
            scrollregion=self._table_cv.bbox("all"))
        def _cfw(e): self._table_cv.itemconfig(self._table_win, width=e.width)
        self._table_inner.bind("<Configure>", _cfg)
        self._table_cv.bind("<Configure>", _cfw)
        self._table_cv.bind("<MouseWheel>",
            lambda e: self._table_cv.yview_scroll(
                int(-1*(e.delta/120)), "units"))

        # ── 하단 요약 ──────────────────────────────
        self._summary = tk.Label(self, text="",
                                 bg=CLR["bg2"], fg=CLR["text3"],
                                 font=_font(9, mono=True))
        self._summary.pack(fill="x", padx=10, pady=4)

    def _refresh_table(self):
        for w in self._table_inner.winfo_children():
            w.destroy()
        self._row_widgets.clear()

        group = self._mgr.get_group(self._iface)
        for entry in group.entries:
            self._add_row(entry)

        self._update_stats()

    def _add_row(self, entry: VirtualMAC):
        row = tk.Frame(self._table_inner, bg=CLR["panel"],
                       highlightbackground=CLR["border"], highlightthickness=1)
        row.pack(fill="x", pady=1)

        # 번호
        tk.Label(row, text=f"{entry.index+1:02d}", bg=CLR["panel"],
                 fg=CLR["text3"], font=_font(9), width=3).pack(
                 side="left", padx=4, pady=5)

        # MAC (편집 가능)
        mac_var = StringVar(value=entry.mac)
        mac_entry = ttk.Entry(row, textvariable=mac_var,
                              font=_font(9, mono=True), width=18)
        mac_entry.pack(side="left", padx=3, pady=4)

        def _save_mac(e=None, v=mac_var, idx=entry.index):
            new_mac = v.get().upper()
            if is_valid_mac(new_mac):
                group = self._mgr.get_group(self._iface)
                ent = next((x for x in group.entries if x.index==idx), None)
                if ent:
                    ent.mac = new_mac

        mac_entry.bind("<FocusOut>", _save_mac)
        mac_entry.bind("<Return>",   _save_mac)

        # 레이블
        label_var = StringVar(value=entry.label)
        label_entry = ttk.Entry(row, textvariable=label_var,
                                font=_font(9), width=12)
        label_entry.pack(side="left", padx=3, pady=4)

        def _save_label(e=None, v=label_var, idx=entry.index):
            group = self._mgr.get_group(self._iface)
            ent = next((x for x in group.entries if x.index==idx), None)
            if ent:
                ent.label = v.get()

        label_entry.bind("<FocusOut>", _save_label)

        # IP (읽기전용)
        ip_var = StringVar(value=entry.assigned_ip or "—")
        ip_lbl = tk.Label(row, textvariable=ip_var, bg=CLR["panel"],
                          fg=CLR["green_fg"] if entry.assigned_ip else CLR["text3"],
                          font=_font(9, mono=True), width=16, anchor="w")
        ip_lbl.pack(side="left", padx=3)

        # 서브넷
        mask_var = StringVar(value=entry.subnet_mask or "—")
        tk.Label(row, textvariable=mask_var, bg=CLR["panel"],
                 fg=CLR["text3"], font=_font(9, mono=True),
                 width=14, anchor="w").pack(side="left", padx=3)

        # 상태
        st_col = self.STATE_COLOR.get(entry.state, CLR["text3"])
        state_lbl = tk.Label(row,
                             text=self.STATE_LABEL.get(entry.state, entry.state),
                             bg=CLR["panel"], fg=st_col,
                             font=_font(9, bold=True), width=8)
        state_lbl.pack(side="left", padx=3)

        # 동작 버튼
        act_frame = tk.Frame(row, bg=CLR["panel"])
        act_frame.pack(side="left", padx=4)

        def _req(idx=entry.index):
            self._mgr.request_single(self._iface, idx)

        def _rel(idx=entry.index):
            self._mgr.release_single(self._iface, idx)

        def _del(idx=entry.index):
            self._mgr.remove_mac(self._iface, idx)
            self._refresh_table()

        tk.Button(act_frame, text="요청", font=_font(8), relief="flat",
                  bg=CLR["blue_bg"], fg=CLR["blue_fg"],
                  cursor="hand2", command=_req).pack(side="left", padx=1)
        tk.Button(act_frame, text="해제", font=_font(8), relief="flat",
                  bg=CLR["bg2"], fg=CLR["text3"],
                  cursor="hand2", command=_rel).pack(side="left", padx=1)
        tk.Button(act_frame, text="✕", font=_font(8), relief="flat",
                  bg=CLR["bg2"], fg=CLR["red_fg"],
                  cursor="hand2", command=_del).pack(side="left", padx=1)

        self._row_widgets[entry.index] = {
            "ip_var":    ip_var,
            "mask_var":  mask_var,
            "state_lbl": state_lbl,
            "ip_lbl":    ip_lbl,
        }

    def _on_state_change(self, iface: str, entry: VirtualMAC):
        """상태 변경 → GUI 즉시 갱신"""
        # 이전 콜백도 호출
        if self._prev_cb:
            self._prev_cb(iface, entry)

        if iface != self._iface:
            return

        def _update():
            if entry.index not in self._row_widgets:
                self._refresh_table()
                return
            w = self._row_widgets[entry.index]
            w["ip_var"].set(entry.assigned_ip or "—")
            w["mask_var"].set(entry.subnet_mask or "—")
            st_col = self.STATE_COLOR.get(entry.state, CLR["text3"])
            st_lbl = self.STATE_LABEL.get(entry.state, entry.state)
            w["state_lbl"].config(text=st_lbl, fg=st_col)
            w["ip_lbl"].config(
                fg=CLR["green_fg"] if entry.assigned_ip else CLR["text3"])
            self._update_stats()

        self.after(0, _update)

    def _update_stats(self):
        group = self._mgr.get_group(self._iface)
        total = len(group.entries)
        bound = sum(1 for e in group.entries if e.state == "bound")
        errs  = sum(1 for e in group.entries if e.state == "error")
        self._lbl_total.config(text=f"총 {total}개")
        self._lbl_bound.config(text=f"할당 {bound}")

        ips = [e.assigned_ip for e in group.entries if e.assigned_ip]
        summary = f"할당 IP: {', '.join(ips[:5])}" + \
                  (f" 외 {len(ips)-5}개" if len(ips) > 5 else "")
        if errs:
            summary += f"  |  오류 {errs}개"
        self._summary.config(text=summary)

    # ── 툴바 동작 ─────────────────────────────

    def _add_one(self):
        self._mgr.get_group(self._iface).prefix = self._prefix_var.get()
        entry = self._mgr.add_mac(self._iface,
                                  label=f"가상 MAC #{len(self._mgr.get_group(self._iface).entries)}")
        self._add_row(entry)
        self._update_stats()
        log.info(f"가상 MAC 추가: {entry.mac} ({self._iface})", source="VMAC")

    def _bulk_add(self):
        dlg = Toplevel(self)
        dlg.title("일괄 생성")
        dlg.geometry("260x160")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg=CLR["bg"])

        tk.Label(dlg, text="생성할 MAC 수:", bg=CLR["bg"],
                 font=_font(10), fg=CLR["text"]).pack(padx=16, pady=(14,4), anchor="w")
        cnt_var = IntVar(value=5)
        ttk.Spinbox(dlg, textvariable=cnt_var, from_=1, to=50,
                    width=8, font=_font(10)).pack(padx=16, anchor="w")
        tk.Label(dlg, text="OUI 프리픽스:", bg=CLR["bg"],
                 font=_font(10), fg=CLR["text"]).pack(padx=16, pady=(8,2), anchor="w")
        pfx_var = StringVar(value=self._prefix_var.get())
        ttk.Entry(dlg, textvariable=pfx_var,
                  font=_font(10), width=14).pack(padx=16, anchor="w")

        def _go():
            prefix = pfx_var.get().strip() or "AA:BB:CC"
            self._prefix_var.set(prefix)
            self._mgr.get_group(self._iface).prefix = prefix
            added = self._mgr.add_mac_bulk(self._iface, cnt_var.get(), prefix)
            for e in added:
                self._add_row(e)
            self._update_stats()
            log.info(f"가상 MAC {len(added)}개 일괄 생성 ({self._iface})",
                     source="VMAC")
            dlg.destroy()

        tk.Button(dlg, text="생성", bg=CLR["blue_mid"], fg="white",
                  font=_font(10), relief="flat", cursor="hand2",
                  command=_go).pack(pady=12, ipadx=16)

    def _request_all(self):
        group = self._mgr.get_group(self._iface)
        if not group.entries:
            messagebox.showinfo("알림", "가상 MAC을 먼저 추가하세요.", parent=self)
            return
        log.info(f"가상 MAC {len(group.entries)}개 DHCP 요청 시작 ({self._iface})",
                 source="VMAC")
        threading.Thread(
            target=self._mgr.request_all,
            args=(self._iface,),
            kwargs={"parallel": True},
            daemon=True,
        ).start()

    def _release_all(self):
        self._mgr.release_all(self._iface)

    def _close(self):
        # 콜백 복원
        self._mgr.on_state_change = self._prev_cb
        if self._on_close:
            self._on_close()
        self.destroy()


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

if __name__ == "__main__":
    app = App()
    app.mainloop()
