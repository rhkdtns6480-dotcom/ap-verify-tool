"""
virtual_mac_manager.py — 가상 MAC 관리 및 DHCP IP 할당 모듈

동작 원리:
  - Scapy로 가상 MAC마다 독립적인 DHCP DISCOVER → OFFER → REQUEST → ACK 시퀀스 실행
  - 물리 어댑터 설정 변경 없음 (OS 레벨 IP 할당 아님)
  - 할당받은 IP는 Lease Table로 관리
  - 결과는 콜백으로 GUI에 전달

요구사항:
  pip install scapy
  Windows: Npcap 설치 필요 (https://npcap.com)
  관리자 권한으로 실행
"""
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional


# ──────────────────────────────────────────────
# 데이터 구조
# ──────────────────────────────────────────────

@dataclass
class VirtualMAC:
    """가상 MAC 엔트리"""
    index:      int
    mac:        str           # "AA:BB:CC:DD:EE:FF"
    label:      str = ""      # 사용자 메모
    assigned_ip:str = ""      # DHCP로 할당받은 IP
    subnet_mask:str = ""
    gateway:    str = ""
    lease_time: int = 0       # 초
    state:      str = "idle"  # idle | requesting | bound | released | error
    error_msg:  str = ""
    assigned_at:Optional[datetime] = None

    @property
    def mac_short(self) -> str:
        """마지막 3옥텟만 표시용"""
        parts = self.mac.split(":")
        return ":".join(parts[-3:]) if len(parts) == 6 else self.mac

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "mac":   self.mac,
            "label": self.label,
            "assigned_ip":  self.assigned_ip,
            "subnet_mask":  self.subnet_mask,
            "gateway":      self.gateway,
            "lease_time":   self.lease_time,
            "state":        self.state,
            "error_msg":    self.error_msg,
            "assigned_at":  self.assigned_at.isoformat() if self.assigned_at else "",
        }


@dataclass
class VirtualMACGroup:
    """인터페이스 하나에 속한 가상 MAC 그룹"""
    iface_name: str
    entries:    list[VirtualMAC] = field(default_factory=list)
    prefix:     str = "AA:BB:CC"   # OUI 프리픽스


# ──────────────────────────────────────────────
# MAC 생성 유틸
# ──────────────────────────────────────────────

def generate_mac(index: int, prefix: str = "AA:BB:CC") -> str:
    """인덱스 기반 결정적 MAC 생성 (충돌 없음)"""
    b3 = (index >> 16) & 0xFF
    b4 = (index >>  8) & 0xFF
    b5 =  index        & 0xFF
    parts = prefix.split(":")[:3]
    return f"{parts[0]}:{parts[1]}:{parts[2]}:{b3:02X}:{b4:02X}:{b5:02X}"


def random_mac(prefix: str = "AA:BB:CC") -> str:
    parts = prefix.split(":")[:3]
    tail = [f"{random.randint(0,255):02X}" for _ in range(3)]
    return ":".join(parts + tail)


def is_valid_mac(mac: str) -> bool:
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    try:
        return all(0 <= int(p, 16) <= 255 for p in parts)
    except ValueError:
        return False


# ──────────────────────────────────────────────
# Scapy DHCP 엔진
# ──────────────────────────────────────────────

class ScapyDHCPClient:
    """단일 가상 MAC에 대한 DHCP 클라이언트"""

    def __init__(self, iface: str, mac: str, timeout: int = 5):
        self.iface   = iface
        self.mac     = mac
        self.timeout = timeout
        self._xid    = random.randint(1, 0xFFFFFFFF)

    def request(self) -> dict:
        """
        DHCP DISCOVER → OFFER → REQUEST → ACK 수행
        반환: {"ip": str, "mask": str, "gw": str, "lease": int, "error": str}
        """
        try:
            from scapy.all import (BOOTP, DHCP, Ether, IP, UDP,
                                   conf, sendp, sniff)
        except ImportError:
            return {"error": "scapy 미설치. pip install scapy"}

        result = {"ip": "", "mask": "", "gw": "", "lease": 0, "error": ""}

        # ── DISCOVER ──────────────────────────
        discover = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(":", "")),
                  xid=self._xid, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), "end"])
        )

        offer_pkt = [None]
        stop_evt  = threading.Event()

        def _filter(pkt):
            return (
                DHCP in pkt and
                pkt[DHCP].options[0][1] == 2 and   # OFFER
                pkt[BOOTP].xid == self._xid
            )

        def _sniff_offer():
            pkts = sniff(iface=self.iface, filter="udp and port 67",
                         lfilter=_filter, count=1, timeout=self.timeout)
            if pkts:
                offer_pkt[0] = pkts[0]
            stop_evt.set()

        t = threading.Thread(target=_sniff_offer, daemon=True)
        t.start()
        sendp(discover, iface=self.iface, verbose=False)
        stop_evt.wait(timeout=self.timeout + 1)

        if not offer_pkt[0]:
            result["error"] = "OFFER 수신 실패 (타임아웃)"
            return result

        offered_ip = offer_pkt[0][BOOTP].yiaddr

        # ── REQUEST ───────────────────────────
        request_pkt = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(":", "")),
                  xid=self._xid, flags=0x8000) /
            DHCP(options=[
                ("message-type",  "request"),
                ("requested_addr", offered_ip),
                "end",
            ])
        )

        ack_pkt  = [None]
        stop_evt2 = threading.Event()

        def _filter_ack(pkt):
            return (
                DHCP in pkt and
                pkt[DHCP].options[0][1] == 5 and   # ACK
                pkt[BOOTP].xid == self._xid
            )

        def _sniff_ack():
            pkts = sniff(iface=self.iface, filter="udp and port 67",
                         lfilter=_filter_ack, count=1, timeout=self.timeout)
            if pkts:
                ack_pkt[0] = pkts[0]
            stop_evt2.set()

        t2 = threading.Thread(target=_sniff_ack, daemon=True)
        t2.start()
        sendp(request_pkt, iface=self.iface, verbose=False)
        stop_evt2.wait(timeout=self.timeout + 1)

        if not ack_pkt[0]:
            result["error"] = "ACK 수신 실패 (NACK 또는 타임아웃)"
            return result

        # ── 옵션 파싱 ──────────────────────────
        ack = ack_pkt[0]
        result["ip"] = ack[BOOTP].yiaddr

        for opt in ack[DHCP].options:
            if isinstance(opt, tuple):
                k, v = opt[0], opt[1]
                if k == "subnet_mask":      result["mask"]  = v
                if k == "router":           result["gw"]    = v
                if k == "lease_time":       result["lease"] = v

        return result


# ──────────────────────────────────────────────
# 가상 MAC 관리자 (GUI 연동)
# ──────────────────────────────────────────────

class VirtualMACManager:
    def __init__(self):
        self._groups: dict[str, VirtualMACGroup] = {}   # iface_name → group
        self._lock   = threading.Lock()

        # 콜백
        self.on_state_change: Optional[Callable[[str, VirtualMAC], None]] = None
        # on_state_change(iface_name, entry)

    # ── 그룹 관리 ──────────────────────────────

    def get_group(self, iface: str) -> VirtualMACGroup:
        with self._lock:
            if iface not in self._groups:
                self._groups[iface] = VirtualMACGroup(iface_name=iface)
            return self._groups[iface]

    def add_mac(self, iface: str, mac: str = "", label: str = "") -> VirtualMAC:
        group = self.get_group(iface)
        with self._lock:
            idx = len(group.entries)
            if not mac:
                mac = generate_mac(idx + 1, group.prefix)
            entry = VirtualMAC(index=idx, mac=mac, label=label)
            group.entries.append(entry)
        return entry

    def add_mac_bulk(self, iface: str, count: int,
                     prefix: str = "AA:BB:CC") -> list[VirtualMAC]:
        group = self.get_group(iface)
        group.prefix = prefix
        added = []
        for i in range(count):
            with self._lock:
                idx = len(group.entries)
            entry = self.add_mac(iface, generate_mac(idx + 1, prefix),
                                 label=f"가상 MAC #{idx+1}")
            added.append(entry)
        return added

    def remove_mac(self, iface: str, index: int):
        group = self.get_group(iface)
        with self._lock:
            group.entries = [e for e in group.entries if e.index != index]
            # 인덱스 재정렬
            for i, e in enumerate(group.entries):
                e.index = i

    def clear_group(self, iface: str):
        with self._lock:
            if iface in self._groups:
                self._groups[iface].entries.clear()

    # ── DHCP 요청 ──────────────────────────────

    def request_all(self, iface: str, timeout: int = 5,
                    parallel: bool = True):
        """그룹 내 모든 가상 MAC에 DHCP 요청 (병렬 또는 순차)"""
        group = self.get_group(iface)
        entries = list(group.entries)

        if parallel:
            threads = []
            for entry in entries:
                t = threading.Thread(
                    target=self._request_single,
                    args=(iface, entry, timeout),
                    daemon=True,
                )
                threads.append(t)
            for t in threads:
                t.start()
                time.sleep(0.05)   # 살짝 지연으로 패킷 충돌 완화
            for t in threads:
                t.join()
        else:
            for entry in entries:
                self._request_single(iface, entry, timeout)

    def request_single(self, iface: str, index: int, timeout: int = 5):
        group = self.get_group(iface)
        entry = next((e for e in group.entries if e.index == index), None)
        if entry:
            threading.Thread(
                target=self._request_single,
                args=(iface, entry, timeout),
                daemon=True,
            ).start()

    def _request_single(self, iface: str, entry: VirtualMAC, timeout: int):
        entry.state = "requesting"
        self._notify(iface, entry)

        client = ScapyDHCPClient(iface, entry.mac, timeout)
        result = client.request()

        if result.get("error"):
            entry.state     = "error"
            entry.error_msg = result["error"]
        else:
            entry.state       = "bound"
            entry.assigned_ip = result.get("ip", "")
            entry.subnet_mask = result.get("mask", "")
            entry.gateway     = result.get("gw", "")
            entry.lease_time  = result.get("lease", 0)
            entry.assigned_at = datetime.now()
            entry.error_msg   = ""

        self._notify(iface, entry)

    def release_single(self, iface: str, index: int):
        """DHCP RELEASE 전송"""
        group = self.get_group(iface)
        entry = next((e for e in group.entries if e.index == index), None)
        if not entry or not entry.assigned_ip:
            return

        def _do_release():
            try:
                from scapy.all import (BOOTP, DHCP, Ether, IP, UDP, sendp)
                release = (
                    Ether(src=entry.mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src=entry.assigned_ip, dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=bytes.fromhex(entry.mac.replace(":", "")),
                          ciaddr=entry.assigned_ip,
                          xid=random.randint(1, 0xFFFFFFFF)) /
                    DHCP(options=[("message-type", "release"), "end"])
                )
                sendp(release, iface=iface, verbose=False)
            except Exception as e:
                pass
            entry.state       = "released"
            entry.assigned_ip = ""
            entry.subnet_mask = ""
            entry.gateway     = ""
            entry.lease_time  = 0
            self._notify(iface, entry)

        threading.Thread(target=_do_release, daemon=True).start()

    def release_all(self, iface: str):
        group = self.get_group(iface)
        for entry in list(group.entries):
            if entry.state == "bound":
                self.release_single(iface, entry.index)

    # ── 내부 ────────────────────────────────────

    def _notify(self, iface: str, entry: VirtualMAC):
        if self.on_state_change:
            try:
                self.on_state_change(iface, entry)
            except Exception:
                pass


# ──────────────────────────────────────────────
# 테스트용 시뮬레이션 모드 (Scapy 없을 때)
# ──────────────────────────────────────────────

class SimulatedDHCPClient:
    """개발/테스트용 가상 DHCP 시뮬레이터"""

    def __init__(self, base_ip: str = "192.168.1", start: int = 100):
        self._base   = base_ip
        self._pool   = start
        self._lock   = threading.Lock()

    def request(self, mac: str) -> dict:
        time.sleep(random.uniform(0.1, 0.6))   # 네트워크 지연 시뮬레이션
        if random.random() < 0.05:              # 5% 실패율
            return {"error": "DHCP NACK (시뮬레이션)"}
        with self._lock:
            ip = f"{self._base}.{self._pool}"
            self._pool += 1
        return {
            "ip":    ip,
            "mask":  "255.255.255.0",
            "gw":    f"{self._base}.1",
            "lease": 3600,
            "error": "",
        }


class VirtualMACManagerSim(VirtualMACManager):
    """Scapy 없는 환경에서 동작하는 시뮬레이션 버전"""

    def __init__(self):
        super().__init__()
        self._sim = SimulatedDHCPClient()

    def _request_single(self, iface: str, entry: VirtualMAC, timeout: int):
        entry.state = "requesting"
        self._notify(iface, entry)

        result = self._sim.request(entry.mac)

        if result.get("error"):
            entry.state     = "error"
            entry.error_msg = result["error"]
        else:
            entry.state       = "bound"
            entry.assigned_ip = result["ip"]
            entry.subnet_mask = result["mask"]
            entry.gateway     = result["gw"]
            entry.lease_time  = result["lease"]
            entry.assigned_at = datetime.now()
            entry.error_msg   = ""

        self._notify(iface, entry)


def create_manager() -> VirtualMACManager:
    """환경에 따라 실제 또는 시뮬레이션 매니저 반환"""
    try:
        import scapy.all  # noqa
        print("[VMAC] Scapy 감지됨 → 실제 패킷 모드")
        return VirtualMACManager()
    except ImportError:
        print("[VMAC] Scapy 없음 → 시뮬레이션 모드 (pip install scapy 필요)")
        return VirtualMACManagerSim()
