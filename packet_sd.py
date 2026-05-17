"""
packet_sd.py — Packet Sender/Receiver 엔진 v2

주요 수정:
  - 수신 BPF 필터: dst port + dst ip 명시 → 자기 송신 패킷 제외
  - RTT: Echo 방식 제거, 단순 One-way 지연으로 변경
  - 임계값 경고 중복 제거 (1초에 한 번만)
  - 통계 업데이트 주기 정리
"""
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


MAGIC        = 0x41505644   # "APVD"
PAYLOAD_HDR  = 16           # Magic(4) + Seq(4) + Timestamp(8)
DEFAULT_PORT = 19999
DEFAULT_PPS  = 1000
DEFAULT_SIZE = 1024


class Mode(Enum):
    SEND_TO_RECV  = "S→R"
    RECV_TO_SEND  = "R→S"
    BIDIRECTIONAL = "양방향"
    SEND_ONLY     = "송신만"
    RECV_ONLY     = "수신만"

class Protocol(Enum):
    UDP = "UDP"
    TCP = "TCP"

class SizeMode(Enum):
    FIXED  = "고정"
    RANDOM = "랜덤"

class DurationMode(Enum):
    COUNT    = "패킷수"
    TIME     = "시간"
    INFINITE = "지속"

class SpeedMode(Enum):
    PPS  = "PPS"
    MBPS = "Mbps"
    MAX  = "최대속도"


@dataclass
class PacketSDConfig:
    mode:           Mode     = Mode.SEND_TO_RECV
    protocol:       Protocol = Protocol.UDP
    sender_iface:   str  = ""
    receiver_iface: str  = ""
    src_ip:         str  = ""
    dst_ip:         str  = ""
    src_port:       int  = 0
    dst_port:       int  = DEFAULT_PORT
    ttl:            int  = 64
    size_mode:      SizeMode     = SizeMode.FIXED
    pkt_size:       int  = DEFAULT_SIZE
    size_min:       int  = 64
    size_max:       int  = 1500
    duration_mode:  DurationMode = DurationMode.COUNT
    pkt_count:      int  = 10000
    duration_sec:   float = 60.0
    speed_mode:     SpeedMode    = SpeedMode.PPS
    pps:            int  = DEFAULT_PPS
    mbps:           float = 10.0
    nat_mode:       bool = False
    nat_wan_ip:     str  = ""
    nat_wan_port:   int  = 0
    loss_threshold:    float = 1.0
    rtt_threshold:     float = 100.0
    jitter_threshold:  float = 10.0


@dataclass
class PacketSDStats:
    sent:       int   = 0
    received:   int   = 0
    lost:       int   = 0
    loss_pct:   float = 0.0
    rtt_avg:    float = 0.0
    rtt_min:    float = 9999.0
    rtt_max:    float = 0.0
    jitter:     float = 0.0
    throughput: float = 0.0
    elapsed:    float = 0.0
    status:     str   = "idle"
    error_msg:  str   = ""

    _rtt_samples: list  = field(default_factory=list)
    _prev_rtt:    float = 0.0
    _jitter_sum:  float = 0.0
    _rx_bytes:    int   = 0
    _t_start:     float = 0.0

    def update_rtt(self, rtt_ms: float):
        self._rtt_samples.append(rtt_ms)
        n = len(self._rtt_samples)
        self.rtt_avg = sum(self._rtt_samples) / n
        self.rtt_min = min(self.rtt_min, rtt_ms)
        self.rtt_max = max(self.rtt_max, rtt_ms)
        if self._prev_rtt > 0:
            self._jitter_sum += abs(rtt_ms - self._prev_rtt)
            self.jitter = self._jitter_sum / max(n - 1, 1)
        self._prev_rtt = rtt_ms

    def update_loss(self):
        self.lost     = max(0, self.sent - self.received)
        self.loss_pct = (self.lost / self.sent * 100) if self.sent > 0 else 0.0

    def update_rx_bytes(self, n: int):
        self._rx_bytes += n
        if self.elapsed > 0:
            self.throughput = (self._rx_bytes * 8 / 1_000_000) / self.elapsed

    def tick(self):
        if self._t_start > 0:
            self.elapsed = time.time() - self._t_start


class PacketSDEngine:
    def __init__(self, config: PacketSDConfig):
        self.config = config
        self.stats  = PacketSDStats()

        self.on_stats_update: Optional[Callable] = None
        self.on_warn:         Optional[Callable] = None
        self.on_log:          Optional[Callable] = None

        self._stop_evt   = threading.Event()
        self._threads:   list = []
        self._seq_lock   = threading.Lock()
        self._seq:       int  = 0
        self._rx_seqs:   set  = set()
        self._warn_t:    float = 0   # 마지막 경고 시각 (중복 방지)

    def start(self):
        self._stop_evt.clear()
        self.stats           = PacketSDStats()
        self.stats.status    = "running"
        self.stats._t_start  = time.time()
        self._seq            = 0
        self._rx_seqs        = set()
        self._warn_t         = 0

        self._log("info",
            f"시작 — {self.config.protocol.value} {self.config.mode.value} "
            f"PPS={self.config.pps} 크기={self.config.pkt_size}B "
            f"{self.config.src_ip} → {self.config.dst_ip}:{self.config.dst_port}")

        t = threading.Thread(
            target=self._start_with_nat if self.config.nat_mode
                   else self._start_direct,
            daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self):
        self._stop_evt.set()
        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()
        self.stats.status = "done"
        self.stats.tick()
        self.stats.update_loss()
        self._notify()
        self._log("info",
            f"완료 — 송={self.stats.sent} 수={self.stats.received} "
            f"손실률={self.stats.loss_pct:.2f}% "
            f"RTT평균={self.stats.rtt_avg:.1f}ms")

    # ── NAT 세션 ─────────────────────────────────

    def _start_with_nat(self):
        self._log("info", "NAT 세션 선개통 중...")
        nat_ip, nat_port = self._open_nat_session()
        if nat_ip:
            self.config.nat_wan_ip   = nat_ip
            self.config.nat_wan_port = nat_port
            self._log("info", f"NAT 세션 완료: {nat_ip}:{nat_port}")
        else:
            self._log("warn", "NAT 세션 실패 — 직접 전송으로 진행")
        self._start_direct()

    def _open_nat_session(self) -> tuple:
        try:
            from scapy.all import Ether, IP, UDP, sniff, sendp
            from scapy.arch import get_if_hwaddr
            from main_app import _resolve_scapy_iface
        except ImportError:
            return "", 0

        scapy_s = _resolve_scapy_iface(self.config.sender_iface)
        scapy_m = _resolve_scapy_iface(self.config.receiver_iface)
        s_ip = self.config.src_ip
        m_ip = self.config.dst_ip

        result = {"ip": "", "port": 0}
        ready  = threading.Event()

        def _sniff():
            def _f(pkt):
                return (UDP in pkt and IP in pkt and
                        pkt[UDP].dport == self.config.dst_port and
                        pkt[IP].dst == m_ip)
            pkts = sniff(iface=scapy_m, lfilter=_f, count=1, timeout=5,
                         started_callback=lambda: ready.set())
            if pkts:
                result["ip"]   = pkts[0][IP].src
                result["port"] = pkts[0][UDP].sport

        t = threading.Thread(target=_sniff, daemon=True)
        t.start()
        ready.wait(timeout=1.0)
        time.sleep(0.1)

        try:
            hw = get_if_hwaddr(scapy_s)
            payload = struct.pack(">I I d", MAGIC, 0, time.time())
            sport   = self.config.src_port or 40000
            for _ in range(3):
                pkt = (Ether(src=hw, dst="ff:ff:ff:ff:ff:ff") /
                       IP(src=s_ip, dst=m_ip, ttl=self.config.ttl) /
                       UDP(sport=sport, dport=self.config.dst_port) /
                       payload)
                sendp(pkt, iface=scapy_s, verbose=False)
                time.sleep(0.5)
                if result["ip"]:
                    break
        except Exception as e:
            self._log("err", f"NAT 선송신 오류: {e}")

        t.join(timeout=6)
        return result["ip"], result["port"]

    # ── 직접 전송 ────────────────────────────────

    def _start_direct(self):
        mode    = self.config.mode
        s_iface = self.config.sender_iface
        r_iface = self.config.receiver_iface
        s_ip    = self.config.src_ip
        d_ip    = (self.config.nat_wan_ip
                   if self.config.nat_mode and self.config.nat_wan_ip
                   else self.config.dst_ip)
        r_ip    = self.config.dst_ip   # 수신 측 실제 IP

        if mode == Mode.SEND_ONLY:
            self._run_sender(s_iface, s_ip, d_ip)

        elif mode == Mode.RECV_ONLY:
            self._run_receiver(r_iface, r_ip)

        elif mode in (Mode.SEND_TO_RECV, Mode.RECV_TO_SEND):
            ts = threading.Thread(target=self._run_sender,
                                  args=(s_iface, s_ip, d_ip), daemon=True)
            tr = threading.Thread(target=self._run_receiver,
                                  args=(r_iface, r_ip), daemon=True)
            ts.start(); tr.start()
            self._threads += [ts, tr]
            ts.join(); tr.join()

        elif mode == Mode.BIDIRECTIONAL:
            threads = [
                threading.Thread(target=self._run_sender,
                    args=(s_iface, s_ip, d_ip), daemon=True),
                threading.Thread(target=self._run_sender,
                    args=(r_iface, r_ip, s_ip), daemon=True),
                threading.Thread(target=self._run_receiver,
                    args=(r_iface, r_ip), daemon=True),
                threading.Thread(target=self._run_receiver,
                    args=(s_iface, s_ip), daemon=True),
            ]
            for t in threads: t.start(); self._threads.append(t)
            for t in threads: t.join()

    # ── 송신 루프 ────────────────────────────────

    def _run_sender(self, iface: str, src_ip: str, dst_ip: str):
        try:
            from scapy.all import Ether, IP, UDP, sendp
            from scapy.arch import get_if_hwaddr
            from main_app import _resolve_scapy_iface
        except ImportError:
            self._log("err", "Scapy 없음")
            return

        scapy_if = _resolve_scapy_iface(iface)
        try:
            hw = get_if_hwaddr(scapy_if)
        except Exception:
            hw = "00:00:00:00:00:00"

        dst_port  = (self.config.nat_wan_port
                     if self.config.nat_mode and self.config.nat_wan_port
                     else self.config.dst_port)
        src_port  = self.config.src_port or 40001
        interval  = 1.0 / self.config.pps if self.config.pps > 0 else 0

        t_start    = time.perf_counter()
        sent_local = 0
        t_stat     = time.time()
        STAT_INTV  = 0.5   # 0.5초마다 통계

        while not self._stop_evt.is_set():
            # 종료 조건
            if self.config.duration_mode == DurationMode.COUNT:
                if self.stats.sent >= self.config.pkt_count:
                    break
            elif self.config.duration_mode == DurationMode.TIME:
                if self.stats.elapsed >= self.config.duration_sec:
                    break

            with self._seq_lock:
                seq = self._seq
                self._seq += 1

            import random
            pkt_size = (random.randint(self.config.size_min, self.config.size_max)
                        if self.config.size_mode == SizeMode.RANDOM
                        else self.config.pkt_size)

            ts      = time.time()
            hdr     = struct.pack(">I I d", MAGIC, seq, ts)
            pad_len = max(0, pkt_size - PAYLOAD_HDR - 28)
            payload = hdr + b"\x55\xAA" * (pad_len // 2) + b"\x00" * (pad_len % 2)

            try:
                pkt = (Ether(src=hw, dst="ff:ff:ff:ff:ff:ff") /
                       IP(src=src_ip, dst=dst_ip, ttl=self.config.ttl) /
                       UDP(sport=src_port, dport=dst_port) /
                       payload)
                sendp(pkt, iface=scapy_if, verbose=False)
                self.stats.sent += 1
                sent_local      += 1
            except Exception as e:
                self._log("err", f"송신 오류: {e}")
                break

            # PPS 제어
            if interval > 0:
                t_next  = t_start + sent_local * interval
                t_sleep = t_next - time.perf_counter()
                if t_sleep > 0:
                    time.sleep(t_sleep)

            # 통계 업데이트
            now = time.time()
            if now - t_stat >= STAT_INTV:
                self.stats.tick()
                self.stats.update_loss()
                self._check_thresholds()
                self._notify()
                t_stat = now

        self._log("info", f"송신 완료: {self.stats.sent}패킷")

    # ── 수신 루프 ────────────────────────────────

    def _run_receiver(self, iface: str, my_ip: str):
        """
        수신 루프 핵심 수정:
        BPF 필터에 dst host 추가 → 자기가 보낸 패킷 제외
        RTT는 페이로드 타임스탬프 기반 One-way (동일 클럭 환경)
        """
        try:
            from scapy.all import IP, UDP, sniff
            from main_app import _resolve_scapy_iface
        except ImportError:
            return

        scapy_if = _resolve_scapy_iface(iface)

        # BPF: 내 IP가 목적지인 UDP + 지정 포트 → 자기 송신 패킷 완전 제외
        bpf = (f"udp dst port {self.config.dst_port} "
               f"and dst host {my_ip}")

        self._log("info", f"수신 대기: {my_ip}:{self.config.dst_port} ({iface})")

        def _on_pkt(pkt):
            if self._stop_evt.is_set():
                return
            if UDP not in pkt or IP not in pkt:
                return

            # 자기 IP → 자기 IP (루프백) 제외
            if pkt[IP].src == my_ip:
                return

            raw = bytes(pkt[UDP].payload)
            if len(raw) < PAYLOAD_HDR:
                return

            try:
                magic, seq, ts = struct.unpack(">I I d", raw[:PAYLOAD_HDR])
            except struct.error:
                return

            if magic != MAGIC:
                return

            # 중복 수신 제거
            if seq in self._rx_seqs:
                return
            self._rx_seqs.add(seq)

            self.stats.received += 1
            self.stats.update_rx_bytes(len(raw))

            # One-way 지연 (송신 측과 동일 시스템 클럭 기준)
            rtt_ms = (time.time() - ts) * 1000
            if 0 < rtt_ms < 5000:
                self.stats.update_rtt(rtt_ms)

            self.stats.tick()
            self.stats.update_loss()
            self._notify()

        try:
            sniff(iface=scapy_if,
                  filter=bpf,
                  prn=_on_pkt,
                  stop_filter=lambda p: self._stop_evt.is_set(),
                  store=False)
        except Exception as e:
            self._log("err", f"수신 오류: {e}")

    # ── 내부 유틸 ────────────────────────────────

    def _check_thresholds(self):
        now = time.time()
        # 5초에 한 번만 경고 (로그 폭주 방지)
        if now - self._warn_t < 5.0:
            return
        cfg = self.config
        warned = False
        if self.stats.loss_pct > cfg.loss_threshold and self.stats.sent > 10:
            self._warn(f"손실률 {self.stats.loss_pct:.2f}% 임계값({cfg.loss_threshold}%) 초과")
            warned = True
        if self.stats.rtt_avg > cfg.rtt_threshold and self.stats.rtt_avg > 0:
            self._warn(f"평균 RTT {self.stats.rtt_avg:.1f}ms 임계값 초과")
            warned = True
        if warned:
            self._warn_t = now

    def _notify(self):
        if self.on_stats_update:
            try:
                self.on_stats_update(self.stats)
            except Exception:
                pass

    def _warn(self, msg: str):
        self._log("warn", msg)
        if self.on_warn:
            try:
                self.on_warn(msg)
            except Exception:
                pass

    def _log(self, level: str, msg: str):
        if self.on_log:
            try:
                self.on_log(level, f"[Packet S/D] {msg}")
            except Exception:
                pass
