"""
plugins/dummy_plugins.py — 개발용 더미 플러그인
실제 패킷 동작 없이 랜덤 PASS/FAIL 시뮬레이션
나중에 각 플러그인 파일로 분리 예정
"""
import random
import time
from .base_plugin import BasePlugin, PluginParam, StepResult


class DhcpPlugin(BasePlugin):
    NAME        = "DHCP"
    VERSION     = "0.1.0"
    DESCRIPTION = "DHCP Server/Client 동작 검증 (RFC 2131)"
    ICON        = "ti-server-2"

    def get_params(self) -> list[PluginParam]:
        return [
            PluginParam("server_ip",   "서버 IP",         "192.168.1.1",  "str"),
            PluginParam("pool_start",  "풀 시작 IP",      "192.168.1.100","str"),
            PluginParam("pool_end",    "풀 끝 IP",        "192.168.1.200","str"),
            PluginParam("lease_time",  "Lease Time (s)",  3600,           "int"),
            PluginParam("timeout_ms",  "응답 타임아웃",   3000,           "int"),
        ]

    def on_start(self, master_iface: str, slave_iface: str) -> bool:
        self.enabled = True
        return True

    def on_stop(self):
        self.enabled = False

    def run_step(self, step: dict) -> StepResult:
        time.sleep(random.uniform(0.05, 0.3))
        step_type = step.get("type", "Send")
        name      = step.get("name", "")
        expected  = step.get("expected", "")
        # 간단한 시뮬레이션: 95% PASS
        passed   = random.random() > 0.05
        actual   = expected if passed else f"오류({random.randint(1,99)})"
        return StepResult(
            step_index=step.get("index", 0),
            step_name=name,
            step_type=step_type,
            expected=expected,
            actual=actual,
            passed=passed,
            elapsed_ms=random.uniform(50, 300),
            message="" if passed else f"예상값 불일치: {expected} ≠ {actual}",
        )


class NatPlugin(BasePlugin):
    NAME        = "NAT"
    VERSION     = "0.1.0"
    DESCRIPTION = "NAT 포트 매핑 / 세션 유지 검증"
    ICON        = "ti-arrows-exchange"

    def get_params(self) -> list[PluginParam]:
        return [
            PluginParam("wan_ip",      "WAN IP",          "10.0.0.1",    "str"),
            PluginParam("lan_subnet",  "LAN 서브넷",      "192.168.1.0/24","str"),
            PluginParam("session_timeout","세션 타임아웃(s)", 300,        "int"),
        ]

    def on_start(self, master_iface: str, slave_iface: str) -> bool:
        self.enabled = True
        return True

    def on_stop(self):
        self.enabled = False

    def run_step(self, step: dict) -> StepResult:
        time.sleep(random.uniform(0.05, 0.2))
        passed = random.random() > 0.08
        expected = step.get("expected", "")
        actual   = expected if passed else "NAT 변환 실패"
        return StepResult(
            step_index=step.get("index", 0),
            step_name=step.get("name", ""),
            step_type=step.get("type", "Check"),
            expected=expected,
            actual=actual,
            passed=passed,
            elapsed_ms=random.uniform(30, 200),
            message="" if passed else "NAT 엔트리 미생성",
        )


class IgmpPlugin(BasePlugin):
    NAME        = "IGMP"
    VERSION     = "0.1.0"
    DESCRIPTION = "IGMP Multicast 가입/탈퇴 및 트래픽 검증"
    ICON        = "ti-broadcast"

    def get_params(self) -> list[PluginParam]:
        return [
            PluginParam("multicast_group", "멀티캐스트 그룹", "224.0.0.1", "str"),
            PluginParam("igmp_version",    "IGMP 버전",       "v2",        "choice",
                        choices=["v1","v2","v3"]),
            PluginParam("query_interval",  "Query 간격(s)",   125,         "int"),
        ]

    def on_start(self, master_iface: str, slave_iface: str) -> bool:
        self.enabled = True
        return True

    def on_stop(self):
        self.enabled = False

    def run_step(self, step: dict) -> StepResult:
        time.sleep(random.uniform(0.1, 0.4))
        passed = random.random() > 0.1
        expected = step.get("expected", "")
        actual   = expected if passed else "그룹 가입 실패"
        return StepResult(
            step_index=step.get("index", 0),
            step_name=step.get("name", ""),
            step_type=step.get("type", "Check"),
            expected=expected,
            actual=actual,
            passed=passed,
            elapsed_ms=random.uniform(80, 400),
            message="" if passed else "IGMP Membership Report 미수신",
        )


class PacketSdPlugin(BasePlugin):
    NAME        = "Packet S/D"
    VERSION     = "0.1.0"
    DESCRIPTION = "범용 패킷 송수신 및 지연 측정"
    ICON        = "ti-activity"

    def get_params(self) -> list[PluginParam]:
        return [
            PluginParam("pkt_size",    "패킷 크기(bytes)", 1024,  "int"),
            PluginParam("pkt_count",   "패킷 수",          100,   "int"),
            PluginParam("interval_ms", "전송 간격(ms)",    10,    "int"),
            PluginParam("loss_threshold","허용 손실률(%)", 1.0,   "float"),
        ]

    def on_start(self, master_iface: str, slave_iface: str) -> bool:
        self.enabled = True
        return True

    def on_stop(self):
        self.enabled = False

    def run_step(self, step: dict) -> StepResult:
        time.sleep(random.uniform(0.05, 0.25))
        passed = random.random() > 0.05
        expected = step.get("expected", "")
        actual   = expected if passed else f"손실률 {random.uniform(1,5):.1f}%"
        return StepResult(
            step_index=step.get("index", 0),
            step_name=step.get("name", ""),
            step_type=step.get("type", "Check"),
            expected=expected,
            actual=actual,
            passed=passed,
            elapsed_ms=random.uniform(20, 250),
            message="" if passed else "패킷 손실 허용치 초과",
        )


PLUGIN_REGISTRY: dict[str, BasePlugin] = {
    "DHCP":      DhcpPlugin(),
    "NAT":       NatPlugin(),
    "IGMP":      IgmpPlugin(),
    "Packet S/D": PacketSdPlugin(),
}
