"""
scenario_engine.py — 시나리오 실행 엔진
반복 테스트 / Aging 기능 포함
"""
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

from logger import log
from plugins.base_plugin import StepResult


# ──────────────────────────────────────────────
# 데이터 구조
# ──────────────────────────────────────────────

@dataclass
class ScenarioStep:
    index:      int
    name:       str
    type:       str          # Send | Wait | Check | Delay | Assert
    expected:   str  = ""
    tolerance:  float = 0.0  # 허용 오차 %
    timeout_ms: int  = 3000
    repeat:     int  = 1
    interval_ms:int  = 0
    condition:  str  = ""    # Assert용 조건식
    on_fail:    str  = "stop"   # stop | continue | retry
    retry_count:int  = 3


@dataclass
class RepeatConfig:
    enabled:       bool  = False
    mode:          str   = "count"    # count | duration
    count:         int   = 1
    duration_sec:  int   = 3600       # Aging: 지속 시간(초)
    interval_sec:  int   = 0          # 반복 사이 대기


@dataclass
class Scenario:
    id:          str
    name:        str
    plugin:      str
    description: str               = ""
    on_fail:     str               = "stop"
    steps:       list[ScenarioStep] = field(default_factory=list)
    repeat:      RepeatConfig       = field(default_factory=RepeatConfig)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "plugin": self.plugin,
            "description": self.description, "on_fail": self.on_fail,
            "steps": [s.__dict__ for s in self.steps],
            "repeat": self.repeat.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Scenario":
        sc = cls(id=d["id"], name=d["name"], plugin=d["plugin"],
                 description=d.get("description",""), on_fail=d.get("on_fail","stop"))
        sc.steps = [ScenarioStep(**s) for s in d.get("steps",[])]
        sc.repeat = RepeatConfig(**d.get("repeat", {}))
        return sc


@dataclass
class RunRecord:
    """단일 실행 회차 결과"""
    iteration:  int
    started_at: datetime
    ended_at:   Optional[datetime] = None
    step_results: list[StepResult] = field(default_factory=list)

    @property
    def pass_count(self):  return sum(1 for r in self.step_results if r.passed)
    @property
    def fail_count(self):  return sum(1 for r in self.step_results if not r.passed)
    @property
    def total(self):       return len(self.step_results)
    @property
    def pass_rate(self):   return (self.pass_count / self.total * 100) if self.total else 0


# ──────────────────────────────────────────────
# 엔진
# ──────────────────────────────────────────────

class ScenarioEngine:
    def __init__(self):
        self._thread:   Optional[threading.Thread] = None
        self._stop_evt: threading.Event = threading.Event()
        self._pause_evt:threading.Event = threading.Event()
        self._pause_evt.set()   # set = 실행 중, clear = 일시정지

        self.current_scenario: Optional[Scenario] = None
        self.records: list[RunRecord] = []
        self.current_step_idx: int = -1
        self.current_iter: int = 0
        self.is_running: bool = False

        # 콜백
        self.on_step_start:    Optional[Callable] = None   # (iter, step_idx, step)
        self.on_step_done:     Optional[Callable] = None   # (iter, step_idx, result)
        self.on_iter_done:     Optional[Callable] = None   # (iter, record)
        self.on_run_done:      Optional[Callable] = None   # (records)
        self.on_status_update: Optional[Callable] = None   # (msg)

    # ── 제어 ──────────────────────────────────

    def start(self, scenario: Scenario, plugin, master_iface: str, slave_iface: str):
        if self.is_running:
            return
        self.current_scenario = scenario
        self.records.clear()
        self._stop_evt.clear()
        self._pause_evt.set()
        self.is_running = True

        self._thread = threading.Thread(
            target=self._run_loop,
            args=(scenario, plugin, master_iface, slave_iface),
            daemon=True,
        )
        self._thread.start()

    def pause(self):
        self._pause_evt.clear()
        self._status("일시정지됨")

    def resume(self):
        self._pause_evt.set()
        self._status("재개됨")

    def stop(self):
        self._stop_evt.set()
        self._pause_evt.set()   # 일시정지 상태라면 해제해서 루프 탈출

    # ── 내부 실행 루프 ─────────────────────────

    def _run_loop(self, scenario: Scenario, plugin, master_iface: str, slave_iface: str):
        try:
            log.info(f"시나리오 시작 — {scenario.name}", source="SCENARIO")
            if not plugin.on_start(master_iface, slave_iface):
                log.error("플러그인 시작 실패", source="SCENARIO")
                return

            rc = scenario.repeat
            end_time = (datetime.now() + timedelta(seconds=rc.duration_sec)
                        if rc.enabled and rc.mode == "duration" else None)
            max_iter = rc.count if rc.enabled and rc.mode == "count" else 1

            iter_num = 0
            while not self._stop_evt.is_set():
                iter_num += 1
                self.current_iter = iter_num
                record = RunRecord(iteration=iter_num, started_at=datetime.now())
                self.records.append(record)

                self._status(f"반복 {iter_num}회차 시작")
                log.info(f"[반복 {iter_num}] 시작", source="SCENARIO")

                aborted = False
                for step in scenario.steps:
                    if self._stop_evt.is_set():
                        aborted = True
                        break

                    # 일시정지 대기
                    self._pause_evt.wait()
                    if self._stop_evt.is_set():
                        aborted = True
                        break

                    self.current_step_idx = step.index
                    if self.on_step_start:
                        self.on_step_start(iter_num, step.index, step)

                    log.debug(f"Step {step.index:02d} [{step.type}] {step.name}", source="SCENARIO")

                    result = plugin.run_step({
                        "index": step.index, "name": step.name,
                        "type": step.type, "expected": step.expected,
                        "timeout_ms": step.timeout_ms,
                    })
                    record.step_results.append(result)

                    level = "INFO" if result.passed else "ERROR"
                    judge = "PASS" if result.passed else "FAIL"
                    getattr(log, level.lower())(
                        f"Step {step.index:02d} {judge} — {step.name}"
                        + (f" | 실측: {result.actual}" if result.actual else ""),
                        source=scenario.plugin,
                    )

                    if self.on_step_done:
                        self.on_step_done(iter_num, step.index, result)

                    if not result.passed and step.on_fail == "stop":
                        log.warn(f"Step {step.index:02d} FAIL → 시나리오 중단", source="SCENARIO")
                        aborted = True
                        break

                    # Step 사이 딜레이
                    if step.type == "Delay":
                        time.sleep(step.timeout_ms / 1000.0)

                record.ended_at = datetime.now()
                log.info(
                    f"[반복 {iter_num}] 완료 — PASS {record.pass_count}/{record.total} "
                    f"({record.pass_rate:.1f}%)",
                    source="SCENARIO",
                )

                if self.on_iter_done:
                    self.on_iter_done(iter_num, record)

                if aborted or self._stop_evt.is_set():
                    break

                # 반복 종료 조건 체크
                if not rc.enabled:
                    break
                if rc.mode == "count" and iter_num >= max_iter:
                    break
                if rc.mode == "duration" and end_time and datetime.now() >= end_time:
                    log.info("Aging 시간 만료 → 종료", source="SCENARIO")
                    break

                # 반복 간 대기
                if rc.interval_sec > 0:
                    self._status(f"다음 반복까지 {rc.interval_sec}초 대기...")
                    for _ in range(rc.interval_sec):
                        if self._stop_evt.is_set():
                            break
                        time.sleep(1)

        finally:
            plugin.on_stop()
            self.is_running = False
            self.current_step_idx = -1
            log.info(f"시나리오 종료 — 총 {len(self.records)}회 실행", source="SCENARIO")
            if self.on_run_done:
                self.on_run_done(self.records)

    def _status(self, msg: str):
        if self.on_status_update:
            self.on_status_update(msg)


# ──────────────────────────────────────────────
# 시나리오 저장/불러오기
# ──────────────────────────────────────────────

SCENARIO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios")


def save_scenario(sc: Scenario) -> str:
    os.makedirs(SCENARIO_DIR, exist_ok=True)
    path = os.path.join(SCENARIO_DIR, f"{sc.id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sc.to_dict(), f, ensure_ascii=False, indent=2)
    return path


def load_scenario(sc_id: str) -> Optional[Scenario]:
    path = os.path.join(SCENARIO_DIR, f"{sc_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return Scenario.from_dict(json.load(f))


def list_scenarios() -> list[Scenario]:
    if not os.path.isdir(SCENARIO_DIR):
        return []
    result = []
    for fn in sorted(os.listdir(SCENARIO_DIR)):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(SCENARIO_DIR, fn), encoding="utf-8") as f:
                    result.append(Scenario.from_dict(json.load(f)))
            except Exception:
                pass
    return result


def _make_default_scenarios():
    """최초 실행 시 기본 시나리오 생성"""
    defaults = [
        Scenario(
            id="dhcp_basic", name="기본 할당 검증", plugin="DHCP",
            description="DISCOVER → OFFER → REQUEST → ACK 정상 흐름 검증",
            steps=[
                ScenarioStep(0,"DHCP DISCOVER 송신","Send","",0,3000),
                ScenarioStep(1,"DHCP OFFER 수신 대기","Wait","0x02",0,3000),
                ScenarioStep(2,"제안 IP 주소 검증","Check","192.168.1.x",5,3000),
                ScenarioStep(3,"DHCP REQUEST 송신","Send","",0,3000),
                ScenarioStep(4,"DHCP ACK 수신 대기","Wait","0x05",0,3000),
                ScenarioStep(5,"Lease Time ≥ 3600s 확인","Assert","≥3600s",0,3000,on_fail="stop"),
                ScenarioStep(6,"안정화 대기","Delay","",0,500),
            ],
        ),
        Scenario(
            id="dhcp_aging", name="Aging 장시간 검증", plugin="DHCP",
            description="24시간 연속 DHCP 갱신 사이클 안정성 검증",
            repeat=RepeatConfig(enabled=True, mode="duration", duration_sec=86400, interval_sec=60),
            steps=[
                ScenarioStep(0,"DHCP Renew 송신","Send","",0,5000),
                ScenarioStep(1,"ACK 수신 확인","Wait","0x05",0,5000),
                ScenarioStep(2,"Lease Time 검증","Check","≥3600s",10,3000),
            ],
        ),
        Scenario(
            id="nat_port", name="포트 매핑 검증", plugin="NAT",
            description="WAN→LAN 포트 포워딩 동작 검증",
            steps=[
                ScenarioStep(0,"포트 포워딩 규칙 확인","Check","TCP:8080→192.168.1.10:80",0,3000),
                ScenarioStep(1,"외부 패킷 송신","Send","",0,3000),
                ScenarioStep(2,"내부 수신 확인","Wait","수신OK",0,3000),
                ScenarioStep(3,"역방향 패킷 확인","Check","응답정상",5,3000),
            ],
        ),
        Scenario(
            id="igmp_join", name="Multicast 가입 검증", plugin="IGMP",
            description="IGMP Join/Leave 및 멀티캐스트 트래픽 수신 검증",
            steps=[
                ScenarioStep(0,"IGMP Join 송신","Send","224.0.0.1",0,3000),
                ScenarioStep(1,"Membership Report 확인","Wait","수신OK",0,3000),
                ScenarioStep(2,"멀티캐스트 트래픽 수신","Check","수신정상",5,3000),
                ScenarioStep(3,"IGMP Leave 송신","Send","",0,3000),
                ScenarioStep(4,"Leave 처리 확인","Assert","트래픽중단",0,3000),
            ],
        ),
    ]
    for sc in defaults:
        path = os.path.join(SCENARIO_DIR, f"{sc.id}.json")
        if not os.path.exists(path):
            save_scenario(sc)


_make_default_scenarios()
