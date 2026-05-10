"""
plugins/base_plugin.py — 플러그인 베이스 클래스
모든 플러그인은 이 클래스를 상속해야 함
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PluginParam:
    """플러그인 설정 파라미터 정의"""
    key:          str
    label:        str
    default:      Any
    type:         str        = "str"    # str | int | float | bool | choice
    choices:      list       = field(default_factory=list)
    description:  str        = ""


@dataclass
class StepResult:
    step_index:   int
    step_name:    str
    step_type:    str
    expected:     Any        = None
    actual:       Any        = None
    passed:       bool       = True
    elapsed_ms:   float      = 0.0
    message:      str        = ""


class BasePlugin(ABC):
    NAME:        str = "unnamed"
    VERSION:     str = "0.0.0"
    DESCRIPTION: str = ""
    ICON:        str = "ti-plug"       # Tabler icon name (참고용)

    def __init__(self):
        self._params: dict[str, Any] = {p.key: p.default for p in self.get_params()}
        self.enabled: bool = False

    def get_params(self) -> list[PluginParam]:
        """오버라이드 하여 파라미터 목록 반환"""
        return []

    def set_param(self, key: str, value: Any):
        self._params[key] = value

    def get_param(self, key: str) -> Any:
        return self._params.get(key)

    @abstractmethod
    def on_start(self, master_iface: str, slave_iface: str) -> bool:
        """테스트 시작 시 호출. False 반환 시 중단."""
        ...

    @abstractmethod
    def on_stop(self):
        """테스트 중단/완료 시 호출."""
        ...

    @abstractmethod
    def run_step(self, step: dict) -> StepResult:
        """단일 Step 실행. step dict 구조는 scenario_engine 참조."""
        ...

    def get_status(self) -> str:
        """현재 플러그인 상태 문자열"""
        return "실행 중" if self.enabled else "대기 중"
