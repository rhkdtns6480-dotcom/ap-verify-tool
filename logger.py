"""
logger.py — AP Verify Tool 전역 로거
RotatingFileHandler + GUI 콜백 지원
"""
import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Callable, Optional

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO":  logging.INFO,
    "WARN":  logging.WARNING,
    "ERROR": logging.ERROR,
}

LOG_FORMAT = "[%(asctime)s.%(msecs)03d] [%(levelname)s] [%(source)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _get_log_dir() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "APVerifyTool", "logs")
    else:
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(base, exist_ok=True)
    return base


class SourceFilter(logging.Filter):
    def __init__(self, source: str = "SYSTEM"):
        super().__init__()
        self.source = source

    def filter(self, record):
        if not hasattr(record, "source"):
            record.source = self.source
        return True


class AppLogger:
    _instance: Optional["AppLogger"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._callbacks: list[Callable] = []

        log_dir  = _get_log_dir()
        log_file = os.path.join(log_dir, f"ap_verify_{datetime.now().strftime('%Y%m%d')}.log")

        self.logger = logging.getLogger("APVerifyTool")
        self.logger.setLevel(logging.DEBUG)
        self.logger.addFilter(SourceFilter())

        fh = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8-sig"
        )
        fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        self.logger.addHandler(fh)

        self.log_file = log_file

    def add_callback(self, cb: Callable):
        """GUI 로그뷰가 등록하는 콜백. cb(timestamp, level, source, message) 형태."""
        self._callbacks.append(cb)

    def remove_callback(self, cb: Callable):
        self._callbacks.remove(cb)

    def _emit(self, level: str, source: str, message: str):
        extra = {"source": source}
        ts = datetime.now().strftime("%H:%M:%S.") + f"{datetime.now().microsecond//1000:03d}"
        getattr(self.logger, level.lower())(message, extra=extra)
        for cb in self._callbacks:
            try:
                cb(ts, level, source, message)
            except Exception:
                pass

    def debug(self, msg: str, source: str = "SYSTEM"):
        self._emit("DEBUG", source, msg)

    def info(self, msg: str, source: str = "SYSTEM"):
        self._emit("INFO", source, msg)

    def warn(self, msg: str, source: str = "SYSTEM"):
        self._emit("WARN", source, msg)

    def error(self, msg: str, source: str = "SYSTEM"):
        self._emit("ERROR", source, msg)


# 전역 싱글톤 접근
log = AppLogger()
