"""策略包加载失败的可区分错误类型。"""
from __future__ import annotations


class BundleError(Exception):
    """策略包错误基类。"""

    reason: str = "bundle_error"


class BundleParseError(BundleError):
    """策略包无法解析（非 JSON / 结构不是对象等）。"""

    reason = "parse_error"


class BundleValidationError(BundleError):
    """策略包可解析但语义非法。"""

    reason = "validation_error"

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field
