"""策略存储：以原子方式切换版本，评估基于快照完成。"""
from __future__ import annotations

import threading

from .models import PolicyBundle


class PolicyStore:
    """持有当前生效的策略包快照。

    PolicyBundle 本身不可变，读取方拿到快照引用后，
    更新操作只替换引用，不影响正在进行的评估，
    因此同一次评估始终基于同一版本完成。
    """

    def __init__(self, bundle: PolicyBundle | None = None) -> None:
        self._lock = threading.Lock()
        self._bundle = bundle

    def snapshot(self) -> PolicyBundle | None:
        """获取当前版本快照（评估期间引用不变）。"""
        with self._lock:
            return self._bundle

    def update(self, bundle: PolicyBundle) -> str:
        """原子切换到新版本，返回版本号。更新期间旧版本仍可服务。"""
        if not isinstance(bundle, PolicyBundle):
            raise TypeError("update 只接受已校验的 PolicyBundle")
        with self._lock:
            self._bundle = bundle
        return bundle.version
