"""策略更新期间结论按版本保持稳定、记录与结论不丢失错配。"""
import threading

from policy_service.bundle_loader import load_bundle
from policy_service.models import Decision, DecisionRequest

from .conftest import BUNDLE_V2, log_decision


def test_update_is_atomic_and_old_snapshot_unaffected(store, service):
    """已取得的快照在更新后仍按旧版本评估，不混杂新版本。"""
    snapshot = store.snapshot()
    store.update(load_bundle(BUNDLE_V2))

    from policy_service.evaluator import evaluate

    req = DecisionRequest(subject="alice", action="read", resource="doc")
    old_result = evaluate(snapshot, req)
    log_decision(req, old_result)
    assert old_result.policy_version == "v1"
    assert old_result.decision is Decision.ALLOW

    new_result = service.decide(req)
    log_decision(req, new_result)
    assert new_result.policy_version == "v2"
    assert new_result.decision is Decision.DENY


def test_concurrent_decisions_during_update(store, service, log):
    """并发评估与更新同时进行：每条结论的版本只能是 v1 或 v2，
    且与判定记录一一对应，不丢失、不错配。"""
    req = DecisionRequest(subject="alice", action="read", resource="doc")
    errors: list[BaseException] = []
    results: list = []
    results_lock = threading.Lock()
    stop = threading.Event()

    def updater():
        while not stop.is_set():
            store.update(load_bundle(BUNDLE_V2))
            store.update(load_bundle({"version": "v1", "policies": [
                {"id": "allow-read", "effect": "allow",
                 "resource": "doc", "action": "read"},
            ]}))

    def decider():
        try:
            for _ in range(500):
                r = service.decide(req)
                with results_lock:
                    results.append(r)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=updater)] + [
        threading.Thread(target=decider) for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads[1:]:
        t.join()
    stop.set()
    threads[0].join()

    assert not errors
    assert len(results) > 0
    for r in results:
        # 每次评估整体基于单一版本：版本与结论必须自洽
        log_decision(req, r)
        if r.policy_version == "v1":
            assert r.decision is Decision.ALLOW
        elif r.policy_version == "v2":
            assert r.decision is Decision.DENY
        else:
            raise AssertionError(f"出现未知版本: {r.policy_version}")

    records = log.all()
    assert len(records) == len(results)
    for rec in records:
        assert rec.request == req
        assert rec.result.policy_version in {"v1", "v2"}
        # 记录中的结论与版本必须对应
        expected = (
            Decision.ALLOW if rec.result.policy_version == "v1" else Decision.DENY
        )
        assert rec.result.decision is expected
