"""HTTP 接口层：决策、策略包更新与判定记录查询。"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import DecisionLog
from .bundle_loader import BundleParseError, BundleValidationError, load_bundle
from .models import DecisionRequest
from .service import NoPolicyBundleError, PolicyDecisionService
from .store import PolicyStore


class DecideIn(BaseModel):
    subject: str
    action: str
    resource: str
    context: dict[str, Any] = Field(default_factory=dict)


class BundleIn(BaseModel):
    # 类型放宽为 Any，由 load_bundle 统一区分解析错误与语义错误
    bundle: Any


def create_app() -> FastAPI:
    store = PolicyStore()
    log = DecisionLog()
    service = PolicyDecisionService(store, log)

    app = FastAPI(title="policy-decision-service")
    app.state.store = store
    app.state.log = log
    app.state.service = service

    @app.post("/decide")
    def decide(payload: DecideIn) -> dict[str, Any]:
        request = DecisionRequest(
            subject=payload.subject,
            action=payload.action,
            resource=payload.resource,
            context=payload.context,
        )
        try:
            result = service.decide(request)
        except NoPolicyBundleError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "decision": result.decision.value,
            "allowed": result.allowed,
            "policy_version": result.policy_version,
            "reason_code": result.reason_code.value
            if result.reason_code is not None
            else None,
            "reasons": list(result.reasons),
            "matched": [
                {"rule_id": m.rule_id, "effect": m.effect.value, "reason": m.reason}
                for m in result.matched
            ],
            "missing_attributes": [
                {"rule_id": m.rule_id, "attribute": m.attribute}
                for m in result.missing_attributes
            ],
            "required_attributes": list(result.required_attributes),
        }

    @app.post("/policies")
    def update_policies(payload: BundleIn) -> dict[str, str]:
        try:
            bundle = load_bundle(payload.bundle)
        except BundleParseError as exc:
            raise HTTPException(
                status_code=400, detail={"error": "parse_error", "message": str(exc)}
            ) from exc
        except BundleValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "validation_error", "message": str(exc)},
            ) from exc
        version = store.update(bundle)
        return {"status": "updated", "version": version}

    @app.get("/policies/version")
    def current_version() -> dict[str, Any]:
        bundle = store.snapshot()
        return {"version": bundle.version if bundle else None}

    @app.get("/audit")
    def audit_records() -> list[dict[str, Any]]:
        return [
            {
                "record_id": r.record_id,
                "timestamp": r.timestamp,
                "request": {
                    "subject": r.request.subject,
                    "action": r.request.action,
                    "resource": r.request.resource,
                    "context": r.request.context,
                },
                "decision": r.result.decision.value,
                "allowed": r.result.allowed,
                "policy_version": r.result.policy_version,
                "reason_code": r.result.reason_code.value
                if r.result.reason_code is not None
                else None,
                "reasons": list(r.result.reasons),
                "missing_attributes": [
                    {"rule_id": m.rule_id, "attribute": m.attribute}
                    for m in r.result.missing_attributes
                ],
                "required_attributes": list(r.result.required_attributes),
            }
            for r in log.all()
        ]

    return app
