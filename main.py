"""策略决策服务 HTTP 入口（可完全离线运行）。"""
from __future__ import annotations

from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.errors import BundleError
from app.models import DecisionRequest
from app.service import PolicyDecisionService

app = FastAPI(title="policy-decision-service")
service = PolicyDecisionService()


class DecideIn(BaseModel):
    subject: str
    action: str
    resource: str
    attributes: dict[str, Any] = {}


@app.exception_handler(BundleError)
async def bundle_error_handler(_: Request, exc: BundleError) -> JSONResponse:
    # 解析失败与语义校验失败通过 reason 字段可区分
    return JSONResponse(
        status_code=422,
        content={"error": exc.reason, "detail": str(exc), "field": getattr(exc, "field", None)},
    )


@app.post("/bundles", status_code=201)
def update_bundle(raw: dict[str, Any]) -> dict[str, str]:
    import json

    bundle = service.update_bundle(json.dumps(raw))
    return {"version": bundle.version, "policies": str(len(bundle.policies))}


@app.post("/decide")
def decide(body: DecideIn) -> dict[str, Any]:
    result = service.decide(
        DecisionRequest(
            subject=body.subject,
            action=body.action,
            resource=body.resource,
            attributes=body.attributes,
        )
    )
    return {
        "decision": result.decision.value,
        "policy_version": result.policy_version,
        "matched_policy_ids": list(result.matched_policy_ids),
        "reasons": list(result.reasons),
    }


@app.get("/records")
def records() -> list[dict[str, Any]]:
    return [
        {
            "request": {
                "subject": r.request.subject,
                "action": r.request.action,
                "resource": r.request.resource,
                "attributes": r.request.attributes,
            },
            "decision": r.result.decision.value,
            "policy_version": r.result.policy_version,
            "reasons": list(r.result.reasons),
            "timestamp": r.timestamp,
        }
        for r in service.records()
    ]


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
