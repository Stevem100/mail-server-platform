"""API error type + handler so every failure returns {"error": {code, message, ...}}.

Codes mirror the design document: plan_limit_exceeded, feature_not_in_plan, ...
429 for rates, 422 for size/recipients/sender-domain, 409 conflicts, 403 plan/feature.
"""

from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.extra = extra

    def to_response(self) -> JSONResponse:
        body = {"code": self.code, "message": self.message, **self.extra}
        return JSONResponse(status_code=self.status_code, content={"error": body})


class SmtpReject(Exception):
    """Raised by SMTP handlers; carries the numeric SMTP reply code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def plan_limit_exceeded(limit: str) -> ApiError:
    return ApiError(403, "plan_limit_exceeded", f"Plan limit reached: {limit}", limit=limit)


def feature_not_in_plan(feature: str) -> ApiError:
    return ApiError(403, "feature_not_in_plan", f"Feature not in plan: {feature}", feature=feature)


def rate_limited(kind: str) -> ApiError:
    return ApiError(429, "rate_limited", f"Sending rate exceeded: {kind}", window=kind)


async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return exc.to_response()
