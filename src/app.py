import logging
import math
import re
import time
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import Settings, load_settings
from .logging_config import configure_logging
from .model import PhishingModel
from .ratelimit import SlidingWindowRateLimiter, resolve_client_ip
from .signals import SignalConfig, collect_signals
from .signals.netguard import NetworkPolicy
from .validation import InvalidURLError, validate_url

logger = logging.getLogger("phishing_api.app")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class URLRequest(BaseModel):
    # The real URL checks live in validation.validate_url; this cap only keeps
    # absurdly large bodies from being processed at all.
    url: str = Field(..., max_length=4096)
    explain: bool = True      # include SHAP contributions
    deep_scan: bool = False   # also do DNS / certificate / page-content / reputation lookups


class PredictResponse(BaseModel):
    url: str
    prediction: str
    phishing_probability: float
    legitimate_probability: float
    features: dict[str, Any]
    contributions: Optional[dict[str, float]] = None
    explanation: Optional[dict[str, Any]] = None
    signals: dict[str, Any]
    request_id: str


def create_app(settings: Settings | None = None, model: PhishingModel | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(settings.log_level)

    if model is None:
        model = PhishingModel.load(load_explainer=settings.enable_explanations)

    if "*" in settings.cors_allow_origins:
        logger.warning("CORS_ALLOW_ORIGINS contains '*': any website can call this API from a browser.")

    app = FastAPI(
        title="Phishing URL Detection API",
        description="API for detecting phishing URLs using a Random Forest model, "
        "with SHAP explanations and optional network-based signals",
        version="2.0.0",
    )
    app.state.settings = settings
    app.state.model = model

    predict_limiter = SlidingWindowRateLimiter(settings.rate_limit_per_minute)
    deep_limiter = SlidingWindowRateLimiter(settings.deep_scan_rate_limit_per_minute)
    signal_config = SignalConfig(
        overall_timeout=settings.deep_scan_timeout_seconds,
        policy=NetworkPolicy(),
        safe_browsing_api_key=settings.safe_browsing_api_key,
    )

    # ---- Request id, body-size guard and access log -----------------------
    @app.middleware("http")
    async def request_context(request: Request, call_next):
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
        request.state.request_id = request_id
        client_ip = resolve_client_ip(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            settings.trusted_proxy_count,
        )
        request.state.client_ip = client_ip
        started = time.perf_counter()

        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > settings.max_request_body_bytes:
            response = JSONResponse({"detail": "Request body too large.", "request_id": request_id}, status_code=413)
        else:
            try:
                response = await call_next(request)
            except Exception:
                logger.exception("unhandled error", extra={"request_id": request_id, "path": request.url.path})
                response = JSONResponse({"detail": "Internal server error.", "request_id": request_id}, status_code=500)

        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "client_ip": client_ip,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )
        return response

    # ---- CORS -------------------------------------------------------------
    # Added last, so it is the outermost layer: even 413/429/500 responses carry
    # CORS headers and the browser can show the real error instead of a CORS failure.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allow_origins),
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )

    # ---- Error shapes: `detail` is always a short string ------------------
    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
        message = f"{where}: {first.get('msg', 'invalid request')}" if where else "Invalid request."
        return JSONResponse(
            {"detail": message, "request_id": getattr(request.state, "request_id", None)},
            status_code=422,
        )

    def _rate_limit(limiter: SlidingWindowRateLimiter, request: Request, what: str) -> None:
        allowed, retry_after = limiter.check(request.state.client_ip)
        if not allowed:
            seconds = max(1, math.ceil(retry_after))
            logger.warning(
                "rate limited",
                extra={"request_id": request.state.request_id, "client_ip": request.state.client_ip, "bucket": what},
            )
            raise HTTPException(
                status_code=429,
                detail=f"Too many {what} requests. Try again in {seconds} seconds.",
                headers={"Retry-After": str(seconds)},
            )

    # ---- Routes -----------------------------------------------------------
    @app.get("/")
    def root():
        return {"message": "Phishing Detection API is running"}

    @app.get("/health")
    def health():
        """Liveness: the process is up. Point uptime monitors here."""
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        """Readiness: the model is loaded."""
        return {
            "status": "ready",
            "model_loaded": True,
            "explainer_loaded": app.state.model.explainer_loaded,
            "deep_scan_enabled": settings.enable_deep_scan,
        }

    @app.post("/predict", response_model=PredictResponse)
    def predict(payload: URLRequest, request: Request):
        _rate_limit(predict_limiter, request, "prediction")

        try:
            target = validate_url(payload.url)
        except InvalidURLError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

        deep_scan = payload.deep_scan and settings.enable_deep_scan
        if deep_scan:
            _rate_limit(deep_limiter, request, "deep-scan")

        result = app.state.model.predict(target.url, explain=payload.explain)
        signals = collect_signals(target, signal_config, deep_scan=deep_scan)
        if payload.deep_scan and not settings.enable_deep_scan:
            signals["deep_scan_note"] = "Deep scan is disabled on this server."

        result["signals"] = signals
        result["request_id"] = request.state.request_id

        # Log the host and verdict, not the full URL: links often carry private tokens.
        logger.info(
            "prediction",
            extra={
                "request_id": request.state.request_id,
                "host": target.ascii_hostname,
                "prediction": result["prediction"],
                "phishing_probability": round(result["phishing_probability"], 4),
                "deep_scan": deep_scan,
                "explained": result["explanation"] is not None,
                "flags": len(signals["flags"]),
            },
        )
        return result

    return app


app = create_app()
