"""FastAPI server for SentinelGuard.

Provides REST API endpoints for scanning prompts and outputs,
managing configuration, and health checks.

Usage:
    uvicorn sentinelguard.api.server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sentinelguard.core.config import GuardConfig
from sentinelguard.core.guard import SentinelGuard

logger = logging.getLogger(__name__)

# Lazy import FastAPI to avoid requiring it for non-API usage
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


def create_app(config: Optional[GuardConfig] = None) -> Any:
    """Create and configure the FastAPI application.

    Args:
        config: Optional GuardConfig. Uses defaults if not provided.

    Returns:
        FastAPI application instance.
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the API server. "
            "Install with: pip install sentinelguard[api]"
        )

    app = FastAPI(
        title="SentinelGuard API",
        description="LLM Security & Guardrails API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    guard = SentinelGuard(config=config)

    # ── Request/Response Models ──

    class ScanRequest(BaseModel):
        text: str = Field(..., description="Text to scan")
        scanners: Optional[List[str]] = Field(
            None, description="Specific scanners to run"
        )
        threshold: Optional[float] = Field(
            None, description="Override threshold for all scanners"
        )

    class ValidateRequest(BaseModel):
        prompt: str = Field(..., description="Input prompt")
        output: str = Field(..., description="LLM output")

    class ScannerResult(BaseModel):
        scanner_name: str
        is_valid: bool
        score: float
        risk_level: str
        details: Dict[str, Any] = {}
        latency_ms: float = 0.0

    class ScanResponse(BaseModel):
        is_valid: bool
        results: List[ScannerResult]
        failed_scanners: List[str]
        total_latency_ms: float
        highest_risk: str

    class HealthResponse(BaseModel):
        status: str
        version: str
        prompt_scanners: List[str]
        output_scanners: List[str]

    class ConfigUpdateRequest(BaseModel):
        mode: Optional[str] = None
        fail_fast: Optional[bool] = None
        parallel: Optional[bool] = None

    # ── Endpoints ──

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            version="0.1.0",
            prompt_scanners=guard.prompt_scanner_names,
            output_scanners=guard.output_scanner_names,
        )

    @app.post("/scan/prompt", response_model=ScanResponse)
    async def scan_prompt(request: ScanRequest):
        """Scan a prompt for security issues."""
        try:
            result = guard.scan_prompt(request.text)
            return ScanResponse(
                is_valid=result.is_valid,
                results=[
                    ScannerResult(
                        scanner_name=r.scanner_name,
                        is_valid=r.is_valid,
                        score=r.score,
                        risk_level=r.risk_level.value,
                        details=r.details,
                        latency_ms=r.latency_ms,
                    )
                    for r in result.results
                ],
                failed_scanners=result.failed_scanners,
                total_latency_ms=result.total_latency_ms,
                highest_risk=result.highest_risk.value,
            )
        except Exception as e:
            logger.error(f"Error scanning prompt: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/scan/output", response_model=ScanResponse)
    async def scan_output(request: ScanRequest):
        """Scan an LLM output for security issues."""
        try:
            result = guard.scan_output(request.text)
            return ScanResponse(
                is_valid=result.is_valid,
                results=[
                    ScannerResult(
                        scanner_name=r.scanner_name,
                        is_valid=r.is_valid,
                        score=r.score,
                        risk_level=r.risk_level.value,
                        details=r.details,
                        latency_ms=r.latency_ms,
                    )
                    for r in result.results
                ],
                failed_scanners=result.failed_scanners,
                total_latency_ms=result.total_latency_ms,
                highest_risk=result.highest_risk.value,
            )
        except Exception as e:
            logger.error(f"Error scanning output: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/validate")
    async def validate(request: ValidateRequest):
        """Validate both prompt and output."""
        try:
            results = guard.validate(request.prompt, request.output)
            return {
                "prompt": {
                    "is_valid": results["prompt"].is_valid,
                    "failed_scanners": results["prompt"].failed_scanners,
                    "total_latency_ms": results["prompt"].total_latency_ms,
                },
                "output": {
                    "is_valid": results["output"].is_valid,
                    "failed_scanners": results["output"].failed_scanners,
                    "total_latency_ms": results["output"].total_latency_ms,
                },
            }
        except Exception as e:
            logger.error(f"Error validating: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/scanners")
    async def list_scanners():
        """List all available scanners."""
        from sentinelguard.core.scanner import ScannerRegistry

        return {
            "prompt_scanners": ScannerRegistry.list_prompt_scanners(),
            "output_scanners": ScannerRegistry.list_output_scanners(),
        }

    return app


# Default application instance
app = create_app()
