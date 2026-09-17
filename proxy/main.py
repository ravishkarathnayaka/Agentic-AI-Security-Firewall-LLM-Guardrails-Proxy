"""FastAPI Reverse Proxy application exposing OpenAI-compatible /v1/chat/completions with inline guardrails."""

import json
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST

from proxy.config import ProxySettings, get_settings
from proxy.pipeline import SecurityPipeline
from proxy.telemetry.audit_logger import audit_logger


settings: ProxySettings = get_settings()
pipeline: SecurityPipeline = SecurityPipeline(settings)
http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    """Return active HTTP client, initializing in-process mock transport if configured."""
    global http_client
    if http_client is None or http_client.is_closed:
        if settings.UPSTREAM_LLM_URL in ("mock", "http://mock-llm", "http://mock"):
            from proxy.mock_llm import app as mock_app
            transport = httpx.ASGITransport(app=mock_app)
            http_client = httpx.AsyncClient(transport=transport, base_url="http://mock-llm")
        else:
            http_client = httpx.AsyncClient(
                base_url=settings.UPSTREAM_LLM_URL,
                timeout=httpx.Timeout(settings.REQUEST_TIMEOUT_SECONDS, connect=5.0)
            )
    return http_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage lifecycle of HTTP client connections."""
    global http_client
    http_client = get_http_client()
    yield
    if http_client and not http_client.is_closed:
        await http_client.aclose()


app = FastAPI(
    title="Agentic AI Security Firewall & Guardrails Proxy",
    description="Enterprise-grade AI security firewall mitigating OWASP Top 10 for LLMs",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for agent frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_client_ip(request: Request) -> str:
    """Extract client IP addressing proxies and direct connections."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@app.get("/health")
async def health_check():
    """Proxy health check and enabled guardrails status."""
    return {
        "status": "healthy",
        "service": "llm_security_guardrails_proxy",
        "upstream_url": settings.UPSTREAM_LLM_URL,
        "guards": {
            "prompt_injection_guard": settings.ENABLE_PROMPT_INJECTION_GUARD,
            "pii_sanitizer": settings.ENABLE_PII_SANITIZER,
            "system_prompt_guard": settings.ENABLE_SYSTEM_PROMPT_GUARD,
            "output_sanitizer": settings.ENABLE_OUTPUT_SANITIZER,
            "tool_call_validator": settings.ENABLE_TOOL_CALL_VALIDATOR,
        }
    }


@app.get("/metrics")
async def metrics_endpoint():
    """Prometheus metrics scrape endpoint."""
    return Response(
        content=audit_logger.get_prometheus_metrics(),
        media_type=CONTENT_TYPE_LATEST
    )


@app.get("/v1/models")
async def list_models(request: Request):
    """Proxy /v1/models query to upstream LLM or return default catalog."""
    global http_client
    if http_client:
        try:
            resp = await http_client.get("/v1/models")
            if resp.status_code == 200:
                return JSONResponse(status_code=200, content=resp.json())
        except Exception:
            pass

    # Fallback catalog
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "owned_by": "security-proxy"},
            {"id": "llama-3-70b", "object": "model", "owned_by": "security-proxy"},
            {"id": "claude-3-5-sonnet", "object": "model", "owned_by": "security-proxy"},
        ]
    }


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """Inspects inbound prompts, forwards to upstream LLM, and inspects outbound responses."""
    global http_client
    start_time = time.time()
    request_id = request.headers.get("x-request-id", f"req-{uuid.uuid4().hex[:12]}")
    client_ip = get_client_ip(request)

    # 1. Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body in request")

    # 2. Inbound Security Pipeline
    inbound_res = pipeline.process_inbound(
        payload=payload,
        request_id=request_id,
        client_ip=client_ip
    )

    if not inbound_res.is_allowed:
        return JSONResponse(
            status_code=400,
            content=inbound_res.error_response,
            headers={"X-Security-Action": "BLOCKED", "X-Request-ID": request_id}
        )

    sanitized_payload = inbound_res.sanitized_payload or payload
    context = inbound_res.context
    is_streaming = sanitized_payload.get("stream", False)

    # 3. Forward to Upstream LLM
    client = get_http_client()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.UPSTREAM_API_KEY}",
        "X-Request-ID": request_id,
    }

    try:
        if is_streaming:
            # Handle streaming response
            upstream_req = client.build_request(
                "POST",
                "/v1/chat/completions",
                json=sanitized_payload,
                headers=headers,
                timeout=settings.REQUEST_TIMEOUT_SECONDS
            )
            upstream_stream = await client.send(upstream_req, stream=True)

            if upstream_stream.status_code != 200:
                body = await upstream_stream.aread()
                await upstream_stream.aclose()
                return Response(
                    content=body,
                    status_code=upstream_stream.status_code,
                    media_type="application/json"
                )

            async def sse_generator() -> AsyncGenerator[bytes, None]:
                try:
                    async for chunk in upstream_stream.aiter_bytes():
                        yield chunk
                finally:
                    await upstream_stream.aclose()

            return StreamingResponse(
                sse_generator(),
                media_type="text/event-stream",
                headers={"X-Security-Action": "ALLOWED", "X-Request-ID": request_id}
            )

        else:
            # Handle standard JSON request
            resp = await client.post(
                "/v1/chat/completions",
                json=sanitized_payload,
                headers=headers,
                timeout=settings.REQUEST_TIMEOUT_SECONDS
            )

            if resp.status_code != 200:
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    media_type="application/json"
                )

            upstream_json = resp.json()

            # 4. Outbound Security Pipeline
            outbound_res = pipeline.process_outbound(
                response_json=upstream_json,
                context=context
            )

            if not outbound_res.is_allowed:
                return JSONResponse(
                    status_code=400,
                    content=outbound_res.error_response,
                    headers={"X-Security-Action": "BLOCKED", "X-Request-ID": request_id}
                )

            return JSONResponse(
                status_code=200,
                content=outbound_res.sanitized_response,
                headers={"X-Security-Action": "ALLOWED", "X-Request-ID": request_id}
            )

    except httpx.ConnectError:
        error_msg = f"Cannot connect to upstream LLM at {settings.UPSTREAM_LLM_URL}. Is upstream running?"
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "type": "upstream_connection_error",
                    "code": "bad_gateway",
                    "message": error_msg
                }
            }
        )
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={
                "error": {
                    "type": "upstream_timeout_error",
                    "code": "gateway_timeout",
                    "message": f"Upstream LLM timed out after {settings.REQUEST_TIMEOUT_SECONDS}s."
                }
            }
        )
    except Exception as err:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "type": "proxy_internal_error",
                    "code": "internal_error",
                    "message": str(err)
                }
            }
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.PROXY_HOST, port=settings.PROXY_PORT)
