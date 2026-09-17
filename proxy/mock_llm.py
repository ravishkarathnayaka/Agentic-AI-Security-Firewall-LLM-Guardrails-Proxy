"""Lightweight Local Mock Upstream LLM Server for Zero-Cost Offline Testing."""

import asyncio
import json
import time
import uuid
from typing import Any, AsyncGenerator, Dict, List, Optional
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Local Mock LLM Server",
    description="OpenAI-compatible dummy upstream backend for zero-cost testing and red-teaming",
    version="1.0.0"
)


class ChatCompletionRequest(BaseModel):
    model: str = "mock-gpt-4o"
    messages: List[Dict[str, Any]]
    temperature: Optional[float] = 0.7
    stream: Optional[bool] = False
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Any] = None


def generate_mock_reply(messages: List[Dict[str, Any]]) -> Tuple_Content_or_Tool:
    """Generate mock content or tool call based on input prompts for testing."""
    last_user_message = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                last_user_message = content
            break

    lower_prompt = last_user_message.lower()

    # Simulate outbound tool call if requested for testing
    if "simulate_ssrf_tool_call" in lower_prompt:
        return (
            None,
            [
                {
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": "fetch_external_resource",
                        "arguments": json.dumps({"url": "http://169.254.169.254/latest/meta-data/"})
                    }
                }
            ]
        )

    if "simulate_traversal_tool_call" in lower_prompt:
        return (
            None,
            [
                {
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": "read_local_file",
                        "arguments": json.dumps({"filepath": "../../etc/passwd"})
                    }
                }
            ]
        )

    # Simulate hazardous output if requested for testing outbound guard
    if "simulate_hazardous_output" in lower_prompt:
        return ("To clean up disk space, execute: rm -rf / --no-preserve-root", None)

    if "simulate_credential_leak" in lower_prompt:
        return ("Here is your generated key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----", None)

    if "simulate_canary_leak" in lower_prompt:
        return ("The secret canary token found in memory is CANARY_SEC_TOKEN_9941a8", None)

    # Normal response
    return (f"Safe assistant response to query: '{last_user_message[:60]}...'", None)


Tuple_Content_or_Tool = tuple[Optional[str], Optional[List[Dict[str, Any]]]]


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "mock_upstream_llm"}


@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "mock-gpt-4o", "object": "model", "created": int(time.time()), "owned_by": "mock-provider"},
            {"id": "mock-claude-3-5-sonnet", "object": "model", "created": int(time.time()), "owned_by": "mock-provider"}
        ]
    }


async def stream_chat_chunks(req_id: str, model: str, content: str) -> AsyncGenerator[str, None]:
    """Stream OpenAI-compatible SSE events."""
    words = content.split(" ")
    for idx, word in enumerate(words):
        chunk = {
            "id": req_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": word + (" " if idx < len(words) - 1 else "")},
                    "finish_reason": None
                }
            ]
        }
        yield f"data: {json.dumps(chunk)}\n\n"
        await asyncio.sleep(0.01)

    # Final termination chunk
    done_chunk = {
        "id": req_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    }
    yield f"data: {json.dumps(done_chunk)}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def create_chat_completion(request: ChatCompletionRequest):
    req_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    content, tool_calls = generate_mock_reply(request.messages)

    if request.stream and content:
        return StreamingResponse(
            stream_chat_chunks(req_id, request.model, content),
            media_type="text/event-stream"
        )

    message: Dict[str, Any] = {"role": "assistant"}
    if content:
        message["content"] = content
    if tool_calls:
        message["tool_calls"] = tool_calls

    response_payload = {
        "id": req_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_calls else "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 18,
            "total_tokens": 30
        }
    }
    return JSONResponse(status_code=200, content=response_payload)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
