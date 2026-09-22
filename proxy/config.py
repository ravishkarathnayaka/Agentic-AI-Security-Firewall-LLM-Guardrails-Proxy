"""Proxy configuration module for Agentic AI Security Firewall & Guardrails Proxy."""

import os
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxySettings(BaseSettings):
    """Configuration settings for LLM Security Guardrails Proxy."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Upstream LLM Target
    UPSTREAM_LLM_URL: str = Field(
        default="http://mock-llm",
        description="URL for upstream LLM (http://mock-llm for built-in zero-cost mock, http://localhost:8081, or Ollama)"
    )
    UPSTREAM_API_KEY: str = Field(
        default="mock-llm-key",
        description="Optional API key for upstream LLM"
    )
    REQUEST_TIMEOUT_SECONDS: float = Field(
        default=60.0,
        description="Timeout for upstream LLM requests in seconds"
    )

    # Server settings
    PROXY_HOST: str = Field(default="0.0.0.0", description="Proxy listen host")
    PROXY_PORT: int = Field(default=8080, description="Proxy listen port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    AUDIT_LOG_FILE: str = Field(
        default="audit_logs.jsonl",
        description="Path to append structured JSON audit logs"
    )

    # Guard Switches
    ENABLE_PROMPT_INJECTION_GUARD: bool = Field(
        default=True,
        description="Enable multi-layered prompt injection and jailbreak detector"
    )
    ENABLE_PII_SANITIZER: bool = Field(
        default=True,
        description="Enable inbound PII detection and redaction"
    )
    ENABLE_SYSTEM_PROMPT_GUARD: bool = Field(
        default=True,
        description="Enable canary tracking and system prompt extraction guard"
    )
    ENABLE_OUTPUT_SANITIZER: bool = Field(
        default=True,
        description="Enable outbound credential leakage and shell command sanitizer"
    )
    ENABLE_TOOL_CALL_VALIDATOR: bool = Field(
        default=True,
        description="Enable agentic tool call argument validator (SSRF & path traversal)"
    )
    ENABLE_HOMOGLYPH_GUARD: bool = Field(
        default=True,
        description="Enable homoglyph spoofing and leetspeak deobfuscation detector"
    )
    ENABLE_ENTROPY_SCANNER: bool = Field(
        default=True,
        description="Enable Shannon entropy secret scanner for output leakage defense"
    )
    ENABLE_ANOMALY_GUARD: bool = Field(
        default=True,
        description="Enable structural anomaly and glitch token repetition detector"
    )
    ENABLE_MULTILINGUAL_GUARD: bool = Field(
        default=True,
        description="Enable multilingual jailbreak and translation evasion detector"
    )
    ENABLE_MCP_VALIDATOR: bool = Field(
        default=True,
        description="Enable Model Context Protocol (MCP) tool execution validator"
    )
    ENABLE_SQL_GUARD: bool = Field(
        default=True,
        description="Enable SQL and NoSQL injection detector for agentic tools"
    )
    ENABLE_AST_SANDBOX_GUARD: bool = Field(
        default=True,
        description="Enable AST code sandbox policy inspector for generated code"
    )
    ENABLE_DIFFERENTIAL_LEAK_GUARD: bool = Field(
        default=True,
        description="Enable differential n-gram system prompt leakage detector"
    )
    ENABLE_HALLUCINATION_GUARD: bool = Field(
        default=False,
        description="Enable RAG hallucination and citation grounding verifier"
    )
    ENABLE_TOKEN_PADDING_GUARD: bool = Field(
        default=True,
        description="Enable token padding and delimiter evasion guard"
    )
    ENABLE_WATERMARK_GUARD: bool = Field(
        default=True,
        description="Enable sensitive document watermark and classification detector"
    )
    CANARY_SECRET_KEY: str = Field(
        default="llm-guardrails-proxy-canary-secret-salt-2026",
        description="Secret key used to compute HMAC signatures for dynamic canaries"
    )
    ENABLE_RATE_LIMITER: bool = Field(
        default=True,
        description="Enable IP/Client rate limiting against denial of service"
    )
    RATE_LIMIT_RPM: int = Field(
        default=120,
        description="Maximum requests per minute per client IP"
    )
    RATE_LIMIT_BURST: int = Field(
        default=25,
        description="Maximum burst requests per second per client IP"
    )

    # Security Thresholds & Canaries
    INJECTION_THRESHOLD: float = Field(
        default=0.60,
        description="Composite risk score threshold [0.0 - 1.0] for blocking prompt injection"
    )
    CANARY_TOKEN: str = Field(
        default="CANARY_SEC_TOKEN_9941a8",
        description="Internal secret canary token for leak detection"
    )
    DE_ANONYMIZE_OUTPUT: bool = Field(
        default=False,
        description="Whether to de-anonymize redacted PII tokens in model response"
    )


@lru_cache()
def get_settings() -> ProxySettings:
    """Return cached settings instance."""
    return ProxySettings()
