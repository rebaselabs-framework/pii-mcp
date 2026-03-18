"""
PII MCP Server v1.0.0

Exposes the PII Intelligence API as MCP tools.
Agents can detect, mask, and audit PII without sending data to an LLM.

Usage:
    pip install pii-mcp
    # Configure in Claude Desktop:
    # {
    #   "mcpServers": {
    #     "pii": {
    #       "command": "uvx",
    #       "args": ["pii-mcp"],
    #       "env": {"PII_API_KEY": "your-key-here"}
    #     }
    #   }
    # }
"""

from __future__ import annotations

import json
import os
from typing import Literal, Optional

import httpx
from mcp.server.fastmcp import FastMCP

# ── Config ────────────────────────────────────────────────────────────────────
API_BASE = os.environ.get("PII_API_URL", "https://pii-api.rebaselabs.online")
API_KEY = os.environ.get("PII_API_KEY", "")
DEFAULT_TIMEOUT = 30.0

mcp = FastMCP(
    "pii",
    instructions=(
        "PII tools detect and sanitize personally identifiable information (PII) from text. "
        "Use these before processing user data, logging, or passing sensitive content to other APIs. "
        "Supports 20+ PII types: names, emails, phones, SSNs, credit cards, addresses, IPs, and more."
    ),
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _headers() -> dict[str, str]:
    if not API_KEY:
        raise ValueError(
            "PII_API_KEY environment variable is not set. "
            "Get a key at https://pii-api.rebaselabs.online"
        )
    return {"X-API-Key": API_KEY, "Content-Type": "application/json"}


async def _post(path: str, body: dict) -> dict:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        resp = await client.post(f"{API_BASE}{path}", json=body, headers=_headers())
        resp.raise_for_status()
        return resp.json()


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def detect_pii(text: str) -> str:
    """
    Detect all PII in a text string and return a structured report.
    Does NOT modify the text — use mask_pii to redact.

    Detects 20+ types including:
    - Names, email addresses, phone numbers
    - Social Security Numbers (SSN), passport numbers
    - Credit card numbers, bank account numbers
    - IP addresses, URLs with credentials
    - Physical addresses, dates of birth
    - Medical record numbers, driver's license numbers

    Returns: list of detected PII with type, value, position, and confidence score.

    Args:
        text: Text to scan for PII
    """
    result = await _post("/api/detect", {"text": text})
    if "entities" in result:
        entities = result["entities"]
        if not entities:
            return "No PII detected in the provided text."
        lines = [f"Found {len(entities)} PII item(s):"]
        for e in entities:
            lines.append(
                f"  [{e.get('type', '?')}] \"{e.get('text', '')}\" "
                f"at pos {e.get('start', '?')}-{e.get('end', '?')} "
                f"(confidence: {e.get('score', e.get('confidence', '?'))})"
            )
        return "\n".join(lines)
    return json.dumps(result, indent=2)


@mcp.tool()
async def mask_pii(
    text: str,
    strategy: str = "mask",
    entity_types: Optional[list[str]] = None,
) -> str:
    """
    Remove or replace PII from text. Returns sanitized text safe for logging, storage, or sharing.

    Strategies:
    - "mask"    → Replace with [TYPE] markers: "John Smith" → "[PERSON]"
    - "fake"    → Replace with realistic synthetic data: "John Smith" → "Sarah Johnson"
    - "hash"    → Replace with SHA-256 hash: "john@example.com" → "a94f2..."
    - "pseudonymize" → Consistent replacement (same input always → same token)

    Args:
        text: Text containing PII to sanitize
        strategy: Replacement strategy — "mask", "fake", "hash", or "pseudonymize"
        entity_types: Optional list of PII types to target (default: all types).
                      Examples: ["PERSON", "EMAIL", "PHONE", "CREDIT_CARD", "SSN"]
    """
    body: dict = {"text": text, "strategy": strategy}
    if entity_types:
        body["entity_types"] = entity_types
    result = await _post("/api/mask", body)
    if "masked_text" in result:
        lines = [f"Sanitized text ({strategy}):\n{result['masked_text']}"]
        if "entities_masked" in result:
            lines.append(f"\nMasked {result['entities_masked']} PII item(s)")
        return "\n".join(lines)
    return json.dumps(result, indent=2)


@mcp.tool()
async def audit_pii(text: str) -> str:
    """
    Run a full GDPR compliance audit on text.
    Returns a detailed report with PII density score, risk level, compliance recommendations,
    and a complete breakdown by PII category.

    Use before processing user-submitted content, sending data to third-party APIs,
    or storing text in databases.

    Args:
        text: Text to audit for compliance
    """
    result = await _post("/api/audit", {"text": text})
    if "report" in result:
        report = result["report"]
        lines = [
            f"GDPR Compliance Audit",
            f"Risk level: {report.get('risk_level', '?')}",
            f"PII density: {report.get('pii_density', '?')}%",
            f"Total PII found: {report.get('total_pii_count', '?')}",
            f"",
            "By category:",
        ]
        for cat, count in (report.get("by_category") or {}).items():
            lines.append(f"  {cat}: {count}")
        if report.get("recommendations"):
            lines.append("\nRecommendations:")
            for rec in report["recommendations"]:
                lines.append(f"  - {rec}")
        return "\n".join(lines)
    return json.dumps(result, indent=2)


@mcp.tool()
async def scan_and_mask(text: str, strategy: str = "mask") -> str:
    """
    Detect PII and immediately return sanitized text in one call.
    Convenience tool combining detect_pii + mask_pii for the common case.

    Returns both the sanitized text and a summary of what was found and replaced.

    Args:
        text: Text to scan and sanitize
        strategy: How to replace PII — "mask" (default), "fake", "hash", or "pseudonymize"
    """
    body = {"text": text, "strategy": strategy}
    result = await _post("/api/mask", body)
    masked = result.get("masked_text", text)
    count = result.get("entities_masked", 0)
    entities = result.get("entities", [])
    lines = [f"Sanitized ({count} PII item(s) replaced with strategy='{strategy}'):\n"]
    lines.append(masked)
    if entities:
        lines.append(f"\nReplaced:")
        for e in entities:
            lines.append(f"  [{e.get('type', '?')}] \"{e.get('original', e.get('text', ''))}\" → \"{e.get('replacement', '[REDACTED]')}\"")
    return "\n".join(lines)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    """Run the PII MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
