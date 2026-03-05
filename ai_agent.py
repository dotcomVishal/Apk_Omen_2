"""
ai_agent.py
────────────────────────────────────────────────────────────────────────────────
AI Security Assistant — Groq-powered conversational layer over APK scan reports.

Exposes a single public function:
    ask_security_assistant(question: str, report_context: dict) -> str

The function injects the full MappedReport JSON as grounded context into the
system prompt so the model answers strictly from real scan data — no guessing.

Dependencies:
    pip install groq

Environment variable (required):
    
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import logging
import os
import textwrap
from functools import lru_cache

from groq import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    Groq,
    RateLimitError,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

# Primary model: high-quality, fast, large context.
# Swap to "mixtral-8x7b-32768" for a larger context window if needed.
_MODEL = "llama-3.3-70b-versatile"

# Groq's context window for llama3-70b is 8 192 tokens.
# We allocate a safe ceiling for the response and leave the rest for the prompt.
_MAX_COMPLETION_TOKENS = 1_024

# System prompt template — {report_json} is substituted at call time.
# Intentionally strict: ground the model to the report, forbid fabrication.
_SYSTEM_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an elite Android Security Researcher and penetration tester with deep \
    expertise in mobile application security, OWASP Mobile Top 10, and Android \
    internals.

    A developer has just completed a static analysis scan of their Android APK and \
    is asking you a question about the results. The FULL scan report is provided \
    below as structured JSON.

    STRICT RULES:
    - Answer ONLY from the data in the report. Do NOT hallucinate findings, files, \
      line numbers, or vulnerabilities that are not present in the report JSON.
    - When referencing a finding, cite the exact file path and line number from the \
      evidence array (e.g. "in `src/crypto/CryptoUtil.java` at line 55").
    - When referencing a URL or endpoint, quote it verbatim from the report.
    - If the report does not contain enough information to answer the question, say \
      so explicitly rather than guessing.
    - Be concise and professional. Use markdown for code snippets and emphasis.
    - Prioritise CRITICAL and HIGH severity findings when summarising risk.

    ── SCAN REPORT JSON ────────────────────────────────────────────────────────
    {report_json}
    ── END OF REPORT ───────────────────────────────────────────────────────────
""")


# ──────────────────────────────────────────────────────────────────────────────
# Groq client factory (cached — one client per process)
# ──────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _get_client() -> Groq:
    """
    Instantiate and cache the Groq client.

    Reads GROQ_API_KEY from the environment.  Raises ``RuntimeError`` at
    call time (not import time) if the key is absent so the rest of the
    application can still start without the key configured.
    """
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY environment variable is not set. "
            "Export it before starting the server: export GROQ_API_KEY=gsk_..."
        )
    logger.info("Groq client initialised (model=%s)", _MODEL)
    return Groq(api_key=api_key)


# ──────────────────────────────────────────────────────────────────────────────
# Report serialisation helper
# ──────────────────────────────────────────────────────────────────────────────

def _serialise_report(report_context: dict) -> str:
    """
    Convert the report dict to a compact JSON string for prompt injection.

    Compact separators (no trailing spaces) shave ~15 % off token count
    compared to the default ``json.dumps`` output — important given the
    8 192-token context ceiling.
    """
    try:
        return json.dumps(report_context, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        logger.warning("Could not serialise report_context to JSON: %s", exc)
        # Fallback: str() representation is always safe to embed
        return str(report_context)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def ask_security_assistant(question: str, report_context: dict) -> str:
    """
    Ask the AI security assistant a question grounded in a specific scan report.

    Parameters
    ----------
    question:
        The developer's natural-language question, e.g.
        "Which of my vulnerabilities are most urgent to fix?"
    report_context:
        The full ``MappedReport`` dict from ``vulnerability_mapper.generate_report``.
        Injected verbatim as JSON into the system prompt so every answer is
        traceable back to real scan data.

    Returns
    -------
    str
        The assistant's markdown-formatted response.

    Raises
    ------
    RuntimeError
        If GROQ_API_KEY is not configured.
    ValueError
        If ``question`` is blank.
    Exception
        Re-raises Groq API errors after logging — callers should wrap in try/except.
    """
    question = question.strip()
    if not question:
        raise ValueError("question must not be empty.")

    report_json = _serialise_report(report_context)

    system_message = _SYSTEM_PROMPT_TEMPLATE.format(report_json=report_json)

    logger.info(
        "Sending question to Groq (model=%s, question_len=%d, report_len=%d chars)",
        _MODEL, len(question), len(report_json),
    )

    client = _get_client()

    try:
        completion = client.chat.completions.create(
            model=_MODEL,
            max_tokens=_MAX_COMPLETION_TOKENS,
            temperature=0.2,        # low temperature = factual, grounded answers
            messages=[
                {"role": "system",  "content": system_message},
                {"role": "user",    "content": question},
            ],
        )
    except RateLimitError as exc:
        logger.warning("Groq rate limit reached: %s", exc)
        raise
    except APITimeoutError as exc:
        logger.error("Groq request timed out: %s", exc)
        raise
    except APIConnectionError as exc:
        logger.error("Groq connection error: %s", exc)
        raise
    except APIStatusError as exc:
        logger.error("Groq API error %d: %s", exc.status_code, exc.message)
        raise

    answer: str = completion.choices[0].message.content or ""

    logger.info(
        "Groq response received (tokens used: prompt=%s completion=%s total=%s)",
        completion.usage.prompt_tokens     if completion.usage else "?",
        completion.usage.completion_tokens if completion.usage else "?",
        completion.usage.total_tokens      if completion.usage else "?",
    )

    return answer.strip()
