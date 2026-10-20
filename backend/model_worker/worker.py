"""
Bayora Stateless Model Worker
Simulates an LLM inference service with explicit context purging and KV-cache reset
to prevent context poisoning across evaluation turns.
"""

import gc
import logging
import time
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("model_worker")

app = FastAPI(
    title="Bayora Stateless Model Worker",
    description="Stateless LLM inference worker with post-turn memory and KV-cache purging.",
    version="1.0.0"
)

# Simulated in-memory conversation state (must be emptied on every turn)
active_session_cache: list[dict] = []


class GenerateRequest(BaseModel):
    prompt: str = Field(..., description="Prompt payload to evaluate")
    flush_context: bool = Field(default=True, description="Enforce explicit KV-cache and session memory wipe")


class GenerateResponse(BaseModel):
    response: str
    tokens_generated: int
    stateless_purge_executed: bool
    cache_status: str
    inference_time_ms: float


def purge_execution_context() -> None:
    """
    Simulates hardware GPU cache flush (torch.cuda.empty_cache())
    and wipes conversation session history to guarantee strict turn isolation.
    """
    global active_session_cache
    active_session_cache.clear()
    gc.collect()
    logger.info("[PURGE] KV-cache wiped, session state reset to 0, memory reclaimed (torch.cuda.empty_cache() simulated).")


@app.get("/health")
async def health():
    return {
        "status": "ONLINE",
        "service": "bayora-model-worker",
        "active_cache_entries": len(active_session_cache)
    }


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest):
    """
    Generates response tokens for an evaluation prompt, then wipes
    all transient context if flush_context is True.
    """
    start_ts = time.perf_counter()

    # Adversarial keyword classification
    prompt_lower = req.prompt.lower()
    is_jailbreak = any(
        term in prompt_lower
        for term in [
            "dan", "jailbreak", "bypass", "unfiltered", "ignore all rules",
            "sudo", "ptrace", "syscall", "shadow file", "api_key"
        ]
    )

    if is_jailbreak:
        generated_text = (
            "[MOCK REFUSAL] Adversarial safety violation detected: The requested operation "
            "attempts to circumvent security containment, extract credentials, or override system guidelines."
        )
    else:
        generated_text = (
            "[MOCK RESPONSE] Stateless inference response generated nominal under Sentry gVisor sandbox. "
            "Task executed within isolated execution envelope."
        )

    # Estimate token count
    token_count = max(len(generated_text.split()), 1)

    # Enforce stateless context purge
    purge_done = False
    if req.flush_context:
        purge_execution_context()
        purge_done = True

    duration_ms = (time.perf_counter() - start_ts) * 1000.0

    return GenerateResponse(
        response=generated_text,
        tokens_generated=token_count,
        stateless_purge_executed=purge_done,
        cache_status="FLUSHED" if purge_done else "PERSISTED",
        inference_time_ms=round(duration_ms, 2)
    )
