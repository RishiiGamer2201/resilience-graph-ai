"""
src/agents/__init__.py — Shared contracts for the 10-agent pipeline.

Every agent in the pipeline returns an AgentResult. The Orchestrator (Agent 10)
validates every result at every boundary before passing it downstream.

Usage:
    from src.agents import AgentResult, AgentStatus
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AgentStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"   # partial output, pipeline continues
    FAILED = "failed"       # no usable output; Orchestrator triggers fallback


@dataclass
class AgentResult:
    """Typed contract that every agent must return.

    Fields:
        agent:         canonical agent name (e.g. "investigation", "detection")
        status:        ok | degraded | failed
        confidence:    overall confidence in this agent's output (0.0 – 1.0)
        output:        agent-specific payload dict
        evidence_refs: list of evidence chunk IDs / ATT&CK IDs cited
        ms:            wall-clock execution time in milliseconds
        notes:         optional debug/audit notes (never shown as authoritative)
    """
    agent: str
    status: AgentStatus = AgentStatus.OK
    confidence: float = 1.0
    output: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    ms: float = 0.0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "agent": self.agent,
            "status": self.status.value,
            "confidence": round(self.confidence, 3),
            "output": self.output,
            "evidence_refs": self.evidence_refs,
            "ms": round(self.ms, 1),
            "notes": self.notes,
        }
