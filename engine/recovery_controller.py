"""
engine/recovery_controller.py
-----------------------------
Failure classification and error recovery controller for Raven.

Handles transient network drops, rate limits, timeouts, tool crashes,
and authentication failures gracefully without halting the assessment.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, Optional

from engine_models.actions import AgentAction
from engine_models.state import AssessmentState

logger = logging.getLogger("raven.engine.recovery")


class FailureType(str, Enum):
    """Classification of errors encountered during assessment execution."""

    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    RATE_LIMIT = "rate_limit"
    AUTHENTICATION_FAILURE = "authentication_failure"
    SCOPE_VIOLATION = "scope_violation"
    TOOL_CRASH = "tool_crash"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INVALID_ARGS = "invalid_args"
    MALFORMED_OUTPUT = "malformed_output"
    REPEATED_ACTION = "repeated_action"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    """Decision on how to respond to an encountered failure."""

    RETRY = "retry"
    BACKOFF_RETRY = "backoff_retry"
    SKIP = "skip"
    SWITCH_TOOL = "switch_tool"
    DEGRADE_CAPABILITY = "degrade_capability"
    ABORT = "abort"


TOOL_ALTERNATIVES: Dict[str, str] = {
    "banner_grab": "protocol_probe",
    "protocol_probe": "banner_grab",
    "dir_fuzz": "http_probe",
    "http_probe_batch": "http_probe",
    "config_scan": "secret_scan",
    "secret_scan": "rule_engine_scan",
    "port_scan": "banner_grab",
}


class RecoveryController:
    """
    Classifies tool and network execution failures and decides recovery strategy.
    """

    def __init__(self, max_retries: int = 3) -> None:
        self.max_retries = max_retries

    def suggest_alternative_tool(self, failed_tool: str) -> Optional[str]:
        """Return alternative tool name if one is available."""
        return TOOL_ALTERNATIVES.get(failed_tool)

    def classify_failure(
        self,
        error: Any,
        status_code: Optional[int] = None,
    ) -> FailureType:
        """Categorize an exception or error response into a FailureType."""
        err_str = str(error).lower()

        if status_code == 429 or "rate limit" in err_str or "too many requests" in err_str:
            return FailureType.RATE_LIMIT

        if status_code in (401, 403) or "unauthorized" in err_str or "forbidden" in err_str:
            return FailureType.AUTHENTICATION_FAILURE

        if "timeout" in err_str or "timed out" in err_str:
            return FailureType.TIMEOUT

        if any(w in err_str for w in ("connection refused", "connection reset", "broken pipe", "unreachable")):
            return FailureType.CONNECTION_ERROR

        if "scope" in err_str or "out of scope" in err_str:
            return FailureType.SCOPE_VIOLATION

        if "budget" in err_str or "exhausted" in err_str:
            return FailureType.BUDGET_EXHAUSTED

        if "invalid" in err_str and any(k in err_str for k in ("arg", "param", "schema")):
            return FailureType.INVALID_ARGS

        if "repeated" in err_str or "identical action" in err_str:
            return FailureType.REPEATED_ACTION

        if any(k in err_str for k in ("malformed", "parse error", "jsondecode")):
            return FailureType.MALFORMED_OUTPUT

        return FailureType.TOOL_CRASH

    def determine_recovery(
        self,
        failure_type: FailureType,
        retry_count: int,
        tool_name: Optional[str] = None,
    ) -> RecoveryAction:
        """Determine what recovery action to take given the failure type and retry history."""
        if failure_type == FailureType.SCOPE_VIOLATION:
            return RecoveryAction.SKIP

        if failure_type == FailureType.BUDGET_EXHAUSTED:
            return RecoveryAction.ABORT

        if failure_type == FailureType.REPEATED_ACTION:
            return RecoveryAction.SKIP

        if failure_type in (FailureType.INVALID_ARGS, FailureType.MALFORMED_OUTPUT):
            if tool_name and self.suggest_alternative_tool(tool_name):
                return RecoveryAction.SWITCH_TOOL
            return RecoveryAction.SKIP

        if failure_type == FailureType.RATE_LIMIT:
            if retry_count < self.max_retries:
                return RecoveryAction.BACKOFF_RETRY
            return RecoveryAction.SKIP

        if failure_type in (FailureType.TIMEOUT, FailureType.CONNECTION_ERROR):
            if retry_count < self.max_retries:
                return RecoveryAction.RETRY
            if tool_name and self.suggest_alternative_tool(tool_name):
                return RecoveryAction.SWITCH_TOOL
            return RecoveryAction.SKIP

        if failure_type == FailureType.AUTHENTICATION_FAILURE:
            return RecoveryAction.DEGRADE_CAPABILITY

        # Default fallback for tool crashes or unknown
        if retry_count < 1:
            return RecoveryAction.RETRY
        if tool_name and self.suggest_alternative_tool(tool_name):
            return RecoveryAction.SWITCH_TOOL
        return RecoveryAction.SKIP

    def record_failure(
        self,
        action: AgentAction,
        failure_type: FailureType,
        error_msg: str,
        state: AssessmentState,
    ) -> None:
        """Record the failure in assessment state audit and limitation logs."""
        failure_entry = {
            "action_id": action.action_id,
            "tool_name": action.tool_name,
            "target": action.target,
            "failure_type": failure_type.value,
            "error": error_msg,
        }
        state.tool_failures.append(failure_entry)
        limitation_text = f"Tool '{action.tool_name}' failed on '{action.target}': {failure_type.value} ({error_msg[:100]})"
        if limitation_text not in state.limitations:
            state.limitations.append(limitation_text)
        logger.warning(f"Recorded failure: {limitation_text}")

    async def handle(
        self,
        action: AgentAction,
        error: Any,
        retry_count: int,
        state: AssessmentState,
        status_code: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Classifies failure, logs to state, and produces comprehensive recovery instructions.
        """
        failure_type = self.classify_failure(error, status_code=status_code)
        recovery_action = self.determine_recovery(failure_type, retry_count, tool_name=action.tool_name)
        self.record_failure(action, failure_type, str(error), state)

        alt_tool = self.suggest_alternative_tool(action.tool_name) if recovery_action == RecoveryAction.SWITCH_TOOL else None
        delay_seconds = 0.0

        if recovery_action == RecoveryAction.BACKOFF_RETRY:
            delay_seconds = min(2.0 ** retry_count, 30.0)

        return {
            "failure_type": failure_type,
            "recovery_action": recovery_action,
            "alternative_tool": alt_tool,
            "delay_seconds": delay_seconds,
            "should_retry": recovery_action in (RecoveryAction.RETRY, RecoveryAction.BACKOFF_RETRY),
        }
