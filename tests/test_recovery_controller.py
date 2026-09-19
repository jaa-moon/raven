"""
tests/test_recovery_controller.py
---------------------------------
Unit tests for RecoveryController failure classification and recovery actions.
"""

from engine.recovery_controller import FailureType, RecoveryAction, RecoveryController


def test_failure_classification():
    rc = RecoveryController()

    rate_limit_fail = rc.classify_failure("429 Client Error: Too Many Requests", status_code=429)
    assert rate_limit_fail == FailureType.RATE_LIMIT

    auth_fail = rc.classify_failure("401 Unauthorized", status_code=401)
    assert auth_fail == FailureType.AUTHENTICATION_FAILURE

    timeout_fail = rc.classify_failure("ReadTimeoutError: request timed out")
    assert timeout_fail == FailureType.TIMEOUT

    scope_fail = rc.classify_failure("Target out of scope boundary")
    assert scope_fail == FailureType.SCOPE_VIOLATION


def test_recovery_action_determination():
    rc = RecoveryController(max_retries=3)

    # Rate limit on first attempt should backoff retry
    act1 = rc.determine_recovery(FailureType.RATE_LIMIT, retry_count=1)
    assert act1 == RecoveryAction.BACKOFF_RETRY

    # Scope violation should skip immediately
    act2 = rc.determine_recovery(FailureType.SCOPE_VIOLATION, retry_count=0)
    assert act2 == RecoveryAction.SKIP

    # Exhausted budget should abort
    act3 = rc.determine_recovery(FailureType.BUDGET_EXHAUSTED, retry_count=0)
    assert act3 == RecoveryAction.ABORT
