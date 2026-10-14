"""
intent_guard.py — Deterministic intent-authorization layer.

Before any protected operation reaches the security interceptor, this module
verifies that the proposed action fits within the capabilities the user
explicitly authorized when they submitted their request.

Rules:
- "read"   : SELECT, schema inspection, listing
- "write"  : INSERT, UPDATE (no DELETE, no DROP/ALTER)
- "delete" : DELETE (also requires "write" to be present)
- "admin"  : DROP, ALTER, CREATE, schema changes, config changes

If the proposed operation exceeds the authorized scope, return an
INTENT_SCOPE_VIOLATION structured denial.  This check is entirely
deterministic and independent of trust scores and taint state.
"""
from __future__ import annotations

import math
from typing import Any

from app.security.risk_engine import analyze_sql

# Map SQL statement types to the minimum capability required.
_STATEMENT_CAPABILITY: dict[str, str] = {
    'SELECT': 'read',
    'INSERT': 'write',
    'UPDATE': 'write',
    'DELETE': 'delete',
    'DROP':   'admin',
    'ALTER':  'admin',
    'CREATE': 'admin',
}

# Non-database tools that perform external writes need at least 'write'.
_TOOL_MIN_CAPABILITY: dict[str, str] = {
    'github_reader': 'read',
    'weather_api':   'read',
    'production_database': 'read',   # specific capability determined by SQL below
}


def check_intent(
    tool_name: str,
    arguments: dict[str, Any],
    authorized_capabilities: list[str],
    user_objective: str = '',
    ml_classifier: Any = None,
    proposed_action: dict[str, Any] | None = None,
    taint_state: str = 'CLEAN',
    taint_source_count: int = 0,
) -> dict[str, Any]:
    result = _check_intent_deterministic(
        tool_name, arguments, authorized_capabilities, user_objective,
    )
    if proposed_action and proposed_action.get('classification') == 'PROHIBITED':
        ml_result = {
            'classification': 'UNCERTAIN',
            'confidence': None,
            'reason_codes': ['ACTION_PRECLASSIFIED_PROHIBITED'],
        }
    elif ml_classifier is None:
        ml_result = {
            'classification': 'UNCERTAIN',
            'confidence': None,
            'reason_codes': ['INTENT_MODEL_UNAVAILABLE'],
        }
    else:
        try:
            ml_result = ml_classifier.classify_intent(
                user_objective,
                authorized_capabilities,
                tool_name,
                proposed_action or {},
                arguments,
                taint_state,
                taint_source_count,
            )
        except Exception as exc:
            ml_result = {
                'classification': 'UNCERTAIN',
                'confidence': None,
                'reason_codes': [f'INTENT_INFERENCE_FAILED:{type(exc).__name__}'],
            }
    if not isinstance(ml_result, dict):
        ml_result = {
            'classification': 'UNCERTAIN',
            'confidence': None,
            'reason_codes': ['INTENT_INFERENCE_FAILED:INVALID_RESULT'],
        }
    classification = ml_result.get('classification')
    confidence = ml_result.get('confidence')
    try:
        confidence = None if confidence is None else float(confidence)
        if confidence is not None and (not math.isfinite(confidence) or not 0 <= confidence <= 1):
            raise ValueError('invalid confidence')
    except (TypeError, ValueError, OverflowError):
        confidence = None
        classification = 'UNCERTAIN'
        ml_result['reason_codes'] = ['INTENT_INFERENCE_FAILED:INVALID_CONFIDENCE']
    if classification not in {'INTENDED', 'POTENTIALLY_UNINTENDED', 'UNCERTAIN'}:
        classification = 'UNCERTAIN'
        ml_result['reason_codes'] = ['INTENT_INFERENCE_FAILED:INVALID_CLASSIFICATION']
    if classification == 'POTENTIALLY_UNINTENDED' and (confidence is None or confidence < 0.55):
        classification = 'UNCERTAIN'
        ml_result['reason_codes'] = ['INTENT_MODEL_UNCERTAIN']
    reason_codes = ml_result.get('reason_codes', [])
    if not isinstance(reason_codes, list) or not all(isinstance(code, str) for code in reason_codes):
        reason_codes = ['INTENT_INFERENCE_FAILED:INVALID_REASON_CODES']
    result['ml_intent'] = {
        'classification': classification,
        'confidence': confidence,
        'reason_codes': reason_codes,
    }
    return result


def _check_intent_deterministic(
    tool_name: str,
    arguments: dict[str, Any],
    authorized_capabilities: list[str],
    user_objective: str = '',
) -> dict[str, Any]:
    """
    Return a structured decision.

    ``{'allowed': True}`` if the operation fits the authorized scope.
    ``{'allowed': False, 'policy_code': 'INTENT_SCOPE_VIOLATION', ...}`` otherwise.
    """
    caps = {c.lower() for c in (authorized_capabilities or ['read'])}

    if tool_name == 'production_database':
        sql = str(arguments.get('sql') or '')
        risk = analyze_sql(sql)
        if not risk['allowed']:
            # Defer policy and safety rejections (e.g. PRAGMA, ATTACH, unauthorized table)
            # to the policy risk engine and classifier for precise policy codes.
            return {'allowed': True, 'required_capability': 'read', 'authorized_capabilities': sorted(caps)}

        stmt_type = risk['statement_type']
        required = _STATEMENT_CAPABILITY.get(stmt_type)
        if required is None:
            # Unknown statement type — deny by default.
            return _deny(
                required_capability='write',
                proposed_operation=stmt_type or 'UNKNOWN',
                authorized_capabilities=sorted(caps),
                user_objective=user_objective,
                reason=(
                    f'The statement type "{stmt_type}" is not recognised. '
                    'Only SELECT, INSERT, UPDATE, and DELETE are supported.'
                ),
            )
        if not _has_capability(caps, required):
            return _deny(
                required_capability=required,
                proposed_operation=stmt_type,
                authorized_capabilities=sorted(caps),
                user_objective=user_objective,
                reason=_scope_reason(stmt_type, caps, user_objective),
            )
        return {'allowed': True, 'required_capability': required, 'authorized_capabilities': sorted(caps)}

    # Non-database tools
    min_cap = _TOOL_MIN_CAPABILITY.get(tool_name, 'write')
    if not _has_capability(caps, min_cap):
        return _deny(
            required_capability=min_cap,
            proposed_operation='tool_call',
            authorized_capabilities=sorted(caps),
            user_objective=user_objective,
            reason=(
                f'The tool "{tool_name}" requires "{min_cap}" capability, '
                f'but the current request only authorized: {sorted(caps) or ["read"]}.'
            ),
        )
    return {'allowed': True, 'required_capability': min_cap, 'authorized_capabilities': sorted(caps)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_capability(caps: set[str], required: str) -> bool:
    """
    Capability hierarchy:
      admin  ⊇  delete  ⊇  write  ⊇  read
    """
    if 'admin' in caps:
        return True
    if required == 'read':
        return True      # every request has at least read
    if required == 'write':
        return 'write' in caps or 'delete' in caps
    if required == 'delete':
        return 'delete' in caps
    return False


def _scope_reason(stmt_type: str, caps: set[str], user_objective: str) -> str:
    base = (
        f'The agent proposed a {stmt_type} operation, but the original request '
        f'only authorized: {sorted(caps) or ["read"]}.'
    )
    if user_objective:
        snippet = user_objective[:120].replace('\n', ' ')
        base += f' Original objective: "{snippet}".'
    if stmt_type == 'DELETE':
        base += ' Deletion is a destructive, irreversible mutation. Explicitly include "delete" in authorized_capabilities to permit it.'
    elif stmt_type in ('UPDATE', 'INSERT'):
        base += ' Data mutation requires "write" in authorized_capabilities.'
    elif stmt_type in ('DROP', 'ALTER', 'CREATE'):
        base += ' Schema changes require "admin" in authorized_capabilities.'
    return base


def _deny(
    required_capability: str,
    proposed_operation: str,
    authorized_capabilities: list[str],
    user_objective: str,
    reason: str,
) -> dict[str, Any]:
    return {
        'allowed': False,
        'policy_code': 'INTENT_SCOPE_VIOLATION',
        'required_capability': required_capability,
        'proposed_operation': proposed_operation,
        'authorized_capabilities': authorized_capabilities,
        'user_objective_snippet': user_objective[:200] if user_objective else '',
        'reason': reason,
    }
