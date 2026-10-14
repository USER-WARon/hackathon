from __future__ import annotations

import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


TRUST_CLASSES = ('HIGH_TRUST', 'LOW_TRUST')
INTENT_CLASSES = ('INTENDED', 'POTENTIALLY_UNINTENDED', 'UNCERTAIN')
TRUST_FEATURE_NAMES = (
    'identity_valid',
    'authenticated',
    'permissions_revoked',
    'prohibited_behavior',
    'capability_count',
    'resource_count',
    'permission_violations',
    'behavior_anomaly_count',
    'data_sensitivity_level',
    'outbound_permission_count',
    'approved_relationship_count',
    'transport_secure',
    'tool_definition_integrity_valid',
    'output_provenance_valid',
    'policy_compliant',
)
MODEL_ARTIFACT_PATH = Path(__file__).with_name('model_artifacts') / 'shadowguard_models.joblib'


def extract_trust_features(tool: dict[str, Any]) -> tuple[list[float] | None, list[str]]:
    required = (
        'identity_valid', 'authenticated', 'permissions_revoked',
        'prohibited_behavior', 'capabilities', 'permitted_resources',
        'permission_violations', 'data_sensitivity', 'outbound_permissions',
        'approved_relationships',
    )
    missing = [name for name in required if name not in tool]
    if missing:
        return None, ['TRUST_FEATURES_MISSING']

    try:
        identity_valid = _required_flag(tool['identity_valid'])
        authenticated = _required_flag(tool['authenticated'])
        permissions_revoked = _required_flag(tool['permissions_revoked'])
        prohibited_behavior = _required_flag(tool['prohibited_behavior'])
        violations = _non_negative_int(tool['permission_violations'])
        sensitivity = str(tool['data_sensitivity']).lower()
        sensitivity_level = {'public': 0, 'internal': 1, 'protected': 2, 'secret': 3}[sensitivity]
        capabilities = _sequence_count(tool['capabilities'])
        resources = _sequence_count(tool['permitted_resources'])
        outbound = _sequence_count(tool['outbound_permissions'])
        relationships = _sequence_count(tool['approved_relationships'])
        observed = tool.get('observed_behavior', {})
        if not isinstance(observed, dict):
            raise ValueError('observed_behavior must be an object')
        anomalies = sum(
            _non_negative_int(observed.get(key, 0))
            for key in ('anomaly_count', 'suspicious_events', 'policy_violations')
        )
        optional_flags = [
            _optional_flag(tool.get(name))
            for name in (
                'transport_secure',
                'tool_definition_integrity_valid',
                'output_provenance_valid',
                'policy_compliant',
            )
        ]
    except (KeyError, TypeError, ValueError, OverflowError):
        return None, ['TRUST_FEATURES_INVALID']

    features = [
        identity_valid,
        authenticated,
        permissions_revoked,
        prohibited_behavior,
        capabilities,
        resources,
        violations,
        anomalies,
        sensitivity_level,
        outbound,
        relationships,
        *(value if value is not None else math.nan for value in optional_flags),
    ]
    return features, []


def mandatory_trust_checks(tool: dict[str, Any]) -> list[str]:
    checks: list[str] = []
    if not _is_true(tool.get('identity_valid')):
        checks.append('IDENTITY_INVALID')
    if not _is_true(tool.get('authenticated')):
        checks.append('AUTHENTICATION_EVIDENCE_MISSING')
    if _is_true(tool.get('permissions_revoked')):
        checks.append('PERMISSIONS_REVOKED')
    if _is_true(tool.get('prohibited_behavior')):
        checks.append('PROHIBITED_BEHAVIOR')
    if not tool.get('capabilities') or not tool.get('permitted_resources'):
        checks.append('PERMISSION_EVIDENCE_INCOMPLETE')
    try:
        if _non_negative_int(tool.get('permission_violations', 0)) > 0:
            checks.append('PERMISSION_VIOLATIONS_OBSERVED')
    except (TypeError, ValueError, OverflowError):
        checks.append('PERMISSION_EVIDENCE_INVALID')
    observed_behavior = tool.get('observed_behavior', {})
    if isinstance(observed_behavior, dict):
        try:
            if _non_negative_int(observed_behavior.get('policy_violations', 0)) > 0:
                checks.append('POLICY_VIOLATION_OBSERVED')
        except (TypeError, ValueError, OverflowError):
            checks.append('POLICY_EVIDENCE_INVALID')
    for field, reason in (
        ('transport_secure', 'INSECURE_TRANSPORT'),
        ('tool_definition_integrity_valid', 'TOOL_DEFINITION_INTEGRITY_FAILED'),
        ('policy_compliant', 'POLICY_COMPLIANCE_FAILED'),
    ):
        value = tool.get(field)
        if value is not None and not _is_true(value):
            checks.append(reason)
    return checks


def _required_flag(value: Any) -> int:
    parsed = _optional_flag(value)
    if parsed is None:
        raise ValueError('required boolean evidence is missing')
    return parsed


def _optional_flag(value: Any) -> int | None:
    if value is None:
        return None
    if value is True or value == 1:
        return 1
    if value is False or value == 0:
        return 0
    raise ValueError('security flags must be boolean')


def _is_true(value: Any) -> bool:
    try:
        return _optional_flag(value) == 1
    except (TypeError, ValueError):
        return False


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError('boolean is not an integer count')
    parsed = int(value)
    if parsed < 0 or parsed != value:
        raise ValueError('count must be a non-negative integer')
    return parsed


def _sequence_count(value: Any) -> int:
    if not isinstance(value, (list, tuple, set)):
        raise ValueError('security evidence must be a sequence')
    return len(value)


def build_intent_text(
    user_objective: str,
    authorized_capabilities: list[str],
    tool_name: str,
    action: dict[str, Any],
    arguments: dict[str, Any],
    taint_state: str,
    taint_source_count: int,
) -> str:
    parameter_text = ' '.join(
        f'{key} {str(value)[:120]}'
        for key, value in sorted(arguments.items())
        if isinstance(value, (str, int, float, bool))
    )
    operation = str(action.get('operation', '')).upper()
    objective = str(user_objective).lower()
    authorized = {value.lower() for value in authorized_capabilities}
    required_capability = (
        'delete' if operation == 'DELETE'
        else 'write' if operation in {'INSERT', 'UPDATE'}
        else 'admin' if operation in {'CREATE', 'ALTER', 'DROP'}
        else str(action.get('capability') or 'read').lower()
    )
    capability_authorized = (
        'admin' in authorized
        or required_capability in authorized
        or required_capability == 'write' and 'delete' in authorized
    )
    tool_terms = {
        'weather_api': ('weather', 'forecast', 'temperature', 'conditions'),
        'github_reader': ('github', 'repository', 'repo', 'code', 'script'),
        'production_database': ('database', 'data', 'user', 'record', 'table', 'sql'),
    }
    mentioned_tools = [
        name for name, terms in tool_terms.items()
        if any(re.search(rf'\b{re.escape(term)}\b', objective) for term in terms)
    ]
    tool_alignment = (
        'unknown' if not mentioned_tools
        else 'match' if tool_name in mentioned_tools
        else 'mismatch'
    )
    requested_ids = re.findall(
        r'\b(?:user|record|id)\s*(?:number|#|=|is|with)?\s*(\d+)\b', objective,
    )
    proposed_ids = re.findall(r'\bid\s*=\s*(\d+)\b', str(arguments.get('sql', '')), re.IGNORECASE)
    parameter_values = [
        str(value).lower()
        for key, value in arguments.items()
        if key != 'sql' and isinstance(value, (str, int, float))
    ]
    if requested_ids and proposed_ids:
        parameter_alignment = 'match' if requested_ids[-1] == proposed_ids[-1] else 'mismatch'
    elif parameter_values and all(value in objective for value in parameter_values):
        parameter_alignment = 'match'
    elif parameter_values and any(
        re.search(r'\b(?:weather|forecast|repository|repo|city|user|record)\b', objective)
        for _ in parameter_values
    ):
        parameter_alignment = 'mismatch'
    else:
        parameter_alignment = 'unknown'
    read_only_request = any(term in objective for term in (
        'read only', 'read-only', 'without changing', 'do not change', 'do not modify',
        'list ', 'inspect ', 'show ', 'summarize ', 'review ',
    ))
    modification_request = any(term in objective for term in (
        'delete ', 'remove ', 'update ', 'insert ', 'change ', 'modify ', 'write ',
    ))
    if operation in {'DELETE', 'INSERT', 'UPDATE', 'DROP', 'ALTER', 'CREATE'}:
        operation_alignment = (
            'mismatch' if read_only_request or not modification_request
            else 'match'
        )
    elif operation == 'SELECT' and read_only_request:
        operation_alignment = 'match'
    else:
        operation_alignment = 'unknown'
    return ' '.join((
        f'objective {user_objective}',
        f'authorized capabilities {" ".join(sorted(authorized_capabilities))}',
        f'proposed tool {tool_name}',
        f'action category {action.get("operation", "unknown")}',
        f'action type {action.get("classification", "unknown")}',
        f'target resource {action.get("target_resource", "unknown")}',
        f'parameters {parameter_text}',
        f'read only {action.get("capability") == "read"}',
        f'parameter alignment {parameter_alignment}',
        f'tool alignment {tool_alignment}',
        f'operation alignment {operation_alignment}',
        f'capability scope {"authorized" if capability_authorized else "unauthorized"}',
        f'taint state {taint_state}',
        f'taint sources {max(0, int(taint_source_count))}',
    ))


class MLModelRuntime:
    def __init__(
        self,
        trust_model: Any = None,
        intent_model: Any = None,
        load_errors: dict[str, str] | None = None,
    ):
        self.trust_model = trust_model
        self.intent_model = intent_model
        self.load_errors = load_errors or {}

    @classmethod
    def load(cls, path: Path = MODEL_ARTIFACT_PATH) -> MLModelRuntime:
        errors: dict[str, str] = {}
        try:
            import joblib

            payload = joblib.load(path)
        except Exception as exc:
            message = f'Model artifact unavailable ({type(exc).__name__})'
            return cls(load_errors={'trust': message, 'intent': message})

        trust_model = payload.get('trust_model') if isinstance(payload, dict) else None
        intent_model = payload.get('intent_model') if isinstance(payload, dict) else None
        if not _has_classes(trust_model, TRUST_CLASSES):
            errors['trust'] = 'Trust model is missing or has an invalid class set'
            trust_model = None
        if not _has_classes(intent_model, INTENT_CLASSES):
            errors['intent'] = 'Intent model is missing or has an invalid class set'
            intent_model = None
        return cls(trust_model, intent_model, errors)

    def predict_trust(self, tool: dict[str, Any]) -> dict[str, Any]:
        features, errors = extract_trust_features(tool)
        if errors:
            return {
                'ml_trust_score': None,
                'ml_classification': None,
                'reason_codes': errors,
            }
        if self.trust_model is None:
            return {
                'ml_trust_score': None,
                'ml_classification': None,
                'reason_codes': ['TRUST_MODEL_UNAVAILABLE'],
            }
        try:
            probabilities = self.trust_model.predict_proba([features])[0]
            classes = list(self.trust_model.classes_)
            high_probability = float(probabilities[classes.index('HIGH_TRUST')])
            score = round(min(100.0, max(0.0, high_probability * 100.0)), 2)
            prediction = str(self.trust_model.predict([features])[0])
            if prediction not in TRUST_CLASSES or not math.isfinite(score):
                raise ValueError('invalid trust prediction')
            return {
                'ml_trust_score': score,
                'ml_classification': prediction,
                'reason_codes': [],
            }
        except Exception as exc:
            return {
                'ml_trust_score': None,
                'ml_classification': None,
                'reason_codes': [f'TRUST_INFERENCE_FAILED:{type(exc).__name__}'],
            }

    def classify_intent(
        self,
        user_objective: str,
        authorized_capabilities: list[str],
        tool_name: str,
        action: dict[str, Any],
        arguments: dict[str, Any],
        taint_state: str,
        taint_source_count: int,
    ) -> dict[str, Any]:
        if self.intent_model is None:
            return {
                'classification': 'UNCERTAIN',
                'confidence': None,
                'reason_codes': ['INTENT_MODEL_UNAVAILABLE'],
            }
        if not isinstance(user_objective, str) or not user_objective.strip():
            return {
                'classification': 'UNCERTAIN',
                'confidence': None,
                'reason_codes': ['ORIGINAL_REQUEST_MISSING'],
            }
        try:
            text = build_intent_text(
                user_objective,
                authorized_capabilities,
                tool_name,
                action,
                arguments,
                taint_state,
                taint_source_count,
            )
            probabilities = self.intent_model.predict_proba([text])[0]
            classes = list(self.intent_model.classes_)
            index = max(range(len(classes)), key=lambda item: float(probabilities[item]))
            confidence = float(probabilities[index])
            prediction = str(classes[index])
            if not math.isfinite(confidence) or prediction not in INTENT_CLASSES:
                raise ValueError('invalid intent prediction')
            if confidence < 0.55:
                prediction = 'UNCERTAIN'
            reason_code = {
                'INTENDED': 'ACTION_ALIGNS_WITH_REQUEST',
                'POTENTIALLY_UNINTENDED': 'ACTION_SCOPE_MISMATCH_SIGNAL',
                'UNCERTAIN': 'INTENT_MODEL_UNCERTAIN',
            }[prediction]
            return {
                'classification': prediction,
                'confidence': round(confidence, 4),
                'reason_codes': [reason_code],
            }
        except Exception as exc:
            return {
                'classification': 'UNCERTAIN',
                'confidence': None,
                'reason_codes': [f'INTENT_INFERENCE_FAILED:{type(exc).__name__}'],
            }


def _has_classes(model: Any, expected: tuple[str, ...]) -> bool:
    classes = getattr(model, 'classes_', None)
    return classes is not None and set(str(value) for value in classes) == set(expected)


@lru_cache(maxsize=1)
def get_ml_models() -> MLModelRuntime:
    return MLModelRuntime.load()