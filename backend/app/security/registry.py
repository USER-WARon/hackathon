import json
import math
import os
import sqlite3
from typing import Any

from app.database import get_connection
from app.security.ml_models import (
    MLModelRuntime,
    extract_trust_features,
    get_ml_models,
    mandatory_trust_checks,
)


TRUST_WEIGHTS = {
    'identity': 25,
    'permissions': 25,
    'behavior': 20,
    'data_handling': 20,
    'relationships': 10,
}
HIGH_TRUST_THRESHOLD = 70


class TrustRegistry:
    def __init__(self, db_path: str | None = None, ml_models: MLModelRuntime | None = None):
        self.db_path = db_path
        self.ml_models = ml_models if ml_models is not None else get_ml_models()

    def list_tools(self) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute('SELECT * FROM tool_registry ORDER BY name').fetchall()
            tools = [self._hydrate_tool(dict(row)) for row in rows]
            return [self._with_evaluation(tool) for tool in tools]
        finally:
            conn.close()

    def get_tool(self, name: str) -> dict[str, Any] | None:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT * FROM tool_registry WHERE name = ?', (name,)).fetchone()
            return self._hydrate_tool(dict(row)) if row else None
        finally:
            conn.close()

    def _hydrate_tool(self, tool: dict[str, Any]) -> dict[str, Any]:
        for key, fallback in {
            'capabilities_json': [],
            'permitted_resources_json': [],
            'observed_behavior_json': {},
            'outbound_permissions_json': [],
            'approved_relationships_json': [],
        }.items():
            public_key = key.removesuffix('_json')
            try:
                tool[public_key] = json.loads(tool.get(key) or json.dumps(fallback))
            except json.JSONDecodeError:
                tool[public_key] = fallback
        if tool.get('trust_score') is None:
            tool['trust_score'] = 0
        classification = tool.get('trust_classification')
        tool['trust_classification'] = (
            'HIGH_TRUST' if classification in {'HIGH', 'HIGH_TRUST'} else 'LOW_TRUST'
        )
        return tool

    def evaluate_trust(self, tool: dict[str, Any]) -> dict[str, Any]:
        capabilities = tool.get('capabilities') or []
        resources = tool.get('permitted_resources') or []
        try:
            violations = max(0, int(tool.get('permission_violations') or 0))
        except (TypeError, ValueError, OverflowError):
            violations = 0
        outbound = tool.get('outbound_permissions') or []
        relationships = tool.get('approved_relationships') or []
        sensitivity = (tool.get('data_sensitivity') or 'public').lower()

        weighted_score = 0
        reasons = []
        reason_codes = []
        identity_valid = tool.get('identity_valid', 1) in (True, 1)
        if tool.get('authenticated') and identity_valid:
            weighted_score += TRUST_WEIGHTS['identity']
        else:
            reasons.append('identity/authentication evidence missing')
            reason_codes.append('IDENTITY_OR_AUTHENTICATION_EVIDENCE_MISSING')

        if capabilities and resources and violations == 0:
            weighted_score += TRUST_WEIGHTS['permissions']
        else:
            reasons.append('least-privilege evidence incomplete or violations observed')
            reason_codes.append('PERMISSION_EVIDENCE_INCOMPLETE_OR_VIOLATED')

        observed_behavior = tool.get('observed_behavior') or {}
        try:
            behavior_anomalies = sum(
                max(0, int(observed_behavior.get(key, 0)))
                for key in ('anomaly_count', 'suspicious_events', 'policy_violations')
            ) if isinstance(observed_behavior, dict) else TRUST_WEIGHTS['behavior'] // 5
        except (TypeError, ValueError, OverflowError):
            behavior_anomalies = TRUST_WEIGHTS['behavior'] // 5
        behavior_events = violations + behavior_anomalies
        behavior_score = max(0, TRUST_WEIGHTS['behavior'] - min(behavior_events * 5, TRUST_WEIGHTS['behavior']))
        weighted_score += behavior_score
        if behavior_score < TRUST_WEIGHTS['behavior']:
            reasons.append('observed behavior reduced trust')
            reason_codes.append('BEHAVIOR_HISTORY_REDUCED_TRUST')

        if sensitivity in {'public', 'internal'} or (sensitivity == 'protected' and not outbound):
            weighted_score += TRUST_WEIGHTS['data_handling']
        else:
            reasons.append('sensitive data has outbound exposure')
            reason_codes.append('SENSITIVE_DATA_OUTBOUND_EXPOSURE')

        if relationships or not outbound:
            weighted_score += TRUST_WEIGHTS['relationships']
        else:
            reasons.append('outbound interaction patterns are not authorized')
            reason_codes.append('OUTBOUND_RELATIONSHIP_NOT_AUTHORIZED')

        weighted_score = min(100.0, max(0.0, float(weighted_score)))
        mandatory_failures = mandatory_trust_checks(tool)
        hard_deny = (
            not identity_valid
            or bool(tool.get('permissions_revoked'))
            or bool(tool.get('prohibited_behavior'))
        )
        reason_codes.extend(mandatory_failures)
        try:
            weighted_weight = float(os.getenv('SHADOWGUARD_TRUST_WEIGHTED_WEIGHT', '0.70'))
            ml_weight = float(os.getenv('SHADOWGUARD_TRUST_ML_WEIGHT', '0.30'))
            threshold = float(os.getenv('SHADOWGUARD_TRUST_THRESHOLD', str(HIGH_TRUST_THRESHOLD)))
            if (
                not math.isfinite(weighted_weight)
                or not math.isfinite(ml_weight)
                or not math.isfinite(threshold)
                or not 0 <= weighted_weight <= 1
                or not 0 <= ml_weight <= 1
                or not math.isclose(weighted_weight + ml_weight, 1.0, abs_tol=1e-9)
                or not 0 <= threshold <= 100
            ):
                raise ValueError('invalid trust model configuration')
        except (TypeError, ValueError, OverflowError):
            return {
                'score': None,
                'weighted_trust_score': round(weighted_score, 2),
                'ml_trust_score': None,
                'combined_trust_score': None,
                'ml_classification': None,
                'classification': 'LOW_TRUST',
                'reason': 'Trust scoring configuration is invalid; classification failed closed.',
                'reason_codes': sorted(set(reason_codes + ['TRUST_CONFIGURATION_INVALID'])),
                'mandatory_checks_passed': not mandatory_failures and not hard_deny,
                'mandatory_override': False,
                'hard_deny': hard_deny,
            }

        _, feature_errors = extract_trust_features(tool)
        try:
            ml_evaluation = (
                {
                    'ml_trust_score': None,
                    'ml_classification': None,
                    'reason_codes': feature_errors,
                }
                if feature_errors
                else self.ml_models.predict_trust(tool)
            )
        except Exception as exc:
            ml_evaluation = {
                'ml_trust_score': None,
                'ml_classification': None,
                'reason_codes': [f'TRUST_INFERENCE_FAILED:{type(exc).__name__}'],
            }
        ml_score = ml_evaluation.get('ml_trust_score')
        if ml_score is None:
            reason_codes.extend(ml_evaluation.get('reason_codes', ['TRUST_MODEL_UNAVAILABLE']))
            combined_score = None
            classification = 'LOW_TRUST'
        else:
            try:
                ml_score = float(ml_score)
                if not math.isfinite(ml_score) or not 0 <= ml_score <= 100:
                    raise ValueError('invalid model score')
                combined_score = round(weighted_weight * weighted_score + ml_weight * ml_score, 2)
                combined_score = min(100.0, max(0.0, combined_score))
                classification = (
                    'HIGH_TRUST'
                    if combined_score >= threshold and not mandatory_failures and not hard_deny
                    else 'LOW_TRUST'
                )
            except (TypeError, ValueError, OverflowError):
                ml_score = None
                combined_score = None
                classification = 'LOW_TRUST'
                reason_codes.append('TRUST_INFERENCE_FAILED:INVALID_SCORE')

        mandatory_override = bool(mandatory_failures or hard_deny) and (
            combined_score is not None and combined_score >= threshold
        )
        if mandatory_override:
            reason_codes.append('MANDATORY_SECURITY_CHECK_OVERRIDES_SCORE')
        if combined_score is None:
            reasons.append('ML trust score unavailable; no combined score was produced')
        if mandatory_failures:
            reasons.append('mandatory trust evidence or policy checks failed')
        if hard_deny:
            reasons.append('hard-deny security rule matched')
        if not reasons:
            reasons.append('All configured trust evidence satisfied')
        return {
            'score': combined_score,
            'weighted_trust_score': round(weighted_score, 2),
            'ml_trust_score': ml_score,
            'combined_trust_score': combined_score,
            'ml_classification': ml_evaluation.get('ml_classification'),
            'classification': classification,
            'reason': '; '.join(reasons),
            'reason_codes': sorted(set(reason_codes + ml_evaluation.get('reason_codes', []))),
            'mandatory_checks_passed': not mandatory_failures and not hard_deny,
            'mandatory_override': mandatory_override,
            'hard_deny': hard_deny,
        }

    def _with_evaluation(self, tool: dict[str, Any]) -> dict[str, Any]:
        evaluation = self.evaluate_trust(tool)
        tool.update({
            'trust_score': evaluation['score'],
            'weighted_trust_score': evaluation['weighted_trust_score'],
            'ml_trust_score': evaluation['ml_trust_score'],
            'combined_trust_score': evaluation['combined_trust_score'],
            'ml_classification': evaluation['ml_classification'],
            'trust_classification': evaluation['classification'],
            'trust_reason': evaluation['reason'],
            'trust_reason_codes': evaluation['reason_codes'],
            'mandatory_checks_passed': evaluation['mandatory_checks_passed'],
            'mandatory_override': evaluation['mandatory_override'],
        })
        return tool

    def refresh_trust(self, name: str) -> dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT * FROM tool_registry WHERE name = ?', (name,)).fetchone()
            if row is None:
                raise ValueError('Unknown tool')
            tool = self._hydrate_tool(dict(row))
            evaluation = self.evaluate_trust(tool)
            if evaluation['score'] is None:
                conn.execute(
                    """
                    UPDATE tool_registry
                    SET trust_classification = ?, trust_reason = ?, trust_evaluated_at = datetime('now')
                    WHERE name = ?
                    """,
                    (evaluation['classification'], evaluation['reason'], name),
                )
            else:
                conn.execute(
                    """
                    UPDATE tool_registry
                    SET trust_score = ?, trust_classification = ?, trust_reason = ?,
                        trust_evaluated_at = datetime('now')
                    WHERE name = ?
                    """,
                    (round(evaluation['score']), evaluation['classification'], evaluation['reason'], name),
                )
            conn.commit()
            updated = conn.execute('SELECT * FROM tool_registry WHERE name = ?', (name,)).fetchone()
            return self._with_evaluation(self._hydrate_tool(dict(updated)))
        finally:
            conn.close()

    def set_trust_zone(self, name: str, trust_zone: str) -> dict[str, Any]:
        allowed = {'HIGH', 'LOW', 'MEDIUM'}
        if trust_zone.upper() not in allowed:
            raise ValueError('Unsupported trust zone')
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                'INSERT INTO tool_registry (name, trust_zone, enabled, description) VALUES (?, ?, 1, ?) ON CONFLICT(name) DO UPDATE SET trust_zone = excluded.trust_zone',
                (name, trust_zone.upper(), f'{name} trust assignment'),
            )
            conn.execute(
                'INSERT INTO integration_settings (name, trust_zone, updated_at) VALUES (?, ?, datetime("now")) ON CONFLICT(name) DO UPDATE SET trust_zone = excluded.trust_zone, updated_at = datetime("now")',
                (name, trust_zone.upper()),
            )
            conn.commit()
            return self.refresh_trust(name)
        finally:
            conn.close()

    def has_active_grant(
        self,
        user_id: str,
        session_id: str,
        source_mcp: str,
        destination_mcp: str,
        operation: str,
        target_resource: str,
        capability: str,
    ) -> bool:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT capabilities_json FROM trust_grants
                WHERE user_id = ? AND session_id = ? AND source_mcp = ? AND destination_mcp = ?
                  AND operation = ? AND target_resource = ? AND revoked_at IS NULL
                  AND datetime(expires_at) > datetime('now')
                """,
                (user_id, session_id, source_mcp, destination_mcp, operation, target_resource),
            ).fetchall()
            for row in rows:
                capabilities = json.loads(row['capabilities_json'] or '[]')
                if capability in capabilities:
                    return True
            return False
        finally:
            conn.close()
