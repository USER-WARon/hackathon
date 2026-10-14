from __future__ import annotations

import sqlite3

from app.database import ensure_production_demo_db, initialize_database
from app.api.events import EventHub
from app.security.approvals import ApprovalManager
from app.security.audit import AuditLogger
from app.security.intent_guard import check_intent
from app.security.interceptor import ShadowGuardInterceptor
from app.security.ml_models import MLModelRuntime, get_ml_models
from app.security.registry import TrustRegistry
from app.security.shadow_state import ShadowStateManager
from app.security.taint import TaintEngine


def secure_tool() -> dict:
    return {
        'identity_valid': 1,
        'authenticated': 1,
        'permissions_revoked': 0,
        'prohibited_behavior': 0,
        'capabilities': ['read', 'write'],
        'permitted_resources': ['users'],
        'permission_violations': 0,
        'observed_behavior': {},
        'data_sensitivity': 'internal',
        'outbound_permissions': [],
        'approved_relationships': [],
        'transport_secure': True,
        'tool_definition_integrity_valid': True,
        'policy_compliant': True,
    }


class FixedModels:
    def __init__(self, trust_score: float = 100, intent: str = 'INTENDED'):
        self.trust_score = trust_score
        self.intent = intent

    def predict_trust(self, tool):
        return {
            'ml_trust_score': self.trust_score,
            'ml_classification': 'HIGH_TRUST' if self.trust_score >= 50 else 'LOW_TRUST',
            'reason_codes': [],
        }

    def classify_intent(self, *args):
        return {
            'classification': self.intent,
            'confidence': 0.99,
            'reason_codes': ['TEST_SIGNAL'],
        }


def test_trust_score_fusion_threshold_and_exact_classes(monkeypatch):
    monkeypatch.setenv('SHADOWGUARD_TRUST_THRESHOLD', '70')
    evaluation = TrustRegistry(ml_models=FixedModels(trust_score=0)).evaluate_trust(secure_tool())

    assert evaluation['weighted_trust_score'] == 100
    assert evaluation['ml_trust_score'] == 0
    assert evaluation['combined_trust_score'] == 70
    assert evaluation['classification'] == 'HIGH_TRUST'
    assert evaluation['classification'] in {'HIGH_TRUST', 'LOW_TRUST'}

    low = TrustRegistry(ml_models=FixedModels(trust_score=0)).evaluate_trust(
        secure_tool() | {'data_sensitivity': 'secret', 'outbound_permissions': ['external']},
    )
    assert low['combined_trust_score'] < 70
    assert low['classification'] == 'LOW_TRUST'


def test_mandatory_security_failure_overrides_high_combined_score():
    evaluation = TrustRegistry(ml_models=FixedModels()).evaluate_trust(
        secure_tool() | {'prohibited_behavior': 1},
    )

    assert evaluation['combined_trust_score'] == 100
    assert evaluation['classification'] == 'LOW_TRUST'
    assert evaluation['hard_deny'] is True
    assert evaluation['mandatory_override'] is True
    assert 'MANDATORY_SECURITY_CHECK_OVERRIDES_SCORE' in evaluation['reason_codes']


def test_policy_violations_in_behavioral_history_are_mandatory():
    evaluation = TrustRegistry(ml_models=FixedModels()).evaluate_trust(
        secure_tool() | {'observed_behavior': {'policy_violations': 1}},
    )

    assert evaluation['combined_trust_score'] >= 70
    assert evaluation['classification'] == 'LOW_TRUST'
    assert evaluation['mandatory_override'] is True
    assert 'POLICY_VIOLATION_OBSERVED' in evaluation['reason_codes']


def test_missing_or_invalid_trust_features_do_not_create_ml_score():
    registry = TrustRegistry(ml_models=FixedModels())
    missing = secure_tool()
    del missing['permitted_resources']
    invalid = secure_tool() | {'data_sensitivity': 'unknown'}

    for tool in (missing, invalid):
        evaluation = registry.evaluate_trust(tool)
        assert evaluation['ml_trust_score'] is None
        assert evaluation['combined_trust_score'] is None
        assert evaluation['score'] is None
        assert evaluation['classification'] == 'LOW_TRUST'


def test_model_loading_and_inference_failures_fail_closed(tmp_path):
    unavailable = MLModelRuntime.load(tmp_path / 'missing.joblib')
    trust_result = unavailable.predict_trust(secure_tool())
    intent_result = unavailable.classify_intent(
        'check the weather in Seattle', ['read'], 'weather_api',
        {'operation': 'tool_call', 'classification': 'READ_ONLY', 'target_resource': 'weather:Seattle', 'capability': 'read'},
        {'city': 'Seattle'}, 'CLEAN', 0,
    )
    assert trust_result['ml_trust_score'] is None
    assert intent_result['classification'] == 'UNCERTAIN'

    class BrokenModel:
        classes_ = ['HIGH_TRUST', 'LOW_TRUST']

        def predict_proba(self, _features):
            raise RuntimeError('inference unavailable')

    failed = MLModelRuntime(trust_model=BrokenModel()).predict_trust(secure_tool())
    assert failed['ml_trust_score'] is None
    assert failed['reason_codes'][0].startswith('TRUST_INFERENCE_FAILED')


def test_intent_model_distinguishes_aligned_mismatched_and_uncertain_actions():
    runtime = get_ml_models()
    action = {
        'operation': 'tool_call',
        'classification': 'READ_ONLY',
        'target_resource': 'weather:Seattle',
        'capability': 'read',
    }
    aligned = runtime.classify_intent(
        'Check the weather in Seattle', ['read'], 'weather_api', action,
        {'city': 'Seattle'}, 'CLEAN', 0,
    )
    mismatched = runtime.classify_intent(
        'Check the weather in Seattle', ['read'], 'weather_api',
        action | {'target_resource': 'weather:Boston'},
        {'city': 'Boston'}, 'CLEAN', 0,
    )
    uncertain = runtime.classify_intent(
        '', ['read'], 'weather_api', action, {'city': 'Seattle'}, 'CLEAN', 0,
    )

    assert aligned['classification'] == 'INTENDED'
    assert mismatched['classification'] == 'POTENTIALLY_UNINTENDED'
    assert uncertain['classification'] == 'UNCERTAIN'
    assert set((aligned['classification'], mismatched['classification'], uncertain['classification'])) == {
        'INTENDED', 'POTENTIALLY_UNINTENDED', 'UNCERTAIN',
    }


def test_persisted_random_forest_returns_normalized_probability_score():
    runtime = MLModelRuntime.load()
    result = runtime.predict_trust(secure_tool())

    assert set(runtime.trust_model.classes_) == {'HIGH_TRUST', 'LOW_TRUST'}
    assert result['ml_classification'] in {'HIGH_TRUST', 'LOW_TRUST'}
    assert 0 <= result['ml_trust_score'] <= 100


def test_read_only_request_with_delete_action_is_potentially_unintended():
    result = get_ml_models().classify_intent(
        'List users without changing data', ['read'], 'production_database',
        {
            'operation': 'DELETE',
            'classification': 'REVERSIBLE_WRITE',
            'target_resource': 'users',
            'capability': 'write',
        },
        {'sql': 'DELETE FROM users WHERE id = 1'}, 'CLEAN', 0,
    )

    assert result['classification'] == 'POTENTIALLY_UNINTENDED'


def test_deterministic_scope_denial_is_not_overridden_by_intended_prediction():
    result = check_intent(
        'production_database',
        {'sql': 'DELETE FROM users WHERE id = 1'},
        ['read'],
        'Delete user 1',
        ml_classifier=FixedModels(intent='INTENDED'),
        proposed_action={
            'operation': 'DELETE',
            'classification': 'REVERSIBLE_WRITE',
            'target_resource': 'users',
            'capability': 'write',
        },
    )

    assert result['allowed'] is False
    assert result['policy_code'] == 'INTENT_SCOPE_VIOLATION'
    assert result['ml_intent']['classification'] == 'INTENDED'


def test_invalid_intent_model_output_fails_to_uncertain():
    class InvalidIntentModel:
        def classify_intent(self, *_args):
            return {'classification': 'ALLOW', 'confidence': float('nan'), 'reason_codes': 'unsafe'}

    result = check_intent(
        'weather_api', {'city': 'Seattle'}, ['read'], 'Check weather in Seattle',
        ml_classifier=InvalidIntentModel(),
        proposed_action={'operation': 'tool_call', 'classification': 'READ_ONLY'},
    )

    assert result['allowed'] is True
    assert result['ml_intent']['classification'] == 'UNCERTAIN'
    assert result['ml_intent']['confidence'] is None


def test_interceptor_audits_ml_scores_and_blocks_mismatched_action(tmp_path):
    app_db = str(tmp_path / 'app.db')
    production_db = str(tmp_path / 'production.db')
    initialize_database(app_db)
    ensure_production_demo_db(production_db)
    runtime = FixedModels(intent='INTENDED')
    audit = AuditLogger(app_db)
    hub = EventHub()
    calls = []
    interceptor = ShadowGuardInterceptor(
        app_db,
        TrustRegistry(app_db, ml_models=runtime),
        TaintEngine(app_db),
        ShadowStateManager(production_db),
        ApprovalManager(app_db),
        audit,
        hub,
        {'weather_api': lambda city: calls.append(city) or {'city': city}},
        ml_models=runtime,
    )

    allowed = interceptor.execute(
        'weather_api', {'city': 'Seattle'}, 'ml-session', 'user-1',
        user_objective='Check the weather in Seattle',
        authorized_capabilities=['read'],
    )
    assert allowed.get('city') == 'Seattle'
    trust_event = next(event for event in audit.get_events() if event['event_type'] == 'TRUST_EVALUATED')
    assert trust_event['details']['weighted_trust_score'] is not None
    assert trust_event['details']['ml_trust_score'] == 100
    assert trust_event['details']['combined_trust_score'] is not None

    runtime.intent = 'POTENTIALLY_UNINTENDED'
    blocked = interceptor.execute(
        'weather_api', {'city': 'Boston'}, 'ml-session-2', 'user-1',
        user_objective='Check the weather in Seattle',
        authorized_capabilities=['read'],
    )
    assert blocked['policy_code'] == 'ML_INTENT_SCOPE_MISMATCH'
    assert calls == ['Seattle']
    blocked_event = next(event for event in audit.get_events() if event['event_type'] == 'ML_INTENT_BLOCKED')
    assert blocked_event['details']['classification'] == 'POTENTIALLY_UNINTENDED'
    live_event = next(event for event in hub.get_recent() if event['policy_code'] == 'ML_INTENT_SCOPE_MISMATCH')
    assert live_event['details']['reason_codes'] == ['TEST_SIGNAL']


def test_model_low_tool_uses_low_taint_zone_without_mutating_configured_zone(tmp_path, monkeypatch):
    monkeypatch.setenv('SHADOWGUARD_TRUST_THRESHOLD', '71')
    app_db = str(tmp_path / 'app.db')
    production_db = str(tmp_path / 'production.db')
    initialize_database(app_db)
    ensure_production_demo_db(production_db)
    with sqlite3.connect(app_db) as conn:
        conn.execute("UPDATE tool_registry SET trust_zone = 'HIGH' WHERE name = 'weather_api'")

    class PerToolModels(FixedModels):
        def predict_trust(self, tool):
            score = 0 if tool['name'] == 'weather_api' else 100
            return {
                'ml_trust_score': score,
                'ml_classification': 'LOW_TRUST' if score == 0 else 'HIGH_TRUST',
                'reason_codes': [],
            }

    runtime = PerToolModels()
    interceptor = ShadowGuardInterceptor(
        app_db,
        TrustRegistry(app_db, ml_models=runtime),
        TaintEngine(app_db),
        ShadowStateManager(production_db),
        ApprovalManager(app_db),
        AuditLogger(app_db),
        EventHub(),
        {
            'weather_api': lambda city: {'city': city},
            'production_database': lambda sql: {'rows': []},
        },
        ml_models=runtime,
    )

    weather = interceptor.execute(
        'weather_api', {'city': 'Seattle'}, 'model-taint-session', 'user-1',
        user_objective='Check the weather in Seattle', authorized_capabilities=['read'],
    )
    database = interceptor.execute(
        'production_database', {'sql': 'SELECT * FROM users'},
        'model-taint-session', 'user-1',
        user_objective='List users', authorized_capabilities=['read'],
    )
    with sqlite3.connect(app_db) as conn:
        configured_zone = conn.execute(
            "SELECT trust_zone FROM tool_registry WHERE name = 'weather_api'",
        ).fetchone()[0]

    assert weather.get('city') == 'Seattle'
    assert database.get('policy_code') == 'TAINTED_HIGH_TRUST_BLOCK', database
    assert configured_zone == 'HIGH'