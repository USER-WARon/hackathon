from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.security.ml_models import (  # noqa: E402
    INTENT_CLASSES,
    MODEL_ARTIFACT_PATH,
    TRUST_CLASSES,
    TRUST_FEATURE_NAMES,
    build_intent_text,
)


def build_trust_dataset() -> tuple[list[list[float]], list[str]]:
    rng = random.Random(20261015)
    rows: list[list[float]] = []
    labels: list[str] = []
    for index in range(360):
        features: dict[str, float | None] = {
            'identity_valid': 1,
            'authenticated': 1,
            'permissions_revoked': 0,
            'prohibited_behavior': 0,
            'capability_count': rng.randint(1, 4),
            'resource_count': rng.randint(1, 4),
            'permission_violations': 0,
            'behavior_anomaly_count': 0,
            'data_sensitivity_level': rng.choice((0, 1, 2)),
            'outbound_permission_count': 0,
            'approved_relationship_count': rng.randint(0, 3),
            'transport_secure': rng.choice((1, 1, None)),
            'tool_definition_integrity_valid': rng.choice((1, 1, None)),
            'output_provenance_valid': rng.choice((1, 1, None)),
            'policy_compliant': rng.choice((1, 1, None)),
        }
        if features['data_sensitivity_level'] == 2:
            features['approved_relationship_count'] = max(1, int(features['approved_relationship_count'] or 0))

        if index % 2:
            failure = (index // 2) % 12
            if failure == 0:
                features['identity_valid'] = 0
            elif failure == 1:
                features['authenticated'] = 0
            elif failure == 2:
                features['permissions_revoked'] = 1
            elif failure == 3:
                features['prohibited_behavior'] = 1
            elif failure == 4:
                features['capability_count'] = 0
            elif failure == 5:
                features['resource_count'] = 0
            elif failure == 6:
                features['permission_violations'] = rng.randint(1, 3)
            elif failure == 7:
                features['behavior_anomaly_count'] = rng.randint(1, 3)
            elif failure == 8:
                features['data_sensitivity_level'] = 3
                features['outbound_permission_count'] = 1
            elif failure == 9:
                features['outbound_permission_count'] = 1
                features['approved_relationship_count'] = 0
            elif failure == 10:
                features['transport_secure'] = 0
            else:
                features['tool_definition_integrity_valid'] = 0
        label = 'HIGH_TRUST'
        if (
            not features['identity_valid']
            or not features['authenticated']
            or features['permissions_revoked']
            or features['prohibited_behavior']
            or not features['capability_count']
            or not features['resource_count']
            or features['permission_violations']
            or features['behavior_anomaly_count']
            or features['transport_secure'] == 0
            or features['tool_definition_integrity_valid'] == 0
            or (features['data_sensitivity_level'] == 3 and features['outbound_permission_count'])
            or (features['outbound_permission_count'] and not features['approved_relationship_count'])
        ):
            label = 'LOW_TRUST'
        rows.append([float(features[name]) if features[name] is not None else float('nan') for name in TRUST_FEATURE_NAMES])
        labels.append(label)
    return rows, labels


def _intent_example(
    objective: str,
    tool_name: str,
    operation: str,
    action_type: str,
    target: str,
    capability: str,
    arguments: dict[str, Any],
    authorized: list[str],
    label: str,
    taint_state: str = 'CLEAN',
    taint_sources: int = 0,
) -> tuple[str, str]:
    text = build_intent_text(
        objective,
        authorized,
        tool_name,
        {
            'operation': operation,
            'classification': action_type,
            'target_resource': target,
            'capability': capability,
        },
        arguments,
        taint_state,
        taint_sources,
    )
    return text, label


def build_intent_dataset() -> tuple[list[str], list[str]]:
    examples: list[tuple[str, str]] = []
    cities = ('Seattle', 'Austin', 'Boston', 'Denver', 'Miami', 'Portland')
    for city in cities:
        other_city = cities[(cities.index(city) + 1) % len(cities)]
        for verb in ('check the weather in', 'get weather for', 'tell me the forecast for'):
            examples.append(_intent_example(
                f'{verb} {city}', 'weather_api', 'tool_call', 'READ_ONLY',
                f'weather:{city}', 'read', {'city': city}, ['read'], 'INTENDED',
            ))
            examples.append(_intent_example(
                f'{verb} {city}', 'weather_api', 'tool_call', 'READ_ONLY',
                f'weather:{other_city}', 'read', {'city': other_city}, ['read'],
                'POTENTIALLY_UNINTENDED',
            ))

    for index in range(24):
        user_id = index % 6 + 1
        other_id = user_id % 6 + 1
        sql = f'DELETE FROM users WHERE id = {user_id}'
        examples.append(_intent_example(
            f'delete user with id {user_id}', 'production_database', 'DELETE',
            'REVERSIBLE_WRITE', 'users', 'write', {'sql': sql},
            ['read', 'write', 'delete'], 'INTENDED',
        ))
        examples.append(_intent_example(
            f'delete user with id {user_id}', 'production_database', 'DELETE',
            'REVERSIBLE_WRITE', 'users', 'write',
            {'sql': f'DELETE FROM users WHERE id = {other_id}'},
            ['read', 'write', 'delete'], 'POTENTIALLY_UNINTENDED',
        ))
        examples.append(_intent_example(
            f'list users and summarize their names, do not change data {index}',
            'production_database', 'DELETE', 'REVERSIBLE_WRITE', 'users', 'write',
            {'sql': 'DELETE FROM users WHERE id = 1'}, ['read'],
            'POTENTIALLY_UNINTENDED',
        ))

    for index in range(30):
        examples.append(_intent_example(
            f'look up repository demo number {index}', 'github_reader', 'tool_call',
            'READ_ONLY', 'repo:demo', 'read', {'repo': 'demo'}, ['read'], 'INTENDED',
        ))
        examples.append(_intent_example(
            f'check weather in Seattle and summarize it {index}', 'github_reader',
            'tool_call', 'READ_ONLY', 'repo:demo', 'read', {'repo': 'demo'},
            ['read'], 'POTENTIALLY_UNINTENDED',
        ))
        examples.append(_intent_example(
            f'handle request {index}', 'production_database', 'UNKNOWN',
            'IRREVERSIBLE_OR_UNCERTAIN', 'unknown', 'write', {'sql': 'unknown'},
            ['read'], 'UNCERTAIN', 'TAINTED', 1,
        ))

    return [text for text, _ in examples], [label for _, label in examples]


def _evaluate(
    model: Any,
    x_values: list[Any],
    labels: list[str],
    class_names: tuple[str, ...],
) -> dict[str, Any]:
    x_train, x_test, y_train, y_test = train_test_split(
        x_values,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)
    return {
        'precision_recall_f1': classification_report(
            y_test,
            predicted,
            labels=list(class_names),
            output_dict=True,
            zero_division=0,
        ),
        'confusion_matrix': confusion_matrix(y_test, predicted, labels=list(class_names)).tolist(),
        'class_order': list(class_names),
        'class_distribution': {
            'all': dict(Counter(labels)),
            'train': dict(Counter(y_train)),
            'test': dict(Counter(y_test)),
        },
        'test_size': len(y_test),
    }


def train_models(output_path: Path = MODEL_ARTIFACT_PATH) -> dict[str, Any]:
    trust_x, trust_y = build_trust_dataset()
    trust_model = Pipeline([
        ('imputer', SimpleImputer(strategy='median', add_indicator=True)),
        ('classifier', RandomForestClassifier(
            n_estimators=180,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
        )),
    ])
    trust_report = _evaluate(trust_model, trust_x, trust_y, TRUST_CLASSES)
    trust_model.fit(trust_x, trust_y)

    intent_x, intent_y = build_intent_dataset()
    intent_model = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
        ('classifier', LogisticRegression(
            max_iter=1500,
            class_weight='balanced',
            random_state=42,
        )),
    ])
    intent_report = _evaluate(intent_model, intent_x, intent_y, INTENT_CLASSES)
    intent_model.fit(intent_x, intent_y)

    artifact = {
        'model_version': 1,
        'data_kind': 'synthetic_demonstration_only',
        'limitation': 'Metrics are held-out synthetic-data demonstration results, not validated real-world performance.',
        'trust_model': trust_model,
        'intent_model': intent_model,
        'evaluation': {'trust': trust_report, 'intent': intent_report},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(artifact, output_path)
    return {
        'artifact': str(output_path),
        'data_kind': artifact['data_kind'],
        'limitation': artifact['limitation'],
        'evaluation': artifact['evaluation'],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Train synthetic ShadowGuard ML demonstration models.')
    parser.add_argument('--output', type=Path, default=MODEL_ARTIFACT_PATH)
    args = parser.parse_args()
    print(json.dumps(train_models(args.output), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()