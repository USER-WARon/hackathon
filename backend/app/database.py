import json
import sqlite3
from pathlib import Path
from typing import Any

from app.config import DB_PATH, PRODUCTION_DB_PATH

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS tool_registry (
        name TEXT PRIMARY KEY,
        trust_zone TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        description TEXT,
        authenticated INTEGER NOT NULL DEFAULT 0,
        identity_valid INTEGER NOT NULL DEFAULT 1,
        permissions_revoked INTEGER NOT NULL DEFAULT 0,
        prohibited_behavior INTEGER NOT NULL DEFAULT 0,
        capabilities_json TEXT NOT NULL DEFAULT '[]',
        permitted_resources_json TEXT NOT NULL DEFAULT '[]',
        permission_violations INTEGER NOT NULL DEFAULT 0,
        observed_behavior_json TEXT NOT NULL DEFAULT '{}',
        data_sensitivity TEXT NOT NULL DEFAULT 'public',
        outbound_permissions_json TEXT NOT NULL DEFAULT '[]',
        approved_relationships_json TEXT NOT NULL DEFAULT '[]',
        trust_score INTEGER NOT NULL DEFAULT 0,
        trust_classification TEXT NOT NULL DEFAULT 'LOW_TRUST',
        trust_reason TEXT,
        trust_evaluated_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS integration_settings (
        name TEXT PRIMARY KEY,
        trust_zone TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'CLEAN',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        tainted_at TEXT,
        taint_source TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        request_id TEXT,
        session_id TEXT,
        action_id TEXT,
        tool_name TEXT,
        policy_code TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        summary TEXT NOT NULL,
        details_json TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        request_id TEXT,
        session_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        user_objective TEXT,
        tool_name TEXT NOT NULL,
        action_hash TEXT NOT NULL,
        sql_text TEXT,
        status TEXT NOT NULL,
        approval_kind TEXT NOT NULL DEFAULT 'one_time',
        operation TEXT,
        target_resource TEXT,
        destination_mcp TEXT,
        permitted_capabilities_json TEXT NOT NULL DEFAULT '[]',
        grant_duration_seconds INTEGER,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        approved_at TEXT,
        rejected_at TEXT,
        snapshot_fingerprint TEXT,
        result_json TEXT,
        staged_json TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS trust_grants (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        source_mcp TEXT NOT NULL,
        destination_mcp TEXT NOT NULL,
        operation TEXT NOT NULL,
        target_resource TEXT NOT NULL,
        capabilities_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        approval_id TEXT NOT NULL,
        action_hash TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS taint_sources (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        source_tool TEXT NOT NULL,
        tool_call_id TEXT NOT NULL,
        affected_fields_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(session_id, tool_call_id)
    )
    """,
]


def get_connection(path: str | None = None) -> sqlite3.Connection:
    db_path = Path(path or DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(path: str | None = None) -> None:
    conn = get_connection(path)
    try:
        for statement in SCHEMA:
            conn.execute(statement)
        migrate_schema(conn)
        conn.commit()
        seed_defaults(conn)
    finally:
        conn.close()


def migrate_schema(conn: sqlite3.Connection) -> None:
    existing_tool_columns = {row['name'] for row in conn.execute('PRAGMA table_info(tool_registry)').fetchall()}
    tool_columns = {
        'authenticated': "INTEGER NOT NULL DEFAULT 0",
        'identity_valid': "INTEGER NOT NULL DEFAULT 1",
        'permissions_revoked': "INTEGER NOT NULL DEFAULT 0",
        'prohibited_behavior': "INTEGER NOT NULL DEFAULT 0",
        'capabilities_json': "TEXT NOT NULL DEFAULT '[]'",
        'permitted_resources_json': "TEXT NOT NULL DEFAULT '[]'",
        'permission_violations': "INTEGER NOT NULL DEFAULT 0",
        'observed_behavior_json': "TEXT NOT NULL DEFAULT '{}'",
        'data_sensitivity': "TEXT NOT NULL DEFAULT 'public'",
        'outbound_permissions_json': "TEXT NOT NULL DEFAULT '[]'",
        'approved_relationships_json': "TEXT NOT NULL DEFAULT '[]'",
        'trust_score': "INTEGER NOT NULL DEFAULT 0",
        'trust_classification': "TEXT NOT NULL DEFAULT 'LOW_TRUST'",
        'trust_reason': "TEXT",
        'trust_evaluated_at': "TEXT",
    }
    for name, definition in tool_columns.items():
        if name not in existing_tool_columns:
            conn.execute(f'ALTER TABLE tool_registry ADD COLUMN {name} {definition}')

    existing_audit_columns = {row['name'] for row in conn.execute('PRAGMA table_info(audit_events)').fetchall()}
    audit_columns = {
        'request_id': 'TEXT',
        'severity': "TEXT NOT NULL DEFAULT 'info'",
    }
    for name, definition in audit_columns.items():
        if name not in existing_audit_columns:
            conn.execute(f'ALTER TABLE audit_events ADD COLUMN {name} {definition}')

    existing_approval_columns = {row['name'] for row in conn.execute('PRAGMA table_info(approvals)').fetchall()}
    approval_columns = {
        'approval_kind': "TEXT NOT NULL DEFAULT 'one_time'",
        'operation': "TEXT",
        'target_resource': "TEXT",
        'destination_mcp': "TEXT",
        'permitted_capabilities_json': "TEXT NOT NULL DEFAULT '[]'",
        'grant_duration_seconds': "INTEGER",
        'request_id': 'TEXT',
        'user_objective': 'TEXT',
    }
    for name, definition in approval_columns.items():
        if name not in existing_approval_columns:
            conn.execute(f'ALTER TABLE approvals ADD COLUMN {name} {definition}')


def ensure_production_demo_db(path: str | None = None) -> None:
    db_path = Path(path or PRODUCTION_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            )
            """
        )
        if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            conn.executemany(
                'INSERT INTO users (id, name, email) VALUES (?, ?, ?)',
                [
                    (1, 'Alice', 'alice@example.com'),
                    (2, 'Bob', 'bob@example.com'),
                    (3, 'Charlie', 'charlie@example.com'),
                ],
            )
        conn.commit()
    finally:
        conn.close()


def seed_defaults(conn: sqlite3.Connection) -> None:
    defaults = [
        ('github_reader', 'HIGH', 'Local GitHub cleanup script fixture', ['read'], ['repo:demo', 'cleanup_script.sql'], 'internal', ['production_database'], []),
        ('production_database', 'HIGH', 'Protected SQLite database', ['read', 'write'], ['users'], 'protected', [], []),
        ('weather_api', 'LOW', 'Mock weather service', ['read', 'external_read'], ['weather:city'], 'public', [], []),
    ]
    for name, trust_zone, description, capabilities, resources, sensitivity, relationships, outbound in defaults:
        score = 90 if trust_zone == 'HIGH' else 55
        classification = 'HIGH_TRUST' if score >= 70 else 'LOW_TRUST'
        conn.execute(
            """
            INSERT OR IGNORE INTO tool_registry (
                name, trust_zone, enabled, description, authenticated, identity_valid,
                capabilities_json, permitted_resources_json, data_sensitivity,
                approved_relationships_json, outbound_permissions_json, trust_score,
                trust_classification, trust_reason, trust_evaluated_at
            ) VALUES (?, ?, 1, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                name,
                trust_zone,
                description,
                json.dumps(capabilities),
                json.dumps(resources),
                sensitivity,
                json.dumps(relationships),
                json.dumps(outbound),
                score,
                classification,
                'Seeded default trust evidence',
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO integration_settings (name, trust_zone, updated_at) VALUES (?, ?, datetime('now'))",
            (name, trust_zone),
        )
        conn.execute(
            """
            UPDATE tool_registry
            SET authenticated = 1,
                identity_valid = 1,
                capabilities_json = ?,
                permitted_resources_json = ?,
                data_sensitivity = ?,
                approved_relationships_json = ?,
                outbound_permissions_json = ?,
                trust_score = ?,
                trust_classification = ?,
                trust_reason = COALESCE(trust_reason, ?),
                trust_evaluated_at = COALESCE(trust_evaluated_at, datetime('now'))
            WHERE name = ? AND trust_score = 0
            """,
            (
                json.dumps(capabilities),
                json.dumps(resources),
                sensitivity,
                json.dumps(relationships),
                json.dumps(outbound),
                score,
                classification,
                'Seeded default trust evidence',
                name,
            ),
        )
    conn.commit()


def fetch_one(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    return conn.execute(query, params).fetchone()


def fetch_all(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return conn.execute(query, params).fetchall()


def read_json(value: str | None) -> dict | list | None:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None
