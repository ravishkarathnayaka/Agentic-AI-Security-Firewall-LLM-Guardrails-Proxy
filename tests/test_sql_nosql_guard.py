"""Unit tests for SQL and NoSQL Injection Guard."""

import pytest
from proxy.guards.sql_nosql_guard import SqlNoSqlInjectionGuard


@pytest.fixture
def guard():
    return SqlNoSqlInjectionGuard()


def test_benign_sql_queries_pass(guard):
    benign_queries = [
        "SELECT id, name, email FROM customers WHERE active = 1 ORDER BY created_at DESC",
        "INSERT INTO audit_logs (user_id, action) VALUES (104, 'login')",
        "UPDATE settings SET theme = 'dark' WHERE user_id = 99",
        "SELECT COUNT(*) FROM telemetry_events WHERE timestamp >= '2026-09-01'",
    ]
    for q in benign_queries:
        res = guard.inspect(q)
        assert not res.is_blocked, f"Benign query unexpectedly blocked: {q}"


def test_sql_tautology_bypass_blocked(guard):
    payloads = [
        "SELECT * FROM users WHERE name = 'admin' OR 1=1",
        "SELECT * FROM accounts WHERE id = 10 OR 'a'='a'",
        "SELECT * FROM products WHERE price > 0 AND 1=1",
    ]
    for p in payloads:
        res = guard.inspect(p)
        assert res.is_blocked
        assert res.threat_category == "sql_injection"
        assert "sql_tautology" in res.violation_code


def test_sql_union_select_blocked(guard):
    payload = "SELECT title, body FROM articles WHERE id = -1 UNION SELECT username, password_hash FROM admin_users"
    res = guard.inspect(payload)
    assert res.is_blocked
    assert res.violation_code == "sql_union_select_exfiltration"


def test_sql_stacked_drop_table_blocked(guard):
    payload = "SELECT * FROM orders WHERE customer_id = 42; DROP TABLE users; --"
    res = guard.inspect(payload)
    assert res.is_blocked
    assert res.violation_code == "sql_destructive_stacked_query"


def test_sql_time_based_delay_blocked(guard):
    payloads = [
        "SELECT * FROM items WHERE sku = 'abc'; WAITFOR DELAY '0:0:10'",
        "SELECT * FROM items WHERE sku = 'abc' AND pg_sleep(5)",
        "SELECT * FROM items WHERE sku = 'abc' AND sleep(5)",
    ]
    for p in payloads:
        res = guard.inspect(p)
        assert res.is_blocked
        assert res.violation_code == "sql_time_based_blind_injection"


def test_nosql_where_injection_blocked(guard):
    payload = '{"$where": "this.role == \'admin\' || true"}'
    res = guard.inspect(payload)
    assert res.is_blocked
    assert res.threat_category == "nosql_injection"
    assert res.violation_code == "nosql_where_clause_injection"


def test_nosql_operator_tampering_blocked(guard):
    payload = '{"username": "admin", "password": {"$gt": ""}}'
    res = guard.inspect(payload)
    assert res.is_blocked
    assert res.threat_category == "nosql_injection"
    assert res.violation_code == "nosql_operator_tampering"


def test_empty_query_handling(guard):
    assert not guard.inspect("").is_blocked
    assert not guard.inspect("   ").is_blocked
