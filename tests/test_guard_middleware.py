from sentinel.guard.blocklist import BlocklistManager
from sentinel.guard.fast_rules import FastRuleEngine


def test_fast_rules_detect_sql_and_cmd_injection():
    score, rules = FastRuleEngine.inspect(
        method="GET",
        path="/api/users",
        query="id=1' UNION SELECT username, password FROM admin--",
        body="",
        user_agent="Mozilla/5.0",
    )
    assert score >= 40
    assert "sql_injection" in rules

    score2, rules2 = FastRuleEngine.inspect(
        method="POST",
        path="/api/ping",
        query="",
        body="host=127.0.0.1; cat /etc/passwd",
        user_agent="curl/7.68.0",
    )
    assert score2 >= 45
    assert "cmd_injection" in rules2 or "path_traversal" in rules2


def test_blocklist_manager_ttl_and_unblock():
    mgr = BlocklistManager(default_ttl_seconds=1)  # 1 second TTL
    ip = "198.51.100.42"

    mgr.block_ip(ip, reason="Repeated injection attempts")
    blocked, reason = mgr.is_blocked(ip)
    assert blocked is True
    assert reason == "Repeated injection attempts"

    # Manual unblock
    assert mgr.unblock_ip(ip) is True
    blocked_after, _ = mgr.is_blocked(ip)
    assert blocked_after is False
