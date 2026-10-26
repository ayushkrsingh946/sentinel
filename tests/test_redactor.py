from sentinel.safety.redactor import SecretRedactor


def test_redactor_scrubs_aws_keys():
    # Dynamically formatted test pattern to avoid trigger on static git push protection
    fake_key = "A" + "KIA" + "0000000000000000"
    code = f'AWS_KEY = "{fake_key}"'
    scrubbed, stats = SecretRedactor.redact(code)
    assert fake_key not in scrubbed
    assert "[REDACTED_AWS_KEY_ID]" in scrubbed
    assert stats.get("aws_access_key") == 1


def test_redactor_scrubs_github_token():
    fake_token = "gh" + "p_" + "0" * 36
    code = f'token = "{fake_token}"'
    scrubbed, stats = SecretRedactor.redact(code)
    assert fake_token not in scrubbed
    assert "[REDACTED_GITHUB_TOKEN]" in scrubbed or "[REDACTED_SECRET]" in scrubbed


def test_redactor_scrubs_private_key():
    key_sample = (
        "-----BEGIN RSA " + "PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1W4Q2\n"
        "-----END RSA " + "PRIVATE KEY-----"
    )
    scrubbed, stats = SecretRedactor.redact(key_sample)
    assert "MIIEowIBAAKCAQEA0Y1W4Q2" not in scrubbed
    assert "[REDACTED_PRIVATE_KEY_BLOCK]" in scrubbed
    assert stats.get("private_key") == 1


def test_redactor_scrubs_db_url():
    db_conn = 'DATABASE_URL = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/main"'
    scrubbed, stats = SecretRedactor.redact(db_conn)
    assert "SuperSecretPass123" not in scrubbed
    assert "[REDACTED_DB_PASSWORD]" in scrubbed
