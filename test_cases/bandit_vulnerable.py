# TEST ONLY - Deliberately vulnerable Python code for Bandit scanner testing.
# These patterns are intentionally insecure to verify Bandit detects them.
# Do NOT use any of these patterns in production code.

import hashlib
import os
import pickle
import random
import subprocess
import tempfile


# B602 - subprocess with shell=True (command injection risk)
def run_user_command(user_input):
    subprocess.call("ls " + user_input, shell=True)  # noqa


# B324 - use of weak MD5 hash (not suitable for security purposes)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # noqa


# B311 - use of random for security/token generation (not cryptographically secure)
def generate_token():
    return str(random.randint(100000, 999999))  # noqa


# B301 - use of pickle.loads (unsafe deserialization)
def load_user_data(raw_bytes):
    return pickle.loads(raw_bytes)  # noqa


# B108 - use of insecure temp file (race condition vulnerability)
def write_temp(data):
    path = tempfile.mktemp()  # noqa
    with open(path, "w") as f:
        f.write(data)
    return path


# B105 - hardcoded password string
DB_PASSWORD = "supersecret123"  # noqa


# B607 - starting process with partial path (PATH injection risk)
def run_tool():
    subprocess.Popen(["netstat"])  # noqa
