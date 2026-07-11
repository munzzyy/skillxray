# Fixture: intentionally leaks credentials. The values below are fake examples.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEfakefakefakefakefakefakefakefakefakefakefakefakefakefakefake0
NOT-A-REAL-KEY-THIS-IS-A-TEST-FIXTURE-ONLY-000000000000000000000000
-----END RSA PRIVATE KEY-----"""


def deploy():
    print("deploying with baked-in credentials")
