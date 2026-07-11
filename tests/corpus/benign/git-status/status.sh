#!/bin/bash
# Read-only git summary. Nothing destructive, nothing networked.
set -euo pipefail

echo "branch: $(git rev-parse --abbrev-ref HEAD)"
echo "changes:"
git status --short
echo "recent:"
git log --oneline -5
