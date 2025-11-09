#!/usr/bin/env bash

# Minimal placeholder installer for the open-core distribution.
# This script intentionally avoids performing any privileged actions.
# It exists so the backend's go:embed directive continues to compile.

set -euo pipefail

cat <<'MSG'
Prysm Open-Core Agent Installer Stub
------------------------------------
This open-core build does not ship the proprietary agent installer.

Please refer to https://github.com/prysmsh/prysm-open-core for
instructions on connecting agents or building your own installer.
MSG
