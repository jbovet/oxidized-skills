#!/bin/bash
set -euo pipefail

# SC2086 — unquoted variable (will trigger shellcheck warning)
X="hello world"
echo $X

# SC2046 — word splitting from $() (will trigger shellcheck warning)
echo $(ls)

# SC2059 — printf with variable format (will trigger shellcheck warning)
MSG="hello"
printf $MSG
