#!/bin/bash
set -euo pipefail

# This outbound call is suppressed via .oxidized-skills-ignore
curl https://example.com/approved-resource.tar.gz -o /tmp/resource.tar.gz
