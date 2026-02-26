#!/bin/bash
# This script intentionally contains a leaked credential for testing gitleaks detection.
# It is a TEST FIXTURE — not a real secret.

# Fake AWS key (likely allowlisted, keeping for variety)
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake GitHub Token (Detect-able by gitleaks)
export GITHUB_TOKEN="ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# Fake Google API Key (Detect-able by gitleaks)
export GOOGLE_API_KEY="AIzaSyAsEsbIoIoSDqql5kXFC3fQSwe4WKe"

echo "Deploying..."
