#!/bin/bash
# Script to run go mod tidy with appropriate settings

set -euo pipefail

go mod tidy -v
