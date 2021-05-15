#!/usr/bin/env bash

set -eo pipefail

THIS_DIR=$( cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P )

set -x
cd "$THIS_DIR/.."
git submodule update --recursive --remote
