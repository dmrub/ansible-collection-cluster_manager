#!/usr/bin/env bash

set -eo pipefail

THIS_DIR=$( cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P )

"$THIS_DIR/update.sh"

set -x
cd "$THIS_DIR/.."
ansible-galaxy collection build "$@"
