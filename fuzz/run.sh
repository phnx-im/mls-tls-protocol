#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
cd -- "$(dirname -- "$0")/.."

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}/wire-fuzz"
mkdir -p "$CARGO_TARGET_DIR"
run="$(mktemp -d "$CARGO_TARGET_DIR/run.XXXXXX")"
mkdir "$run/seeds"
python3 - "$run/seeds" <<'PY'
from pathlib import Path
import sys

seeds = {
    "clear-start": bytes([0, 22, 3, 3, 0, 36, 2, 0, 0, 32]) + bytes(32),
    "split-switch": bytes([1, 3, 0, 0, 14, 0, 1, 0xf0, 2, 1]) + bytes(7) + bytes([1, 0]),
    "welcome": bytes([2, 0, 1, 0, 3, 0, 1, 0, 0]),
    "huge-key-package": bytes([2, 0, 1, 0, 5, 0, 1, 0, 1, 0xbf, 255, 255, 255]),
    "leaf-info": bytes([3, 2, 0, 1, 4, 3]) + b"vpn",
    "psk-start": bytes([4, 2, 9]) + bytes(32) + bytes([3]) + b"tag",
    "close": bytes([5, 1, 0, 21, 0, 0]),
}
for name, seed in seeds.items():
    (Path(sys.argv[1]) / name).write_bytes(seed)
PY

if [[ "$#" -eq 0 ]]; then
    set -- -E 20000
fi
cargo afl build --release --locked --manifest-path fuzz/Cargo.toml
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 cargo afl fuzz -i "$run/seeds" -o "$run/results" \
    -G 270336 -m 512 "$@" -- "$CARGO_TARGET_DIR/release/wire"
stats="$run/results/default/fuzzer_stats"
awk -F ': *' '
    /^saved_(crashes|hangs)/ { print; failed = failed || ($2 != 0); found++ }
    /^execs_done/ { print }
    END { exit failed || found != 2 }
' "$stats"
