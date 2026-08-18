#!/usr/bin/env python3
# This file is part of midnight-ledger.
# Copyright (C) Midnight Foundation
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Merges per-run acceptance CSVs into the single retained raw-results artifact.

Every run is kept, admissible or not. The protocol requires that rejected runs be
recorded rather than discarded, so the merged CSV carries two extra leading columns --
`run_id` and `admissible` -- and the admissibility verdict is recomputed here from the
run's own samples rather than copied from a note. A reviewer can therefore re-derive
which runs were used, and why the others were not, from this one file.

Usage:
    merge-memo-runs.py <out.csv> <run-id>=<raw.csv> ...
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "derive", Path(__file__).resolve().parent / "derive-memo-schedule.py"
)
derive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(derive)


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = Path(argv[1])

    runs = []
    for spec in argv[2:]:
        run_id, _, path = spec.partition("=")
        runs.append(derive.Run(run_id, path))

    admissible, verdicts = derive.screen(runs)
    admissible_ids = {r.run_id for r in admissible}

    rows = []
    fields = None
    for run in runs:
        with open(run.csv_path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if fields is None:
                fields = ["run_id", "admissible"] + reader.fieldnames
            for row in reader:
                row["run_id"] = run.run_id
                row["admissible"] = str(run.run_id in admissible_ids).lower()
                rows.append(row)

    rows.sort(
        key=lambda r: (
            r["run_id"],
            r["group"],
            int(r["memo_len"] or 0),
            int(r["memo_inputs"] or 0),
            r["control"],
        )
    )
    with open(out_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {out_path}: {len(rows)} rows from {len(runs)} run(s)")
    for run in runs:
        verdict = verdicts[run.run_id]
        print(
            f"  {run.run_id}: dispersion {verdict['dispersion'] * 100:.2f}% "
            f"(class {verdict['dispersion_worst_class']}), floor {verdict['floor_ns']:.4f} ns, "
            f"anchor {verdict['anchor_ns']:.1f} ns -> "
            f"{'ADMISSIBLE' if verdict['admissible'] else 'REJECTED'}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
