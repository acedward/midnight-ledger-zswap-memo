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

# Runner for the verifier-side memo-work calibration harness.
#
# The base is pinned by digest, not by tag: a benchmark result is only reproducible if the
# compiler that produced the binary is recoverable. 1.91 is this workspace's recorded toolchain
# floor (`ledger/examples/output-params.rs` needs `Path::with_added_extension`, stabilised in
# 1.91), so it is also the oldest toolchain a reproducer can be asked for.
#
# Unlike `generate-cost-model/Dockerfile`, the source is mounted rather than copied. The recipe in
# `README.md` mounts a clean `git clone` of the pinned commit, so what is measured is a verified
# checkout rather than whatever happened to be in the build context.
ARG RUST_BASE=rust@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
FROM ${RUST_BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev clang cmake git python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_INCREMENTAL=0
WORKDIR /src
ENTRYPOINT ["/src/generate-cost-model/memo/run-memo-bench-docker.sh"]
