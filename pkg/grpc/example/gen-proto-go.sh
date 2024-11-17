#!/usr/bin/env bash
# Copyright 2024 FootprintAI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# ====buf installation====
#
# BIN="/usr/local/bin" && \
# VERSION="1.0.0-rc9" && \
# BINARY_NAME="buf" && \
#   curl -sSL \
#     "https://github.com/bufbuild/buf/releases/download/v${VERSION}/${BINARY_NAME}-$(uname -s)-$(uname -m)" \
#     -o "${BIN}/${BINARY_NAME}" && \
#   chmod +x "${BIN}/${BINARY_NAME}"
#
# ====Init====
# run `buf config init` to setup buf.yaml

buf dep update
buf generate
