# dependencies.cmake
#
# Third party sources used by the driver, fetched at configure time.
#
# Copyright (c) 2000-2026 Åke Hedman, the VSCP Project
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Every dependency is pinned to a commit and checked with a SHA-256 hash.
# None of them is added to the build with add_subdirectory(); only their
# source files are used (SOURCE_SUBDIR points to a folder without a
# CMakeLists.txt).
#
# To build against a local copy instead of downloading, set
# FETCHCONTENT_SOURCE_DIR_<NAME>, for example
#
#   cmake .. -DFETCHCONTENT_SOURCE_DIR_VSCP=/path/to/vscp
#
# To build offline once everything has been downloaded, add
# -DFETCHCONTENT_FULLY_DISCONNECTED=ON.
#
# Sets VSCP_DIR, MONGOOSE_DIR, NLOHMANN_JSON_DIR, SPDLOG_DIR, MUSTACHE_DIR
# and CRYPTO_ALGORITHMS_DIR.

include_guard(GLOBAL)
include(FetchContent)

# vscp 1ab1314 (development)
FetchContent_Declare(vscp
  URL https://codeload.github.com/grodansparadis/vscp/tar.gz/1ab1314702bc093ec77b5ac75691ec867a582cbc
  URL_HASH SHA256=0924859b4dbdeb46b6cbbd5d3c950f9b69728c5e96d44dc04bc2390dc5b5fdba
  SOURCE_SUBDIR _no_cmake_)

# mongoose 7.22 (9ccfc02)
FetchContent_Declare(mongoose
  URL https://codeload.github.com/cesanta/mongoose/tar.gz/9ccfc02a86fa3aa78f6bb412f98e74650fb1579f
  URL_HASH SHA256=bb7232c59e44424c7b983967c75653b434fb3a6b2e56df6da762041e3342c03c
  SOURCE_SUBDIR _no_cmake_)

# nlohmann json 3.12.0 (21af527)
FetchContent_Declare(nlohmann_json
  URL https://codeload.github.com/nlohmann/json/tar.gz/21af527e756435701f23e01aa8ea8dab6e050c90
  URL_HASH SHA256=a4de85a312eb41a9a47b3756800f9c0dfec3afb3dec257fb1ee22c8f435245fe
  SOURCE_SUBDIR _no_cmake_)

# spdlog 1.17.0 (f5f173a)
FetchContent_Declare(spdlog
  URL https://codeload.github.com/gabime/spdlog/tar.gz/f5f173a1a57d0e2e0115f2ed71ee7ea316516853
  URL_HASH SHA256=897a1f8d9b1978559fda73e08f94e30ea83c298e768625ae0ec2c3e2237ea952
  SOURCE_SUBDIR _no_cmake_)

# mustache 4.1+ (3f65494)
FetchContent_Declare(mustache
  URL https://codeload.github.com/kainjow/mustache/tar.gz/3f654942a70c46a775070d7a09ca7acfa3e205b7
  URL_HASH SHA256=959b8fcaecc14fc0b6243c078a39fd13dab107dcda086ed2ca90e1a486269a36
  SOURCE_SUBDIR _no_cmake_)

# crypto-algorithms (cfbde48), sha256
FetchContent_Declare(crypto_algorithms
  URL https://codeload.github.com/B-Con/crypto-algorithms/tar.gz/cfbde48414baacf51fc7c74f275190881f037d32
  URL_HASH SHA256=525d7b38eb549e52b21f6fc5e21362b912d66912aa458a5e4819f9427fc8f477
  SOURCE_SUBDIR _no_cmake_)

FetchContent_MakeAvailable(vscp mongoose nlohmann_json spdlog mustache crypto_algorithms)

set(VSCP_DIR              "${vscp_SOURCE_DIR}")
set(MONGOOSE_DIR          "${mongoose_SOURCE_DIR}")
set(NLOHMANN_JSON_DIR     "${nlohmann_json_SOURCE_DIR}")
set(SPDLOG_DIR            "${spdlog_SOURCE_DIR}")
set(MUSTACHE_DIR          "${mustache_SOURCE_DIR}")
set(CRYPTO_ALGORITHMS_DIR "${crypto_algorithms_SOURCE_DIR}")
