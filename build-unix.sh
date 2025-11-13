#!/bin/bash
# Linux/macOS build script for vscpl2drv-websocksrv

mkdir -p build
cd build

# Configure with Unix Makefiles
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build the project
make

echo "Build completed!"