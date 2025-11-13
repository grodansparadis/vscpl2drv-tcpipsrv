@echo off
REM Windows build script for vscpl2drv-websocksrv

if not exist build mkdir build
cd build

REM Configure with Visual Studio generator, override vcpkg toolchain
cmake .. -G "Visual Studio 17 2022"  -DCMAKE_BUILD_TYPE=Debug -DVCPKG_ROOT=G:/vcpkg/ -DCMAKE_TOOLCHAIN_FILE=G:/vcpkg/scripts/buildsystems/vcpkg.cmake

REM Build the project
cmake --build . --config Debug

echo Build completed!
pause