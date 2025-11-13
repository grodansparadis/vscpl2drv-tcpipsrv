# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2025 Åke Hedman, the VSCP Project
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#

cmake_minimum_required(VERSION 3.5)
project(testapp LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# --- System Libraries ---
include(GNUInstallDirs)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Disable abi warnings (nlohmann)
if(WIN32)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
  add_definitions(-DWIN32)
  add_definitions(-D_WIN32)
endif() 

# Threading support - cross-platform
if(WIN32)
    # On Windows with vcpkg, use the pthreads package
    find_package(pthreads CONFIG QUIET)
    if(pthreads_FOUND)
        message(STATUS "Found pthreads via vcpkg")
        set(THREAD_LIBRARY PThreads4W::PThreads4W)
        set(THREAD_INCLUDE_DIR "")  # vcpkg handles includes automatically
    else()
        # Fallback to Windows threads
        message(STATUS "Using Windows native threads")
        set(CMAKE_USE_WIN32_THREADS_INIT 1)
        set(CMAKE_USE_PTHREADS_INIT 0)
        set(THREAD_LIBRARY "")
        set(THREAD_INCLUDE_DIR "")
    endif()
else()
    # Unix/Linux/macOS - use standard pthread
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    set(THREAD_LIBRARY Threads::Threads)
    set(THREAD_INCLUDE_DIR "")
endif()

#openssl
#find_package(OpenSSL REQUIRED)

# Expat C library
if(WIN32)
find_package(expat CONFIG REQUIRED)
else()	
include(FindEXPAT)
find_package(EXPAT REQUIRED)
include_directories(${EXPAT_INCLUDE_DIRS})
endif()

# dlfcn
if (WIN32)
    find_package(dlfcn-win32 CONFIG REQUIRED)
endif()

add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE main.cpp
  ../third_party/Mustache/mustache.hpp
  ../third_party/spdlog/include
  ../third_party/vscp/src/vscp/common/guid.h
  ../third_party/vscp/src/vscp/common/guid.cpp 
  ../third_party/vscp/src/vscp/common/vscp.h
  ../third_party/vscp/src/vscp/common/vscpdatetime.h
  ../third_party/vscp/src/vscp/common/vscpdatetime.cpp
  ../third_party/vscp/src/vscp/common/vscphelper.h
  ../third_party/vscp/src/vscp/common/vscphelper.cpp
  ../third_party/vscp/src/vscp/common/canal.h
  ../third_party/vscp/src/common/vscpbase64.h
  ../third_party/vscp/src/common/vscpbase64.c
  ../third_party/vscp/src/common/vscp-aes.h
  ../third_party/vscp/src/common/vscp-aes.c
  ../third_party/vscp/src/common/crc.h
  ../third_party/vscp/src/common/crc.c
  ../third_party/vscp/src/common/crc8.h
  ../third_party/vscp/src/common/crc8.c
  ../third_party/vscp/src/common/vscpmd5.h
  ../third_party/vscp/src/common/vscpmd5.c
  ../third_party/crypto-algorithms/sha256.h
  ../third_party/crypto-algorithms/sha256.c)

# Include directories
if (WIN32)  
  target_include_directories(${PROJECT_NAME} PRIVATE
    src/
    ../third_party/vscp/src/vscp/common/  
    ../third_party/vscp/src/common/
    ../third_party/json/single_include/
    ../third_party/spdlog/include/
    ${CMAKE_BINARY_DIR}
    ${THREAD_INCLUDE_DIR}
    ${LOCAL_WIN_INCLUDE}

    # Add a compile definition to use our compatibility header
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
     BYTESWAP_H_INCLUDED  # This prevents vscphelper.h from including byteswap.h
    )
  )
else()
  target_include_directories(${PROJECT_NAME} PRIVATE
    src/
    ../third_party/vscp/src/vscp/common/
    ../third_party/vscp/src/common
    ../third_party/json/single_include/
    ../third_party/spdlog/include/
    ${CMAKE_BINARY_DIR}
    ${THREAD_INCLUDE_DIR}
  )
endif()  

# Link libraries
if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    expat::expat
    dlfcn-win32::dl
  )
  
  # Add threading library if found
  if(THREAD_LIBRARY)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${THREAD_LIBRARY})
  endif()
        
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    m
    dl
    ${EXPAT_LIBRARIES}
  )
  
  # Add threading library
  if(THREAD_LIBRARY)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${THREAD_LIBRARY})
  endif()
endif()

# Debug output
message(STATUS "Threading library: ${THREAD_LIBRARY}")
if(WIN32 AND pthreads_FOUND)
    message(STATUS "Using pthreads on Windows")
elseif(WIN32)
    message(STATUS "Using Windows native threading")
else()
    message(STATUS "Using POSIX threads")
endif()
