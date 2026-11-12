# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2025 Åke Hedman, the VSCP Project
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

cmake_minimum_required(VERSION 3.18...3.31)
project(testapp LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# --- System Libraries ---
include(GNUInstallDirs)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Third party sources (vscp, json, spdlog, mustache, sha256)
include(${PROJECT_SOURCE_DIR}/../cmake/dependencies.cmake)

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
find_package(OpenSSL REQUIRED)

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
  ${MUSTACHE_DIR}/mustache.hpp
  ${VSCP_DIR}/src/vscp/common/guid.h
  ${VSCP_DIR}/src/vscp/common/guid.cpp 
  ${VSCP_DIR}/src/vscp/common/vscp.h
  ${VSCP_DIR}/src/vscp/common/vscpdatetime.h
  ${VSCP_DIR}/src/vscp/common/vscpdatetime.cpp
  ${VSCP_DIR}/src/vscp/common/vscphelper.h
  ${VSCP_DIR}/src/vscp/common/vscphelper.cpp
  ${VSCP_DIR}/src/vscp/common/vscphelperlogging.cpp
  ${VSCP_DIR}/src/vscp/common/vscphelperlogging-forward.cpp
  ${VSCP_DIR}/src/common/vscphelper-common.cpp
  ${VSCP_DIR}/src/vscp/common/canal.h
  ${VSCP_DIR}/src/common/vscpbase64.h
  ${VSCP_DIR}/src/common/vscpbase64.c
  ${VSCP_DIR}/src/common/vscp-aes.h
  ${VSCP_DIR}/src/common/vscp-aes.c
  ${VSCP_DIR}/src/common/crc.h
  ${VSCP_DIR}/src/common/crc.c
  ${VSCP_DIR}/src/common/crc8.h
  ${VSCP_DIR}/src/common/crc8.c
  ${VSCP_DIR}/src/common/vscpmd5.h
  ${VSCP_DIR}/src/common/vscpmd5.c
  ${CRYPTO_ALGORITHMS_DIR}/sha256.h
  ${CRYPTO_ALGORITHMS_DIR}/sha256.c)

# Include directories
if (WIN32)  
  target_include_directories(${PROJECT_NAME} PRIVATE
    src/
    ${VSCP_DIR}/src/vscp/common/  
    ${VSCP_DIR}/src/common/
    ${NLOHMANN_JSON_DIR}/single_include/
    ${SPDLOG_DIR}/include/
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
    ${VSCP_DIR}/src/vscp/common/
    ${VSCP_DIR}/src/common
    ${NLOHMANN_JSON_DIR}/single_include/
    ${SPDLOG_DIR}/include/
    ${CMAKE_BINARY_DIR}
    ${THREAD_INCLUDE_DIR}
  )
endif()  

# Link libraries
if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    expat::expat
    dlfcn-win32::dl
    OpenSSL::Crypto
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
    OpenSSL::Crypto
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
