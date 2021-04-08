# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2021 Åke Hedman, Grodans Paradis AB
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
# VSCP_PATH - set to path to local vscp repository. Default is "../vscp". Set with
# -DVSCP_PATH="path"
#

cmake_minimum_required(VERSION 3.5)
project(vscpl2drv-tcpipsrv LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, Grodans Paradis AB")

SET(MAJOR_VERSION "1")
SET(MINOR_VERSION "0")
SET(PATCH_VERSION "0")

add_subdirectory(man)

option(USE_SSL "Use SSL" TRUE)

## --- C++11 build flags ---
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build locations
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Default location for VSCP level II drivers
set(VSCP_LEVEL2_DRV_DIR /var/lib/vscp/drivers/level2/)



# Generate position-independent code (-fPIC on UNIX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- System Libraries ---
include(GNUInstallDirs)

# --- Path to vscp --- 
if (NOT DEFINED VSCP_PATH)
set (VSCP_PATH "${PROJECT_SOURCE_DIR}/../vscp")
endif()

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEANS)
    add_definitions(-DOPENSSL_API_1_1)
    add_definitions(-D_POSIX_C_SOURCE)    
    add_definitions(-DVCPKG_TARGET_TRIPLET=x64-windows)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(LIBS_SYSTEM ws2_32)
elseif(UNIX)
    set(LIBS_SYSTEM c stdc++)
endif()

#              * * * cpack * * *
IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
INCLUDE(InstallRequiredSystemLibraries)

SET(CPACK_SET_DESTDIR "on")
SET(CPACK_PACKAGING_INSTALL_PREFIX "/tmp")
SET(CPACK_GENERATOR "DEB" "RPM" "TGZ" "zip")
 
SET(CPACK_PACKAGE_DESCRIPTION "VSCP driver for tcp/ip server")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VSCP level II Driver for VSCP that export a server interface for the VSCP tcp/ip link protocol")
SET(CPACK_PACKAGE_VENDOR "Grodans Paradis AB")
SET(CPACK_PACKAGE_CONTACT "akhe@grodansparadis.com")
SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")

SET(CPACK_DEBIAN_PACKAGE_DEPENDS " libexpat-dev, libssl-dev ")

SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
SET(CPACK_DEBIAN_PACKAGE_SECTION "network")
SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
 
SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)

INCLUDE(CPack)
 
ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")

if (MSVC)

endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# pthreads
set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#openssl
find_package(OpenSSL REQUIRED)

# Windows Libs
if (WIN32)

else()

endif()

# Set sockettcp build flags
add_definitions(-DUSE_IPV6)
string(FIND "${OPENSSL_VERSION}" "1.1." SSL_VER_POS)
if(${SSL_VER_POS})
    add_definitions(-DOPENSSL_API_1_0)
else()
    add_definitions(-DOPENSSL_API_1_1)
endif()

set(RESOURCE_FILES
    README.md
    forms/index.html)

# Add files to library
add_library(vscpl2drv-tcpipsrv
    src/vscpl2drv-tcpipsrv.cpp
    src/tcpipsrv.cpp
    src/srv.cpp
    src/userlist.h
    src/userlist.cpp
    src/clientlist.h
    src/clientlist.cpp
    ${VSCP_PATH}/src/vscp/common/vscp.h
    ${VSCP_PATH}/src/vscp/common/vscpremotetcpif.h
    ${VSCP_PATH}/src/vscp/common/vscpremotetcpif.cpp
    ${VSCP_PATH}/src/vscp/common/vscpdatetime.h
    ${VSCP_PATH}/src/vscp/common/vscpdatetime.cpp
    ${VSCP_PATH}/src/vscp/common/guid.h
    ${VSCP_PATH}/src/vscp/common/guid.cpp
    ${VSCP_PATH}/src/vscp/common/mdf.h
    ${VSCP_PATH}/src/vscp/common/mdf.cpp
    ${VSCP_PATH}/src/vscp/common/vscphelper.h
    ${VSCP_PATH}/src/vscp/common/vscphelper.cpp
    ${VSCP_PATH}/src/vscp/common/canal.h
    ${VSCP_PATH}/src/vscp/common/canaldlldef.h
    ${VSCP_PATH}/src/vscp/common/vscpcanaldeviceif.h
    ${VSCP_PATH}/src/vscp/common/vscpcanaldeviceif.cpp
    ${VSCP_PATH}/src/common/third_party/mustache.hpp
    ${VSCP_PATH}/src/common/sockettcp.h
    ${VSCP_PATH}/src/common/sockettcp.c
    ${VSCP_PATH}/src/common/vscpbase64.h
    ${VSCP_PATH}/src/common/vscpbase64.c
    ${VSCP_PATH}/src/common/vscp_aes.h
    ${VSCP_PATH}/src/common/vscp_aes.c
    ${VSCP_PATH}/src/common/crc.h
    ${VSCP_PATH}/src/common/crc.c
    ${VSCP_PATH}/src/common/crc8.h
    ${VSCP_PATH}/src/common/crc8.c
    ${VSCP_PATH}/src/common/vscpmd5.h
    ${VSCP_PATH}/src/common/vscpmd5.c
    ${VSCP_PATH}/src/common/fastpbkdf2.h
    ${VSCP_PATH}/src/common/fastpbkdf2.c      
  ) 

if (WIN32)
    include_directories( PUBLIC ./windows 
        ${VSCP_PATH}/src/vscp/common/  
        ${VSCP_PATH}/src/common
        ${VSCP_PATH}/src/common/third_party
        ${VSCP_PATH}/src/common/third_party/nlohmann
        ${PThreads4W_INCLUDE_DIR}
        ${CMAKE_BINARY_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${LOCAL_WIN_INCLUDE}
        ${LOCAL_SYSLOG_INCLUDE} )
else()
    include_directories( PUBLIC ./linux 
        ${VSCP_PATH}/src/vscp/common/
        ${VSCP_PATH}/src/common
        ${VSCP_PATH}/src/common/third_party
        ${VSCP_PATH}/src/common/third_party/nlohmann
        ${CMAKE_BINARY_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${LOCAL_SYSLOG_INCLUDE} )
 endif()   

if (WIN32)
    target_link_libraries(vscpl2drv-tcpipsrv PRIVATE     
        PThreads4W::PThreads4W_CXXEXC
        OpenSSL::SSL 
        OpenSSL::Crypto
        OpenSSL::SSL OpenSSL::Crypto)
    else()
    target_link_libraries(vscpl2drv-tcpipsrv PRIVATE     
        m
        dl
        Threads::Threads
        OpenSSL::SSL 
        OpenSSL::Crypto)
endif()

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEANS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(LIBS_SYSTEM ws2_32)
elseif(UNIX)
    set(LIBS_SYSTEM c stdc++)
endif()

# Install
if(WIN32)
    install(TARGETS vscpl2drv-tcpipsrv
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
else()
    install(TARGETS vscpl2drv-tcpipsrv
            LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_}${VSCP_LEVEL2_DRV_DIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_MANDIR}            
            RESOURCE DESTINATION ${CMAKE_INSTALL_FULL_}/var/lib/vscp/vscpd) 
endif()
