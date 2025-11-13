// vscp2drv_tcpiplink.cpp : Defines the initialization routines for the DLL.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2025 Ake Hedman,
// Ake Hedman, the VSCP Project, <akhe@vscp.org>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#ifdef __GNUG__
// #pragma implementation
#endif

#ifdef WIN32
#include "StdAfx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <string>
#include <dlfcn.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <map>

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>

#include <vscp.h>
#include <vscp-class.h>
#include <vscp-type.h>
#include <guid.h>

#ifdef _WIN32
// Include Windows byteswap compatibility before any VSCP headers
#include "byteswap_compat.h"
#define byteswap_h_included  // Prevent vscphelper.h from including byteswap.h
#endif

#include <vscphelper.h>
#include <level2drvdef.h>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

using namespace std::chrono;

static std::string s_strDriverPath      = "/home/akhe/development/VSCP/vscpl2drv-websocksrv/build/libvscpl2drv-websocksrv.so";
static std::string s_strParameter = "/home/akhe/development/VSCP/vscpl2drv-websocksrv/debug/linux/websocksrv.json";
static cguid s_guid("FF:FF:FF:FF:FF:FF:FF:FE:00:00:00:00:00:00:00:01");

// Demo credentials
static std::string s_username = "admin";
static std::string s_password = "secret";
static std::string s_key    = "2DBB079A38985AF00EBEEFE22F9FFA0E7F72DF06EBE44563EDF4A1073CABC7D44FB0EEC1271C7D75316154F2C6FF80B8627B27D9A5C1C6E88E1CB4E8D7EE4B711F512B5B9E23B7EEB660D133AC3201D6581CB0639A9382171175CB14DC828C98282BED750A8059E5CF864BB55381AA9DA950B9E3CE8285E1EA38D21AFC9A4AE5CA5F375208F72E5B9113EA3F7570415E6EA0A637DB1848B38485B7103EAE8053DA6ABAD02D8820929021EB64503AC6FE6A38F14045A2164412FAC13E9707EB6407B1FB01FA771D07B58D5C3C1D4A584E3EC1AEBC449EC1CBAFC06CEAEDA975F7C936419A90C3F3BCC9F4419E35E08C50DA9280C097D07E7E77D5720EFA46D32F";

// Level II driver methods
LPFNDLL_VSCPOPEN proc_VSCPOpen;
LPFNDLL_VSCPCLOSE proc_VSCPClose;
LPFNDLL_VSCPWRITE proc_VSCPWrite;
LPFNDLL_VSCPREAD proc_VSCPRead;
LPFNDLL_VSCPGETVERSION proc_VSCPGetVersion;

void *hdll; // Handle to DLL  libvscpl2drv-websocksrv.so

int
main(int argc, char *argv[])
{
  void *hdll;       // Handle to libvscpl2drv-websocksrv.so
  long openHandle;  // Driver handle
  vscpEvent evSend; // VSCP send event

  uint32_t counter = 0; // used for event data

  // Define counter event
  memset(&evSend, 0, sizeof(vscpEvent));
  evSend.vscp_class = VSCP_CLASS1_MEASUREMENT;
  evSend.vscp_type  = VSCP_TYPE_MEASUREMENT_COUNT;
  evSend.timestamp  = vscp_makeTimeStamp();
  evSend.sizeData   = 4;
  evSend.pdata      = new uint8_t[3];
  evSend.pdata[0]   = 0x00;
  evSend.pdata[1]   = 0x00;
  evSend.pdata[2]   = 0x00;
  evSend.pdata[3]   = 0x00;

  // -------------------------------------------------------------

  // Now find methods in library
  spdlog::info("Loading level II driver -");

  // Load dynamic library
  hdll = dlopen(s_strDriverPath.c_str(), RTLD_LAZY);
  if (!hdll) {
    spdlog::error("Unable to load dynamic library. path = {}", dlerror());
    exit(-1);
  }

  // * * * * VSCP OPEN * * * *
  if (nullptr == (proc_VSCPOpen = (LPFNDLL_VSCPOPEN) dlsym(hdll, "VSCPOpen"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPOpen.");
    exit(-1);
  }

  // * * * * VSCP CLOSE * * * *
  if (nullptr == (proc_VSCPClose = (LPFNDLL_VSCPCLOSE) dlsym(hdll, "VSCPClose"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPClose.");
    exit(-1);
  }

  // * * * * VSCPWRITE * * * *
  if (nullptr == (proc_VSCPWrite = (LPFNDLL_VSCPWRITE) dlsym(hdll, "VSCPWrite"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPWrite.");
    exit(-1);
  }

  // * * * * VSCPREAD * * * *
  if (nullptr == (proc_VSCPRead = (LPFNDLL_VSCPREAD) dlsym(hdll, "VSCPRead"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPBlockingReceive.");
    exit(-1);
  }

  // * * * * VSCP GET VERSION * * * *
  if (nullptr == (proc_VSCPGetVersion = (LPFNDLL_VSCPGETVERSION) dlsym(hdll, "VSCPGetVersion"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPGetVersion.");
    exit(-1);
  }

  spdlog::debug("Discovered all methods");

  // -------------------------------------------------------------

  // Open up the L2 driver
  openHandle = proc_VSCPOpen(s_strParameter.c_str(), s_guid.getGUID());

  if (0 == openHandle) {
    // Free the library
    spdlog::error("Unable to open VSCP "
                  " level II driver (path, config file access rights)."
                  " There may be additional info from driver "
                  "in log. If not enable debug flag in drivers config file");
    exit(-1);
  }

  // Wait for connection to be established and +;AUTH0;iv
  // int cntTries = 0;
  // while (CANAL_ERROR_SUCCESS != proc_VSCPRead(openHandle, pev, 1000)) {
  //   if (++cntTries > 10) {
  //     spdlog::error("Timeout waiting for AUTH0 from server");
  //     exit(-1);
  //   }
  // }

  while (true) {

    vscpEvent ev;
    memset(&ev, 0, sizeof(vscpEvent));

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    Sleep(1000);
#else     
    sleep(1);
#endif

    // Block until event is received
    if (CANAL_ERROR_SUCCESS != proc_VSCPRead(openHandle, &ev, 1000)) {
      // Send event
      proc_VSCPWrite(openHandle, &evSend, 500);
      counter++;
      evSend.pdata[0] = (counter >> 24) & 0xff;
      evSend.pdata[1] = (counter >> 16) & 0xff;
      evSend.pdata[2] = (counter >> 8) & 0xff;
      evSend.pdata[3] = counter & 0xff;
      continue;
    }

    // If timestamp is zero we set it here
    if (0 == ev.timestamp) {
      ev.timestamp = vscp_makeTimeStamp();
    }

    // We have an event - just show something on console
    spdlog::info("Received event: Class: {}, Type: {}, Timestamp: {}, SizeData: {}",
                 ev.vscp_class,
                 ev.vscp_type,
                 ev.timestamp,
                 ev.sizeData);

  } // while

  // Close channel
  proc_VSCPClose(openHandle);

  // Unload dll
  dlclose(hdll);

  // Cleanup
  vscp_deleteEvent(&evSend);
}