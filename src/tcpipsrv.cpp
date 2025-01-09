// tcpipsrv.cpp: implementation of the CTcpipSrv class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2025 Ake Hedman,
// the VSCP Project, <akhe@vscp.org>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#else
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

#include <sys/types.h>

#ifdef WIN32
#else
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include <ctype.h>
#include <sys/types.h>
#include <time.h>

#include <expat.h>

#include "tcpipsrv.h"
#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp-class.h>
#include <vscp-type.h>
#include <vscp.h>
#include <vscpdatetime.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <string>

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

// Forward declaration
void*
tcpipListenThread(void* pData);

//////////////////////////////////////////////////////////////////////
// CTcpipSrv
//

CTcpipSrv::CTcpipSrv()
{
  m_bQuit = false;

  vscp_clearVSCPFilter(&m_rxfilter); // Accept all events
  vscp_clearVSCPFilter(&m_txfilter); // Send all events

  m_responseTimeout = TCPIP_DEFAULT_INNER_RESPONSE_TIMEOUT;

  sem_init(&m_semSendQueue, 0, 0);
  sem_init(&m_semReceiveQueue, 0, 0);

  pthread_mutex_init(&m_mutexSendQueue, NULL);
  pthread_mutex_init(&m_mutexReceiveQueue, NULL);

  pthread_mutex_init(&m_mutex_UserList, NULL);

  // Init pool
  spdlog::init_thread_pool(8192, 1);

  // Flush log every five seconds
  spdlog::flush_every(std::chrono::seconds(5));

  auto console = spdlog::stdout_color_mt("console");
  // Start out with level=info. Config may change this
  console->set_level(spdlog::level::debug);
  console->set_pattern("[vscpl2drv-tcpipsrv: %c] [%^%l%$] %v");
  spdlog::set_default_logger(console);

  console->debug("Starting the vscpl2drv-tcpipsrv...");

  // Setting up logging defaults
  m_bConsoleLogEnable = true;
  m_consoleLogLevel   = spdlog::level::info;
  m_consoleLogPattern = "[vscpl2drv-tcpipsrv %c] [%^%l%$] %v";

  m_bEnableFileLog   = true;
  m_fileLogLevel     = spdlog::level::info;
  m_fileLogPattern   = "[vscpl2drv-tcpipsrv %c] [%^%l%$] %v";
  m_path_to_log_file = "/var/log/vscp/vscpl2drv-tcpipsrv.log";
  m_max_log_size     = 5242880;
  m_max_log_files    = 7;

  m_bReceiveOwnEvents = true; // Receive our own events
}

//////////////////////////////////////////////////////////////////////
// ~CTcpipSrv
//

CTcpipSrv::~CTcpipSrv()
{
  close();

  sem_destroy(&m_semSendQueue);
  sem_destroy(&m_semReceiveQueue);

  pthread_mutex_destroy(&m_mutexSendQueue);
  pthread_mutex_destroy(&m_mutexReceiveQueue);

  pthread_mutex_destroy(&m_mutex_UserList);
}

//////////////////////////////////////////////////////////////////////
// open
//

bool
CTcpipSrv::open(std::string& path, const uint8_t* pguid)
{
  if (NULL == pguid) {
    return false;
  }

  // Set GUID
  m_guid.getFromArray(pguid);

  // Save path to config file
  m_path = path;

  // Init pool
  // spdlog::init_thread_pool(8192, 1);

  // // Flush log every five seconds
  // spdlog::flush_every(std::chrono::seconds(5));

  // auto console = spdlog::stdout_color_mt("console");
  // // Start out with level=info. Config may change this
  // console->set_level(spdlog::level::info);
  // console->set_pattern("[vscp] [%^%l%$] %v");
  // spdlog::set_default_logger(console);

  // Read configuration file
  if (!doLoadConfig(path)) {
    spdlog::error("Failed to load configuration file [{}]", path.c_str());
    spdlog::drop_all();
    return false;
  }

  // // Set up logger
  // if (m_path_to_log_file.length()) {
  //   auto rotating_file_sink =
  //     std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
  //       m_path_to_log_file.c_str(),
  //       m_max_log_size,
  //       m_max_log_files);
  //   if (m_bEnableFileLog) {
  //     rotating_file_sink->set_level(m_fileLogLevel);
  //     rotating_file_sink->set_pattern(m_fileLogPattern);
  //   }
  //   else {
  //     // If disabled set to off
  //     rotating_file_sink->set_level(spdlog::level::off);
  //   }

  //   std::vector<spdlog::sink_ptr> sinks{ rotating_file_sink };
  //   auto logger = std::make_shared<spdlog::async_logger>(
  //     "logger",
  //     sinks.begin(),
  //     sinks.end(),
  //     spdlog::thread_pool(),
  //     spdlog::async_overflow_policy::block);
  //   // The separate sub loggers will handle trace levels
  //   logger->set_level(spdlog::level::trace);
  //   spdlog::register_logger(logger);
  //   spdlog::set_default_logger(logger);
  // }

  spdlog::debug("---> Open");

  if (!startTcpipSrvThread()) {
    spdlog::critical("Failed to start server.");
    spdlog::drop_all();
    return false;
  }

  spdlog::debug("Open <---");

  return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CTcpipSrv::close(void)
{
  // Do nothing if already terminated
  if (m_bQuit) {
    spdlog::drop_all();
    return;
  }

  m_bQuit = true; // terminate the thread
#ifndef WIN32
  sleep(1); // Give the thread some time to terminate
#else
  Sleep(1000);
#endif

  spdlog::drop_all();
  spdlog::shutdown();
}

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
CTcpipSrv::doLoadConfig(std::string& path)
{
  try {
    std::ifstream in(m_path, std::ifstream::in);
    in >> m_j_config;
  }
  catch (json::parse_error) {
    spdlog::critical("Failed to load/parse JSON configuration.");
    return false;
  }

  // write
  if (m_j_config.contains("write")) {
    try {
      m_bWriteEnable = m_j_config["write"].get<bool>();
    }
    catch (const std::exception& ex) {
      spdlog::error("Failed to read 'write' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'write' due to unknown error.");
    }
  }
  else {
    spdlog::error(
      "ReadConfig: Failed to read LOGGING 'write' Defaults will be used.");
  }

  // VSCP key file
  if (m_j_config.contains("key-file") && m_j_config["key-file"].is_string()) {
    if (!readEncryptionKey(m_j_config["key-file"].get<std::string>())) {
      spdlog::warn("WARNING!!! Default key will be used.");
    }
  }
  else {
    spdlog::warn("WARNING!!! Default key will be used.");
  }

  // Receive own events
  if (m_j_config.contains("receive-sent-events") &&
      m_j_config["receive-sent-events"].is_boolean()) {
    m_bReceiveOwnEvents = m_j_config["receive-sent-events"].get<bool>();
    if (m_bReceiveOwnEvents) {
      spdlog::info("Our sent event will be received.");
    }
    else {
      spdlog::info("Our sent events will be masked.");
    }
  }
  else {
    spdlog::info("Our sent event will be received.");
  }

  // Logging
  if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

    json j = m_j_config["logging"];

    // Logging: file-log-level
    if (j.contains("file-log-level")) {
      std::string str;
      try {
        str = j["file-log-level"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error(
          "[vscpl2drv-tcpipsrv]Failed to read 'file-log-level' Error='{}'",
          ex.what());
      }
      catch (...) {
        spdlog::error("[vscpl2drv-tcpipsrv]Failed to read 'file-log-level' due "
                      "to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_fileLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_fileLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_fileLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_fileLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_fileLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_fileLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_fileLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("ReadConfig: LOGGING 'file-log-level' has invalid value "
                      "[{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-log-level' "
                    "Defaults will be used.");
    }

    // Logging: file-pattern
    if (j.contains("file-pattern")) {
      try {
        m_fileLogPattern = j["file-pattern"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig:Failed to read 'file-pattern' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'file-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read LOGGING 'file-pattern' "
                    "Defaults will be used.");
    }

    // Logging: file-path
    if (j.contains("file-path")) {
      try {
        m_path_to_log_file = j["file-path"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'file-path' due to unknown error.");
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-path' Defaults "
                    "will be used.");
    }

    // Logging: file-max-size
    if (j.contains("file-max-size")) {
      try {
        m_max_log_size = j["file-max-size"].get<uint32_t>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig:Failed to read 'file-max-size' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'file-max-size' due to unknown error.");
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-max-size' "
                    "Defaults will be used.");
    }

    // Logging: file-max-files
    if (j.contains("file-max-files")) {
      try {
        m_max_log_files = j["file-max-files"].get<uint16_t>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig:Failed to read 'file-max-files' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'file-max-files' due to unknown error.");
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-max-files' "
                    "Defaults will be used.");
    }

  } // Logging
  else {
    spdlog::error("ReadConfig: No logging has been setup.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          Setup logger
  ///////////////////////////////////////////////////////////////////////////

  // Console log
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  if (m_bConsoleLogEnable) {
    console_sink->set_level(m_consoleLogLevel);
    console_sink->set_pattern(m_consoleLogPattern);
  }
  else {
    // If disabled set to off
    console_sink->set_level(spdlog::level::off);
  }

  // auto rotating =
  // std::make_shared<spdlog::sinks::rotating_file_sink_mt>("log_filename",
  // 1024*1024, 5, false);
  auto rotating_file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
      m_path_to_log_file.c_str(),
      m_max_log_size,
      m_max_log_files);

  if (m_bEnableFileLog) {
    rotating_file_sink->set_level(m_fileLogLevel);
    rotating_file_sink->set_pattern(m_fileLogPattern);
  }
  else {
    // If disabled set to off
    rotating_file_sink->set_level(spdlog::level::off);
  }

  std::vector<spdlog::sink_ptr> sinks{ console_sink, rotating_file_sink };
  auto logger = std::make_shared<spdlog::async_logger>(
    "logger",
    sinks.begin(),
    sinks.end(),
    spdlog::thread_pool(),
    spdlog::async_overflow_policy::block);
  // The separate sub loggers will handle trace levels
  logger->set_level(spdlog::level::trace);
  spdlog::register_logger(logger);

  // ------------------------------------------------------------------------

  // interface
  if (m_j_config.contains("interface")) {
    try {
      m_interface = m_j_config["interface"].get<std::string>();
    }
    catch (const std::exception& ex) {
      spdlog::error("ReadConfig: Failed to read 'interface' Error='{}'",
                    ex.what());
    }
    catch (...) {
      spdlog::error(
        "ReadConfig: Failed to read 'interface' due to unknown error.");
    }
  }
  else {
    spdlog::warn(
      "ReadConfig: Failed to read 'interface' Defaults will be used.");
  }

  // Path to user database
  if (m_j_config.contains("path-users")) {
    try {
      m_pathUsers = m_j_config["path-users"].get<std::string>();
      if (!m_userList.loadUsersFromFile(m_pathUsers)) {
        spdlog::critical("ReadConfig: Failed to load users from file "
                         "'user-path'='{}'. Terminating!",
                         path);
        return false;
      }
    }
    catch (const std::exception& ex) {
      spdlog::error("ReadConfig: Failed to read 'path-users' Error='{}'",
                    ex.what());
    }
    catch (...) {
      spdlog::error(
        "ReadConfig: Failed to read 'path-users' due to unknown error.");
    }
  }
  else {
    spdlog::warn(
      "ReadConfig: Failed to read 'path-users' Defaults will be used.");
  }

  // Response timeout m_responseTimeout
  if (m_j_config.contains("response-timeout")) {
    try {
      m_responseTimeout = m_j_config["response-timeout"].get<uint32_t>();
    }
    catch (const std::exception& ex) {
      spdlog::error("ReadConfig: Failed to read 'response-timeout' Error='{}'",
                    ex.what());
    }
    catch (...) {
      spdlog::error(
        "ReadConfig: Failed to read 'response-timeout' due to unknown error.");
    }
  }
  else {
    spdlog::warn(
      "ReadConfig: Failed to read 'response-timeout' Defaults will be used.");
  }

  // Filter
  if (m_j_config.contains("filter") && m_j_config["filter"].is_object()) {

    json j = m_j_config["filter"];

    // IN filter
    if (j.contains("in-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'in-filter' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'in-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'in-filter' Defaults "
                    "will be used.");
    }

    // IN mask
    if (j.contains("in-mask")) {
      try {
        std::string str = j["in-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'in-mask' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'in-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'in-mask' Defaults will be used.");
    }

    // OUT filter
    if (j.contains("out-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'out-filter' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'out-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'out-filter' Defaults will be used.");
    }

    // OUT mask
    if (j.contains("out-mask")) {
      try {
        std::string str = j["out-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'out-mask' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'out-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'out-mask' Defaults will be used.");
    }
  }

  // TLS / SSL
  if (m_j_config.contains("tls") && m_j_config["tls"].is_object()) {

    json j = m_j_config["tls"];

    // Certificate
    if (j.contains("certificate")) {
      try {
        m_tls_certificate = j["certificate"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'certificate' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'certificate' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'certificate' Defaults will be used.");
    }

    // certificate chain
    if (j.contains("certificate_chain")) {
      try {
        m_tls_certificate_chain = j["certificate_chain"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error(
          "ReadConfig: Failed to read 'certificate_chain' Error='{}'",
          ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'certificate_chain' due to "
                      "unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'certificate_chain' Defaults "
                    "will be used.");
    }

    // verify peer
    if (j.contains("verify-peer")) {
      try {
        m_tls_verify_peer = j["verify-peer"].get<bool>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'verify-peer' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'verify-peer' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'verify-peer' Defaults will be used.");
    }

    // CA Path
    if (j.contains("ca-path")) {
      try {
        m_tls_ca_file = j["ca-path"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'ca-path' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'ca-path' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: ReadConfig: Failed to read 'ca-path' Defaults "
                    "will be used.");
    }

    // CA File
    if (j.contains("ca-file")) {
      try {
        m_tls_ca_file = j["ca-file"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'ca-file' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'ca-file' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: ReadConfig: Failed to read 'ca-file' Defaults "
                    "will be used.");
    }

    // Verify depth
    if (j.contains("verify_depth")) {
      try {
        m_tls_verify_depth = j["verify_depth"].get<uint16_t>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig: Failed to read 'verify_depth' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig: Failed to read 'verify_depth' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'verify_depth' Defaults will be used.");
    }

    // Default verify paths
    if (j.contains("default-verify-paths")) {
      try {
        m_tls_default_verify_paths = j["default-verify-paths"].get<bool>();
      }
      catch (const std::exception& ex) {
        spdlog::error(
          "ReadConfig:Failed to read 'default-verify-paths' Error='{}'",
          ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'default-verify-paths' due to "
                      "unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'default-verify-paths' "
                    "Defaults will be used.");
    }

    // Chiper list
    if (j.contains("cipher-list")) {
      try {
        m_tls_cipher_list = j["cipher-list"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig:Failed to read 'cipher-list' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'cipher-list' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'cipher-list' Defaults will be used.");
    }

    // Protocol version
    if (j.contains("protocol-version")) {
      try {
        m_tls_protocol_version = j["protocol-version"].get<uint16_t>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig:Failed to read 'protocol-version' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'protocol-version' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'protocol-version' Defaults will be used.");
    }

    // Short trust
    if (j.contains("short-trust")) {
      try {
        m_tls_short_trust = j["short-trust"].get<bool>();
      }
      catch (const std::exception& ex) {
        spdlog::error("ReadConfig:Failed to read 'short-trust' Error='{}'",
                      ex.what());
      }
      catch (...) {
        spdlog::error(
          "ReadConfig:Failed to read 'short-trust' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "ReadConfig: Failed to read 'short-trust' Defaults will be used.");
    }
  }

  // vscpEvent ev;
  // ev.vscp_class = VSCP_CLASS2_HLO;
  // ev.vscp_type = VSCP2_TYPE_HLO_COMMAND;

  // std::string jj = "{\"op\" : 1, \"name\": \"\"}";
  // json j;
  // j["op"] = "noop";
  // j["arg"]["currency"] = "USD";
  // j["arg"]["value"] = 42.99;
  // j["arr"] = json::array();
  // j["arr"][0]["ettan"] = 1;
  // j["arr"][0]["tvan"] = 2;
  // j["arr"][1]["ettan"] = 1;
  // j["arr"][1]["tvan"] = 2;
  // j["arr"][2]["ettan"] = 1;
  // j["arr"][2]["tvan"] = 2;
  // printf("%s\n",j.dump().c_str());

  // json aa;
  // aa["ettan"] = 55;
  // aa["tva"] = 66;
  // j["arr"][1] = aa;
  // j["arr"][3] = aa;
  // printf("%s\n",j.dump().c_str());
  // j["arr"].erase(1);

  // printf("%s\n",j.dump().c_str());

  // ev.pdata = new uint8_t[200];

  // memset(ev.pdata, 0, sizeof(ev.pdata));
  // for ( int i=0; i<16; i++) {
  //     ev.pdata[i] = 11 * i;
  // }
  // ev.pdata[16] = 0x20;  // JSON, no encryption
  // memcpy(ev.pdata+17, j.dump().c_str(), j.dump().length());
  // ev.sizeData = 16 + 1 + (uint16_t)j.dump().length();

  // handleHLO(&ev);

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CTcpipSrv::doSaveConfig(void)
{
  if (m_j_config.value("write", false)) {
  }
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CTcpipSrv::handleHLO(vscpEvent* pEvent)
{
  vscpEventEx ex;

  // Check pointers
  if (NULL == pEvent || (NULL == pEvent->pdata)) {
    spdlog::error("HLO handler: NULL event pointer.");
    return false;
  }

  // > 18  pos 0-15 = GUID, 16 type >> 4, encryption & 0x0f
  // JSON if type = 2
  // JSON from 17 onwards

  // CHLO hlo;
  // if (!hlo.parseHLO(j, pEvent )) {
  spdlog::error("Failed to parse HLO.");
  //     return false;
  // }

  // Must be HLO command event
  if ((pEvent->vscp_class != VSCP_CLASS2_HLO) &&
      (pEvent->vscp_type != VSCP2_TYPE_HLO_COMMAND)) {
    return false;
  }

  // Get GUID / encryption / type
  cguid hlo_guid(pEvent->pdata);
  uint8_t hlo_encryption = pEvent->pdata[16] & 0x0f;
  uint8_t hlo_type       = (pEvent->pdata[16] >> 4) & 0x0f;

  char buf[512];
  memset(buf, 0, sizeof(buf));
  memcpy(buf, (pEvent->pdata + 17), pEvent->sizeData);
  auto j = json::parse(buf);
  printf("%s\n", j.dump().c_str());

  if (m_j_config["users"].is_array()) {
    printf("Yes it's an array %zu - %s\n",
           m_j_config["users"].size(),
           m_j_config["users"][0]["name"].get<std::string>().c_str());
  }

  // Must be an operation
  if (!j["op"].is_string() || j["op"].is_null()) {
    spdlog::error("HLO-command: Missing op [%s]", j.dump().c_str());
    return false;
  }

  if (j["arg"].is_object() && !j["arg"].is_null()) {
    printf("Argument is object\n");
  }

  if (j["arg"].is_string() && !j["arg"].is_null()) {
    printf("Argument is string\n");
  }

  if (j["arg"].is_number() && !j["arg"].is_null()) {
    printf("Argument is number\n");
  }

  // Make HLO response event
  ex.obid      = 0;
  ex.head      = 0;
  ex.timestamp = vscp_makeTimeStamp();
  vscp_setEventExToNow(&ex); // Set time to current time
  ex.vscp_class = VSCP_CLASS2_PROTOCOL;
  ex.vscp_type  = VSCP2_TYPE_HLO_RESPONSE;
  m_guid.writeGUID(ex.GUID);

  json j_response;

  if (j.value("op", "") == "noop") {
    // Send positive response
    j_response["op"]          = "vscp-reply";
    j_response["name"]        = "noop";
    j_response["result"]      = "OK";
    j_response["description"] = "NOOP commaned executed correctly.";

    memset(ex.data, 0, sizeof(ex.data));
    ex.sizeData = (uint16_t)strlen(buf);
    memcpy(ex.data, buf, ex.sizeData);
  }
  else if (j.value("op", "") == "readvar") {
    readVariable(ex, j);
  }
  else if (j.value("op", "") == "writevar") {
    writeVariable(ex, j);
  }
  else if (j.value("op", "") == "delvar") {
    deleteVariable(ex, j);
  }
  else if (j.value("op", "") == "load") {
    std::string path = "";
    doLoadConfig(path);
  }
  else if (j.value("op", "") == "save") {
    doSaveConfig();
  }
  else if (j.value("op", "") == "stop") {
    stop();
  }
  else if (j.value("op", "") == "start") {
    start();
  }
  else if (j.value("op", "") == "restart") {
    restart();
  }

  // Put event in receive queue
  return eventExToReceiveQueue(ex);
}

///////////////////////////////////////////////////////////////////////////////
// readVariable
//

bool
CTcpipSrv::readVariable(vscpEventEx& ex, const json& json_req)
{
  json j;

  j["op"]          = "readvar";
  j["result"]      = VSCP_ERROR_SUCCESS;
  j["arg"]["name"] = j.value("name", "");

  if ("debug" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
    j["arg"]["value"] = m_j_config.value("debug", false);
  }
  else if ("write" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
    j["arg"]["value"] = m_j_config.value("write", false);
  }
  else if ("interface" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("interface", ""));
  }
  else if ("vscp-key-file" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("vscp-key-file", ""));
  }
  else if ("max-out-queue" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("max-out-queue", 0);
  }
  else if ("max-in-queue" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("max-in-queue", 0);
  }
  else if ("encryption" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("encryption", ""));
  }
  else if ("ssl-certificate" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-certificate", ""));
  }
  else if ("ssl-certificate-chain" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-certificate-chain", ""));
  }
  else if ("ssl-ca-path" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-ca-path", ""));
  }
  else if ("ssl-ca-file" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-ca-file", ""));
  }
  else if ("ssl-verify-depth" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("ssl-verify-depth", 9);
  }
  else if ("ssl-default-verify-paths" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-default-verify-paths", ""));
  }
  else if ("ssl-cipher-list" == j.value("name", "")) {
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-cipher-list", ""));
  }
  else if ("ssl-protocol-version" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("ssl-protocol-version", 3);
  }
  else if ("ssl-short-trust" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
    j["arg"]["value"] = m_j_config.value("ssl-short-trust", false);
  }
  else if ("user-count" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = 9;
  }
  // else if ("users" == j.value("name", "")) {

  //   if (!m_j_config["users"].is_array()) {
  //     spdlog::warn("'users' must be of type array.");
  //     j["result"] = VSCP_ERROR_SUCCESS;
  //     goto abort;
  //   }

  //   int index = j.value("index", 0); // get index
  //   if (index >= m_j_config["users"].size()) {
  //     // Index to large
  //     spdlog::warn("index of array is to large [%u].",
  //                                 index >= m_j_config["users"].size());
  //     j["result"] = VSCP_ERROR_INDEX_OOB;
  //     goto abort;
  //   }

  //   j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_JSON;
  //   j["arg"]["value"] = m_j_config["users"][index].dump();
  // }
  else {
    j["result"] = VSCP_ERROR_MISSING;
    spdlog::error("Variable [] is unknown.");
  }

abort:

  memset(ex.data, 0, sizeof(ex.data));
  ex.sizeData = (uint16_t)j.dump().length();
  memcpy(ex.data, j.dump().c_str(), ex.sizeData);

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// writeVariable
//

bool
CTcpipSrv::writeVariable(vscpEventEx& ex, const json& json_req)
{
  json j;

  j["op"]          = "writevar";
  j["result"]      = VSCP_ERROR_SUCCESS;
  j["arg"]["name"] = j.value("name", "");

  if ("debug" == j.value("name", "")) {

    // arg should be boolean
    if (!j["arg"].is_boolean() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }

    // set new value
    m_j_config["debug"] = j["arg"].get<bool>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
    j["arg"]["value"] = m_j_config.value("debug", false);
  }
  else if ("write" == j.value("name", "")) {

    // arg should be boolean
    if (!j["arg"].is_boolean() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["write"] = j["arg"].get<bool>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
    j["arg"]["value"] = m_j_config.value("write", false);
  }
  else if ("interface" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["interface"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] = vscp_convertToBase64(m_j_config["interface"]);
  }
  else if ("vscp-key-file" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["vscp-key-file"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("vscp-key-file", ""));
  }
  else if ("max-out-queue" == j.value("name", "")) {

    // arg should be number
    if (!j["arg"].is_number() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["max-out-queue"] = j["arg"].get<int>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("max-out-queue", 0);
  }
  else if ("max-in-queue" == j.value("name", "")) {

    // arg should be number
    if (!j["arg"].is_number() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["max-in-queue"] = j["arg"].get<int>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("max-in-queue", 0);
  }
  else if ("encryption" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["encryption"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("encryption", ""));
  }
  else if ("ssl-certificate" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-certificate"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-certificate", ""));
  }
  else if ("ssl-certificate-chain" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-certificate-chain"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-certificate-chain", ""));
  }
  else if ("ssl-ca-path" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-ca-path"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-ca-path", ""));
  }
  else if ("ssl-ca-file" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-ca-file"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-ca-file", ""));
  }
  else if ("ssl-verify-depth" == j.value("name", "")) {
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("ssl-verify-depth", 9);
  }
  else if ("ssl-default-verify-paths" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-default-verify-paths"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-default-verify-paths", ""));
  }
  else if ("ssl-cipher-list" == j.value("name", "")) {

    // arg should be string
    if (!j["arg"].is_string() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-cipher-list"] = j["arg"].get<std::string>();

    // report back
    j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
    j["arg"]["value"] =
      vscp_convertToBase64(m_j_config.value("ssl-cipher-list", ""));
  }
  else if ("ssl-protocol-version" == j.value("name", "")) {

    // arg should be number
    if (!j["arg"].is_number() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-protocol-version"] = j["arg"].get<bool>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
    j["arg"]["value"] = m_j_config.value("ssl-protocol-version", 3);
  }
  else if ("ssl-short-trust" == j.value("name", "")) {

    // arg should be boolean
    if (!j["arg"].is_boolean() || j["arg"].is_null()) {
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }
    // set new value
    m_j_config["ssl-short-trust"] = j["arg"].get<bool>();

    // report back
    j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
    j["arg"]["value"] = m_j_config.value("ssl-short-trust", false);
  }
  // else if ("users" == j.value("name", "")) {

  //   // users must be array
  //   if (!m_j_config["users"].is_array()) {
  //     spdlog::warn("'users' must be of type array.");
  //     j["result"] = VSCP_ERROR_INVALID_TYPE;
  //     goto abort;
  //   }

  //   // Must be object
  //   if (!m_j_config["args"].is_object()) {
  //     spdlog::warn("The user info must be an object.");
  //     j["result"] = VSCP_ERROR_INVALID_TYPE;
  //     goto abort;
  //   }

  //   int index = j.value("index", 0); // get index
  //   if (index >= m_j_config["users"].size()) {
  //     // Index to large
  //     spdlog::warn("index of array is to large [%u].",
  //                                 index >= m_j_config["users"].size());
  //     j["result"] = VSCP_ERROR_INDEX_OOB;
  //     goto abort;
  //   }

  //   m_j_config["users"][index] = j["args"];

  //   j["arg"]["type"]  = VSCP_REMOTE_VARIABLE_CODE_JSON;
  //   j["arg"]["value"] = m_j_config["users"][index].dump();
  // }
  else {
    j["result"] = VSCP_ERROR_MISSING;
    spdlog::error("Variable [] is unknown.");
  }

abort:

  memset(ex.data, 0, sizeof(ex.data));
  ex.sizeData = (uint16_t)j.dump().length();
  memcpy(ex.data, j.dump().c_str(), ex.sizeData);

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// deleteVariable
//

bool
CTcpipSrv::deleteVariable(vscpEventEx& ex, const json& json_reg)
{
  json j;

  j["op"]          = "deletevar";
  j["result"]      = VSCP_ERROR_SUCCESS;
  j["arg"]["name"] = j.value("name", "");

  if ("users" == j.value("name", "")) {

    // users must be array
    if (!m_j_config["users"].is_array()) {
      spdlog::warn("'users' must be of type array.");
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }

    // Must be object
    if (!m_j_config["args"].is_object()) {
      spdlog::warn("The user info must be an object.");
      j["result"] = VSCP_ERROR_INVALID_TYPE;
      goto abort;
    }

    int index = j.value("index", 0); // get index
    if (index >= m_j_config["users"].size()) {
      // Index to large
      spdlog::warn("index of array is to large [%u].",
                   index >= m_j_config["users"].size());
      j["result"] = VSCP_ERROR_INDEX_OOB;
      goto abort;
    }

    m_j_config["users"].erase(index);
  }
  else {
    j["result"] = VSCP_ERROR_MISSING;
    spdlog::warn("Variable [%s] is unknown.", j.value("name", "").c_str());
  }

abort:

  memset(ex.data, 0, sizeof(ex.data));
  ex.sizeData = (uint16_t)j.dump().length();
  memcpy(ex.data, j.dump().c_str(), ex.sizeData);

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// stop
//

bool
CTcpipSrv::stop(void)
{
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// start
//

bool
CTcpipSrv::start(void)
{
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// restart
//

bool
CTcpipSrv::restart(void)
{
  if (!stop()) {
    spdlog::warn("Failed to stop VSCP tcp/ip server.");
  }

  if (!start()) {
    spdlog::warn("Failed to start VSCP tcp/ip server.");
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CTcpipSrv::eventExToReceiveQueue(vscpEventEx& ex)
{
  vscpEvent* pev = new vscpEvent();
  if (!vscp_convertEventExToEvent(pev, &ex)) {
    spdlog::error("Failed to convert event from ex to ev.");
    vscp_deleteEvent(pev);
    return false;
  }

  if (NULL != pev) {
    if (vscp_doLevel2Filter(pev, &m_rxfilter)) {
      pthread_mutex_lock(&m_mutexReceiveQueue);
      m_receiveList.push_back(pev);
      pthread_mutex_unlock(&m_mutexReceiveQueue);
      sem_post(&m_semReceiveQueue);
    }
    else {
      vscp_deleteEvent(pev);
    }
  }
  else {
    spdlog::error("Unable to allocate event storage.");
  }
  return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//
//

bool
CTcpipSrv::addEvent2SendQueue(const vscpEvent* pEvent)
{
  pthread_mutex_lock(&m_mutexSendQueue);
  m_sendList.push_back((vscpEvent*)pEvent);
  sem_post(&m_semSendQueue);
  pthread_mutex_unlock(&m_mutexSendQueue);
  return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//
//  Send event to host
//

bool
CTcpipSrv::addEvent2ReceiveQueue(const vscpEvent* pEvent)
{
  pthread_mutex_lock(&m_mutexReceiveQueue);
  m_receiveList.push_back((vscpEvent*)pEvent);
  pthread_mutex_unlock(&m_mutexReceiveQueue);
  sem_post(&m_semReceiveQueue);
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventToClient
//

bool
CTcpipSrv::sendEventToClient(CClientItem* pClientItem, const vscpEvent* pEvent)
{
  // Must be valid pointers
  if (NULL == pClientItem) {
    spdlog::error("sendEventToClient - Pointer to clientitem is null");
    return false;
  }
  if (NULL == pEvent) {
    spdlog::error("sendEventToClient - Pointer to event is null");
    return false;
  }

  // Check if filtered out - if so do nothing here
  if (!vscp_doLevel2Filter(pEvent, &pClientItem->m_filter)) {
    if (m_j_config.contains("debug") && m_j_config["debug"].get<bool>()) {
      spdlog::debug("sendEventToClient - Filtered out");
    }
    return false;
  }

  // If the client queue is full for this client then the
  // client will not receive the message
  if (pClientItem->m_clientInputQueue.size() >
      m_j_config.value("max-out-queue", MAX_ITEMS_IN_QUEUE)) {
    if (m_j_config.contains("debug") && m_j_config["debug"].get<bool>()) {
      spdlog::debug("sendEventToClient - overrun");
    }
    // Overrun
    pClientItem->m_statistics.cntOverruns++;
    return false;
  }

  // Create a new event
  vscpEvent* pnewvscpEvent = new vscpEvent;
  if (NULL != pnewvscpEvent) {

    // Copy in the new event
    if (!vscp_copyEvent(pnewvscpEvent, pEvent)) {
      vscp_deleteEvent_v2(&pnewvscpEvent);
      return false;
    }

    // Add the new event to the input queue
    pthread_mutex_lock(&pClientItem->m_mutexClientInputQueue);
    pClientItem->m_clientInputQueue.push_back(pnewvscpEvent);
    pthread_mutex_unlock(&pClientItem->m_mutexClientInputQueue);
    sem_post(&pClientItem->m_semClientInputQueue);
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

bool
CTcpipSrv::sendEventAllClients(const vscpEvent* pEvent)
{
  CClientItem* pClientItem;
  std::deque<CClientItem*>::iterator it;

  if (NULL == pEvent) {
    spdlog::error("sendEventAllClients - No event to send");
    return false;
  }

  pthread_mutex_lock(&m_clientList.m_mutexItemList);
  for (it = m_clientList.m_itemList.begin();
       it != m_clientList.m_itemList.end();
       ++it) {
    pClientItem = *it;

    if (NULL != pClientItem) {
      if (m_j_config.contains("debug") && m_j_config["debug"].get<bool>()) {
        spdlog::debug("Send event to client [%s]",
                      pClientItem->m_strDeviceName.c_str());
      }
      if (!sendEventToClient(pClientItem, pEvent)) {
        spdlog::error("sendEventAllClients - Failed to send event");
      }
    }
  }

  pthread_mutex_unlock(&m_clientList.m_mutexItemList);

  return true;
}

/////////////////////////////////////////////////////////////////////////////
// startTcpWorkerThread
//

bool
CTcpipSrv::startTcpipSrvThread(void)
{
  if (__VSCP_DEBUG_TCP) {
    spdlog::debug("Controlobject: Starting TCP/IP interface...");
  }

  // Create the tcp/ip server data object
  m_ptcpipSrvObject = (tcpipListenThreadObj*)new tcpipListenThreadObj(this);
  if (NULL == m_ptcpipSrvObject) {
    spdlog::error("Controlobject: Failed to allocate storage for tcp/ip.");
  }

  // Set the port to listen for connections on
  m_ptcpipSrvObject->setListeningPort(
    m_j_config["interface"].get<std::string>());

  if (pthread_create(&m_tcpipListenThread,
                     NULL,
                     tcpipListenThread,
                     m_ptcpipSrvObject)) {
    delete m_ptcpipSrvObject;
    m_ptcpipSrvObject = NULL;
    spdlog::error("Controlobject: Unable to start the tcp/ip listen thread.");
    return false;
  }

  return true;
}

/////////////////////////////////////////////////////////////////////////////
// stopTcpWorkerThread
//

bool
CTcpipSrv::stopTcpipSrvThread(void)
{
  // Tell the thread it's time to quit
  m_ptcpipSrvObject->m_nStopTcpIpSrv = VSCP_TCPIP_SRV_STOP;

  if (__VSCP_DEBUG_TCP) {
    spdlog::debug("Controlobject: Terminating TCP thread.");
  }

  pthread_join(m_tcpipListenThread, NULL);
  delete m_ptcpipSrvObject;
  m_ptcpipSrvObject = NULL;

  if (__VSCP_DEBUG_TCP) {
    spdlog::debug("Controlobject: Terminated TCP thread.");
  }

  return true;
}

//////////////////////////////////////////////////////////////////////////////
// addClient
//

bool
CTcpipSrv::addClient(CClientItem* pClientItem, uint32_t id)
{
  // Check pointer
  if (NULL == pClientItem) {
    return false;
  }

  // Add client to client list
  if (!m_clientList.addClient(pClientItem, id)) {
    return false;
  }

  // Set GUID for interface
  pClientItem->m_guid = m_guid;

  // Fill in client id
  pClientItem->m_guid.setNicknameID(0);
  pClientItem->m_guid.setClientID(pClientItem->m_clientID);

  return true;
}

//////////////////////////////////////////////////////////////////////////////
// addClient - GUID (for drivers with set GUID)
//

bool
CTcpipSrv::addClient(CClientItem* pClientItem, cguid& guid)
{
  // Check pointer
  if (NULL == pClientItem) {
    return false;
  }

  // Add client to client list
  if (!m_clientList.addClient(pClientItem, guid)) {
    return false;
  }

  return true;
}

//////////////////////////////////////////////////////////////////////////////
// removeClient
//

void
CTcpipSrv::removeClient(CClientItem* pClientItem)
{
  // Do not try to handle invalid clients
  if (NULL == pClientItem)
    return;

  // Remove the client
  m_clientList.removeClient(pClientItem);
}

/////////////////////////////////////////////////////////////////////////////
// generateSessionId
//

bool
CTcpipSrv::generateSessionId(const char* pKey, char* psid)
{
  char buf[8193];

  // Check pointers
  if (NULL == pKey)
    return false;
  if (NULL == psid)
    return false;

  if (strlen(pKey) > 256)
    return false;

  // Generate a random session ID
  time_t t;
  t = time(NULL);
  snprintf(buf,
           sizeof(buf),
           "__%s_%X%X%X%X_be_hungry_stay_foolish_%X%X",
           pKey,
           (unsigned int)rand(),
           (unsigned int)rand(),
           (unsigned int)rand(),
           (unsigned int)t,
           (unsigned int)rand(),
           1337);

  vscp_md5(psid, (const unsigned char*)buf, strlen(buf));

  return true;
}

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CTcpipSrv::readEncryptionKey(const std::string& path)
{
  try {
    std::ifstream in(path, std::ifstream::in);
    std::stringstream strStream;
    strStream << in.rdbuf();
    return vscp_hexStr2ByteArray(m_vscp_key, 32, strStream.str().c_str());
  }
  catch (...) {
    spdlog::error("Failed to read encryption key file [%s]", m_path.c_str());
    return false;
  }

  return true;
}
