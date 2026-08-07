// tcpipsrvdrv.h: interface for the socketcan class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
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

#if !defined(VSCPTCPIPSRVDRV_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
#define VSCPTCPIPSRVDRV_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_

#define _POSIX

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <list>
#include <string>

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#if WIN32
#else
#include <syslog.h>
#include <unistd.h>
#endif
#include <time.h>

#include "clientlist.h"
#include "tcpipsrv.h"
#include <canal-macro.h>
#include <canal.h>
#include <dllist.h>
#include <guid.h>
#include <vscp.h>
#include <vscpremotetcpif.h>

#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/spdlog.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

const uint16_t MAX_ITEMS_IN_QUEUE = 32000;

#define DRIVER_COPYRIGHT                                                       \
  "Copyright © 2000-2025 Ake Hedman, the VSCP Project, https://www.vscp.org"

// Seconds before trying to reconnect to a broken connection
#define VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME 30

#define VSCP_TCPIPLINK_SYSLOG_DRIVER_ID "[vscpl2drv-tcpipsrv] "
// #define VSCP_LEVEL2_DLL_LOGGER_OBJ_MUTEX                                       \
//     "___VSCP__DLL_L2TCPIPLINKSRV_OBJ_MUTEX____"
#define VSCP_SOCKETCAN_LIST_MAX_MSG 2048
#ifndef __VSCP_DEBUG_TCP
#define __VSCP_DEBUG_TCP 0
#endif

// Module Local HLO op's
#define HLO_OP_LOCAL_CONNECT    HLO_OP_USER_DEFINED + 0
#define HLO_OP_LOCAL_DISCONNECT HLO_OP_USER_DEFINED + 1

// Forward declarations
// class CWrkSendTread;
// class CWrkReceiveTread;
class CHLO;
class CClientItem;

class CTcpipSrvDrv {
public:
  /// Constructor
  CTcpipSrvDrv();
  /// Destructor
  virtual ~CTcpipSrvDrv();

  /*!
      Open
      @return True on success.
   */
  bool open(std::string& path, const uint8_t* pguid);

  /*! Close driver */
  void close(void);

  /*!
    Load configuration if allowed to do so
    @param path Oath to configuration file
    @return True on success, false on failure.
  */
  bool doLoadConfig(std::string& path);

  /*!
    Save configuration if allowed to do so
  */
  bool doSaveConfig(void);

  /*! Send event to all connected clients */
  bool sendEventAllClients(const vscpEvent* pEvent);

  bool handleHLO(vscpEvent* pEvent);
  bool readVariable(vscpEventEx& ex, const json& json_req);
  bool writeVariable(vscpEventEx& ex, const json& json_req);
  bool deleteVariable(vscpEventEx& ex, const json& json_req);

  bool stop(void);
  bool start(void);
  bool restart(void);

  bool eventExToReceiveQueue(vscpEventEx& ex);
  bool addEvent2SendQueue(const vscpEvent* pEvent);
  bool addEvent2ReceiveQueue(const vscpEvent* pEvent);
  bool sendEventToClient(CClientItem* pClientItem, const vscpEvent* pEvent);

  /*!
      Starting TCP/IP worker thread
      @return true on success
   */
  bool startTcpipSrvThread(void);

  /*!
      Stop the TCP/IP worker thread
      @return true on success
   */
  bool stopTcpipSrvThread(void);

  bool addClient(CClientItem* pClientItem, uint32_t id = 0);
  bool addClient(CClientItem* pClientItem, cguid& guid);
  void removeClient(CClientItem* pClientItem);
  bool generateSessionId(const char* pKey, char* psid);
  bool readEncryptionKey(const std::string& path);

  // Receive queue exposed for compatibility with the exported C API wrapper.
#ifdef WIN32
  HANDLE m_semSendQueue;
  HANDLE m_semReceiveQueue;
#else
  sem_t m_semSendQueue;
  sem_t m_semReceiveQueue;
#endif

  pthread_mutex_t m_mutexSendQueue;
  pthread_mutex_t m_mutexReceiveQueue;
  std::list<vscpEvent*> m_receiveList;

  /// * * * Getters/setters * * *

  std::string getCaPath(void) const { return m_ca_path; }
  void setCaPath(const std::string& ca_path) { m_ca_path = ca_path; }

  std::string getCertPath(void) const { return m_cert_path; }
  void setCertPath(const std::string& cert_path) { m_cert_path = cert_path; }

  std::string getKeyPath(void) const { return m_key_path; }
  void setKeyPath(const std::string& key_path) { m_key_path = key_path; }

  std::string getListeningInterface(void) const { return m_strListenInterface; }
  bool shouldQuit(void) const { return m_bQuit; }
  void requestQuit(void) { m_bQuit = true; }

private:

  /// Debug flag (gives extra debug output)
  bool m_bDebug; 

  /// Parsed Config file
  json m_j_config;

  // ------------------------------------------------------------------------

  // * * * Configuration

  /// Path to configuration file
  std::string m_pathConfig;

  // Runtime state
  bool m_bQuit;
  bool m_bReceiveOwnEvents;
  pthread_t m_tcpipListenThread;

  // Main interface/listening endpoint and config paths
  std::string m_strListenInterface;
  std::string m_strInterface;
  std::string m_path;
  std::string m_pathUsers;

  // Driver identity and protocol settings
  cguid m_guid;
  uint32_t m_responseTimeout;
  uint8_t m_vscp_key[32];

  // Filters
  vscpEventFilter m_rxfilter;
  vscpEventFilter m_txfilter;
  vscpEventFilter m_filterIn;
  vscpEventFilter m_filterOut;

  // User/client data
  CUserList m_userList;
  CClientList m_clientList;
  pthread_mutex_t m_mutex_UserList;

  // Event queues
  std::list<vscpEvent*> m_sendList;

  /// True if config is remote writable
  bool m_bWriteEnable;

  /////////////////////////////////////////////////////////
  //                      Security
  /////////////////////////////////////////////////////////

  /// Path to CA certificate
  std::string m_ca_path;

  /// Path to certificate
  std::string m_cert_path;

  /// Path to key
  std::string m_key_path;

  /////////////////////////////////////////////////////////
  //                      Logging
  /////////////////////////////////////////////////////////

  bool m_bEnableFileLog;                    // True to enable logging
  spdlog::level::level_enum m_fileLogLevel; // log level
  std::string m_fileLogPattern;             // log file pattern
  std::string m_path_to_log_file;           // Path to logfile
  uint32_t m_max_log_size;  // Max size for logfile before rotating occures
  uint16_t m_max_log_files; // Max log files to keep

  bool m_bConsoleLogEnable; // True to enable logging to console
  spdlog::level::level_enum m_consoleLogLevel; // Console log level
  std::string m_consoleLogPattern;             // Console log pattern
};

#endif // !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
