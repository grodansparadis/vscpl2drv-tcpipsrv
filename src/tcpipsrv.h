// tcpipsrv.h: interface for the socketcan class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2021 Ake Hedman,
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

#if !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
#define VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_

#define _POSIX

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <list>
#include <string>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#if WIN32
#else
#include <syslog.h>
#include <unistd.h>
#endif
#include <time.h>

#include <canal.h>
#include <canal_macro.h>
#include <dllist.h>
#include <guid.h>
#include <vscp.h>
#include "srv.h"
#include <vscpremotetcpif.h>
#include "clientlist.h"

#include <json.hpp>  // Needs C++11  -std=c++11

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

const uint16_t MAX_ITEMS_IN_QUEUE = 32000;

#define DRIVER_COPYRIGHT "Copyright © 2000-2021 Ake Hedman, the VSCP Project, https://www.vscp.org"

// Seconds before trying to reconnect to a broken connection
#define VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME 30

#define VSCP_TCPIPLINK_SYSLOG_DRIVER_ID "[vscpl2drv-tcpipsrv] "
#define VSCP_LEVEL2_DLL_LOGGER_OBJ_MUTEX                                       \
    "___VSCP__DLL_L2TCPIPLINK_OBJ_MUTEX____"
#define VSCP_SOCKETCAN_LIST_MAX_MSG 2048

// Module Local HLO op's
#define HLO_OP_LOCAL_CONNECT      HLO_OP_USER_DEFINED + 0
#define HLO_OP_LOCAL_DISCONNECT   HLO_OP_USER_DEFINED + 1

// Forward declarations
class CWrkSendTread;
class CWrkReceiveTread;
class VscpRemoteTcpIf;
class CHLO;
class CClientItem;

class CTcpipSrv
{
  public:
    /// Constructor
    CTcpipSrv();

    /// Destructor
    virtual ~CTcpipSrv();

    /*!
        Open
        @return True on success.
     */
    bool open(std::string& path, const uint8_t* pguid);

    /*!
        Flush and close the log file
     */
    void close(void);

    /*!
      Parse HLO object
    */
    bool parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo);

    /*!
      Handle high level object
    */
    bool handleHLO(vscpEvent* pEvent);

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

    bool readVariable(vscpEventEx& ex, const json& json_req);

    bool writeVariable(vscpEventEx& ex, const json& json_req);

    bool deleteVariable(vscpEventEx& ex, const json& json_req);

    bool stop(void);

    bool start(void);

    bool restart(void);  

    /*!
        Put event on receive queue and signal
        that a new event is available

        @param ex Event to send
        @return true on success, false on failure
    */
    bool eventExToReceiveQueue(vscpEventEx& ex);

    /*!
      Add event to send queue
     */
    bool addEvent2SendQueue(const vscpEvent* pEvent);

    /*!
      Add event to receive queue
    */
    bool addEvent2ReceiveQueue(const vscpEvent* pEvent);

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

    /*!
        Add a new client to the client list

        @param Pointer to client that should be added.
        @param Normally not used but can be used to set a special
        client id.
        @return True on success.
    */
    bool addClient(CClientItem* pClientItem, uint32_t id = 0);

    /*!
        Add a new client to the client list using GUID. 

        This add client method is for drivers that specify a
        full GUID (two lsb nilled).

        @param Pointer to client that should be added.
        @param guid The guid that is used for the client. Two least
        significant bytes will be set to zero.
        @return True on success.
     */
    bool addClient(CClientItem* pClientItem, cguid& guid);

    /*!
        Remove a new client from the client list

        @param pClientItem Pointer to client that should be added.
     */
    void removeClient(CClientItem* pClientItem);

    // Send event to host
    bool sendEvent( CClientItem *pClientItem, vscpEvent *pEvent);

    /*!
      Send event to specific client

      @param pClientItem Pointer to client that should received event.
      @param pEvent Pointer to VSCP event that should be sent.
      @return True on success, false on failure.
    */
    bool sendEventToClient(CClientItem* pClientItem, const vscpEvent* pEvent);

    /*!
      Send event to all clients

      @param pEvent Pointer to VSCP event that should be sent.
      @return True on success, false on failure.
    */
    bool sendEventAllClients(const vscpEvent* pEvent);

    /*!
        Generate a random session key from a string key
        @param pKey Null terminated string key (max 255 characters)
        @param pSid Pointer to 33 byte sid that will receive sid
     */
    bool generateSessionId(const char* pKey, char* pSid);

    /*!
      Read encryption key
      @param path Path to file holding encryption key.
      @return True if read OK.
    */
    bool readEncryptionKey(const std::string& path);

  public:

    /// Parsed Config file
    json m_j_config;

    // ------------------------------------------------------------------------

    // * * * Configuration    

    /// Path to configuration file
    std::string m_path;

    /// True if config is remote writable
    bool m_bWriteEnable;
    
    /// interface to listen on
    std::string m_interface;

    /// Path to user data base (must be present)
    std::string m_pathUsers;

    /// Response timeout
    uint32_t m_responseTimeout;

    /// Filters for input/output
    vscpEventFilter m_filterIn;
    vscpEventFilter m_filterOut;

    /// TLS / SSL
    std::string m_tls_certificate;
    std::string m_tls_certificate_chain;
    bool m_tls_verify_peer;
    std::string m_tls_ca_path;
    std::string m_tls_ca_file;
    uint8_t m_tls_verify_depth;
    bool m_tls_default_verify_paths;
    std::string  m_tls_cipher_list;
    uint8_t m_tls_protocol_version;
    bool m_tls_short_trust;

    /////////////////////////////////////////////////////////
    //                      Logging
    /////////////////////////////////////////////////////////
    
    bool m_bEnableFileLog;                    // True to enable logging
    spdlog::level::level_enum m_fileLogLevel; // log level
    std::string m_fileLogPattern;             // log file pattern
    std::string m_path_to_log_file;           // Path to logfile      
    uint32_t m_max_log_size;                  // Max size for logfile before rotating occures 
    uint16_t m_max_log_files;                 // Max log files to keep

    // ------------------------------------------------------------------------

    /// Run flag
    bool m_bQuit;

    /// Our GUID
    cguid m_guid;

    /// Filter for receive
    vscpEventFilter m_rxfilter;

    /// Filter for transmitt
    vscpEventFilter m_txfilter;

    // The default random encryption key
    uint8_t m_vscp_key[32] = {
        0x2d, 0xbb, 0x07, 0x9a, 0x38, 0x98, 0x5a, 0xf0, 0x0e, 0xbe, 0xef, 0xe2, 0x2f, 0x9f, 0xfa, 0x0e,
        0x7f, 0x72, 0xdf, 0x06, 0xeb, 0xe4, 0x45, 0x63, 0xed, 0xf4, 0xa1, 0x07, 0x3c, 0xab, 0xc7, 0xd4
    };

    /////////////////////////////////////////////////////////
    //                      TCP/IP server
    /////////////////////////////////////////////////////////

    // Enable encryption on tcp/ip interface if enabled.
    // 0 = Disabled
    // 1 = AES-128
    // 2 = AES-192
    // 3 = AES-256
    uint8_t m_encryptionTcpip;

    // Data object for the tcp/ip Listen thread
    tcpipListenThreadObj* m_ptcpipSrvObject;

    // Listen thread for tcp/ip connections
    pthread_t m_tcpipListenThread;

    //**************************************************************************
    //                                USERS
    //**************************************************************************

    // The list of users
    CUserList m_userList;

    // Mutex for users
    pthread_mutex_t m_mutex_UserList;


    //**************************************************************************
    //                                CLIENTS
    //**************************************************************************

    // The list with active clients. (protecting mutex in object)
    CClientList m_clientList;

    // Mutex for client queue
    pthread_mutex_t m_mutex_clientList;

    // Queue
    std::list<vscpEvent*> m_sendList;
    std::list<vscpEvent*> m_receiveList;

    // ------------------------------------------------------------------------

    // Maximum number of events in the outgoing queue
    uint16_t m_maxItemsInClientReceiveQueue;

    /*!
        Event object to indicate that there is an event in the output queue
     */
    sem_t m_semSendQueue;
    sem_t m_semReceiveQueue;

    // Mutex to protect the output queue
    pthread_mutex_t m_mutexSendQueue;
    pthread_mutex_t m_mutexReceiveQueue;
};

#endif  // !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
