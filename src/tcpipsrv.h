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
// Grodans Paradis AB, <akhe@grodansparadis.com>
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

#define DRIVER_COPYRIGHT "Copyright © 2000-2021 Ake Hedman, Grodans Paradis AB, https://www.grodansparadis.com"

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
    bool open(std::string& path, const cguid& guid);

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

    /// Authorization domain
    std::string m_authDomain;

    /// Encryption key for passwords
    std::string m_vscpkey;

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
    uint8_t m_vscp_key[256] = {
        0x2d, 0xbb, 0x07, 0x9a, 0x38, 0x98, 0x5a, 0xf0, 0x0e, 0xbe, 0xef, 0xe2, 0x2f, 0x9f, 0xfa, 0x0e,
        0x7f, 0x72, 0xdf, 0x06, 0xeb, 0xe4, 0x45, 0x63, 0xed, 0xf4, 0xa1, 0x07, 0x3c, 0xab, 0xc7, 0xd4,
        0x4f, 0xb0, 0xee, 0xc1, 0x27, 0x1c, 0x7d, 0x75, 0x31, 0x61, 0x54, 0xf2, 0xc6, 0xff, 0x80, 0xb8,
        0x62, 0x7b, 0x27, 0xd9, 0xa5, 0xc1, 0xc6, 0xe8, 0x8e, 0x1c, 0xb4, 0xe8, 0xd7, 0xee, 0x4b, 0x71,
        0x1f, 0x51, 0x2b, 0x5b, 0x9e, 0x23, 0xb7, 0xee, 0xb6, 0x60, 0xd1, 0x33, 0xac, 0x32, 0x01, 0xd6,
        0x58, 0x1c, 0xb0, 0x63, 0x9a, 0x93, 0x82, 0x17, 0x11, 0x75, 0xcb, 0x14, 0xdc, 0x82, 0x8c, 0x98,
        0x28, 0x2b, 0xed, 0x75, 0x0a, 0x80, 0x59, 0xe5, 0xcf, 0x86, 0x4b, 0xb5, 0x53, 0x81, 0xaa, 0x9d,
        0xa9, 0x50, 0xb9, 0xe3, 0xce, 0x82, 0x85, 0xe1, 0xea, 0x38, 0xd2, 0x1a, 0xfc, 0x9a, 0x4a, 0xe5,
        0xca, 0x5f, 0x37, 0x52, 0x08, 0xf7, 0x2e, 0x5b, 0x91, 0x13, 0xea, 0x3f, 0x75, 0x70, 0x41, 0x5e,
        0x6e, 0xa0, 0xa6, 0x37, 0xdb, 0x18, 0x48, 0xb3, 0x84, 0x85, 0xb7, 0x10, 0x3e, 0xae, 0x80, 0x53,
        0xda, 0x6a, 0xba, 0xd0, 0x2d, 0x88, 0x20, 0x92, 0x90, 0x21, 0xeb, 0x64, 0x50, 0x3a, 0xc6, 0xfe,
        0x6a, 0x38, 0xf1, 0x40, 0x45, 0xa2, 0x16, 0x44, 0x12, 0xfa, 0xc1, 0x3e, 0x97, 0x07, 0xeb, 0x64,
        0x07, 0xb1, 0xfb, 0x01, 0xfa, 0x77, 0x1d, 0x07, 0xb5, 0x8d, 0x5c, 0x3c, 0x1d, 0x4a, 0x58, 0x4e,
        0x3e, 0xc1, 0xae, 0xbc, 0x44, 0x9e, 0xc1, 0xcb, 0xaf, 0xc0, 0x6c, 0xea, 0xed, 0xa9, 0x75, 0xf7,
        0xc9, 0x36, 0x41, 0x9a, 0x90, 0xc3, 0xf3, 0xbc, 0xc9, 0xf4, 0x41, 0x9e, 0x35, 0xe0, 0x8c, 0x50,
        0xda, 0x92, 0x80, 0xc0, 0x97, 0xd0, 0x7e, 0x7e, 0x77, 0xd5, 0x72, 0x0e, 0xfa, 0x46, 0xd3, 0x2f,
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
    //                                CLIENTS
    //**************************************************************************

    // The list with active clients. (protecting mutex in object)
    CClientList m_clientList;

    // Mutex for client queue
    pthread_mutex_t m_mutex_clientList;

    // The list of users
    CUserList m_userList;
    pthread_mutex_t m_mutex_UserList;

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
