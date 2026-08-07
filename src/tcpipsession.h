// tcpipsession.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2025 Ake Hedman, the VSCP Project
// <akhe@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#if !defined(VSCP_TCPIPSRV_H__INCLUDED_)
#define VSCP_TCPIPSRV_H__INCLUDED_

#include <deque>

#include <mongoose.h>

// #include<sockettcp.h>
#include "clientlist.h"

typedef const char* (*COMMAND_METHOD)(void);

// Forward declarations
class CTcpipSessionDrv;

#define __VSCP_DEBUG_TCP 1

#define VSCP_TCPIP_SRV_RUN  0
#define VSCP_TCPIP_SRV_STOP 1

#define VSCP_TCPIP_COMMAND_LIST_MAX 200 // Max number of saved old commands

#define VSCP_TCPIP_RV_OK    0
#define VSCP_TCPIP_RV_ERROR -1
#define VSCP_TCPIP_RV_CLOSE 99 // Connection should be closed.

#define VSCP_TCP_MAX_CLIENTS 1024

#define MSG_WELCOME       "Welcome to the VSCP tcp/ip server [l2drv].\r\n"
#define MSG_OK            "+OK - Success.\r\n"
#define MSG_GOODBY        "+OK - Connection closed by client.\r\n"
#define MSG_GOODBY2       "+OK - Connection closed.\r\n"
#define MSG_USENAME_OK    "+OK - User name accepted, password please\r\n"
#define MSG_PASSWORD_OK   "+OK - Ready to work.\r\n"
#define MSG_QUEUE_CLEARED "+OK - All events cleared.\r\n"
#define MSG_RECEIVE_LOOP                                                       \
  "+OK - Receive loop entered. QUITLOOP to terminate.\r\n"
#define MSG_QUIT_LOOP "+OK - Quit receive loop.\r\n"

#define MSG_ERROR           "-OK - Error\r\n"
#define MSG_UNKNOWN_COMMAND "-OK - Unknown command\r\n"
#define MSG_PARAMETER_ERROR "-OK - Invalid parameter or format\r\n"
#define MSG_BUFFER_FULL     "-OK - Buffer Full\r\n"
#define MSG_NO_MSG          "-OK - No event(s) available\r\n"

#define MSG_PASSWORD_ERROR "-OK - Invalid username or password.\r\n"
#define MSG_NOT_ACCREDITED "-OK - Need to log in to perform this command.\r\n"
#define MSG_INVALID_USER   "-OK - Invalid user.\r\n"
#define MSG_NEED_USERNAME                                                      \
  "-OK - Need a Username before a password can be entered.\r\n"

#define MSG_MAX_NUMBER_OF_CLIENTS "-OK - Max number of clients connected.\r\n"
#define MSG_INTERNAL_ERROR        "-OK - Server Internal error.\r\n"
#define MSG_INTERNAL_MEMORY_ERROR "-OK - Internal Memory error.\r\n"
#define MSG_INVALID_REMOTE_ERROR  "-OK - Invalid or unknown peer.\r\n"

#define MSG_LOW_PRIVILEGE_ERROR                                                \
  "-OK - User need higher privilege level to perform this operation.\r\n"
#define MSG_INTERFACE_NOT_FOUND   "-OK - Interface not found.\r\n"
#define MSG_UNABLE_TO_SEND_EVENT  "-OK - Unable to send event.\r\n"
#define MSG_COMMAND_NOT_SUPPORTED "-OK - Command is not supported here.\r\n"

#define MSG_VARIABLE_NOT_DEFINED "-OK - Variable is not defined.\r\n"
#define MSG_VARIABLE_MUST_BE_EVENT_TYPE                                        \
  "-OK - Variable must be of event type.\r\n"
#define MSG_VARIABLE_NOT_STOCK                                                 \
  "-OK - Operation does not work with stock variables.\r\n"
#define MSG_VARIABLE_NO_SAVE     "-OK - Variable could not be saved.\r\n"
#define MSG_VARIABLE_NOT_NUMERIC "-OK - Variable is not numeric.\r\n"
#define MSG_VARIABLE_UNABLE_ADD  "-OK - Unable to add variable.\r\n"

#define MSG_NO_TCPIP_ERROR                                                     \
  "-OK - User does not have rights to use tcp/ip interface.\r\n"

#define MSG_NO_RIGHTS_ERROR                                                    \
  "-OK - User does not have rights to perform this operation.\r\n"

#define MSG_INTERFACE_NOT_FOUND "-OK - Interface not found.\r\n"

#define MSG_VARIABLE_NOT_DEFINED "-OK - Variable is not defined.\r\n"
#define MSG_MOT_ALLOWED_TO_SEND_EVENT                                          \
  "-OK - Not allowed to sen this event (contact admin).\r\n"
#define MSG_INVALID_PATH           "-OK - Invalid path.\r\n"
#define MSG_FAILED_TO_GENERATE_SID "-OK - Failed to generate sid.\r\n"

#define MSG_FAILED_TO_CREATE_TABLE                                             \
  "-OK - Failed to create (one or more) table(s).\r\n"
#define MSG_FAILED_TO_ADD_TABLE_TO_DB                                          \
  "-OK - Failed to add table to database.\r\n"
#define MSG_FAILED_TO_INIT_TABLE   "-OK - Failed to initialize table.\r\n"
#define MSG_FAILED_GET_TABLE_NAMES "-OK - Failed to get table names.\r\n"
#define MSG_FAILED_UNKNOWN_TABLE                                               \
  "-OK - No table with that name can be found.\r\n"
#define MSG_FAILED_TABLE_NAME_IN_USE                                           \
  "-OK - This table name is already in use.\r\n"
#define MSG_FAILED_TO_PREPARE_TABLE "-OK - Failed to prepare table search.\r\n"
#define MSG_FAILED_TO_FINALIZE_TABLE                                           \
  "-OK - Failed to finalize table search.\r\n"
#define MSG_FAILED_TO_CLEAR_TABLE  "-OK - Failed to clear table.\r\n"
#define MSG_FAILED_TO_WRITE_TABLE  "-OK - Failed to write data to table.\r\n"
#define MSG_FAILED_TO_REMOVE_TABLE "-OK - Failed to remove table.\r\n"

/*!
    Class that defines one command
*/
typedef struct {
  std::string m_strCmd;    // Command name
  uint8_t m_securityLevel; // Security level for command (0-15)
} structCommand;

// ----------------------------------------------------------------------------

/*!
    This class implement the worker thread for
    the vscpd connections on the TCP interface
*/

class CTcpipSession {

public:
  /// Constructor
  CTcpipSession(void);

  /// Destructor
  ~CTcpipSession();

  /*!
    @brief Add event to the input queue
    @param pEvent Pointer to the VSCP event to add to the input queue
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int addToInputQueue(const vscpEvent* pEvent);

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

  // Send event to host
  bool sendEvent(CClientItem* pClientItem, vscpEvent* pEvent);

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
    Check if a user has been verified
    @return true if verified, else false.
  */
  bool isVerified(void);

  /*!
    Check if a user has enough privilege
    @param reqiredPrivilege Privileges required to do operation.
    @return true if yes, else false.
  */
  bool checkPrivilege(unsigned long reqiredPrivilege);

  /*!
    Client send event
  */
  void handleClientSend(void);

  /*!
    Client receive
  */
  void handleClientReceive(void);

  /*!
    sendOneEventFromQueue
    @param 	bStatusMsg True if response messages (+OK/-OK) should be sent.
    Default.
    @return True on success/false on failure.
  */
  bool sendOneEventFromQueue(bool bStatusMsg = true);

  /*!
    @brief Send an event to a specific client
    @param pClientItem Pointer to the client item
    @param pEvent Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int sendEventToClient(CWebSockSession* pSessionItem, const vscpEvent* pEvent);

  /*!
    @brief Send an event to all connected and authorised clients
    @param pEvent Pointer to the VSCP event to send
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int sendEventAllClients(const vscpEvent* pEvent);

  ////////////////////////////////////////////////
  //           Client command handlers
  ////////////////////////////////////////////////

  /*!
    Client DataAvailable
  */
  void handleClientDataAvailable(void);

  /*!
    Client Clear Input queue
  */
  void handleClientClearInputQueue(void);

  /*!
    Client Get statistics
  */
  void handleClientGetStatistics(void);

  /*!
    Client get status
  */
  void handleClientGetStatus(void);

  /*!
    Client get channel GUID
  */
  void handleClientGetChannelGUID(void);

  /*!
    Client set channel ID
  */
  void handleClientSetChannelGUID(void);

  /*!
    Client get version
  */
  void handleClientGetVersion(void);

  /*!
    Client set filter
  */
  void handleClientSetFilter(void);

  /*!
    Client set mask
  */
  void handleClientSetMask(void);

  /*!
    Client issue user
  */
  void handleClientUser(void);

  /*!
    Client issue password
  */
  bool handleClientPassword(void);

  /*!
    Handle challenge
   */
  void handleChallenge(void);

  /*!
    Client Get channel ID
  */
  void handleClientGetChannelID(void);

  /*!
    Handle RcvLoop
  */
  void handleClientRcvLoop(void);

  /*!
    Client Help
    */
  void handleClientHelp(void);

  /*!
    Client Test
    */
  void handleClientTest(void);

  /*!
    Client Restart
  */
  void handleClientRestart(void);

  /*!
    Client Shutdown
  */
  void handleClientShutdown(void);

  /*!
    Client REMOTE command
  */
  void handleClientRemote(void);

  /*!
    Client CLIENT/INTERFACE command
  */
  void handleClientInterface(void);

  /*!
    Client INTERFACE LIST command
  */
  void handleClientInterface_List(void);

  /*!
    Client INTERFACE UNIQUE command
  */
  void handleClientInterface_Unique(void);

  /*!
    Client INTERFACE NORMAL command
  */
  void handleClientInterface_Normal(void);

  /*!
    Client INTERFACE CLOSE command
  */
  void handleClientInterface_Close(void);

  /*!
    Client WhatCanYouDo command
  */
  void handleClientCapabilityRequest(void);

  /*!
    Handle client measurement
   */
  void handleClientMeasurement(void);

  ///////////////////////////////////////////////////////
  //                    Getters / Setters
  ///////////////////////////////////////////////////////

  /*!
    @brief Get the encryption key for this session
    @return Pointer to the encryption key for this session
  */
  const uint8_t* getKey(void) { return m_key; }

  /*!
    @brief Set the encryption key for this session
    @param pKey 16 byte encryption key
  */
  void setKey(const uint8_t* pKey)
  {
    if (pKey) {
      memcpy(m_key, pKey, sizeof(m_key));
    }
    else {
      memset(m_key, 0, sizeof(m_key));
    }
  }

  int getVersion(void) { return m_version; }
  void setVersion(int version) { m_version = version; }

  int getConnState(void) { return m_conn_state; }
  void setConnState(int state) { m_conn_state = state; }

  // Get last active time
  time_t getLastActiveTime(void) { return lastActiveTime; }
  void setLastActiveTime(time_t t) { lastActiveTime = t; }

  struct mg_connection* getConnection() { return m_conn; };
  void setConnection(struct mg_connection* conn) { m_conn = conn; };

  bool isOpen(void) { return m_bOpen; };
  void setOpen(bool bOpen) { m_bOpen = bOpen; };

  vscpEventFilter* getFilter(void) { return &m_filter; };
  void setFilter(const vscpEventFilter* pfilter)
  {
    vscp_copyVSCPFilter(&m_filter, pfilter);
  };

  cguid* getGuid() { return &m_guid; };
  void setGuid(const cguid& guid) { m_guid = guid; };

  CUserItem* getUserItem(void) { return m_pUserItem; };
  void setUserItem(CUserItem* puser) { m_pUserItem = puser; };

  bool isAuthenticated(void) { return m_bAuthenticated; };
  void setAuthenticated(bool bAuthenticated)
  {
    m_bAuthenticated = bAuthenticated;
  };

  /*!
    Parse HLO object
  */
  bool parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo);

  /*!
    Handle high level object
  */
  bool handleHLO(vscpEvent* pEvent);

  /*!
    Read variable
    @param ex Event with variable read request
    @param json_req JSON request object
    @return True on success, false on failure.
  */
  bool readVariable(vscpEventEx& ex, const json& json_req);

  /*!
    Write variable
    @param ex Event with variable write request
    @param json_req JSON request object
    @return True on success, false on failure.
  */
  bool writeVariable(vscpEventEx& ex, const json& json_req);

  /*!
    Delete variable
    @param ex Event with variable delete request
    @param json_req JSON request object
    @return True on success, false on failure.
  */
  bool deleteVariable(vscpEventEx& ex, const json& json_req);

  /*!
    Set listening port
    Examples for IPv4: 80, 443s, 127.0.0.1:3128, 192.0.2.3:8080s
    Examples for IPv6: [::]:80, [::1]:80
  */
  void setListeningInterface(const std::string& str) { m_strInterface = str; };
  /*!
    Get listening port
  */
  std::string getListeningInterface(void) { return m_strInterface; };

  // Getters/setters for driver object
  void setDriverObject(CTcpipSessionDrv* pDrvObj) { m_pDrvObj = pDrvObj; };
  CTcpipSessionDrv* getDriverObject(void) { return m_pDrvObj; };

private:

  // TCP/IP client thread
  pthread_t m_tcpipClientThread;

  // Clients connected to us
  CClientList m_clientList;

  /*!
    Pointer to driver object
  */
  CTcpipSessionDrv* m_pDrvObj;

  // * * * Input queue

  // Input Queue (events directed to this client)
  std::deque<vscpEvent*> m_inputQueue;

  // Semaphore to signal that an event has been received
#ifdef WIN32
  HANDLE m_semInputQueue;
#else
  sem_t m_semInputQueue;
#endif

  // Mutex handle that is used for sharing of the client object
  pthread_mutex_t m_mutexInputQueue;

  // Max size of input queue per client
  uint16_t m_maxInputQueue; 

  /// interface to listen on
  std::string m_interface;

  /// Path to user data base (must be present)
  std::string m_pathUsers;

  /*
    If true our own sent events will be received, if
    false they will be masked. The clientid for
    the channel is used to detect from whom the events
    originates. obid will be set to this clientid if
    it is set to zero on send. The command "CHID" command
    can be used to get the clientid for the channel.
  */
  bool m_bReceiveOwnEvents;

  /// Response timeout
  uint32_t m_responseTimeout;

  /// Filters for input/output
  vscpEventFilter m_filterIn;
  vscpEventFilter m_filterOut;

  /// TLS / SSL

  // TSL certificate path for the tcp/ip server
  std::string m_ca_path;

  // TSL certificate path for the tcp/ip server
  std::string m_cert_path;

  // TSL key path for the tcp/ip server
  std::string m_key_path;

  /*!
      Logged in client
  */
  CClientItem* m_pClientItem;

  // Max size of client queues
  uint16_t m_maxClientQueueSize; 

  /// Run flag
  bool m_bQuit;

  /// Our GUID
  cguid m_guid;

  /// Filter for receive
  vscpEventFilter m_rxfilter;

  /// Filter for transmit
  vscpEventFilter m_txfilter;

  // All input is added to the receive buf. as it is
  // received. Commands are then fetched from this buffer
  // as we go
  std::string m_strResponse;

  // Saved return value for last sockettcp operation
  size_t m_rv;

  // Flag for receive loop active
  bool m_bReceiveLoop;

  // List of old commands
  std::deque<std::string> m_commandArray;

  //**************************************************************************
  //                                USERS
  //**************************************************************************

  // True if authenticated
  bool m_bAuthenticated; 

  // User item (NULL if no user)
  CUserItem* m_pUserItem;

  //**************************************************************************
  //                                CLIENTS
  //**************************************************************************

  // Client item (NULL if no client)
  CClientItem* m_pClientItem; 

  // Time when this session was last active.
  time_t lastActiveTime;

  // ------------------------------------------------------------------------
  //                      Send and receive queues
  // ------------------------------------------------------------------------

  // Maximum number of events in the outgoing queue
  uint16_t m_maxItemsInClientReceiveQueue;

#ifdef WIN32
  HANDLE m_semReceiveQueue;
  HANDLE m_semSendQueue;
#else
  sem_t m_semReceiveQueue;
  sem_t m_semSendQueue;
#endif

  // Mutex to protect the output queue
  pthread_mutex_t m_mutexSendQueue;
  pthread_mutex_t m_mutexReceiveQueue;

  // Queues
  std::list<vscpEvent*> m_sendQueue;
  std::list<vscpEvent*> m_receiveQueue;

  /////////////////////////////////////////////////////////
  //                      TCP/IP server
  /////////////////////////////////////////////////////////

  /*!
    Interface GUID

    The GUID for a client have the following form MSB -> LSB

    0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFD ip-address ip-address ip-address
    ip-address Client-ID Client-ID 0 0

    ip-address ver 4 interface IP address
    Client-ID mapped id for this client

    This is the default address and it can be changed by the client
    application
  */
  cguid m_guid;

  // Enable encryption on tcp/ip interface if enabled.
  // 0 = Disabled
  // 1 = AES-128
  // 2 = AES-192
  // 3 = AES-256
  uint8_t m_encryption;

  // Encryption key
  uint8_t m_key[32] = { 0x2d, 0xbb, 0x07, 0x9a, 0x38, 0x98, 0x5a, 0xf0,
                        0x0e, 0xbe, 0xef, 0xe2, 0x2f, 0x9f, 0xfa, 0x0e,
                        0x7f, 0x72, 0xdf, 0x06, 0xeb, 0xe4, 0x45, 0x63,
                        0xed, 0xf4, 0xa1, 0x07, 0x3c, 0xab, 0xc7, 0xd4 };

  // Mongoose event manager
  struct mg_mgr m_mgr;

  // Worker thread for tcp/ip connections
  pthread_t m_tcpipListenThread;
};

#endif
