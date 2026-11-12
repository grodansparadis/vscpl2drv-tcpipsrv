// tcpipsession.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2026 Ake Hedman, the VSCP Project
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

#if !defined(VSCP_TCPIPSESSION_H__INCLUDED_)
#define VSCP_TCPIPSESSION_H__INCLUDED_

#include <deque>
#include <string>
#include <vector>

#include <mongoose.h>

#include "clientlist.h"
#include "userlist.h"

class CTcpipSrvDrv;

#define VSCP_TCPIP_COMMAND_LIST_MAX 200 // Max number of saved old commands

#define VSCP_TCPIP_RV_OK    0
#define VSCP_TCPIP_RV_ERROR -1
#define VSCP_TCPIP_RV_CLOSE 99 // Connection should be closed.

/// Close a client connection after this many seconds without activity
#define TCPIPSRV_INACTIVITY_TIMEOUT (3600 * 12)

/// Max length of a command line. Longer lines close the connection.
#define TCPIPSRV_MAX_LINE_LENGTH (64 * 1024)

#define MSG_BINARY_MODE "+OK - Binary mode entered.\r\n"

/// Binary protocol command codes (VSCP-GBP)
#define VSCP_BINARY_CMD_NOOP          0
#define VSCP_BINARY_CMD_QUIT          1
#define VSCP_BINARY_CMD_USER          2
#define VSCP_BINARY_CMD_PASS          3
#define VSCP_BINARY_CMD_CHALLENGE     4
#define VSCP_BINARY_CMD_SEND          5
#define VSCP_BINARY_CMD_RETR          6
#define VSCP_BINARY_CMD_OPEN          7
#define VSCP_BINARY_CMD_CLOSE         8
#define VSCP_BINARY_CMD_CHKDATA       9
#define VSCP_BINARY_CMD_CLEAR         10
#define VSCP_BINARY_CMD_VERSION       16
#define VSCP_BINARY_CMD_WCYD          21
#define VSCP_BINARY_CMD_TEXT          24
#define VSCP_BINARY_CMD_EVENT_CONFIRM 0xffff

/// Max number of events returned for one binary RETR
#define VSCP_BINARY_RETR_MAX 64

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

// ----------------------------------------------------------------------------

/*!
  One client connection on the tcp/ip interface.

  All methods are called from the mongoose event loop thread of the driver,
  which owns the connection, so no locking is needed for the connection
  itself. Events from the driver reach the client through the input queue
  of its client item.
*/

class CTcpipSession {

public:
  /*!
    Create a session for an accepted connection
    @param pObj Driver object
    @param conn The mongoose connection
  */
  CTcpipSession(CTcpipSrvDrv* pObj, struct mg_connection* conn);
  ~CTcpipSession();

  /*!
    Called when the connection has been accepted. Registers the client
    and sends the welcome message.
    @return true on success, false if the connection should be closed.
  */
  bool onAccept(void);

  /*!
    Called when data has been received.
    @param buf Received data
    @param len Number of bytes
  */
  void onRead(const char* buf, size_t len);

  /*!
    Called on every poll of the event loop. Sends events in receive loop
    mode, sends keep alive messages and closes inactive connections.
  */
  void onPoll(void);

  /*!
    Called when the connection is closed. Unregisters the client.
  */
  void onClose(void);

  /// True as long as the connection can be used
  bool isOpen(void) const;

  /// Close the connection after pending data has been sent
  void close(void);

  bool write(std::string& str, bool bAddCRLF = false);
  bool write(const char* buf, size_t len);

  /*!
    When a command is received on the TCP/IP interface the command handler
    is called.
  */
  int CommandHandler(std::string& strCommand);

  bool isVerified(void);
  bool checkPrivilege(unsigned long reqiredPrivilege);
  void handleClientSend(void);
  void handleClientReceive(void);
  bool sendOneEventFromQueue(bool bStatusMsg = true);
  void handleClientDataAvailable(void);
  void handleClientClearInputQueue(void);
  void handleClientGetStatistics(void);
  void handleClientGetStatus(void);
  void handleClientGetChannelGUID(void);
  void handleClientSetChannelGUID(void);
  void handleClientGetVersion(void);
  void handleClientSetFilter(void);
  void handleClientSetMask(void);
  void handleClientUser(void);
  bool handleClientPassword(void);
  void handleChallenge(void);
  void handleClientGetChannelID(void);
  void handleClientRcvLoop(void);
  void handleClientHelp(void);
  void handleClientTest(void);
  void handleClientRestart(void);
  void handleClientShutdown(void);
  void handleClientRemote(void);
  void handleClientInterface(void);
  void handleClientInterface_List(void);
  void handleClientInterface_Unique(void);
  void handleClientInterface_Normal(void);
  void handleClientInterface_Close(void);
  void handleClientCapabilityRequest(void);
  void handleClientMeasurement(void);

  /// Remote address as a string
  std::string getRemoteAddress(void) const;

  /// Text command BINARY: switch the connection to binary mode
  void handleClientBinary(void);

  /// Capabilities reported by WCYD
  uint64_t getCapabilities(void) const;

private:
  // Handle one complete command line
  bool handleLine(std::string strCommand);

  // Handle received data in text mode
  void onTextData(void);

  // Handle received data in binary mode
  void onBinaryData(const uint8_t* buf, size_t len);

  /*!
    Handle one plain binary frame (decrypted if binary mode is authenticated)
    @return false if the connection should be closed
  */
  bool handleBinaryFrame(const std::vector<uint8_t>& frame);

  // Handle a binary event frame from the client
  bool handleBinaryEvent(const std::vector<uint8_t>& frame);

  // Handle a binary command frame from the client
  bool handleBinaryCommand(const std::vector<uint8_t>& frame);

  // Send one plain binary frame, encrypted if binary mode is authenticated
  bool sendBinaryFrame(const uint8_t* frame, size_t len);

  // Send a binary reply
  bool sendBinaryReply(uint16_t command, uint16_t error, const uint8_t* arg = nullptr, size_t arg_len = 0);

  // Send an event as a binary event frame
  bool sendBinaryEvent(const vscpEvent* pEvent);

  /*!
    Take the next event for this client from its input queue. Our own events
    are skipped unless the driver is configured to receive them.
    @return Event (caller owns it) or nullptr if there is none
  */
  vscpEvent* popEvent(void);

  /*!
    Check, without writing anything, if this client may send an event
    @return VSCP_ERROR_SUCCESS if allowed, otherwise an error code
  */
  int checkSendRights(const vscpEvent* pEvent);

public:
  /// The mongoose connection (nullptr when closed)
  struct mg_connection* m_conn;

  /// Driver object
  CTcpipSrvDrv* m_pObj;

  /// Logged in client
  CClientItem* m_pClientItem;

  /// Received data not yet handled
  std::string m_strResponse;

  size_t m_rv;

  /// True when in receive loop mode
  bool m_bReceiveLoop;

  /// Command history
  std::deque<std::string> m_commandArray;

  /// True when the connection is in binary mode
  bool m_bBinaryMode;

  /// True when events are sent asynchronously in binary mode (OPEN)
  bool m_bBinaryOpen;

  /// Received binary data not yet handled
  std::vector<uint8_t> m_binaryInput;
};

#endif // VSCP_TCPIPSESSION_H__INCLUDED_
